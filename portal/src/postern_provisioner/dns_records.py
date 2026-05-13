"""Reconciler for apex/wildcard A/AAAA + CAA records.

Activated when `CERT_RENEWAL=true`. Sibling of [postern_provisioner.cert] -- both
take (state, settings, runner, now) and return the next state via a pure function.
Caller persists the result.

Records published (idempotent: only writes on drift):

  <domain>          A     <PUBLIC_IPV4>
  <domain>          AAAA  <PUBLIC_IPV6>             (if PUBLIC_IPV6 set)
  *.<domain>        A     <PUBLIC_IPV4>             (wildcard for mta-sts.<dom>, etc.)
  *.<domain>        AAAA  <PUBLIC_IPV6>             (if PUBLIC_IPV6 set)
  mail.<domain>     A     <PUBLIC_IPV4>             (explicit; safer than wildcard for MX target)
  mail.<domain>     AAAA  <PUBLIC_IPV6>             (if PUBLIC_IPV6 set)
  <domain>          CAA   0 issue "letsencrypt.org"

Delete-on-unset: if state.last_published_ipv6 was non-empty and PUBLIC_IPV6 is
now unset, the reconciler issues `aaaa-delete` for each AAAA record before
clearing the state. Avoids the foot-gun where stale AAAA records keep pointing
at a stale address after a v6 -> v4-only migration.

Provider invocation: shells out to the existing `postern-dns` Go binary (#113
extended it for A/AAAA/CAA). Subprocess wrapper is injectable for tests.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import subprocess
from dataclasses import dataclass, field
from typing import Iterable

from postern.cert import dns_records as dns_state

logger = logging.getLogger(__name__)

POSTERN_DNS_BIN = "/usr/local/bin/postern-dns"


# Settings =============================================================================================================
@dataclass
class DnsRecordsSettings:
    """Subset of portal settings used by the reconciler. Injected from the
    provisioner entrypoint so this module doesn't import portal.settings (the
    provisioner image doesn't load the portal app config)."""
    domain: str
    dns_provider: str
    public_ipv4: str  # required when CERT_RENEWAL=true; provisioner refuses to start without it
    public_ipv6: str = ""  # optional; empty string means "do not publish AAAA"
    caa_issuer: str = "letsencrypt.org"  # locks issuance to LE; future configurable


# Desired records ======================================================================================================
@dataclass(frozen=True)
class DesiredRecord:
    """One record we expect to be in DNS. The reconciler maps these to
    `postern-dns <type>-set` / `<type>-delete` invocations."""
    name: str  # FQDN
    type: str  # A | AAAA | CAA
    # Per-type fields packed into a tuple so the dataclass stays hashable
    # (frozen=True). Interpretation:
    #   A    : args = (ipv4-string,)
    #   AAAA : args = (ipv6-string,)
    #   CAA  : args = (flags-str, tag, value)
    args: tuple[str, ...] = field(default_factory=tuple)


def desired_records(settings: DnsRecordsSettings) -> list[DesiredRecord]:
    """Compute the set of records the reconciler wants in DNS.

    Stable order so logs/tests are deterministic. AAAA records appear iff
    `public_ipv6` is non-empty."""
    out: list[DesiredRecord] = []
    domain = settings.domain
    v4 = settings.public_ipv4
    v6 = settings.public_ipv6

    for fqdn in (domain, f"*.{domain}", f"mail.{domain}"):
        out.append(DesiredRecord(name=fqdn, type="A", args=(v4, )))
        if v6:
            out.append(DesiredRecord(name=fqdn, type="AAAA", args=(v6, )))

    out.append(DesiredRecord(name=domain, type="CAA", args=("0", "issue", settings.caa_issuer)))
    return out


# postern-dns runner ===================================================================================================
class PosternDnsRunner:
    """Thin subprocess wrapper around the postern-dns Go binary. Swappable in tests."""

    def __init__(self, *, bin_path: str = POSTERN_DNS_BIN, env: dict[str, str] | None = None) -> None:
        self.bin = bin_path
        self.env = env if env is not None else dict(os.environ)

    def set_record(self, rec: DesiredRecord) -> None:
        """Invoke `postern-dns <type>-set <name> <args...>`. Raises CalledProcessError on failure."""
        cmd = [self.bin, f"{rec.type.lower()}-set", rec.name, *rec.args]
        subprocess.run(cmd, env=self.env, check=True, capture_output=True, text=True)

    def delete_record(self, rec: DesiredRecord) -> None:
        cmd = [self.bin, f"{rec.type.lower()}-delete", rec.name, *rec.args]
        subprocess.run(cmd, env=self.env, check=True, capture_output=True, text=True)


# Reconciler ===========================================================================================================
def reconcile_apex_dns(
    state: dns_state.DnsRecordsState,
    *,
    settings: DnsRecordsSettings,
    runner: PosternDnsRunner,
    now: dt.datetime | None = None,
) -> dns_state.DnsRecordsState:
    """One reconciliation tick. Pure function over (state, settings, runner, time);
    caller persists the returned state.

    Strategy:
      1. If state.last_published_ipv6 is non-empty and settings.public_ipv6 is empty,
         delete all AAAA records (delete-on-unset). Clear state.last_published_ipv6.
      2. If state.last_published_ipv4 differs from settings.public_ipv4, delete the
         old A records before publishing the new ones. (Avoids stale A records
         after a host migration.)
      3. Publish every desired record. The underlying `postern-dns *-set` is
         idempotent (treats provider duplicate-detection as success), so
         repeated calls when records already match are no-ops in the wrong
         direction (the provider sees an unnecessary AppendRecords call).
         For minimum churn, skip the call when state shows the value already
         published.

    Errors increment consecutive_failures but don't change record state.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    new_state = dns_state.DnsRecordsState(
        schema_version=dns_state.SCHEMA_VERSION,
        last_published_ipv4=state.last_published_ipv4,
        last_published_ipv6=state.last_published_ipv6,
        last_published_caa=state.last_published_caa,
        last_reconciled_iso=state.last_reconciled_iso,
        consecutive_failures=state.consecutive_failures,
    )
    domain = settings.domain

    try:
        # 1. AAAA delete-on-unset --------------------------------------------------------------------------------------
        if state.last_published_ipv6 and not settings.public_ipv6:
            for fqdn in (domain, f"*.{domain}", f"mail.{domain}"):
                runner.delete_record(DesiredRecord(name=fqdn, type="AAAA", args=(state.last_published_ipv6, )))
                logger.info("dns: deleted AAAA %s -> %s (PUBLIC_IPV6 unset)", fqdn, state.last_published_ipv6)
            new_state.last_published_ipv6 = ""

        # 2. A drift: delete old IPv4 before publishing new ------------------------------------------------------------
        if state.last_published_ipv4 and state.last_published_ipv4 != settings.public_ipv4:
            for fqdn in (domain, f"*.{domain}", f"mail.{domain}"):
                runner.delete_record(DesiredRecord(name=fqdn, type="A", args=(state.last_published_ipv4, )))
                logger.info("dns: deleted stale A %s -> %s (was last_published_ipv4)", fqdn, state.last_published_ipv4)
            new_state.last_published_ipv4 = ""

        # 3. AAAA drift: delete old IPv6 before publishing new ---------------------------------------------------------
        if (state.last_published_ipv6 and settings.public_ipv6 and state.last_published_ipv6 != settings.public_ipv6):
            for fqdn in (domain, f"*.{domain}", f"mail.{domain}"):
                runner.delete_record(DesiredRecord(name=fqdn, type="AAAA", args=(state.last_published_ipv6, )))
                logger.info(
                    "dns: deleted stale AAAA %s -> %s (was last_published_ipv6)", fqdn, state.last_published_ipv6
                )
            new_state.last_published_ipv6 = ""

        # 4. Publish all desired records. Skip per-record if the state already shows the same value
        # (saves a provider API call; postern-dns is idempotent but we don't pay the round-trip).
        for rec in desired_records(settings):
            if _already_published(rec, new_state):
                continue
            runner.set_record(rec)
            logger.info("dns: published %s %s %s", rec.type, rec.name, " ".join(rec.args))

        # Update state from settings now that all the publishes succeeded.
        new_state.last_published_ipv4 = settings.public_ipv4
        new_state.last_published_ipv6 = settings.public_ipv6
        new_state.last_published_caa = f'0 issue "{settings.caa_issuer}"'
        new_state.last_reconciled_iso = now.isoformat()
        new_state.consecutive_failures = 0
    except subprocess.CalledProcessError as e:
        new_state.consecutive_failures = state.consecutive_failures + 1
        stderr = (e.stderr or "").strip()
        logger.error(
            "dns: reconcile step failed (%d consecutive): %s%s", new_state.consecutive_failures, e,
            f": {stderr}" if stderr else ""
        )

    return new_state


def _already_published(rec: DesiredRecord, state: dns_state.DnsRecordsState) -> bool:
    """Return True if `state` already reflects this record being live in DNS.

    Used to skip per-record API calls when the reconciler has no work to do.
    A False return doesn't necessarily mean "we will write" -- it means "we can't
    prove we won't need to", so we hand the call to postern-dns and let its
    duplicate-detection idempotency cover the case."""
    if rec.type == "A":
        return state.last_published_ipv4 == rec.args[0]
    if rec.type == "AAAA":
        return state.last_published_ipv6 == rec.args[0]
    if rec.type == "CAA":
        want = f'{rec.args[0]} {rec.args[1]} "{rec.args[2]}"'
        return state.last_published_caa == want
    return False


# Settings validation ==================================================================================================
def validate_ipv4(s: str) -> str:
    """Parse and re-render an IPv4 string (rejects IPv6, invalid formats).
    Returns the canonical string form."""
    try:
        addr = ipaddress.IPv4Address(s)
    except ValueError as e:
        raise ValueError(f"PUBLIC_IPV4 must be a valid IPv4 address (got {s!r}): {e}") from e
    return str(addr)


def validate_ipv6(s: str) -> str:
    if not s:
        return ""
    try:
        addr = ipaddress.IPv6Address(s)
    except ValueError as e:
        raise ValueError(f"PUBLIC_IPV6 must be a valid IPv6 address (got {s!r}): {e}") from e
    return str(addr)


# Helpers ==============================================================================================================
def all_desired_fqdns(domain: str) -> Iterable[str]:
    """The set of FQDNs this reconciler manages records under. Useful for the
    `postern dns show` CLI to list-without-publish."""
    return (domain, f"*.{domain}", f"mail.{domain}")
