"""Reconciler for apex/wildcard A/AAAA + CAA records.

Activated when `CERT_RENEWAL=true` or `EDGE_PROFILE=cloudflare`. Sibling of
[postern_provisioner.cert] -- both take (state, settings, runner, now) and
return the next state via a pure function. Caller persists the result.

Records published by subsystem (idempotent: only writes on drift):

  cert_enabled OR edge_enabled:
    <domain>          A     <PUBLIC_IPV4>             (proxied when edge+cloudflare)
    <domain>          AAAA  <PUBLIC_IPV6>             (if PUBLIC_IPV6 set; same proxied)

  cert_enabled:
    *.<domain>        A     <PUBLIC_IPV4>             (wildcard for sub-hosts; gray)
    *.<domain>        AAAA  <PUBLIC_IPV6>             (if PUBLIC_IPV6 set)
    <domain>          CAA   0 issue "letsencrypt.org"

  mta_enabled:
    mail.<domain>     A     <PUBLIC_IPV4>             (MX target; gray -- DANE pins origin)
    mail.<domain>     AAAA  <PUBLIC_IPV6>             (if PUBLIC_IPV6 set)

  mta_enabled AND edge_enabled:
    mta-sts.<domain>  A     <PUBLIC_IPV4>             (proxied -- routes policy through CF)
    mta-sts.<domain>  AAAA  <PUBLIC_IPV6>             (if PUBLIC_IPV6 set; same proxied)

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
    public_ipv4: str  # required when the publisher runs; provisioner refuses to start without it
    public_ipv6: str = ""  # optional; empty string means "do not publish AAAA"
    caa_issuer: str = "letsencrypt.org"  # locks issuance to LE; future configurable
    # Per-subsystem enablement (computed by the entrypoint from env). The
    # reconciler publishes each record group only for the subsystems that need it.
    cert_enabled: bool = False  # wildcard A/AAAA + apex CAA
    mta_enabled: bool = False  # mail.<domain> A/AAAA (MX target host)
    edge_enabled: bool = False  # Cloudflare edge profile: apex/mta-sts orange-clouded


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
    # Cloudflare "orange cloud". Advisory: the runner only emits --proxied for
    # A/AAAA under DNS_PROVIDER=cloudflare; otherwise it is ignored on the wire.
    proxied: bool = False


def desired_records(settings: DnsRecordsSettings) -> list[DesiredRecord]:
    """Compute the records the reconciler wants in DNS, per active subsystem.

    Stable order so logs/tests are deterministic. AAAA records appear iff
    `public_ipv6` is non-empty. Groups:
      apex A/AAAA   : cert issuance OR a Cloudflare edge profile
      wildcard+CAA  : cert issuance only (wildcard fronts sub-hosts for the
                      shared cert; CAA locks issuance to LE)
      mail A/AAAA   : the MTA's MX-target host, only when the MTA runs (gray:
                      Cloudflare's proxy carries no SMTP and DANE pins the origin)
      mta-sts A/AAAA: only under an edge profile *and* the MTA -- publishes an
                      explicit orange record so the policy fetch routes through
                      Cloudflare (the gray wildcard already covers it otherwise)
    """
    out: list[DesiredRecord] = []
    domain = settings.domain
    v4 = settings.public_ipv4
    v6 = settings.public_ipv6
    # Proxied only where it is both wanted (edge) and honoured (CF provider),
    # so a misconfig never desires a state the CF-only runner can't converge.
    apex_proxied = settings.edge_enabled and settings.dns_provider == "cloudflare"

    if settings.cert_enabled or settings.edge_enabled:
        out.append(DesiredRecord(name=domain, type="A", args=(v4, ), proxied=apex_proxied))
        if v6:
            out.append(DesiredRecord(name=domain, type="AAAA", args=(v6, ), proxied=apex_proxied))

    if settings.cert_enabled:
        out.append(DesiredRecord(name=f"*.{domain}", type="A", args=(v4, )))
        if v6:
            out.append(DesiredRecord(name=f"*.{domain}", type="AAAA", args=(v6, )))
        out.append(DesiredRecord(name=domain, type="CAA", args=("0", "issue", settings.caa_issuer)))

    if settings.mta_enabled:
        out.append(DesiredRecord(name=f"mail.{domain}", type="A", args=(v4, )))
        if v6:
            out.append(DesiredRecord(name=f"mail.{domain}", type="AAAA", args=(v6, )))

    if settings.mta_enabled and settings.edge_enabled:
        out.append(DesiredRecord(name=f"mta-sts.{domain}", type="A", args=(v4, ), proxied=apex_proxied))
        if v6:
            out.append(DesiredRecord(name=f"mta-sts.{domain}", type="AAAA", args=(v6, ), proxied=apex_proxied))

    return out


# postern-dns runner ===================================================================================================
class PosternDnsRunner:
    """Thin subprocess wrapper around the postern-dns Go binary. Swappable in tests."""

    def __init__(
        self,
        *,
        bin_path: str = POSTERN_DNS_BIN,
        env: dict[str, str] | None = None,
        dns_provider: str | None = None,
    ) -> None:
        self.bin = bin_path
        self.env = env if env is not None else dict(os.environ)
        # Falls back to the same env the Go binary reads, so tests that inject a
        # bare env dict stay consistent with the subprocess it drives.
        raw = dns_provider if dns_provider is not None else self.env.get("DNS_PROVIDER", "")
        self.dns_provider = raw.strip().lower()

    def _proxied_flag(self, rec: DesiredRecord) -> list[str]:
        # --proxied is a Cloudflare-only concept and only meaningful for address
        # records. Every other provider gets nothing (byte-for-byte unchanged
        # publishing); non-address types are never proxied so there is nothing
        # to convey. Matching CF-direct POST-then-PATCH(true)/GET-then-PATCH(false).
        if self.dns_provider != "cloudflare" or rec.type not in ("A", "AAAA"):
            return []
        return [f"--proxied={'true' if rec.proxied else 'false'}"]

    def set_record(self, rec: DesiredRecord) -> None:
        """Invoke `postern-dns <type>-set <name> <args...> [--proxied=...]`. Raises on failure."""
        cmd = [self.bin, f"{rec.type.lower()}-set", rec.name, *rec.args, *self._proxied_flag(rec)]
        subprocess.run(cmd, env=self.env, check=True, capture_output=True, text=True)

    def delete_record(self, rec: DesiredRecord) -> None:
        cmd = [self.bin, f"{rec.type.lower()}-delete", rec.name, *rec.args]
        subprocess.run(cmd, env=self.env, check=True, capture_output=True, text=True)


# Reconciler ===========================================================================================================
def _managed_fqdns(state: dns_state.DnsRecordsState, domain: str) -> tuple[str, ...]:
    """FQDNs this reconciler may have published address records under, for the
    over-broad (idempotent) delete loops. The classic three are always included
    (matching pre-edge behaviour); mta-sts only when state says it was live."""
    names = [domain, f"*.{domain}", f"mail.{domain}"]
    if state.last_published_mta_sts_present:
        names.append(f"mta-sts.{domain}")
    return tuple(names)


def reconcile_apex_dns(
    state: dns_state.DnsRecordsState,
    *,
    settings: DnsRecordsSettings,
    runner: PosternDnsRunner,
    now: dt.datetime | None = None,
) -> dns_state.DnsRecordsState:
    """One reconciliation tick. Pure function over (state, settings, runner, time);
    caller persists the returned state.

    Beyond the original A/AAAA drift + AAAA delete-on-unset handling this now:
      * retracts the explicit mta-sts record when edge+mta no longer both hold,
      * republishes the apex when its proxied bit drifts (edge toggled), relying
        on the CF-direct PATCH inside `set_record` to flip the orange cloud.

    Precise pruning of wildcard/mail when cert/mta are turned off remains the
    job of the deferred set-based reconciler; scalar state can't express it
    without a per-record store.

    Errors increment consecutive_failures but don't change record state.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    new_state = dns_state.DnsRecordsState(
        schema_version=dns_state.SCHEMA_VERSION,
        last_published_ipv4=state.last_published_ipv4,
        last_published_ipv6=state.last_published_ipv6,
        last_published_caa=state.last_published_caa,
        last_published_apex_proxied=state.last_published_apex_proxied,
        last_published_mta_sts_present=state.last_published_mta_sts_present,
        last_reconciled_iso=state.last_reconciled_iso,
        consecutive_failures=state.consecutive_failures,
    )
    domain = settings.domain
    apex_managed = settings.cert_enabled or settings.edge_enabled
    apex_proxied = settings.edge_enabled and settings.dns_provider == "cloudflare"
    mta_sts_desired = settings.mta_enabled and settings.edge_enabled

    try:
        # 1. AAAA delete-on-unset --------------------------------------------------------------------------------------
        if state.last_published_ipv6 and not settings.public_ipv6:
            for fqdn in _managed_fqdns(state, domain):
                runner.delete_record(DesiredRecord(name=fqdn, type="AAAA", args=(state.last_published_ipv6, )))
                logger.info("dns: deleted AAAA %s -> %s (PUBLIC_IPV6 unset)", fqdn, state.last_published_ipv6)
            new_state.last_published_ipv6 = ""

        # 2. A drift: delete old IPv4 before publishing new ------------------------------------------------------------
        if state.last_published_ipv4 and state.last_published_ipv4 != settings.public_ipv4:
            for fqdn in _managed_fqdns(state, domain):
                runner.delete_record(DesiredRecord(name=fqdn, type="A", args=(state.last_published_ipv4, )))
                logger.info("dns: deleted stale A %s -> %s (was last_published_ipv4)", fqdn, state.last_published_ipv4)
            new_state.last_published_ipv4 = ""

        # 3. AAAA drift: delete old IPv6 before publishing new ---------------------------------------------------------
        if (state.last_published_ipv6 and settings.public_ipv6 and state.last_published_ipv6 != settings.public_ipv6):
            for fqdn in _managed_fqdns(state, domain):
                runner.delete_record(DesiredRecord(name=fqdn, type="AAAA", args=(state.last_published_ipv6, )))
                logger.info(
                    "dns: deleted stale AAAA %s -> %s (was last_published_ipv6)", fqdn, state.last_published_ipv6
                )
            new_state.last_published_ipv6 = ""

        # 4. mta-sts retract-on-disable --------------------------------------------------------------------------------
        # Published before but no longer both edge+mta: retract so a stale orange
        # record doesn't keep routing the policy host through Cloudflare.
        if state.last_published_mta_sts_present and not mta_sts_desired:
            host = f"mta-sts.{domain}"
            retract_v4 = state.last_published_ipv4 or settings.public_ipv4
            runner.delete_record(DesiredRecord(name=host, type="A", args=(retract_v4, )))
            if state.last_published_ipv6:
                runner.delete_record(DesiredRecord(name=host, type="AAAA", args=(state.last_published_ipv6, )))
            logger.info("dns: retracted %s (edge+mta no longer both enabled)", host)
            new_state.last_published_mta_sts_present = False

        # 5. Publish all desired records. Skip per-record when state already matches (value + proxied dimension). ------
        for rec in desired_records(settings):
            if _already_published(rec, new_state, domain):
                continue
            runner.set_record(rec)
            logger.info(
                "dns: published %s %s %s%s", rec.type, rec.name, " ".join(rec.args), " (proxied)" if rec.proxied else ""
            )

        # 6. Flush state from settings now that all the publishes succeeded --------------------------------------------
        new_state.last_published_ipv4 = settings.public_ipv4
        new_state.last_published_ipv6 = settings.public_ipv6
        if settings.cert_enabled:
            new_state.last_published_caa = f'0 issue "{settings.caa_issuer}"'
        if apex_managed:
            new_state.last_published_apex_proxied = apex_proxied
        new_state.last_published_mta_sts_present = mta_sts_desired
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


def _already_published(rec: DesiredRecord, state: dns_state.DnsRecordsState, domain: str) -> bool:
    """Return True if `state` already reflects this record being live in DNS.

    Name-aware so the apex and the mta-sts host (which carry the edge proxied
    dimension) are only "already published" when both the address value AND the
    proxied bit match, while gray wildcard/mail records short-circuit on value.
    A False return means "we can't prove we won't need to write", so we hand the
    call to postern-dns and let its idempotency/PATCH cover the rest."""
    if rec.type == "CAA":
        want = f'{rec.args[0]} {rec.args[1]} "{rec.args[2]}"'
        return state.last_published_caa == want
    if rec.type not in ("A", "AAAA"):
        return False
    have = state.last_published_ipv4 if rec.type == "A" else state.last_published_ipv6
    if have != rec.args[0]:
        return False
    if rec.name == f"mta-sts.{domain}":
        return state.last_published_mta_sts_present and state.last_published_apex_proxied == rec.proxied
    if rec.name == domain:  # apex carries the proxied dimension
        return state.last_published_apex_proxied == rec.proxied
    return True  # gray wildcard/mail: value match is sufficient


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
