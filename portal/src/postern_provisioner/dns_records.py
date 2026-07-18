"""Reconciler for apex/wildcard A/AAAA + CAA records.

Activated when `CERT_RENEWAL=true` or `EDGE_PROFILE=cloudflare`. Sibling of
[postern_provisioner.cert] -- both take (state, settings, runner, now) and
return the next state via a pure function. Caller persists the result.

Set-diff model: each tick computes the desired record set and diffs it against
the last-published snapshot (persisted in `DnsRecordsState.last_published`).
Records that dropped out are deleted; changed ones (IP/CAA/proxied) are re-set;
unchanged ones are left alone. This gives correct delete-on-unset (PUBLIC_IPV6
cleared -> AAAA records leave the desired set -> deleted), mta-sts retract, and
precise pruning of wildcard/mail/CAA when cert/mta are disabled, with no
per-scalar special cases. The first tick after a pre-v3 upgrade diffs against a
baseline reconstructed from the old scalar state (see `_reconstruct_legacy`).

Records published by subsystem:

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
    mta-sts.<domain>  A     <PUBLIC_IPV4>             (gray -- origin's wildcard cert serves it)
    mta-sts.<domain>  AAAA  <PUBLIC_IPV6>             (if PUBLIC_IPV6 set; also gray)

Provider invocation: shells out to the existing `postern-dns` Go binary (#113
extended it for A/AAAA/CAA). Subprocess wrapper is injectable for tests.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import subprocess
from dataclasses import dataclass

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
    edge_enabled: bool = False  # Cloudflare edge profile: apex orange-clouded (mta-sts stays gray)


# Desired records ======================================================================================================
# Historical alias: a "desired" record and a "last-published" snapshot entry share
# one shape (defined in the state module -- see dns_state.DnsRecord).
DesiredRecord = dns_state.DnsRecord


def desired_records(settings: DnsRecordsSettings) -> list[DesiredRecord]:
    """Compute the records the reconciler wants in DNS, per active subsystem.

    Stable order so logs/tests are deterministic. AAAA records appear iff
    `public_ipv6` is non-empty. Groups:
      apex A/AAAA   : cert issuance OR a Cloudflare edge profile
      wildcard+CAA  : cert issuance only (wildcard fronts sub-hosts for the
                      shared cert; CAA locks issuance to LE)
      mail A/AAAA   : the MTA's MX-target host, only when the MTA runs (gray:
                      Cloudflare's proxy carries no SMTP and DANE pins the origin)
      mta-sts A/AAAA: only under an edge profile *and* the MTA -- an explicit GRAY
                      record. Never orange: CF's edge cert can't authenticate a
                      multi-level subdomain (cert wildcards are single-label), and
                      MTA-STS needs a valid public cert, not proxying;
                      the origin's *.<domain> LE cert serves it. Explicit (not left
                      to the gray *.<domain> wildcard) so it exists even in BYO-cert
                      edge deployments that publish no wildcard.
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
        # Gray, never orange -- see the mta-sts note in this function's docstring.
        out.append(DesiredRecord(name=f"mta-sts.{domain}", type="A", args=(v4, )))
        if v6:
            out.append(DesiredRecord(name=f"mta-sts.{domain}", type="AAAA", args=(v6, )))

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
def reconcile_apex_dns(
    state: dns_state.DnsRecordsState,
    *,
    settings: DnsRecordsSettings,
    runner: PosternDnsRunner,
    now: dt.datetime | None = None,
) -> dns_state.DnsRecordsState:
    """One reconciliation tick. Pure function over (state, settings, runner, time);
    caller persists the returned state.

    Set-diff: compute the desired record set from settings and diff it against
    the last-published snapshot. A record dropping out of desired is deleted; a
    value (IP/CAA) change deletes the old content before appending the new (the
    provider APPENDS, so the old must go first); a proxied-only flip re-sets in
    place (the CF-direct PATCH flips the orange cloud). This subsumes the old
    per-scalar AAAA-unset / A-drift / mta-sts-retract special cases AND gains
    precise pruning of wildcard/mail/CAA when cert/mta are turned off.

    Errors increment consecutive_failures and keep the previous snapshot (the
    diff is idempotent, so a partial tick converges on the next).
    """
    now = now or dt.datetime.now(dt.timezone.utc)

    # The diff baseline. On a pre-v3 upgrade the snapshot is empty but the scalar
    # values were stashed: reconstruct the last-published set (evidence-attributed
    # names at the old content -- see _reconstruct_legacy) so the first v3 tick
    # deletes stale content, and re-sets -- idempotently -- every desired record
    # the scalars can't prove was published. Unattributable leftovers (published
    # by a subsystem since disabled, no evidence) are warned about, not deleted.
    if state.legacy_scalars is not None:
        last = _reconstruct_legacy(state.legacy_scalars, settings)
        _warn_unattributable_legacy(state.legacy_scalars, settings)
    else:
        last = list(state.last_published)

    new_state = dns_state.DnsRecordsState(
        schema_version=dns_state.SCHEMA_VERSION,
        last_published=last,  # seed with the current-wire view; overwritten on a clean tick
        last_reconciled_iso=state.last_reconciled_iso,
        consecutive_failures=state.consecutive_failures,
    )
    desired = desired_records(settings)

    try:
        _apply_diff(last, desired, runner)
        new_state.last_published = desired
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


def _apply_diff(last: list[DesiredRecord], desired: list[DesiredRecord], runner: PosternDnsRunner) -> None:
    """Drive the runner to converge DNS from `last` to `desired`.

    Identity is (name, type); content is (args, proxied). Deletes run before sets
    so a value change removes the stale content before the new one is appended.
    Repeated no-op deletes across ticks are cheap (postern-dns treats a 0-match
    delete as success) -- that idempotency is what makes a partial-failure tick
    safe to retry."""
    last_by_id = {(r.name, r.type): r for r in last}
    desired_by_id = {(r.name, r.type): r for r in desired}
    # desired_records / the reconstruction never emit two records at one identity.
    assert len(last_by_id) == len(last), "duplicate (name, type) in last-published snapshot"
    assert len(desired_by_id) == len(desired), "duplicate (name, type) in desired records"

    # Deletes: an identity that dropped out of desired, or whose value (args) changed.
    for ident, old in last_by_id.items():
        new = desired_by_id.get(ident)
        if new is None or new.args != old.args:
            runner.delete_record(old)
            logger.info("dns: deleted %s %s %s", old.type, old.name, " ".join(old.args))

    # Sets: a new identity, a changed value, or a proxied-only flip.
    for new in desired:
        old = last_by_id.get((new.name, new.type))
        if old is None or old.args != new.args or old.proxied != new.proxied:
            runner.set_record(new)
            logger.info(
                "dns: published %s %s %s%s", new.type, new.name, " ".join(new.args), " (proxied)" if new.proxied else ""
            )


def _legacy_evidence_names(scalars: dict, domain: str) -> set[str]:
    """FQDNs the pre-v3 scalars prove the reconciler managed:
      * a non-empty CAA  <=> cert was on   -> apex + wildcard;
      * apex_proxied     <=> edge+CF was on -> apex;
      * mta_sts_present  <=> edge+MTA was on -> apex + mta-sts."""
    names: set[str] = set()
    if scalars.get("last_published_caa"):
        names |= {domain, f"*.{domain}"}
    if scalars.get("last_published_apex_proxied"):
        names.add(domain)
    if scalars.get("last_published_mta_sts_present"):
        names |= {domain, f"mta-sts.{domain}"}
    return names


def _reconstruct_legacy(scalars: dict, settings: DnsRecordsSettings) -> list[DesiredRecord]:
    """Rebuild the last-published snapshot from a pre-v3 (scalar) state file, using
    the OLD content, so the first v3 diff converges DNS to the new desired set.

    The scalars record the live IPs/CAA/proxied/mta-sts but NOT which subsystems
    were enabled, so entries are attributed per name:
      * scalar evidence (see `_legacy_evidence_names`) -> reconstructed as
        published, at the old content;
      * currently-desired names -> reconstructed at the old content ONLY when that
        differs from the desired record; the entry then encodes a pending
        delete-old/set-new. An old-content entry EQUAL to desired is omitted so
        the migration tick re-SETs it: idempotent if it was really published,
        required if the subsystem was enabled coincident with the upgrade (an
        equal snapshot entry would suppress the first set forever). This holds on
        the failure path too -- the persisted snapshot never affirmatively claims
        an unevidenced record, so the re-set survives to the next tick.
    Names with neither evidence nor a desired counterpart are not reconstructed:
    deleting them would require guessing, so the migration leaves them and
    `reconcile_apex_dns` warns the operator instead. Each record is gated on its
    backing scalar being non-empty so a failed pre-v3 first tick (empty IP) never
    reconstructs an invalid empty-content record."""
    domain = settings.domain
    mta_sts_host = f"mta-sts.{domain}"
    v4 = str(scalars.get("last_published_ipv4", "") or "")
    v6 = str(scalars.get("last_published_ipv6", "") or "")
    caa = str(scalars.get("last_published_caa", "") or "")
    apex_proxied = bool(scalars.get("last_published_apex_proxied", False))

    desired_by_id = {(r.name, r.type): r for r in desired_records(settings)}
    evidence_names = _legacy_evidence_names(scalars, domain)
    addr_names = {r.name for r in desired_records(settings) if r.type == "A"} | evidence_names

    def _proxied_for(name: str) -> bool:
        # Only the apex and the mta-sts host ever carried the edge proxied bit.
        return apex_proxied if name in (domain, mta_sts_host) else False

    out: list[DesiredRecord] = []
    for name in sorted(addr_names):
        for type_, value in (("A", v4), ("AAAA", v6)):
            if not value:
                continue
            rec = DesiredRecord(name=name, type=type_, args=(value, ), proxied=_proxied_for(name))
            if name in evidence_names or rec != desired_by_id.get((name, type_)):
                out.append(rec)
    caa_args = _parse_caa(caa)
    if caa_args is not None:
        out.append(DesiredRecord(name=domain, type="CAA", args=caa_args))
    return out


def _warn_unattributable_legacy(scalars: dict, settings: DnsRecordsSettings) -> None:
    """One-shot, migration tick only: the pre-v3 scalars prove SOMETHING was
    published (an IP is set) but not at which names. Managed names that are
    neither currently desired nor evidence-attributed cannot be reconstructed, so
    the migration never deletes them -- tell the operator to check the zone.

    Negative evidence is deliberately NOT used to shrink the suspect set. The
    pre-v3 tick flushed its scalars only AFTER every publish in the tick
    succeeded, so `mta_sts_present=False` (or the key absent) does not prove
    mta-sts.<domain> was never published: a tick that set the mta-sts A record
    and then failed at a later set persisted False with the record live, and
    the state does not record whether edge was ever enabled. The same
    end-of-tick gating applies to `last_published_caa` (an empty CAA scalar
    cannot clear *.<domain>), and no scalar ever tracked mail.<domain>. On the
    common cert+mta (no-edge) upgrade this warns once about mta-sts.<domain> --
    a false positive whenever edge really never ran, accepted because
    suppressing it would silence exactly the leaked-record case above
    (fail-noisy beats fail-silent)."""
    if not (scalars.get("last_published_ipv4") or scalars.get("last_published_ipv6")):
        return
    domain = settings.domain
    universe = {domain, f"*.{domain}", f"mail.{domain}", f"mta-sts.{domain}"}
    desired_names = {r.name for r in desired_records(settings)}
    suspects = universe - desired_names - _legacy_evidence_names(scalars, domain)
    if not suspects:
        return
    logger.warning(
        "dns: the pre-v3 state migration cannot attribute possible leftover records at: %s. "
        "If A/AAAA records exist at these names and you did not create them yourself, they are "
        "Postern-published leftovers -- remove them from the DNS zone manually; the reconciler "
        "will not touch them.", ", ".join(sorted(suspects))
    )


def _parse_caa(caa: str) -> tuple[str, str, str] | None:
    """Parse the canonical zone-file CAA string (`0 issue "letsencrypt.org"`) the
    pre-v3 state stored back into (flags, tag, value) so the reconstructed record
    matches `desired_records`' 3-tuple shape. Returns None if empty/malformed (the
    diff then re-sets CAA fresh, which is idempotent)."""
    if not caa:
        return None
    parts = caa.split(" ", 2)
    if len(parts) != 3:
        return None
    flags, tag, value = parts
    return (flags, tag, value.strip('"'))


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
