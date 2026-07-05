"""DNS-records state for the cert manager's apex/wildcard A/AAAA + CAA publisher.

When `CERT_RENEWAL=true`, the provisioner publishes the apex/wildcard A/AAAA
records (so clients can reach <domain>) and a CAA record (locking issuance to
LE) automatically. State persisted at `/etc/letsencrypt/dns_records_state.json`
so the reconciler can detect drift (record removed at provider, IP changed) and
delete-on-unset (PUBLIC_IPV6 was set, now isn't).

The driver lives in [postern_provisioner.dns_records](../../../postern_provisioner/dns_records.py)
-- this module is just the schema + read/write, importable from both the
provisioner (writer) and the portal CLI (`postern dns show` / `verify`, reader).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CERTDIR = Path("/etc/letsencrypt")
SCHEMA_VERSION = 3

# Scalar fields written by the pre-v3 (schema 2) reconciler. read_state stashes
# whichever are present so the driver can reconstruct the v3 snapshot on upgrade.
_LEGACY_SCALAR_KEYS = (
    "last_published_ipv4",
    "last_published_ipv6",
    "last_published_caa",
    "last_published_apex_proxied",
    "last_published_mta_sts_present",
)


@dataclass(frozen=True)
class DnsRecord:
    """One DNS record the apex/cert reconciler manages -- used both as a
    "desired" record (computed from settings) and as a "last-published" snapshot
    entry (persisted, then diffed against desired next tick). Frozen so it is
    hashable.

    Defined in the state module (not the provisioner driver) so the schema can
    persist it without importing the driver; the driver re-exports it as
    `DesiredRecord`.
    """
    name: str  # FQDN
    type: str  # A | AAAA | CAA
    # Per-type payload (A: (ipv4,); AAAA: (ipv6,); CAA: (flags, tag, value)).
    args: tuple[str, ...] = ()
    # Cloudflare orange-cloud. Only meaningful for A/AAAA under DNS_PROVIDER=cloudflare.
    proxied: bool = False


@dataclass
class DnsRecordsState:
    """State for the cert-manager-driven DNS reconciler.

    A separate file (`dns_records_state.json`) from `cert/state.json` so the
    cert state machine's schema-version handling stays uncluttered. Provisioner
    is the only writer.

    Set-diff model (schema 3): `last_published` is the full snapshot of records
    the reconciler put on the wire last tick. Each tick diffs the freshly-computed
    desired set against it -- records that dropped out are deleted, changed ones
    (IP or proxied) re-set.
    """
    schema_version: int = SCHEMA_VERSION

    # Full snapshot of last-published records (the diff baseline for next tick).
    last_published: list[DnsRecord] = field(default_factory=list)

    # ISO timestamp of the last successful reconcile. Surfaces via
    # `postern dns show`; used by the healthcheck to gate first-issuance
    # ordering ("not healthy until DNS has been reconciled at least once").
    last_reconciled_iso: str | None = None

    # Per-record drift counters live here only briefly during a tick; flushing
    # them between ticks would mask transient provider hiccups. The reconciler
    # treats each tick as a fresh attempt.
    consecutive_failures: int = 0

    # Transient: populated by read_state ONLY when upgrading a pre-v3 (scalar)
    # file, carrying the old scalar values to the driver so it can reconstruct
    # `last_published` against the settings-known domain. Never persisted
    # (write_state omits it) and excluded from equality so a migrated read still
    # compares equal to a fresh write on the fields that matter.
    legacy_scalars: dict[str, object] | None = field(default=None, compare=False, repr=False)


# Persistence ==========================================================================================================
def _resolve_certdir(certdir: Path | None) -> Path:
    return DEFAULT_CERTDIR if certdir is None else certdir


def state_path(certdir: Path | None = None) -> Path:
    return _resolve_certdir(certdir) / "dns_records_state.json"


def trigger_path(certdir: Path | None = None) -> Path:
    """Operator -> provisioner: force a reconcile on the next tick.
    Same shape as the cert `.renew-cert` trigger; provisioner deletes after handling."""
    return _resolve_certdir(certdir) / ".publish-dns"


def _record_from_dict(d: dict) -> DnsRecord:
    """Parse one persisted snapshot entry. Unknown keys are ignored (forward-compat)
    and `args` is coerced back to a tuple so the diff's `==` matches desired records
    (JSON round-trips tuples as lists, and `[x] != (x,)` in Python)."""
    return DnsRecord(
        name=d["name"],
        type=d["type"],
        args=tuple(d.get("args", ())),
        proxied=bool(d.get("proxied", False)),
    )


def read_state(certdir: Path | None = None) -> DnsRecordsState:
    """Read dns_records_state.json. Returns a default empty state if absent.

    A pre-v3 (scalar) file has no `last_published`; its scalar values are stashed
    in the returned state's transient `legacy_scalars` so the driver can rebuild
    the snapshot against the settings-known domain on the first v3 tick.
    """
    path = state_path(certdir)
    if not path.exists():
        return DnsRecordsState()

    # Total over arbitrary file content: besides unreadable/invalid JSON, a
    # JSON-valid but malformed shape (non-object top level, non-dict snapshot
    # entry, entry missing "name"/"type") raises KeyError/TypeError/Value-
    # Error/AttributeError from the field accesses below. The provisioner
    # healthcheck calls this uncaught, so any raise would wedge first-boot
    # gating; degrade to empty instead.
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))

        schema_version = raw.get("schema_version", 0)
        if schema_version > SCHEMA_VERSION:
            logger.warning(
                "dns_records: state.json schema_version=%d is newer than supported %d; "
                "fields we don't recognise will be ignored", schema_version, SCHEMA_VERSION
            )

        if "last_published" in raw:
            last_published = [_record_from_dict(d) for d in raw["last_published"]]
            legacy_scalars = None
        else:
            # Pre-v3 scalar file: no snapshot. Carry the present scalar values so the
            # driver can reconstruct (and thus correctly diff) the last-published set.
            last_published = []
            legacy_scalars = {k: raw[k] for k in _LEGACY_SCALAR_KEYS if k in raw} or None

        return DnsRecordsState(
            schema_version=schema_version if schema_version else SCHEMA_VERSION,
            last_published=last_published,
            last_reconciled_iso=raw.get("last_reconciled_iso"),
            consecutive_failures=raw.get("consecutive_failures", 0),
            legacy_scalars=legacy_scalars,
        )
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        logger.warning("dns_records: state.json unreadable (%s); treating as empty", e)
        return DnsRecordsState()


def published_summary(state: DnsRecordsState, domain: str) -> tuple[str, str, str]:
    """(ipv4, ipv6, caa) as last published, for `postern dns show`. Reads the v3
    snapshot's apex records; falls back to the stashed pre-v3 scalars right after
    an upgrade (before the first v3 reconcile rebuilds the snapshot)."""
    if not state.last_published and state.legacy_scalars is not None:
        s = state.legacy_scalars
        return (
            str(s.get("last_published_ipv4", "") or ""),
            str(s.get("last_published_ipv6", "") or ""),
            str(s.get("last_published_caa", "") or ""),
        )
    # Prefer the apex records; fall back to any managed A/AAAA (e.g. mail. in an
    # MTA-only deployment that publishes no apex) so the IP still surfaces.
    ipv4 = ipv6 = caa = ""
    for r in state.last_published:
        if r.type == "A" and r.args and (not ipv4 or r.name == domain):
            ipv4 = r.args[0]
        elif r.type == "AAAA" and r.args and (not ipv6 or r.name == domain):
            ipv6 = r.args[0]
        elif r.type == "CAA" and r.name == domain and len(r.args) == 3:
            caa = f'{r.args[0]} {r.args[1]} "{r.args[2]}"'
    return ipv4, ipv6, caa


def write_state(state: DnsRecordsState, *, certdir: Path | None = None) -> None:
    """Atomically replace dns_records_state.json. Provisioner-only writer.

    Hand-serialises the persistent fields (never the transient `legacy_scalars`);
    `last_published` order is preserved (sort_keys only reorders object keys, not
    array elements) so the no-op diff path holds across restarts."""
    path = state_path(certdir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": state.schema_version,
        "last_published": [{
            "name": r.name,
            "type": r.type,
            "args": list(r.args),
            "proxied": r.proxied,
        } for r in state.last_published],
        "last_reconciled_iso": state.last_reconciled_iso,
        "consecutive_failures": state.consecutive_failures,
    }
    serialised = json.dumps(payload, indent=2, sort_keys=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".dns_records_state.", suffix=".json.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(serialised)
            f.write("\n")
        # Match privkey.pem's world-readable mode -- the portal CLI runs as a
        # different UID and needs to read this for `postern dns show`. See
        # CLAUDE.md `Wildcard privkey.pem is mode 0644` for the trust-boundary
        # rationale.
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
