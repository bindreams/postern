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
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CERTDIR = Path("/etc/letsencrypt")
SCHEMA_VERSION = 1


@dataclass
class DnsRecordsState:
    """State for the cert-manager-driven DNS reconciler.

    A separate file (`dns_records_state.json`) from `cert/state.json` so the
    cert state machine's schema-version handling stays uncluttered. Provisioner
    is the only writer.
    """
    schema_version: int = SCHEMA_VERSION

    # Last successfully-published IPs. Used to detect "previously set, now unset"
    # transitions so PUBLIC_IPV6 unset triggers AAAA deletion. Empty strings
    # mean "never published" (initial state) or "deleted" (post-unset).
    last_published_ipv4: str = ""
    last_published_ipv6: str = ""

    # Last successfully-published CAA value. Stored as the canonical zone-file
    # form ("0 issue \"letsencrypt.org\"") so a CERT_ACME_DIRECTORY flip from
    # staging to prod is a no-op (both use letsencrypt.org for CAA purposes).
    last_published_caa: str = ""

    # ISO timestamp of the last successful reconcile. Surfaces via
    # `postern dns show`; used by the healthcheck to gate first-issuance
    # ordering ("not healthy until DNS has been reconciled at least once").
    last_reconciled_iso: str | None = None

    # Per-record drift counters live here only briefly during a tick; flushing
    # them between ticks would mask transient provider hiccups. The reconciler
    # treats each tick as a fresh attempt.
    consecutive_failures: int = 0


# Persistence ==========================================================================================================
def _resolve_certdir(certdir: Path | None) -> Path:
    return DEFAULT_CERTDIR if certdir is None else certdir


def state_path(certdir: Path | None = None) -> Path:
    return _resolve_certdir(certdir) / "dns_records_state.json"


def trigger_path(certdir: Path | None = None) -> Path:
    """Operator -> provisioner: force a reconcile on the next tick.
    Same shape as the cert `.renew-cert` trigger; provisioner deletes after handling."""
    return _resolve_certdir(certdir) / ".publish-dns"


def read_state(certdir: Path | None = None) -> DnsRecordsState:
    """Read dns_records_state.json. Returns a default empty state if absent."""
    path = state_path(certdir)
    if not path.exists():
        return DnsRecordsState()

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("dns_records: state.json unreadable (%s); treating as empty", e)
        return DnsRecordsState()

    schema_version = raw.get("schema_version", 0)
    if schema_version > SCHEMA_VERSION:
        logger.warning(
            "dns_records: state.json schema_version=%d is newer than supported %d; "
            "fields we don't recognise will be ignored", schema_version, SCHEMA_VERSION
        )

    fields_known = set(DnsRecordsState.__dataclass_fields__)
    return DnsRecordsState(**{k: v for k, v in raw.items() if k in fields_known})


def write_state(state: DnsRecordsState, *, certdir: Path | None = None) -> None:
    """Atomically replace dns_records_state.json. Provisioner-only writer."""
    path = state_path(certdir)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialised = json.dumps(asdict(state), indent=2, sort_keys=True)
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
