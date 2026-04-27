"""Cert renewal state -- schema, persistence, trigger files.

The provisioner container advances the state machine. The portal container
reads `state.json` (rw mount of postern-letsencrypt) and writes the
`.renew-cert` trigger file -- same pattern as the DKIM rotation state at
[postern.mta.rotation](rotation.py).

State machine:

    NO_CERT --(adopt: existing on-disk cert with valid SANs)--> INSTALLED
    NO_CERT --(no on-disk cert; or SAN mismatch)--> ISSUING
    ISSUING --(lego success; record last_issued_iso)--> ISSUED_PENDING_INSTALL
    ISSUED_PENDING_INSTALL --(symlink-flip success)--> INSTALLED
    INSTALLED --(expiry / SAN mismatch / directory drift / .renew-cert)--> RENEWING
    RENEWING --(success)--> ISSUED_PENDING_INSTALL
    *  --(consecutive_failures >= 6)--> FAILED
    FAILED --(60-min hold-off)--> prior pre-FAILED state retried

`FAILED` is non-terminal -- after a hold-off the state machine retries
whatever it was doing when it failed. Combined with the 24-hour rate-limit
guard (refuse to call Lego if last_issued_iso < 24h, except when
CERT_FORCE_REISSUE=true), this self-heals through transient outages
without burning Let's Encrypt rate limits.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

DEFAULT_CERTDIR = Path("/etc/letsencrypt")
DEFAULT_KEYDIR = Path("/var/lib/opendkim")
SCHEMA_VERSION = 1

State = Literal["NO_CERT", "ISSUING", "ISSUED_PENDING_INSTALL", "INSTALLED", "RENEWING", "FAILED"]


# Schema ===============================================================================================================
@dataclass
class CertState:
    schema_version: int = SCHEMA_VERSION
    state: State = "NO_CERT"
    not_after_iso: str | None = None
    sans: list[str] = field(default_factory=list)
    last_issued_iso: str | None = None  # set BEFORE calling Lego (defends rate limits)
    last_attempt_iso: str | None = None
    last_failed_state: str | None = None  # so FAILED knows what to retry
    consecutive_failures: int = 0
    acme_directory: str = ""
    acme_account_email: str = ""  # tracks email used for Lego account; mismatch forces account dir recreate
    pending_cert_paths: dict[str,
                             str] = field(default_factory=dict)  # raw Lego output paths during ISSUED_PENDING_INSTALL


# Persistence ==========================================================================================================
def _resolve_certdir(certdir: Path | None) -> Path:
    """Resolve a `certdir=None` argument to the module-level default.

    Default is read at call time (not at function-definition time) so
    monkeypatching ``DEFAULT_CERTDIR`` in tests / alternate runtimes works.
    """
    return DEFAULT_CERTDIR if certdir is None else certdir


def _resolve_keydir(keydir: Path | None) -> Path:
    return DEFAULT_KEYDIR if keydir is None else keydir


def state_path(certdir: Path | None = None) -> Path:
    return _resolve_certdir(certdir) / "state.json"


def trigger_path(certdir: Path | None = None) -> Path:
    return _resolve_certdir(certdir) / ".renew-cert"


def mta_tls_reload_path(keydir: Path | None = None) -> Path:
    """Provisioner -> mta. Lives on postern-mta-data (NOT the cert volume) so it
    works in both BYO and auto-renewal modes -- mta's cert volume mount is
    optional but its mta-data mount is always present."""
    return _resolve_keydir(keydir) / ".reload-mta-tls"


def read_state(certdir: Path | None = None) -> CertState:
    """Read state.json. Returns a default ``NO_CERT`` state if the file is absent.

    Newer schemas are read with best-effort: unknown fields are dropped, missing
    fields fall back to their dataclass defaults. A schema version higher than
    we know logs a warning so the operator can upgrade the portal.
    """
    path = state_path(certdir)
    if not path.exists():
        return CertState()

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("cert: state.json unreadable (%s); treating as NO_CERT", e)
        return CertState()

    schema_version = raw.get("schema_version", 0)
    if schema_version > SCHEMA_VERSION:
        logger.warning(
            "cert: state.json schema_version=%d is newer than supported %d; "
            "fields we don't recognise will be ignored",
            schema_version,
            SCHEMA_VERSION,
        )

    fields_known = {f for f in CertState.__dataclass_fields__}
    return CertState(**{k: v for k, v in raw.items() if k in fields_known})


def write_state(state: CertState, *, certdir: Path | None = None) -> None:
    """Atomically replace state.json with the given state.

    Provisioner-only -- the portal CLI must never write here. The portal's
    rw mount of /etc/letsencrypt is for the .renew-cert trigger file only.
    """
    path = state_path(certdir)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialised = json.dumps(asdict(state), indent=2, sort_keys=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".state.", suffix=".json.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(serialised)
            f.write("\n")
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# Trigger files ========================================================================================================
def trigger_renewal(certdir: Path | None = None) -> Path:
    """Request the provisioner force INSTALLED -> RENEWING regardless of expiry.

    Mirrors the DKIM rotation `.rotate-dkim` pattern: existence is the signal,
    consumer deletes after handling, double-trigger may collapse into one
    advance -- this is acceptable because the state machine is idempotent.
    """
    path = trigger_path(certdir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    return path


def trigger_mta_tls_reload(keydir: Path | None = None) -> Path:
    """Provisioner -> mta. Tell the mta to ``postfix reload`` after a cert install."""
    path = mta_tls_reload_path(keydir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    return path
