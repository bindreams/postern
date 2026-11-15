"""Cert renewal state -- schema, persistence, trigger files.

The provisioner container advances the state machine. The portal container
reads `state.json` (rw mount of postern-letsencrypt) and writes the
`.renew-cert` trigger file -- same pattern as the DKIM rotation state at
[postern.mta.rotation](rotation.py).

State machine:

    NO_CERT --(adopt: existing on-disk cert with valid SANs)--> INSTALLED
    NO_CERT --(no on-disk cert; or SAN mismatch)--> ISSUING
    ISSUING --(lego success and valid output; record pending_cert_paths and its directory)--> ISSUED_PENDING_INSTALL
    ISSUED_PENDING_INSTALL --(symlink-flip success)--> INSTALLED
    INSTALLED --(directory drift / SAN mismatch / .renew-cert; guard clear)--> ISSUING
    INSTALLED --(expiry)--> RENEWING
    RENEWING --(success and valid output)--> ISSUED_PENDING_INSTALL
    *  --(consecutive_failures >= 6)--> FAILED
    FAILED --(60-min hold-off)--> prior pre-FAILED state retried

`FAILED` is non-terminal -- after a hold-off the state machine retries
whatever it was doing when it failed. Combined with the 24-hour rate-limit
guard (refuse to call Lego if last_issued_by_directory[directory] < 24h, except when
CERT_FORCE_REISSUE=true), this self-heals through transient outages
without burning Let's Encrypt rate limits. The guard and the FAILED hold-off
are scoped to one ACME directory: a staging issuance never delays the switch
to production. The guard is checked before leaving INSTALLED (the state stays put while it is active), and a
deferral from ISSUING/RENEWING returns to INSTALLED only when a cert is installed.

`acme_directory` moves only when an install completes, so a failed switch stays visible as drift and is retried.

ISSUING and RENEWING both run `lego run`; they differ only in what moved the state machine there (expiry
for RENEWING). ISSUING, and RENEWING after an ACME directory or email change or with no attempt on record under
the configured directory, pass `--renew-force`; any other RENEWING passes Postern's own `--renew-days`, so lego
declines only a certificate of its own that is newer than the live one, which an earlier run issued before its tick
crashed.

Whatever lego leaves is validated before ISSUED_PENDING_INSTALL (`postern_provisioner.cert._lego_output_problem`): key
pair, exact SAN set, valid now, not already due. A rejected set is a failure, never installed, and lego's stored copy
is deleted so the next run issues anew.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

DEFAULT_CERTDIR = Path("/etc/letsencrypt")
DEFAULT_KEYDIR = Path("/var/lib/opendkim")
SCHEMA_VERSION = 1

State = Literal["NO_CERT", "ISSUING", "ISSUED_PENDING_INSTALL", "INSTALLED", "RENEWING", "FAILED"]


def check_renewal_days(days: int) -> None:
    """Reject a CERT_RENEWAL_DAYS_BEFORE_EXPIRY that lego misreads: it takes 0 as a third of the certificate's lifetime
    and a negative number as always renew. Shared by the portal's settings and the provisioner's."""
    if days < 1:
        raise ValueError("CERT_RENEWAL_DAYS_BEFORE_EXPIRY must be >= 1")


# Schema ===============================================================================================================
@dataclass
class CertState:
    schema_version: int = SCHEMA_VERSION
    state: State = "NO_CERT"
    not_after_iso: str | None = None
    sans: list[str] = field(default_factory=list)
    # Legacy; read only by the migration in `read_state`.
    last_issued_iso: str | None = None
    # ACME directory -> time of the last Lego attempt under it, set BEFORE calling Lego (defends rate limits).
    last_issued_by_directory: dict[str, str] = field(default_factory=dict)
    # ACME directory of the most recent Lego attempt, recorded even when the attempt's guard time is not (a discarded
    # account clears it): failures and the FAILED hold-off are counted per directory by this, not by the guard times.
    last_attempt_directory: str = ""
    last_attempt_iso: str | None = None
    last_failed_state: str | None = None  # so FAILED knows what to retry
    consecutive_failures: int = 0
    # Directory the installed cert was issued under; set only when the install completes.
    acme_directory: str = ""
    acme_account_email: str = ""  # tracks email used for Lego account; mismatch forces account dir recreate
    pending_cert_paths: dict[str,
                             str] = field(default_factory=dict)  # raw Lego output paths during ISSUED_PENDING_INSTALL
    pending_acme_directory: str = ""  # directory Lego ran under for pending_cert_paths; becomes acme_directory

    @property
    def latest_issued_iso(self) -> str | None:
        """Time of the most recent Lego attempt under any directory (display only)."""
        if not self.last_issued_by_directory:
            return None
        return max(self.last_issued_by_directory.values(), key=datetime.fromisoformat)


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

    State written before `last_issued_by_directory` or `last_attempt_directory` existed is migrated on every read until
    the provisioner writes it back (see `_migrate_legacy`, `_migrate_attempt_directory`).
    """
    path = state_path(certdir)
    if not path.exists():
        return CertState()

    # Total over arbitrary file content: besides unreadable/invalid JSON, a
    # JSON-valid but malformed shape (non-object top level, uncomparable
    # schema_version) raises KeyError/TypeError/AttributeError from the field
    # accesses below. The provisioner healthcheck calls this uncaught, so any
    # raise would wedge first-boot gating; degrade to NO_CERT instead.
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        schema_version = raw.get("schema_version", 0)
        if schema_version > SCHEMA_VERSION:
            logger.warning(
                "cert: state.json schema_version=%d is newer than supported %d; "
                "fields we don't recognise will be ignored",
                schema_version,
                SCHEMA_VERSION,
            )
        fields_known = {f for f in CertState.__dataclass_fields__}
        known = {k: v for k, v in raw.items() if k in fields_known}
        state = CertState(**known)
        if "last_issued_by_directory" not in known:
            state = _migrate_legacy(state)
        if "last_attempt_directory" not in known:
            state = _migrate_attempt_directory(state)
        return state
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        logger.warning("cert: state.json unreadable (%s); treating as NO_CERT", e)
        return CertState()


def _migrate_legacy(state: CertState) -> CertState:
    """Seed `last_issued_by_directory` from the single pre-per-directory attempt time, keyed by the state's own
    `acme_directory` (every state with a `last_issued_iso` has one)."""
    if not (state.last_issued_iso and state.acme_directory):
        return state
    return replace(state, last_issued_by_directory={state.acme_directory: state.last_issued_iso})


def _migrate_attempt_directory(state: CertState) -> CertState:
    """Seed `last_attempt_directory` from the directory with the latest guard time, which until it was recorded
    separately was what named it."""
    by_directory = state.last_issued_by_directory
    latest = max(by_directory, key=lambda d: datetime.fromisoformat(by_directory[d]), default="")
    return replace(state, last_attempt_directory=latest)


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
    """Request the provisioner force INSTALLED -> ISSUING (a `lego run` reissue) regardless of expiry.

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
