"""Cert renewal state -- schema, persistence, trigger files.

The provisioner container advances the state machine. The portal container
reads `state.json` (rw mount of postern-letsencrypt) and writes the
`.renew-cert` trigger file -- same pattern as the DKIM rotation state at
[postern.mta.rotation](rotation.py).

State machine:

    NO_CERT --(adopt: existing on-disk cert with valid SANs)--> INSTALLED
    NO_CERT --(no on-disk cert; or SAN mismatch)--> ISSUING
    ISSUING --(lego success; record pending_cert_paths and its directory)--> ISSUED_PENDING_INSTALL
    ISSUED_PENDING_INSTALL --(symlink-flip success)--> INSTALLED
    INSTALLED --(directory drift / SAN mismatch / .renew-cert; guard clear)--> ISSUING
    INSTALLED --(expiry)--> RENEWING
    RENEWING --(success)--> ISSUED_PENDING_INSTALL
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
State written before `last_issued_by_directory` existed is migrated by `read_state`: its `acme_directory` was
set before Lego ran and proves nothing about the installed cert, so it becomes UNKNOWN_DIRECTORY and the ordinary
drift path reissues once under the configured directory.

ISSUING runs `lego run` (always issues); RENEWING runs `lego renew --days N`
(a no-op on a cert that is not yet due, and fatal without both an account
registered for the directory and a certificate under Lego's own path), so only
the expiry path takes it, and only while both exist and the directory has not
drifted -- otherwise it falls back to `run`.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Literal, get_args

logger = logging.getLogger(__name__)

DEFAULT_CERTDIR = Path("/etc/letsencrypt")
DEFAULT_KEYDIR = Path("/var/lib/opendkim")
SCHEMA_VERSION = 1

State = Literal["NO_CERT", "ISSUING", "ISSUED_PENDING_INSTALL", "INSTALLED", "RENEWING", "FAILED"]

# `acme_directory` of an installed cert whose origin is not known: it can never equal a configured directory, so the
# ordinary directory-drift path reissues it until an install under the configured directory records the real one.
UNKNOWN_DIRECTORY = "(unknown)"


# Schema ===============================================================================================================
@dataclass
class CertState:
    schema_version: int = SCHEMA_VERSION
    state: State = "NO_CERT"
    not_after_iso: str | None = None
    sans: list[str] = field(default_factory=list)
    # Legacy: the single pre-per-directory attempt time. No longer updated; `read_state` seeds
    # `last_issued_by_directory` from it once and nothing else reads it.
    last_issued_iso: str | None = None
    # ACME directory -> time of the last Lego attempt under it, set BEFORE calling Lego (defends rate limits). Let's
    # Encrypt limits are per directory, so the 24h guard reads its own directory's entry only.
    last_issued_by_directory: dict[str, str] = field(default_factory=dict)
    last_attempt_iso: str | None = None
    last_failed_state: str | None = None  # so FAILED knows what to retry
    consecutive_failures: int = 0
    # Directory the installed cert was issued under; set when the install completes. UNKNOWN_DIRECTORY: not known.
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


def read_state(certdir: Path | None = None, *, configured_directory: str | None = None) -> CertState:
    """Read state.json. Returns a default ``NO_CERT`` state if the file is absent.

    Newer schemas are read with best-effort: unknown fields are dropped, missing
    fields fall back to their dataclass defaults. A schema version higher than
    we know logs a warning so the operator can upgrade the portal.

    State written before `last_issued_by_directory` existed is migrated on every read until the provisioner
    writes it back (see `_migrate_legacy`); `configured_directory` is the ACME directory the caller is configured
    for, which keys the legacy attempt time when the state names no directory.
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
        _check_field_types(known)
        state = CertState(**known)
        if "last_issued_by_directory" not in known:
            state = _migrate_legacy(state, configured_directory)
        return state
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        logger.warning("cert: state.json unreadable (%s); treating as NO_CERT", e)
        return CertState()


def _migrate_legacy(state: CertState, configured_directory: str | None) -> CertState:
    """Re-express state written before the per-directory attempt times in the current shape.

    The old code set `acme_directory` to the configured directory at the start of every attempt, before Lego ran, so
    a failed `renew` after a directory switch left it naming a directory the installed cert never came from. It
    therefore proves nothing about the installed cert: mark the origin unknown and the ordinary drift path reissues
    under the configured directory, once. The attempt time moves under the directory the attempt ran with (that same
    `acme_directory`, or the configured one when none was recorded), and a pending install keeps that directory too.
    A state with no recorded directory never ran Lego (an adopted BYO cert): nothing to doubt.
    """
    ran_under = state.acme_directory or configured_directory
    by_directory = dict(state.last_issued_by_directory)
    if state.last_issued_iso and ran_under:
        by_directory[ran_under] = state.last_issued_iso
    pending = state.pending_acme_directory
    if state.pending_cert_paths and not pending:
        pending = state.acme_directory
    return replace(
        state,
        last_issued_by_directory=by_directory,
        pending_acme_directory=pending,
        acme_directory=UNKNOWN_DIRECTORY if state.acme_directory else "",
    )


_STR_FIELDS = ("acme_directory", "acme_account_email", "pending_acme_directory")
_ISO_FIELDS = ("not_after_iso", "last_issued_iso", "last_attempt_iso")


def _check_aware_iso(value: object) -> None:
    """Raise unless `value` is an ISO timestamp with a UTC offset: the provisioner compares these against an aware
    `now`, and a naive one raises TypeError mid-tick."""
    if not isinstance(value, str):
        raise TypeError(f"{value!r} is not a string")
    if datetime.fromisoformat(value).tzinfo is None:
        raise ValueError(f"{value!r} has no timezone")


def _check_field_types(fields: dict) -> None:
    """Raise TypeError/ValueError unless the fields the provisioner tick dereferences have the shapes it assumes."""
    valid_states = get_args(State)
    if "state" in fields and fields["state"] not in valid_states:
        raise ValueError(f"state {fields['state']!r} is not one of {valid_states}")
    if fields.get("last_failed_state") is not None and fields["last_failed_state"] not in valid_states:
        raise ValueError(f"last_failed_state {fields['last_failed_state']!r} is not one of {valid_states}")
    failures = fields.get("consecutive_failures", 0)
    if isinstance(failures, bool) or not isinstance(failures, int):
        raise TypeError("consecutive_failures is not an integer")
    sans = fields.get("sans", [])
    if not isinstance(sans, list) or not all(isinstance(s, str) for s in sans):
        raise TypeError("sans is not a list of strings")
    for name in _STR_FIELDS:
        if name in fields and not isinstance(fields[name], str):
            raise TypeError(f"{name} is not a string")
    for name in _ISO_FIELDS:
        if fields.get(name) is not None:
            _check_aware_iso(fields[name])
    for name in ("pending_cert_paths", "last_issued_by_directory"):
        if name in fields:
            mapping = fields[name]
            if not isinstance(mapping,
                              dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()):
                raise TypeError(f"{name} is not a mapping of strings")
    for iso in fields.get("last_issued_by_directory", {}).values():
        _check_aware_iso(iso)


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
