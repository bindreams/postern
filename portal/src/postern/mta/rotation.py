"""DKIM rotation state — schema, persistence, trigger files.

The provisioner container advances the state machine. The portal container
reads `state.json` (read-only mount) and writes trigger files via the
shared `postern-mta-data` volume — same pattern as the reconciler's
`.reconcile-now` trigger at [reconciler.py:163](portal/src/postern/reconciler.py).
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

DEFAULT_KEYDIR = Path("/var/lib/opendkim")
SCHEMA_VERSION = 1

State = Literal["NO_KEYS", "STABLE", "PROPAGATING", "OVERLAP", "RETIRING"]


# Schema ===============================================================================================================
@dataclass
class RotationState:
    schema_version: int = SCHEMA_VERSION
    state: State = "NO_KEYS"
    active_selectors: list[str] = field(default_factory=list)
    retiring_selector: str | None = None
    last_rotation_iso: str | None = None
    next_rotation_iso: str | None = None
    current_step_started_iso: str | None = None
    consecutive_failures: int = 0


# Persistence ==========================================================================================================
def _resolve_keydir(keydir: Path | None) -> Path:
    """Resolve a `keydir=None` argument to the module-level default.

    Default is read at call time (not at function-definition time) so
    monkeypatching ``DEFAULT_KEYDIR`` in tests / alternate runtimes works.
    """
    return DEFAULT_KEYDIR if keydir is None else keydir


def state_path(keydir: Path | None = None) -> Path:
    return _resolve_keydir(keydir) / "state.json"


def trigger_path(keydir: Path | None = None) -> Path:
    return _resolve_keydir(keydir) / ".rotate-dkim"


def reload_path(keydir: Path | None = None) -> Path:
    return _resolve_keydir(keydir) / ".reload-opendkim"


def read_state(keydir: Path | None = None) -> RotationState:
    """Read state.json. Returns a default ``NO_KEYS`` state if the file is absent.

    Newer schemas are read with best-effort: unknown fields are dropped, missing
    fields fall back to their dataclass defaults. A schema version higher than
    we know logs a warning so the operator can upgrade the portal.
    """
    path = state_path(keydir)
    if not path.exists():
        return RotationState()

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("rotation: state.json unreadable (%s); treating as NO_KEYS", e)
        return RotationState()

    schema_version = raw.get("schema_version", 0)
    if schema_version > SCHEMA_VERSION:
        logger.warning(
            "rotation: state.json schema_version=%d is newer than supported %d; "
            "fields we don't recognise will be ignored",
            schema_version,
            SCHEMA_VERSION,
        )

    fields_known = {f for f in RotationState.__dataclass_fields__}
    return RotationState(**{k: v for k, v in raw.items() if k in fields_known})


def write_state(state: RotationState, *, keydir: Path | None = None) -> None:
    """Atomically replace state.json with the given state.

    Provisioner-only — the portal CLI must never write here.
    """
    path = state_path(keydir)
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
def trigger_rotation(keydir: Path | None = None) -> Path:
    """Request the provisioner advance the DKIM rotation state machine.

    Mirrors the reconciler's `.reconcile-now` pattern: existence is the signal,
    the consumer deletes after handling, double-trigger may collapse into one
    advance — this is acceptable because the state machine is idempotent.
    """
    path = trigger_path(keydir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    return path


def trigger_opendkim_reload(keydir: Path | None = None) -> Path:
    """Provisioner -> mta. Tell the mta to HUP opendkim and re-read KeyTable/SigningTable."""
    path = reload_path(keydir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    return path


# Selector naming ======================================================================================================
def make_selector(prefix: str, *, now: dt.datetime | None = None) -> str:
    """Date-suffixed selector name: ``{prefix}-YYYY-MM``."""
    when = now if now is not None else dt.datetime.now(dt.timezone.utc)
    return f"{prefix}-{when.year:04d}-{when.month:02d}"
