"""Reconciler + state for the Cloudflare zone-level ECH setting.

Activated (via the enable-gate) only for a managed-ECH deployment:
EDGE_PROFILE=cloudflare + DNS_PROVIDER=cloudflare + EDGE_CF_MANAGE_ZONE_ECH.
Sibling of [postern_provisioner.dns_records]: each tick shells `postern-dns ech-set
<domain> on` (idempotent GET-then-PATCH inside the Go binary) and persists a small
state file so the provisioner healthcheck can gate startup on "the PATCH succeeded
at least once".

The reconciler only ever sets ON (converge-to-ON, never auto-OFF): the toggle is
zone-WIDE and auto-reverting could break unrelated services in the zone.

Verifying that CF is actually serving `ech=` is NOT done here: it needs a DoH
backend the provisioner image doesn't ship, and it is fully covered by the portal
CLI (`postern ech verify` / `doctor`, via postern.ech.check_apex_ech). The
provisioner's job is to enable ECH and report PATCH success.

State lives on /var/lib/opendkim (postern-mta-data), NOT the edge volume: the edge
volume is inotify-watched by nginx, and it is the only volume mounted by both the
provisioner (writer + healthcheck) and the portal (`ech show` reader).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

POSTERN_DNS_BIN = "/usr/local/bin/postern-dns"
DEFAULT_STATE_DIR = Path("/var/lib/opendkim")  # postern-mta-data; NOT the nginx-watched edge volume
STATE_FILENAME = "ech_zone_state.json"


# Settings + state =====================================================================================================
@dataclass
class EchZoneSettings:
    """Subset of settings the zone-ECH tick needs. Injected from the entrypoint."""
    domain: str


@dataclass
class EchZoneState:
    """Persisted zone-ECH reconcile state.

    `last_enabled_ok_iso` is the health fact: non-null iff the `ech-set on` PATCH
    has succeeded at least once. `consecutive_failures`/`last_error` track the
    current failure streak (read by the healthcheck and `postern ech show`)."""
    last_enabled_ok_iso: str | None = None
    consecutive_failures: int = 0
    last_error: str = ""


# postern-dns runner ===================================================================================================
# Bound each ech-set subprocess: the Go binary's own HTTP client is 30s/request over
# a handful of calls, but a hung child could still stall the shared tick loop -- so
# cap it (a child-process failure bound, not a retry timer). > the Go worst case.
SET_ON_TIMEOUT_SECONDS = 120


class EchZoneRunner:
    """Thin subprocess wrapper around `postern-dns ech-set`. Swappable in tests."""

    def __init__(self, *, bin_path: str = POSTERN_DNS_BIN, env: dict[str, str] | None = None) -> None:
        self.bin = bin_path
        self.env = env if env is not None else dict(os.environ)

    def set_on(self, domain: str) -> None:
        """Invoke `postern-dns ech-set <domain> on`. Raises on failure: CalledProcessError
        (non-zero exit), TimeoutExpired (hung child), or OSError (binary missing/unexecutable)."""
        subprocess.run(
            [self.bin, "ech-set", domain, "on"],
            env=self.env,
            check=True,
            capture_output=True,
            text=True,
            timeout=SET_ON_TIMEOUT_SECONDS,
        )


# Reconciler ===========================================================================================================
def reconcile_zone_ech(
    state: EchZoneState,
    *,
    settings: EchZoneSettings,
    runner: EchZoneRunner,
    now: dt.datetime | None = None,
) -> EchZoneState:
    """One reconcile tick. Pure over (state, settings, runner, time); caller persists
    the result ONLY when it differs from the input.

    Sets zone ECH on (idempotent inside postern-dns). To avoid churning the state
    file, `last_enabled_ok_iso` is stamped only on the FIRST success or a
    recovery-after-failure -- a steady-state success returns a state EQUAL to the
    input, so the caller writes nothing.

    ANY set_on failure -- non-zero exit (CalledProcessError), timeout, or a launch
    error (OSError: binary missing/unexecutable) -- is caught here and recorded into
    consecutive_failures/last_error, so the PERSISTED state (which `ech show` and the
    healthcheck read) always reflects reality; nothing escapes to the entrypoint's
    in-memory-only counter."""
    now = now or dt.datetime.now(dt.timezone.utc)
    new = EchZoneState(
        last_enabled_ok_iso=state.last_enabled_ok_iso,
        consecutive_failures=state.consecutive_failures,
        last_error=state.last_error,
    )
    try:
        runner.set_on(settings.domain)
    except (subprocess.SubprocessError, OSError) as e:
        new.consecutive_failures = state.consecutive_failures + 1
        stderr = (getattr(e, "stderr", None) or "").strip()
        new.last_error = stderr or str(e)
        logger.error(
            "ech: enabling zone ECH failed (%d consecutive): %s%s", new.consecutive_failures, e,
            f": {stderr}" if stderr else ""
        )
        return new

    if state.last_enabled_ok_iso is None or state.consecutive_failures > 0:
        new.last_enabled_ok_iso = now.isoformat()
        logger.info("ech: zone ECH enabled for %s", settings.domain)
    new.consecutive_failures = 0
    new.last_error = ""
    return new


def reconcile_and_persist(
    *,
    settings: EchZoneSettings,
    runner: EchZoneRunner,
    state_dir: Path | None = None,
    now: dt.datetime | None = None,
) -> EchZoneState:
    """Read state, reconcile, and write ONLY when the result differs (steady-state
    no-op = no write). The one importable place the read/reconcile/write-skip glue
    is exercised, so the entrypoint's `_try_advance_ech` stays trivial."""
    state = read_state(state_dir)
    new_state = reconcile_zone_ech(state, settings=settings, runner=runner, now=now)
    if new_state != state:
        write_state(new_state, state_dir=state_dir)
    return new_state


# Persistence ==========================================================================================================
def state_path(state_dir: Path | None = None) -> Path:
    return (DEFAULT_STATE_DIR if state_dir is None else state_dir) / STATE_FILENAME


def read_state(state_dir: Path | None = None) -> EchZoneState:
    """Read ech_zone_state.json; default empty state if absent. Total over bad
    content (the healthcheck calls this uncaught -- a raise would wedge gating)."""
    path = state_path(state_dir)
    if not path.exists():
        return EchZoneState()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return EchZoneState(
            last_enabled_ok_iso=raw.get("last_enabled_ok_iso"),
            consecutive_failures=raw.get("consecutive_failures", 0),
            last_error=raw.get("last_error", ""),
        )
    except (OSError, ValueError, TypeError, AttributeError) as e:
        logger.warning("ech: state.json unreadable (%s); treating as empty", e)
        return EchZoneState()


def write_state(state: EchZoneState, *, state_dir: Path | None = None) -> None:
    """Atomically replace ech_zone_state.json. Mode 0644 so the portal CLI (a
    different UID) can read it, matching dns_records_state.json."""
    path = state_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "last_enabled_ok_iso": state.last_enabled_ok_iso,
        "consecutive_failures": state.consecutive_failures,
        "last_error": state.last_error,
    }
    serialised = json.dumps(payload, indent=2, sort_keys=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".ech_zone_state.", suffix=".json.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(serialised)
            f.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
