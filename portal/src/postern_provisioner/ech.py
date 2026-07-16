"""Reconciler + state for the Cloudflare zone-level ECH setting.

Activated (via the enable-gate) only for a managed-ECH deployment:
ECH_ENABLED + EDGE_PROFILE=cloudflare + DNS_PROVIDER=cloudflare + EDGE_CF_MANAGE_ZONE_ECH.
Sibling of [postern_provisioner.dns_records]: each tick shells `postern-dns ech-set
<domain> on` (idempotent GET-then-PATCH inside the Go binary) and persists a small
state file so the provisioner healthcheck can gate startup on "the PATCH succeeded
at least once". A non-gating DoH serving-check (via postern.ech.check_apex_ech)
warns when CF is not yet publishing ech= -- it never flips the health fact.

The reconciler only ever sets ON (converge-to-ON, never auto-OFF): the toggle is
zone-WIDE and auto-reverting could break unrelated services in the zone.

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
from collections.abc import Callable
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
    ech_doh_url: str


@dataclass
class EchZoneState:
    """Persisted zone-ECH reconcile state.

    `last_enabled_ok_iso` is the health fact: non-null iff the `ech-set on` PATCH
    has succeeded at least once. `last_serving` records the last non-gating DoH
    serving result for observability (`postern ech show`)."""
    last_enabled_ok_iso: str | None = None
    consecutive_failures: int = 0
    last_error: str = ""
    last_serving: bool | None = None


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
            [self.bin, "ech-set", domain, "on"], env=self.env, check=True,
            capture_output=True, text=True, timeout=SET_ON_TIMEOUT_SECONDS,
        )


# Reconciler ===========================================================================================================
def reconcile_zone_ech(
    state: EchZoneState,
    *,
    settings: EchZoneSettings,
    runner: EchZoneRunner,
    serving_check: Callable[[str, str], str],
    now: dt.datetime | None = None,
) -> EchZoneState:
    """One reconcile tick. Pure over (state, settings, runner, serving_check, time);
    caller persists the result ONLY when it differs from the input.

    Sets zone ECH on (idempotent inside postern-dns). To avoid churning the state
    file (and any watcher of its directory), `last_enabled_ok_iso` is stamped only
    on the FIRST success or a recovery-after-failure -- a steady-state success with
    an unchanged serving result returns a state EQUAL to the input, so the caller
    writes nothing. On success it also runs a NON-gating DoH serving-check (wrapped:
    a checker exception or an `inconclusive` result leaves last_serving unchanged,
    never discarding the enablement fact or propagating).

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
        last_serving=state.last_serving,
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

    try:
        status = serving_check(settings.domain, settings.ech_doh_url)
    except Exception as e:
        logger.debug("ech: serving check raised (%s); leaving last_serving unchanged", e)
        return new
    # Only a CONFIRMED "absent" flips last_serving and warns. An "inconclusive" result
    # (transient DoH blip) leaves last_serving untouched -- coercing it to False would
    # churn the state file and emit a misleading publish-side warning for a query-side
    # failure, and is inconsistent with `ech verify`'s distinct inconclusive exit.
    if status == "present":
        new.last_serving = True
    elif status == "absent":
        new.last_serving = False
        logger.warning(
            "ech: zone ECH is enabled but the apex HTTPS record is not serving ech= yet "
            "(for %s). Clients with ech=always fail-closed until CF publishes the record; "
            "run `postern ech verify` to recheck.", settings.domain
        )
    else:  # inconclusive
        logger.debug("ech: serving check inconclusive for %s; leaving last_serving unchanged", settings.domain)
    return new


def reconcile_and_persist(
    *,
    settings: EchZoneSettings,
    runner: EchZoneRunner,
    serving_check: Callable[[str, str], str],
    state_dir: Path | None = None,
    now: dt.datetime | None = None,
) -> EchZoneState:
    """Read state, reconcile, and write ONLY when the result differs (steady-state
    no-op = no write). The one importable place the read/reconcile/write-skip glue
    is exercised, so the entrypoint's `_try_advance_ech` stays trivial."""
    state = read_state(state_dir)
    new_state = reconcile_zone_ech(state, settings=settings, runner=runner, serving_check=serving_check, now=now)
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
            last_serving=raw.get("last_serving"),
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
        "last_serving": state.last_serving,
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
