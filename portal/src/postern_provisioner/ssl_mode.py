"""Reconciler + state for the Cloudflare zone-level SSL/TLS encryption mode.

Sibling of [postern_provisioner.ech]: each tick shells `postern-dns ssl-set <domain>
<target>` (the raise-only logic lives in cloudflare_ssl.go) and persists a small state
file so the healthcheck can gate startup on "the set succeeded at least once". Enabled
for a managed Cloudflare edge (EDGE_PROFILE=cloudflare + DNS_PROVIDER=cloudflare +
EDGE_CF_MANAGE_SSL_MODE); unlike ECH it is not gated on ECH_ENABLED.

State lives on /var/lib/opendkim (postern-mta-data), NOT the nginx-watched edge
volume: it is the only volume both the provisioner (writer + healthcheck) and the
portal (`edge ssl-status` reader) mount.
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
STATE_FILENAME = "ssl_mode_state.json"

# The modes `postern-dns ssl-set` can legitimately leave the zone in: it raises anything
# below `full` up to the target, so a success always reports `full` or `strict`. Anything
# else on stdout is a cross-process contract violation.
_LEFT_MODES = ("full", "strict")


# Settings + state =====================================================================================================
@dataclass
class SslModeSettings:
    """Subset of settings the ssl-mode tick needs. Injected from the entrypoint."""
    domain: str
    target: str  # "full" or "strict"


@dataclass
class SslModeState:
    """Persisted ssl-mode reconcile state.

    `last_set_ok_iso` is the health fact: non-null iff `ssl-set` has succeeded at
    least once. `consecutive_failures`/`last_error` track the current failure streak
    (read by the healthcheck and `edge ssl-status`). `last_observed_mode` is the mode CF
    reported the zone was LEFT in on the last success -- so `edge ssl-status` can surface
    target-vs-actual drift (e.g. target `strict` but the zone was already `full`, which
    raise-only leaves untouched)."""
    last_set_ok_iso: str | None = None
    consecutive_failures: int = 0
    last_error: str = ""
    last_observed_mode: str = ""


# postern-dns runner ===================================================================================================
# Bound each ssl-set subprocess so a hung child can't stall the shared tick loop. This
# is a child-process failure bound, not a retry timer.
SET_TIMEOUT_SECONDS = 120


class SslModeRunner:
    """Thin subprocess wrapper around `postern-dns ssl-set`. Swappable in tests."""

    def __init__(self, *, bin_path: str = POSTERN_DNS_BIN, env: dict[str, str] | None = None) -> None:
        self.bin = bin_path
        self.env = env if env is not None else dict(os.environ)

    def set(self, domain: str, target: str) -> str:
        """Invoke `postern-dns ssl-set <domain> <target>` and return the mode the zone
        was LEFT in (ssl-set prints it on stdout). Raises on failure: CalledProcessError
        (non-zero exit), TimeoutExpired (hung child), or OSError (binary missing)."""
        result = subprocess.run(
            [self.bin, "ssl-set", domain, target],
            env=self.env,
            check=True,
            capture_output=True,
            text=True,
            timeout=SET_TIMEOUT_SECONDS,
        )
        return result.stdout.strip()


# Target parsing =======================================================================================================
def parse_ssl_target(raw: str) -> str:
    """Validate EDGE_CF_SSL_MODE against the exact target set ('full'|'strict'), no case/
    whitespace normalization. Must match the portal's `_check_edge_settings` value-check
    exactly so a stray value fails loud in both containers rather than splitting the stack.
    Deliberately stricter than the `.strip().lower()` on dns_provider / edge_profile."""
    if raw in ("full", "strict"):
        return raw
    raise ValueError(f"EDGE_CF_SSL_MODE must be exactly 'full' or 'strict' (got {raw!r})")


# Reconciler ===========================================================================================================
def reconcile_ssl_mode(
    state: SslModeState,
    *,
    settings: SslModeSettings,
    runner: SslModeRunner,
    now: dt.datetime | None = None,
) -> SslModeState:
    """One reconcile tick. Pure over (state, settings, runner, time); caller persists
    the result ONLY when it differs from the input.

    Raises the zone SSL/TLS mode toward the target (idempotent inside postern-dns). To
    avoid churning the state file, `last_set_ok_iso` is stamped only on the FIRST
    success or a recovery-after-failure -- a steady-state success returns a state
    EQUAL to the input, so the caller writes nothing.

    An expected set() failure -- non-zero exit (CalledProcessError), timeout, or a
    launch error (OSError: binary missing/unexecutable) -- is caught here and recorded
    into consecutive_failures/last_error, so the PERSISTED state (read by `edge
    ssl-status` and the healthcheck) reflects it. A truly-unexpected exception (a programming bug, e.g.
    TypeError/AttributeError) deliberately propagates uncaught, so it surfaces via
    _try_advance_ssl's logger.exception with a full traceback rather than being
    misrecorded as a Cloudflare failure (matches reconcile_zone_ech)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    new = SslModeState(
        last_set_ok_iso=state.last_set_ok_iso,
        consecutive_failures=state.consecutive_failures,
        last_error=state.last_error,
        last_observed_mode=state.last_observed_mode,
    )
    try:
        observed = runner.set(settings.domain, settings.target)
    except (subprocess.SubprocessError, OSError) as e:
        new.consecutive_failures = state.consecutive_failures + 1
        stderr = (getattr(e, "stderr", None) or "").strip()
        new.last_error = stderr or str(e)
        logger.error(
            "ssl: setting zone SSL/TLS mode failed (%d consecutive): %s%s", new.consecutive_failures, e,
            f": {stderr}" if stderr else ""
        )
        return new

    # ssl-set exited 0, but re-validate its stdout: the zone is ALWAYS left at full/strict
    # (ssl-set raises anything below full up to the target). An empty/garbage/off/flexible
    # value is a cross-process contract violation (a Go-side regression, a wrapper swallowing
    # stdout) -- treat it as a FAILURE so the healthcheck goes red, rather than stamping a
    # green success on a bogus observed mode. The Go side validates via sslModeRank; this
    # mirrors that on the Python side of the subprocess boundary.
    if observed not in _LEFT_MODES:
        new.consecutive_failures = state.consecutive_failures + 1
        new.last_error = f"ssl-set returned an unexpected mode {observed!r} (expected full/strict)"
        logger.error(
            "ssl: ssl-set for %s returned an unexpected mode %r (expected full/strict); treating as a failure",
            settings.domain, observed
        )
        return new

    if state.last_set_ok_iso is None or state.consecutive_failures > 0:
        new.last_set_ok_iso = now.isoformat()
        logger.info("ssl: zone SSL/TLS mode set to at least full (target %s) for %s", settings.target, settings.domain)
    # Record the actual mode CF left the zone in (stable in steady state -> no churn). Emit a
    # best-effort heads-up the FIRST time a below-target mode is observed (an observed-mode
    # transition), deduped on the observed value so it doesn't re-fire every tick. It is NOT
    # the authoritative drift signal -- it won't re-fire if the operator later tightens the
    # target against an unchanged observed mode. The authoritative, always-accurate surface is
    # `postern edge ssl-status` (edge_cf_ssl_mode vs zone_ssl_current_mode).
    if observed != settings.target and observed != new.last_observed_mode:
        logger.warning(
            "ssl: zone %s is at %r but the configured target is %r (raise-only leaves an "
            "already-sufficient zone untouched); see `postern edge ssl-status`", settings.domain, observed,
            settings.target
        )
    new.last_observed_mode = observed
    new.consecutive_failures = 0
    new.last_error = ""
    return new


def reconcile_and_persist(
    *,
    settings: SslModeSettings,
    runner: SslModeRunner,
    state_dir: Path | None = None,
    now: dt.datetime | None = None,
) -> SslModeState:
    """Read state, reconcile, and write ONLY when the result differs (steady-state
    no-op = no write)."""
    state = read_state(state_dir)
    try:
        new_state = reconcile_ssl_mode(state, settings=settings, runner=runner, now=now)
    except Exception as e:
        # reconcile_ssl_mode only returns on EXPECTED failures; reaching here means an
        # unexpected (buggy) exception escaped. Persist a distinct internal-error record so
        # ssl-status/the healthcheck stop showing stale success, then re-raise for the traceback.
        internal = SslModeState(
            last_set_ok_iso=state.last_set_ok_iso,
            consecutive_failures=state.consecutive_failures + 1,
            last_error=f"internal error: {e!r}",
            last_observed_mode=state.last_observed_mode,
        )
        try:
            write_state(internal, state_dir=state_dir)
        except OSError as w:
            logger.error("ssl: also failed to persist internal-error state: %s", w)
        raise
    if new_state != state:
        try:
            write_state(new_state, state_dir=state_dir)
        except OSError as e:
            # A local disk/permission problem on postern-mta-data, distinct from a CF
            # failure (which reconcile_ssl_mode already logged + recorded in the state
            # it just built). Log it separately -- but do NOT claim the set succeeded:
            # this branch is also reached after a FAILED set (the failure-state differs
            # from the prior state, so new_state != state). Re-raise so the tick counts.
            logger.error("ssl: persisting ssl-mode state failed: %s", e)
            raise
    return new_state


# Persistence ==========================================================================================================
def state_path(state_dir: Path | None = None) -> Path:
    return (DEFAULT_STATE_DIR if state_dir is None else state_dir) / STATE_FILENAME


def read_state(state_dir: Path | None = None) -> SslModeState:
    """Read ssl_mode_state.json; default empty state if absent. Total over bad content
    (the healthcheck calls this uncaught -- a raise would wedge gating)."""
    path = state_path(state_dir)
    if not path.exists():
        return SslModeState()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return SslModeState(
            last_set_ok_iso=raw.get("last_set_ok_iso"),
            consecutive_failures=raw.get("consecutive_failures", 0),
            last_error=raw.get("last_error", ""),
            last_observed_mode=raw.get("last_observed_mode", ""),
        )
    except (OSError, ValueError, TypeError, AttributeError) as e:
        logger.warning("ssl: state.json unreadable (%s); treating as empty", e)
        return SslModeState()


def write_state(state: SslModeState, *, state_dir: Path | None = None) -> None:
    """Atomically replace ssl_mode_state.json. Mode 0644 so the portal CLI (a
    different UID) can read it, matching ech_zone_state.json."""
    path = state_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "last_set_ok_iso": state.last_set_ok_iso,
        "consecutive_failures": state.consecutive_failures,
        "last_error": state.last_error,
        "last_observed_mode": state.last_observed_mode,
    }
    serialised = json.dumps(payload, indent=2, sort_keys=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".ssl_mode_state.", suffix=".json.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(serialised)
            f.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError as u:
            # Surface the cleanup failure (a leaked .ssl_mode_state.*.tmp would otherwise be
            # invisible in logs), then re-raise the ORIGINAL write error below.
            logger.warning("ssl: failed to remove temp state file %s: %s", tmp, u)
        raise
