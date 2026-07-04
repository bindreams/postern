"""Cloudflare edge IP-range publisher for the reverse-proxy real-IP allowlist.

Active only under EDGE_PROFILE=cloudflare (the provisioner enable-gate decides;
this module never inspects the profile). Each tick fetches Cloudflare's published
IP ranges from https://api.cloudflare.com/client/v4/ips, renders them as nginx
`set_real_ip_from` directives, and atomically replaces
`<edge_dir>/cloudflare-ranges.conf`. nginx's edge watcher (inotifyd on
IN_MOVED_TO) reloads on the rename -- which is exactly what `os.replace`
generates, provided the temp file is created in the same directory.

Pinned invariants for this subsystem:

  * NARROW exception handling, in TWO SEPARATE try blocks. The fetch stage catches
    only the network/IO family; the parse stage catches only the decode/shape
    family. An UNEXPECTED exception type (e.g. a TypeError raised while fetching)
    is NOT folded into result.error -- it propagates so the tick crashes loudly
    rather than silently looping on an unknown fault. Keeping the two stages in
    separate try blocks is load-bearing: a single try covering both families
    would let a fetch-stage TypeError be swallowed by the parse-stage catch.
  * last-known-good. On any fetch/parse failure the on-disk file is left
    untouched; nginx keeps serving the last good allowlist. A degenerate
    success=true-but-empty payload is treated as an error for the same reason --
    never wipe the allowlist to empty.
  * atomic-on-change. The file is rewritten only when the canonical rendering
    differs from what is on disk, so a reordered-but-equal payload is a no-op and
    does not churn nginx reloads. The header carries no timestamp, precisely so
    identical range sets render byte-identically.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

CF_IPS_URL = "https://api.cloudflare.com/client/v4/ips"
DEFAULT_EDGE_DIR = Path("/var/lib/postern-edge")
EDGE_RANGES_FILENAME = "cloudflare-ranges.conf"
DEFAULT_FETCH_TIMEOUT = 30.0

_HEADER = "# Managed by postern provisioner -- Cloudflare edge IP ranges. Do not edit.\n"


# Fetcher ==============================================================================================================
class CloudflareIpsFetcher:
    """Thin urllib wrapper around the public Cloudflare IPs endpoint. Swappable in tests."""

    def __init__(self, *, url: str = CF_IPS_URL, timeout: float = DEFAULT_FETCH_TIMEOUT) -> None:
        self.url = url
        self.timeout = timeout

    def fetch(self) -> str:
        req = urllib.request.Request(self.url, method="GET", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8")


# Result ===============================================================================================================
@dataclass(frozen=True)
class EdgeRangesResult:
    """Outcome of one reconcile tick.

    `error` is a formatted string (`<ExcType>: <detail>`, or the surfaced
    Cloudflare API errors/messages) for EXPECTED failures ONLY. Unexpected
    exception types propagate out of reconcile_edge_ranges instead of landing
    here, so `_try_advance_edge` can simply log `error` and still surface the
    exception type name."""
    changed: bool
    error: str | None = None
    ipv4_count: int = 0
    ipv6_count: int = 0


# Reconciler ===========================================================================================================
def edge_ranges_path(edge_dir: Path | None = None) -> Path:
    return (DEFAULT_EDGE_DIR if edge_dir is None else edge_dir) / EDGE_RANGES_FILENAME


def reconcile_edge_ranges(*, fetcher: CloudflareIpsFetcher, out_path: Path) -> EdgeRangesResult:
    """One reconcile tick. The on-disk .conf IS the state (no state.json); the
    caller persists nothing. Unexpected exception types PROPAGATE."""

    # Stage 1: fetch. NARROW catch -- only the network/IO family. Anything else
    # raised here (e.g. TypeError) propagates: crash the tick loudly.
    try:
        raw = fetcher.fetch()
    except (urllib.error.URLError, http.client.HTTPException, OSError, TimeoutError) as e:
        return EdgeRangesResult(changed=False, error=f"{type(e).__name__}: {e}")

    # Stage 2: parse + canonical numeric sort. SEPARATE try so a fetch-stage
    # out-of-family exception is not swallowed here. Catches the decode/shape
    # family (malformed JSON, wrong container types, bad CIDR strings). A
    # success=true payload SHOULD carry result.ipv4_cidrs/ipv6_cidrs, but the
    # body shape is controlled by a third party we do not own: a missing key
    # (KeyError) or wrong-typed value (TypeError) is a MALFORMED remote response,
    # so it folds into last-known-good rather than crashing every subsystem. Only
    # genuinely unexpected exception types propagate (the propagate-unexpected rule).
    try:
        payload = json.loads(raw)
        if not payload.get("success", False):
            errors = payload.get("errors") or []
            messages = payload.get("messages") or []
            return EdgeRangesResult(
                changed=False, error=f"cloudflare API success=false: errors={errors} messages={messages}"
            )
        result = payload["result"]
        ipv4 = [str(n) for n in sorted(ipaddress.IPv4Network(c) for c in result["ipv4_cidrs"])]
        ipv6 = [str(n) for n in sorted(ipaddress.IPv6Network(c) for c in result["ipv6_cidrs"])]
    except (json.JSONDecodeError, ValueError, TypeError, KeyError) as e:
        return EdgeRangesResult(changed=False, error=f"{type(e).__name__}: {e}")

    # Degenerate guard: an empty range set must never overwrite last-known-good.
    if not ipv4 and not ipv6:
        return EdgeRangesResult(changed=False, error="cloudflare returned no IP ranges (refusing to wipe allowlist)")

    rendered = _render(ipv4, ipv6)

    # Stage 3: atomic-on-change. Skip the write (and the nginx reload it triggers)
    # when the canonical rendering already matches what is on disk.
    if _read_current(out_path) == rendered:
        return EdgeRangesResult(changed=False, error=None, ipv4_count=len(ipv4), ipv6_count=len(ipv6))

    try:
        _atomic_write(out_path, rendered)
    except OSError as e:
        # A write/rename failure (disk full, perms, volume gone) is recoverable:
        # keep the last-known-good allowlist and surface a counted, warned result
        # instead of crashing the shared provisioner loop (edge has no broad except).
        return EdgeRangesResult(changed=False, error=f"{type(e).__name__}: {e}")
    return EdgeRangesResult(changed=True, error=None, ipv4_count=len(ipv4), ipv6_count=len(ipv6))


# Rendering / IO =======================================================================================================
def _render(ipv4: list[str], ipv6: list[str]) -> str:
    lines = [_HEADER]
    for cidr in ipv4:
        lines.append(f"set_real_ip_from {cidr};\n")
    for cidr in ipv6:
        lines.append(f"set_real_ip_from {cidr};\n")
    return "".join(lines)


def _read_current(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _atomic_write(path: Path, content: str) -> None:
    """Write via mkstemp + os.replace in the SAME directory as the destination.
    The rename emits IN_MOVED_TO in the watched dir -- exactly the mask nginx's
    edge watcher listens for. The temp file MUST be a sibling for os.replace to
    be a rename (cross-directory os.replace can fall back to copy+unlink and
    would emit the wrong inotify event)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".cloudflare-ranges.", suffix=".conf.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp, 0o644)  # nginx runs as a different UID and must read it
        os.replace(tmp, path)
    except OSError:
        logger.debug("edge: cleaning up temp file %s after write failure", tmp)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
