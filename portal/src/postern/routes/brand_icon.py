"""Brand-icon serving with a validated allowlist + size cap.

Templates always reference ``/brand-icon`` -- never ``/static/brand-default.svg``
directly -- so an operator can swap in a custom logo by setting
``PRODUCT_ICON_PATH`` to an absolute path of a bind-mounted SVG or PNG. The route
falls back to the built-in default for ANY failure case (missing file, oversized,
disallowed extension, path traversal, etc.) so a misconfigured operator never
takes the portal down.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import Response

logger = logging.getLogger(__name__)

# Hardcoded limits =====================================================================================================
_ALLOWED_SUFFIXES = {".svg": "image/svg+xml", ".png": "image/png"}
_MAX_BYTES = 256 * 1024  # 256 KB; larger than any sane brand icon, smaller than memory-DoS territory.
_CACHE_CONTROL = "public, max-age=3600"

router = APIRouter()

# The built-in default is read once at module import: it ships in the wheel and never
# changes at runtime. Keeping it in-memory avoids a stat+read on every /brand-icon hit.
# A hard-coded 1x1 transparent SVG is used if the bundled default is missing for any
# reason (e.g. packaging regression) so the route always has SOMETHING to serve and
# importing this module never fails the whole app.
_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "static" / "brand-default.svg"
_FALLBACK_BYTES = (
    b"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1 1'>"
    b"<rect width='1' height='1' fill='none'/></svg>"
)
try:
    _DEFAULT_BYTES = _DEFAULT_PATH.read_bytes()
except OSError:
    logger.warning("brand_icon: bundled default SVG missing at %s; using transparent 1x1 fallback", _DEFAULT_PATH)
    _DEFAULT_BYTES = _FALLBACK_BYTES


def _serve_default() -> Response:
    return Response(
        content=_DEFAULT_BYTES,
        media_type="image/svg+xml",
        headers={"Cache-Control": _CACHE_CONTROL},
    )


@router.get("/brand-icon")
async def brand_icon(request: Request) -> Response:
    settings = request.app.state.settings
    raw = (settings.product_icon_path or "").strip()
    if not raw:
        return _serve_default()

    try:
        path = Path(raw)
        # Operator intent is "point at a known bind-mount path" -- never a relative
        # path against the portal's CWD, which is implementation-detail and can move
        # between releases. Refuse anything that isn't absolute up front; fall through
        # to default rather than treat the relative path as resolved-against-CWD.
        if not path.is_absolute():
            logger.warning("brand_icon: PRODUCT_ICON_PATH %r is not absolute; serving default", raw)
            return _serve_default()
        # Suffix allowlist must be checked BEFORE resolve() so a traversal attempt
        # like "../../../etc/passwd" never even reaches the filesystem layer.
        media_type = _ALLOWED_SUFFIXES.get(path.suffix.lower())
        if media_type is None:
            logger.warning("brand_icon: disallowed suffix for %r; serving default", raw)
            return _serve_default()
        # Resolve canonical path; FileNotFoundError -> default.
        resolved = path.resolve(strict=True)
        # Re-check the suffix AFTER resolution to close the symlink TOCTOU:
        # /brand/icon.svg -> /etc/passwd would otherwise pass the pre-resolve
        # check and get served with image/svg+xml content-type.
        resolved_media_type = _ALLOWED_SUFFIXES.get(resolved.suffix.lower())
        if resolved_media_type is None:
            logger.warning(
                "brand_icon: resolved path %s has disallowed suffix; refusing to serve",
                resolved,
            )
            return _serve_default()
        media_type = resolved_media_type
        stat = resolved.stat()
        if stat.st_size > _MAX_BYTES:
            logger.warning("brand_icon: %s is %d bytes (> %d); serving default", resolved, stat.st_size, _MAX_BYTES)
            return _serve_default()
        data = resolved.read_bytes()
    except (OSError, ValueError):
        logger.warning("brand_icon: failed to read %r; serving default", raw, exc_info=True)
        return _serve_default()

    return Response(content=data, media_type=media_type, headers={"Cache-Control": _CACHE_CONTROL})
