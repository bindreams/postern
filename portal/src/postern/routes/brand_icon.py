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
_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "static" / "brand-default.svg"
_DEFAULT_BYTES = _DEFAULT_PATH.read_bytes()


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
        # Suffix allowlist must be checked BEFORE resolve() so a traversal attempt
        # like "../../../etc/passwd" never even reaches the filesystem layer.
        media_type = _ALLOWED_SUFFIXES.get(path.suffix.lower())
        if media_type is None:
            logger.warning("brand_icon: disallowed suffix for %r; serving default", raw)
            return _serve_default()
        # Resolve canonical path; FileNotFoundError -> default.
        resolved = path.resolve(strict=True)
        stat = resolved.stat()
        if stat.st_size > _MAX_BYTES:
            logger.warning("brand_icon: %s is %d bytes (> %d); serving default", resolved, stat.st_size, _MAX_BYTES)
            return _serve_default()
        data = resolved.read_bytes()
    except (OSError, ValueError):
        logger.warning("brand_icon: failed to read %r; serving default", raw, exc_info=True)
        return _serve_default()

    return Response(content=data, media_type=media_type, headers={"Cache-Control": _CACHE_CONTROL})
