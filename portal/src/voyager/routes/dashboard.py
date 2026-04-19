from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from voyager import db
from voyager.ss_config import client_config

router = APIRouter()
_template_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_template_dir))


async def _get_current_user(request: Request):
    """Return the current user or None if not authenticated."""
    session_token = request.cookies.get("session")
    if not session_token:
        return None
    session = await db.get_valid_session(request.state.db, session_token)
    if session is None:
        return None
    return await db.get_user_by_id(request.state.db, session.user_id)


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = await _get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    connections = await db.list_connections(request.state.db, user_id=user.id)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"user": user, "connections": connections},
    )


@router.get("/connection/{connection_id}/config")
async def download_config(request: Request, connection_id: str):
    user = await _get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    conn = await db.get_connection_by_id(request.state.db, connection_id)
    if conn is None or conn.user_id != user.id:
        return Response(status_code=404)

    if not conn.enabled:
        return Response(status_code=404)

    domain = request.app.state.settings.domain
    config = client_config(conn, domain)
    config_json = json.dumps(config, indent=2)

    return Response(
        content=config_json,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="voyager-{re.sub(r"[^a-zA-Z0-9_-]", "_", conn.label)}.json"',
        },
    )


@router.get("/healthz")
async def healthz():
    return {"status": "ok"}
