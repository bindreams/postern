from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from postern import auth, db, email, identity

router = APIRouter()
_template_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_template_dir))


def _identity_context(request: Request) -> dict:
    """Build the template context bits shared by the login and OTP pages.

    The identity card is shown on the login/OTP screens only (the dashboard mockup
    drops it). ``geoip_attribution`` is rendered as a small MaxMind credit link
    when -- and only when -- GeoIP DBs are configured AND have produced enrichment
    on this hit; the MaxMind EULA only requires attribution where the data is in
    use, not on every page that *could* use it.
    """
    readers = getattr(request.app.state, "geoip_readers", None)
    info = identity.lookup(request, readers=readers)
    enriched = info.country_code is not None or info.city is not None or info.isp is not None or info.asn is not None
    return {
        "identity": info,
        "geoip_attribution": bool(readers and readers.db_dir is not None and enriched),
    }


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    # Redirect if already logged in
    session_token = request.cookies.get("session")
    if session_token:
        session = await db.get_valid_session(request.state.db, session_token)
        if session:
            return RedirectResponse("/", status_code=303)

    return templates.TemplateResponse(request, "login.html", {"message": None, **_identity_context(request)})


@router.post("/login")
async def login_submit(request: Request, email_addr: str = Form(alias="email")):
    settings = request.app.state.settings
    code = await auth.request_otp(request.state.db, email_addr, settings)

    if code is not None:
        success = await email.send_otp_email(email_addr, code, settings)
        if not success:
            import logging
            logging.getLogger(__name__).error("SMTP failure for OTP delivery")

    response = RedirectResponse("/login/verify", status_code=303)
    response.set_cookie("otp_email", email_addr, httponly=True, secure=True, samesite="strict", max_age=900)
    return response


@router.get("/login/verify", response_class=HTMLResponse)
async def verify_page(request: Request):
    email_addr = request.cookies.get("otp_email", "")
    return templates.TemplateResponse(
        request,
        "otp.html",
        {"email": email_addr, "error": None, **_identity_context(request)},
    )


@router.post("/login/verify")
async def verify_submit(
    request: Request,
    code: str = Form(),
):
    settings = request.app.state.settings
    email_addr = request.cookies.get("otp_email", "")

    session = await auth.verify_otp_and_create_session(request.state.db, email_addr, code, settings)

    if session is None:
        return templates.TemplateResponse(
            request,
            "otp.html",
            {"email": email_addr, "error": "Invalid or expired code.", **_identity_context(request)},
            status_code=400,
        )

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        "session",
        session.token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=settings.session_expiry_days * 86400,
    )
    response.delete_cookie("otp_email")
    return response


@router.post("/logout")
async def logout(request: Request):
    session_token = request.cookies.get("session")
    if session_token:
        await db.delete_session(request.state.db, session_token)

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("session")
    return response
