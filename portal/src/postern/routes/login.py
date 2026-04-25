from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from postern import auth, db, email

router = APIRouter()
_template_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_template_dir))


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    # Redirect if already logged in
    session_token = request.cookies.get("session")
    if session_token:
        session = await db.get_valid_session(request.state.db, session_token)
        if session:
            return RedirectResponse("/", status_code=303)

    return templates.TemplateResponse(request, "login.html", {"message": None})


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
    return templates.TemplateResponse(request, "otp.html", {"email": email_addr, "error": None})


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
            {"email": email_addr, "error": "Invalid or expired code."},
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
