from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import aiosqlite

from voyager import db
from voyager.models import Session
from voyager.settings import Settings


def generate_otp_code() -> str:
    """Generate a 6-digit OTP code."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(code: str) -> str:
    """SHA-256 hash of an OTP code."""
    return hashlib.sha256(code.encode()).hexdigest()


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


async def request_otp(database: aiosqlite.Connection, email: str, settings: Settings) -> str | None:
    """Generate an OTP for the given email.

    Returns the plaintext code if the email exists (caller should send it via email),
    or None if the email is not registered. An OTP is always created in the DB
    regardless to prevent timing side-channel attacks.
    """
    code = generate_otp_code()
    code_hash = hash_otp(code)
    expires_at = (datetime.now(timezone.utc) +
                  timedelta(seconds=settings.otp_expiry_seconds)).strftime("%Y-%m-%d %H:%M:%S")

    user = await db.get_user_by_email(database, email)

    # Always create OTP to equalize timing, but use a dummy email for non-existent users
    target_email = email if user else f"__dummy__{email}"
    try:
        await db.create_otp(database, target_email, code_hash, expires_at)
    except ValueError:
        # Rate limit exceeded -- still don't reveal whether email exists
        return None

    if user is None:
        return None

    return code


async def verify_otp_and_create_session(
    database: aiosqlite.Connection, email: str, code: str, settings: Settings
) -> Session | None:
    """Verify an OTP code and create a session if valid.

    Returns the Session on success, or None on failure.
    """
    code_hash = hash_otp(code)
    if not await db.verify_otp(database, email, code_hash):
        return None

    user = await db.get_user_by_email(database, email)
    if user is None:
        return None

    expires = (datetime.now(timezone.utc) + timedelta(days=settings.session_expiry_days)).strftime("%Y-%m-%d %H:%M:%S")
    session = Session(
        token=generate_session_token(),
        user_id=user.id,
        expires_at=expires,
    )
    await db.create_session(database, session)
    return session
