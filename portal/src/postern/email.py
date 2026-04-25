from __future__ import annotations

import hashlib
import logging

import aiosmtplib
from email.message import EmailMessage

from postern.settings import Settings

logger = logging.getLogger(__name__)


async def send_otp_email(to: str, code: str, settings: Settings) -> bool:
    """Send a one-time auth code via SMTP. Returns True on success."""
    msg = EmailMessage()
    msg["Subject"] = "Your Postern VPN login code"
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg.set_content(
        f"Your one-time login code is: {code}\n\n"
        f"This code expires in {settings.otp_expiry_seconds // 60} minutes.\n"
        f"If you did not request this code, ignore this email."
    )

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user or None,
            password=settings.smtp_password or None,
            use_tls=settings.smtp_port == 465,
            start_tls=settings.smtp_port == 587,
        )
        return True
    except Exception:
        logger.exception(
            "Failed to send OTP email to %s",
            hashlib.sha256(to.encode()).hexdigest()[:16],
        )
        return False
