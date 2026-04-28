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

    # Built-in mta presents a cert for `mail.<domain>` but the portal connects via
    # the docker-DNS service name `mta` (or a network-scoped alias on the
    # internal-only `mta-submit` network). The mta-submit network is internal
    # with mynetworks scoping, so skipping cert verification on this hop is
    # safe; external relays keep strict validation. The list includes
    # `mta-submit` because the e2e overlay aliases mta on that network only to
    # avoid docker-DNS round-robining the connection through the default
    # network -- which would fail Postfix's mynetworks check.
    validate_certs = settings.smtp_host not in ("mta", "mta-submit")

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user or None,
            password=settings.smtp_password or None,
            use_tls=settings.smtp_port == 465,
            start_tls=settings.smtp_port == 587,
            validate_certs=validate_certs,
        )
        return True
    except Exception:
        logger.exception(
            "Failed to send OTP email to %s",
            hashlib.sha256(to.encode()).hexdigest()[:16],
        )
        return False
