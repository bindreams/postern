"""Tests for email sending."""

from unittest.mock import AsyncMock, patch

from postern.email import send_otp_email
from postern.settings import Settings


def _make_settings(**overrides):
    defaults = {
        "secret_key": "test-secret",
        "smtp_host": "smtp.example.com",
        "smtp_port": 465,
        "smtp_user": "user",
        "smtp_password": "pass",
        "smtp_from": "noreply@example.com",
    }
    defaults.update(overrides)
    return Settings(**defaults)


# Email sending ========================================================================================================
@patch("postern.email.aiosmtplib.send", new_callable=AsyncMock)
async def test_send_otp_email_success(mock_send):
    settings = _make_settings()
    result = await send_otp_email("alice@example.com", "123456", settings)

    assert result is True
    mock_send.assert_called_once()

    # Verify the email message
    call_args = mock_send.call_args
    msg = call_args.args[0]
    assert msg["To"] == "alice@example.com"
    assert msg["From"] == "noreply@example.com"
    assert "login code" in msg["Subject"].lower()
    assert "123456" in msg.get_content()


@patch("postern.email.aiosmtplib.send", new_callable=AsyncMock, side_effect=ConnectionRefusedError("SMTP down"))
async def test_send_otp_email_smtp_failure(mock_send):
    settings = _make_settings()
    result = await send_otp_email("alice@example.com", "123456", settings)

    assert result is False


@patch("postern.email.aiosmtplib.send", new_callable=AsyncMock)
async def test_send_otp_email_tls_port_465(mock_send):
    settings = _make_settings(smtp_port=465)
    await send_otp_email("alice@example.com", "123456", settings)

    call_kwargs = mock_send.call_args.kwargs
    assert call_kwargs["use_tls"] is True
    assert call_kwargs["start_tls"] is False


@patch("postern.email.aiosmtplib.send", new_callable=AsyncMock)
async def test_send_otp_email_starttls_port_587(mock_send):
    settings = _make_settings(smtp_port=587)
    await send_otp_email("alice@example.com", "123456", settings)

    call_kwargs = mock_send.call_args.kwargs
    assert call_kwargs["use_tls"] is False
    assert call_kwargs["start_tls"] is True


@patch("postern.email.aiosmtplib.send", new_callable=AsyncMock)
async def test_send_otp_email_other_port_is_plaintext(mock_send):
    """Invariant: ports other than 465/587 mean plaintext. See CLAUDE.md."""
    settings = _make_settings(smtp_port=25)
    await send_otp_email("alice@example.com", "123456", settings)

    call_kwargs = mock_send.call_args.kwargs
    assert call_kwargs["use_tls"] is False
    assert call_kwargs["start_tls"] is False
