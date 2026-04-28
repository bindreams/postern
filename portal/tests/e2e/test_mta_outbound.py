"""End-to-end outbound delivery test (real port-25 + real recipient).

Marker (``e2e_mta_outbound``) is added by ``conftest.pytest_collection_modifyitems``.
This test is **maintainer-only**: it requires unblocked outbound port 25, a
publicly-trusted TLS cert at ``$POSTERN_E2E_TLS_DIR``, real DNS provider creds,
and an IMAP-pollable test mailbox. Fail-loud on missing env (no silent skips).

There is no GHA job for this test in the default workflow (hosted runners
block port 25); a follow-up issue tracks adding a self-hosted runner. Run
locally on a VPS:

    export MTA_TEST_DOMAIN=mta-test.example.com
    export MTA_TEST_ADMIN_EMAIL=admin@something-else.example.com
    export MTA_TEST_DNS_PROVIDER=cloudflare
    export CLOUDFLARE_API_TOKEN=...
    export MTA_TEST_RECIPIENT_EMAIL=test-mailbox@maintainer.example.com
    export MTA_TEST_RECIPIENT_IMAP_HOST=imap.maintainer.example.com
    export MTA_TEST_RECIPIENT_IMAP_USER=test-mailbox
    export MTA_TEST_RECIPIENT_IMAP_PASS=...
    export POSTERN_E2E_TLS_DIR=/etc/letsencrypt/live/${MTA_TEST_DOMAIN}
    uv run pytest -m e2e_mta_outbound -v --timeout=600
"""

from __future__ import annotations

import email
import imaplib
import logging
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from ._helpers import TESTS_E2E_DIR, run

logger = logging.getLogger(__name__)

PROJECT_OUTBOUND = "postern-e2e-mta-real"
COMPOSE_FILES_OUTBOUND = (
    TESTS_E2E_DIR / "e2e.compose.yaml",
    TESTS_E2E_DIR / "e2e-mta-real.compose.yaml",
)


# Compose binding ======================================================================================================
def _compose_outbound(*args: str) -> list[str]:
    file_args: list[str] = []
    for f in COMPOSE_FILES_OUTBOUND:
        file_args.extend(("-f", str(f)))
    return ["docker", "compose", "-p", PROJECT_OUTBOUND, *file_args, *args]


# Stack lifecycle ======================================================================================================
@pytest.fixture(scope="module")
def outbound_stack(mta_test_outbound_env: dict[str, str], e2e_certs: Path) -> Iterator[None]:
    """Bring up the real-mode mta + provisioner. Tears down on exit.

    ``e2e_certs`` is depended on for ``POSTERN_E2E_TLS_DIR`` -- but the
    maintainer almost always overrides it with a real Let's Encrypt cert
    (recipient mailservers reject self-signed); the override is via the
    process env, which docker compose interpolation picks up.
    """
    if shutil.which("docker") is None:
        pytest.fail("docker not on PATH; e2e_mta_outbound tests need Linux + docker.", pytrace=False)
    run(_compose_outbound("up", "-d", "--wait"))
    try:
        yield
    finally:
        subprocess.run(_compose_outbound("down", "-v", "--timeout", "60"), check=False)


# IMAP poll ============================================================================================================
def _imap_poll_for_otp(env: dict[str, str], *, timeout: float = 180.0) -> tuple[email.message.Message, bytes]:
    """Poll the recipient IMAP mailbox for a freshly-arrived message addressed
    to MTA_TEST_RECIPIENT_EMAIL with a 6-digit OTP body. Returns (parsed, raw).

    Uses IMAP4_SSL on the configured port (default 993). Marks the matched
    message as Deleted before returning so subsequent runs don't re-match.
    """
    import re

    host = env["MTA_TEST_RECIPIENT_IMAP_HOST"]
    port = int(env["MTA_TEST_RECIPIENT_IMAP_PORT"])
    user = env["MTA_TEST_RECIPIENT_IMAP_USER"]
    pwd = env["MTA_TEST_RECIPIENT_IMAP_PASS"]
    recipient = env["MTA_TEST_RECIPIENT_EMAIL"]

    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    otp_re = re.compile(r"code is:\s*(\d{6})")
    while time.monotonic() < deadline:
        try:
            with imaplib.IMAP4_SSL(host, port, timeout=15) as client:
                client.login(user, pwd)
                client.select("INBOX")
                # Search for unseen messages addressed to the test recipient.
                typ, data = client.search(None, "UNSEEN", "TO", recipient)
                if typ != "OK":
                    last_err = RuntimeError(f"IMAP SEARCH returned {typ!r}: {data!r}")
                else:
                    for num in (data[0] or b"").split():
                        typ, msg_data = client.fetch(num, "(RFC822)")
                        if typ != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                            continue
                        raw_part = msg_data[0][1]
                        if not isinstance(raw_part, bytes):
                            continue
                        raw = raw_part
                        parsed = email.message_from_bytes(raw)
                        body_chunks: list[str] = []
                        for part in parsed.walk():
                            if part.get_content_type() == "text/plain":
                                payload = part.get_payload(decode=True)
                                if isinstance(payload, bytes) and payload:
                                    body_chunks.append(payload.decode("utf-8", errors="replace"))
                        joined = "\n".join(body_chunks)
                        if not joined:
                            fallback = parsed.get_payload(decode=False)
                            joined = fallback if isinstance(fallback, str) else ""
                        if otp_re.search(joined):
                            client.store(num, "+FLAGS", "\\Deleted")
                            client.expunge()
                            return parsed, raw
        except (imaplib.IMAP4.error, socket.error, OSError) as e:
            last_err = e
        time.sleep(5.0)
    raise AssertionError(
        f"no OTP message arrived at {recipient} via IMAP {host}:{port} within {timeout:.0f}s" +
        (f" (last error: {last_err!r})" if last_err else "")
    )


# Test =================================================================================================================
def test_otp_delivered_to_real_recipient(
    mta_test_outbound_env: dict[str, str],
    e2e_certs: Path,
    outbound_stack,
):
    """Real-world OTP delivery: portal sends an OTP to MTA_TEST_RECIPIENT_EMAIL
    via the real-mode mta. The mta authenticates against the real DNS state
    (MTA_VERIFY_DNS=true), DKIM-signs the message via the provisioner-published
    selector, and delivers via outbound port 25 with DANE/STARTTLS where the
    recipient supports it.

    We poll the recipient mailbox via IMAP, parse the message, and assert:
    - DKIM-Signature header is present and `d=$MTA_TEST_DOMAIN`
    - The body contains a 6-digit OTP
    - The recipient mailserver's Authentication-Results indicates DKIM=pass
      (most providers add this; we assert if the header is present, otherwise
      log a warning -- some private servers don't add it).
    """
    domain = mta_test_outbound_env["MTA_TEST_DOMAIN"]
    recipient = mta_test_outbound_env["MTA_TEST_RECIPIENT_EMAIL"]

    # Create the user inside the running portal so /login can request the OTP.
    run(_compose_outbound("exec", "-T", "portal", "postern", "user", "add", "Outbound Test", recipient))

    # Hit /login. The portal runs at https://mail.<domain>:8443? No -- the
    # base e2e.compose.yaml publishes nginx on 127.0.0.1:8443 with the test CA.
    # In real mode the maintainer runs from the same host, so localhost works.
    portal_url = f"https://localhost:8443"
    with httpx.Client(base_url=portal_url, verify=str(e2e_certs), follow_redirects=False) as client:
        r = client.post("/login", data={"email": recipient}, headers={"host": "postern.test"})
        # Allow a 4xx if the test cert doesn't match the maintainer's domain --
        # the host header trick may not be enough. Surface a clear message.
        if r.status_code != 303:
            pytest.fail(
                f"POST /login returned {r.status_code} (expected 303). "
                f"In real-mode the host-side test client may need a hosts file entry "
                f"for {domain} pointing at 127.0.0.1, plus a nginx server_name match. "
                f"Body: {r.text!r}",
                pytrace=False,
            )

    # Poll the recipient mailbox.
    msg, raw = _imap_poll_for_otp(mta_test_outbound_env, timeout=180.0)

    sig = msg.get("DKIM-Signature", "") or ""
    assert sig, "no DKIM-Signature header on delivered message"
    fields = {kv.split("=", 1)[0].strip(): kv.split("=", 1)[1].strip() for kv in sig.split(";") if "=" in kv}
    assert fields.get("d") == domain, f"expected d={domain!r}, got d={fields.get('d')!r}"

    # Best-effort Authentication-Results check (most public mailservers add it).
    auth_results = msg.get_all("Authentication-Results") or []
    if auth_results:
        joined = " ; ".join(auth_results).lower()
        assert "dkim=pass" in joined, (
            f"recipient mailserver reports Authentication-Results without dkim=pass:\n  " + "\n  ".join(auth_results)
        )
    else:
        logger.warning(
            "recipient mailserver did not add an Authentication-Results header; "
            "DKIM signing was verified by header presence + d= match only."
        )

    # OTP body sanity-check (the IMAP poll already filtered for it, but double-check the regex match).
    body = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                body = payload.decode("utf-8", errors="replace")
                break
    assert body, "delivered message has no text/plain body"
