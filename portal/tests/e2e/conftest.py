"""Fixtures for the Postern e2e suite.

Boots the real compose stack at session start, tears it down at session end.
Tests should use `portal_client` for HTTPS calls, `mailpit_client` for OTP
extraction, and the helpers in _helpers.py for state mutation through the
portal container.

The test runner needs `127.0.0.1 postern.test` in its /etc/hosts so the
host-side `portal_client` can resolve postern.test -> the host port mapped to
nginx (host:8443 in the e2e compose). Inside the docker network, ssclient
resolves postern.test via the network alias on the nginx service.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator

import httpx
import pytest

from ._helpers import (
    CA_PATH,
    COMPOSE_FILE,
    CONNECTION_ID_RE,
    MAILPIT_BASE_URL,
    PORTAL_BASE_URL,
    TESTS_E2E_DIR,
    compose,
    query_db,
    run,
    trigger_reconcile,
    postern_cli,
    wait_for_container,
)


def pytest_collection_modifyitems(config, items):
    """All tests in this directory get the e2e marker automatically."""
    for item in items:
        if str(TESTS_E2E_DIR) in str(item.fspath):
            item.add_marker(pytest.mark.e2e)


# Stack lifecycle ======================================================================================================
@pytest.fixture(scope="session", autouse=True)
def _patch_dns_for_postern_test() -> Iterator[None]:
    """Map postern.test -> 127.0.0.1 for the host-side pytest process without
    requiring an /etc/hosts edit. TLS SNI + cert verification still use the
    URL hostname, so trust against the test CA works as intended.

    Inside the docker network, ssclient resolves postern.test via the network
    alias on the nginx service -- that path is unaffected by this patch.
    """
    original = socket.getaddrinfo

    def patched(host, *args, **kwargs):
        if host == "postern.test":
            host = "127.0.0.1"
        return original(host, *args, **kwargs)

    socket.getaddrinfo = patched  # ty: ignore[invalid-assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = original


@pytest.fixture(scope="session")
def e2e_stack(_patch_dns_for_postern_test) -> Iterator[None]:
    if shutil.which("docker") is None:
        pytest.fail(
            "docker not on PATH. E2e tests require Linux + docker; see CONTRIBUTING.md. "
            "To opt out, run `pytest -m 'not e2e'`.",
            pytrace=False,
        )
    # Compose images must be pre-built. CI does it (see .github/workflows/test.yaml);
    # locally run `docker compose -p postern-e2e -f portal/tests/e2e/e2e.compose.yaml build`.
    run(compose("up", "-d", "--wait"))
    try:
        yield
    finally:
        subprocess.run(compose("down", "-v", "--timeout", "30"), check=False)


# HTTP clients =========================================================================================================
@pytest.fixture
def portal_client(e2e_stack) -> Iterator[httpx.Client]:
    """HTTPS client trusting the test CA, follow_redirects=False so tests can
    assert on 303s and Set-Cookie headers."""
    with httpx.Client(base_url=PORTAL_BASE_URL, verify=str(CA_PATH), follow_redirects=False) as client:
        yield client


class MailpitClient:
    OTP_PATTERN = re.compile(r"code is:\s*(\d{6})")

    def __init__(self, base_url: str = MAILPIT_BASE_URL) -> None:
        self._http = httpx.Client(base_url=base_url, timeout=5)

    def close(self) -> None:
        self._http.close()

    def delete_all(self) -> None:
        self._http.delete("/api/v1/messages")

    def latest_to(self, recipient: str, *, timeout: float = 10.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = self._http.get("/api/v1/messages")
            r.raise_for_status()
            for msg in r.json().get("messages", []):
                tos = [t.get("Address") for t in msg.get("To", [])]
                if recipient in tos:
                    detail = self._http.get(f"/api/v1/message/{msg['ID']}")
                    detail.raise_for_status()
                    return detail.json()
            time.sleep(0.25)
        raise AssertionError(f"No mailpit message for {recipient} within {timeout}s")

    def extract_otp(self, recipient: str, *, timeout: float = 10.0) -> str:
        msg = self.latest_to(recipient, timeout=timeout)
        body = msg.get("Text", "") or msg.get("HTML", "")
        m = self.OTP_PATTERN.search(body)
        if not m:
            raise AssertionError(f"No 6-digit OTP found in mail body: {body!r}")
        return m.group(1)


@pytest.fixture
def mailpit_client(e2e_stack) -> Iterator[MailpitClient]:
    client = MailpitClient()
    client.delete_all()
    try:
        yield client
    finally:
        client.close()


# Test-data helpers ====================================================================================================
@pytest.fixture
def fresh_user(e2e_stack):
    created: list[str] = []

    def _make(name: str, email: str) -> None:
        postern_cli("user", "add", name, email)
        created.append(email)

    yield _make

    for email in created:
        subprocess.run(compose("exec", "-T", "portal", "postern", "user", "delete", email), check=False)


@pytest.fixture
def fresh_connection(e2e_stack):
    """Create a connection via CLI, return (connection_id, path_token).
    Triggers reconcile and waits for the ss-<token> container to appear."""

    def _make(email: str, label: str) -> tuple[str, str]:
        result = postern_cli("connection", "add", email, label)
        match = CONNECTION_ID_RE.search(result.stdout)
        if not match:
            raise AssertionError(f"connection id not found in CLI output: {result.stdout!r}")
        conn_id = match.group(1)
        path_token = query_db("SELECT path_token FROM connections WHERE id = ?", conn_id)
        if not path_token:
            raise AssertionError(f"path_token not in DB for connection {conn_id}")
        trigger_reconcile()
        wait_for_container(f"ss-{path_token}", timeout=20)
        # Reconciler-spawned ss-* containers must run with tini at PID 1.
        init_state = subprocess.run(
            ["docker", "inspect", f"ss-{path_token}", "--format", "{{.HostConfig.Init}}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert init_state == "true", (f"reconciler-spawned ss-{path_token} missing init=true (got {init_state!r})")
        return conn_id, path_token

    return _make
