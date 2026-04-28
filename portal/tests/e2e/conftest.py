"""Fixtures for the Postern e2e suite.

Boots the real compose stack at session start, tears it down at session end.
Tests should use `portal_client` for HTTPS calls, `mailpit_client` for OTP
extraction, and the helpers in _helpers.py for state mutation through the
portal container.

The test runner needs `127.0.0.1 postern.test` in its /etc/hosts so the
host-side `portal_client` can resolve postern.test -> the host port mapped to
nginx (host:8443 in the e2e compose). Inside the docker network, ssclient
resolves postern.test via the network alias on the nginx service.

Two compose stacks live here:
- ``e2e_stack``    -- the original ``postern-e2e`` project (e2e.compose.yaml).
- ``mta_e2e_stack`` -- the ``postern-e2e-mta`` overlay (e2e.compose.yaml + e2e-mta.compose.yaml).

Markers are added by filename via ``pytest_collection_modifyitems`` (see the
``_MARKER_BY_FILENAME`` map below). Test files do NOT set ``pytestmark`` -- the
conftest is the single source of truth for markers.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from ._certs import generate_test_pki
from ._helpers import (
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
from ._mta_helpers import compose_mta

# Marker map: filename -> pytest marker name. Adding a new MTA test file requires
# registering it here (intentional -- forces the author to think about which tier
# the new tests belong to).
_MARKER_BY_FILENAME: dict[str, str] = {
    "test_mta.py": "e2e_mta",
    "test_mta_disruptive.py": "e2e_mta",
    "test_mta_real.py": "e2e_mta_real",
    "test_mta_outbound.py": "e2e_mta_outbound",
}


def pytest_collection_modifyitems(config, items):
    """Auto-mark every test in this directory by its filename."""
    for item in items:
        fspath = str(item.fspath)
        if str(TESTS_E2E_DIR) not in fspath:
            continue
        name = Path(fspath).name
        marker = _MARKER_BY_FILENAME.get(name, "e2e")
        item.add_marker(getattr(pytest.mark, marker))


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
def e2e_certs(tmp_path_factory) -> Iterator[Path]:
    """Generate a fresh self-signed CA + leaf for the e2e session.

    Sets POSTERN_E2E_TLS_DIR in the process env so docker compose's volume
    interpolation in e2e.compose.yaml resolves. Always overrides any
    pre-existing value (test-state hygiene). The env var must remain set
    through e2e_stack teardown because `compose down -v` re-resolves volume
    sources -- pytest tears fixtures down in reverse creation order, so this
    fixture's `finally` runs after e2e_stack's, which is the correct order.
    """
    tls_dir = tmp_path_factory.mktemp("e2e-tls")
    generate_test_pki(tls_dir)
    prior = os.environ.get("POSTERN_E2E_TLS_DIR")
    os.environ["POSTERN_E2E_TLS_DIR"] = tls_dir.as_posix()  # forward slashes for compose on any host
    try:
        yield tls_dir / "ca.pem"
    finally:
        if prior is None:
            os.environ.pop("POSTERN_E2E_TLS_DIR", None)
        else:
            os.environ["POSTERN_E2E_TLS_DIR"] = prior


@pytest.fixture(scope="session")
def e2e_stack(_patch_dns_for_postern_test, e2e_certs) -> Iterator[None]:
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


@pytest.fixture(scope="session")
def mta_e2e_stack(_patch_dns_for_postern_test, e2e_certs) -> Iterator[None]:
    """Boot the postern-e2e-mta project (e2e.compose.yaml + e2e-mta.compose.yaml).

    Sibling of ``e2e_stack`` but for the MTA overlay; runs only when
    ``e2e_mta`` tests are collected.
    """
    if shutil.which("docker") is None:
        pytest.fail(
            "docker not on PATH. E2e MTA tests require Linux + docker; see CONTRIBUTING.md. "
            "To opt out, run `pytest -m 'not e2e_mta'`.",
            pytrace=False,
        )
    run(compose_mta("up", "-d", "--wait"))
    try:
        yield
    finally:
        # Dump mta + provisioner logs BEFORE down -v so CI failure-log steps see
        # Postfix delivery attempts, opendkim signatures, provisioner state etc.
        # The CI failure-log step runs after fixture teardown -- by then `compose
        # down -v` has wiped everything -- so we have to surface logs here.
        for service in ("mta", "provisioner"):
            print(f"\n===== {service} logs (mta_e2e_stack teardown) =====", flush=True)
            subprocess.run(compose_mta("logs", "--no-color", "--timestamps", service), check=False)
        subprocess.run(compose_mta("down", "-v", "--timeout", "30"), check=False)


# HTTP clients =========================================================================================================
@pytest.fixture
def portal_client(e2e_certs, e2e_stack) -> Iterator[httpx.Client]:
    """HTTPS client trusting the test CA, follow_redirects=False so tests can
    assert on 303s and Set-Cookie headers."""
    with httpx.Client(base_url=PORTAL_BASE_URL, verify=str(e2e_certs), follow_redirects=False) as client:
        yield client


@pytest.fixture
def portal_mta_client(e2e_certs, mta_e2e_stack) -> Iterator[httpx.Client]:
    """HTTPS client for the MTA overlay stack. Same host:port as ``portal_client``
    (only one project's nginx publishes 8443 at a time -- see the local-dev
    caveat in CONTRIBUTING.md)."""
    with httpx.Client(base_url=PORTAL_BASE_URL, verify=str(e2e_certs), follow_redirects=False) as client:
        yield client


class MailpitClient:
    OTP_PATTERN = re.compile(r"code is:\s*(\d{6})")

    def __init__(self, base_url: str = MAILPIT_BASE_URL) -> None:
        self._http = httpx.Client(base_url=base_url, timeout=10)

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

    def get_raw_source(self, message_id: str) -> bytes:
        r = self._http.get(f"/api/v1/message/{message_id}/raw")
        r.raise_for_status()
        return r.content

    def messages_to(self, recipient: str) -> list[dict]:
        """Return all currently-known messages addressed to recipient (no wait)."""
        r = self._http.get("/api/v1/messages")
        r.raise_for_status()
        out: list[dict] = []
        for msg in r.json().get("messages", []):
            tos = [t.get("Address") for t in msg.get("To", [])]
            if recipient in tos:
                out.append(msg)
        return out

    def assert_no_message_to(self, recipient: str, *, wait: float = 10.0) -> None:
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if self.messages_to(recipient):
                raise AssertionError(f"unexpected mailpit message for {recipient!r} (negative-test failure)")
            time.sleep(0.25)

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


@pytest.fixture
def mailpit_mta_client(mta_e2e_stack) -> Iterator[MailpitClient]:
    """``MailpitClient`` bound to the MTA overlay stack (same localhost:8025
    port; the project isolation lives in the compose stacks, not in mailpit)."""
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
def fresh_mta_user(mta_e2e_stack):
    """Like ``fresh_user`` but bound to the MTA overlay project."""
    created: list[str] = []

    def _make(name: str, email: str) -> None:
        run(compose_mta("exec", "-T", "portal", "postern", "user", "add", name, email))
        created.append(email)

    yield _make

    for email in created:
        subprocess.run(compose_mta("exec", "-T", "portal", "postern", "user", "delete", email), check=False)


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


# Real-infra env validation ============================================================================================
def _require_env(*names: str) -> dict[str, str]:
    """Resolve required env vars or fail loudly with an actionable message."""
    missing = [n for n in names if not os.environ.get(n, "").strip()]
    if missing:
        pytest.fail(
            "Missing env for real-infra MTA tests: " + ", ".join(missing) +
            ".\nThese tests require a maintainer-owned test domain and DNS provider creds.\n"
            "See docs/mta.md > 'Real-infra test-domain setup' for the full checklist.\n"
            "Opt out instead: `pytest -m 'not e2e_mta_real'`.",
            pytrace=False,
        )
    return {n: os.environ[n].strip() for n in names}


_PROVIDER_ENV: dict[str, tuple[str, ...]] = {
    "cloudflare": ("CLOUDFLARE_API_TOKEN", ),
    "route53": ("AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
    "gandi": ("GANDI_API_TOKEN", ),
    "digitalocean": ("DO_AUTH_TOKEN", ),
    "ovh": (
        "OVH_ENDPOINT",
        "OVH_APPLICATION_KEY",
        "OVH_APPLICATION_SECRET",
        "OVH_CONSUMER_KEY",
    ),
    "hetzner": ("HETZNER_API_TOKEN", ),
    "linode": ("LINODE_TOKEN", ),
    "namecheap": ("NAMECHEAP_API_KEY", "NAMECHEAP_API_USER", "NAMECHEAP_CLIENT_IP"),
}


@pytest.fixture(scope="session")
def mta_test_env() -> dict[str, str]:
    """Validate the maintainer-supplied env for ``e2e_mta_real`` tests.

    Returns a dict with the resolved values. Calls ``pytest.fail`` if anything
    required is missing -- intentional, per CLAUDE.md's "fail loudly" rule.
    """
    base = _require_env("MTA_TEST_DOMAIN", "MTA_TEST_DNS_PROVIDER")
    provider = base["MTA_TEST_DNS_PROVIDER"].lower()
    provider_envs = _PROVIDER_ENV.get(provider)
    if provider_envs is None:
        pytest.fail(
            f"Unknown MTA_TEST_DNS_PROVIDER {provider!r}. Supported: " + ", ".join(sorted(_PROVIDER_ENV)) + ".",
            pytrace=False,
        )
    base.update(_require_env(*provider_envs))
    base.setdefault(
        "MTA_TEST_ADMIN_EMAIL",
        os.environ.get("MTA_TEST_ADMIN_EMAIL", "").strip() or "postmaster@example.org"
    )
    base.setdefault(
        "MTA_TEST_DNS_PROPAGATION_SECONDS",
        os.environ.get("MTA_TEST_DNS_PROPAGATION_SECONDS", "60").strip(),
    )
    base.setdefault(
        "MTA_TEST_REQUIRE_DNSSEC",
        os.environ.get("MTA_TEST_REQUIRE_DNSSEC", "false").strip().lower(),
    )
    return base


@pytest.fixture(scope="session")
def mta_test_outbound_env(mta_test_env: dict[str, str]) -> dict[str, str]:
    """Layered on ``mta_test_env``; adds IMAP poller creds for outbound tests."""
    extra = _require_env(
        "MTA_TEST_RECIPIENT_EMAIL",
        "MTA_TEST_RECIPIENT_IMAP_HOST",
        "MTA_TEST_RECIPIENT_IMAP_USER",
        "MTA_TEST_RECIPIENT_IMAP_PASS",
    )
    out = dict(mta_test_env)
    out.update(extra)
    out.setdefault("MTA_TEST_RECIPIENT_IMAP_PORT", os.environ.get("MTA_TEST_RECIPIENT_IMAP_PORT", "993").strip())
    return out
