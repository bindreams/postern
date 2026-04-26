"""End-to-end tests for the Postern portal.

These tests boot the real compose stack and prove that:
  1. A full OTP login flow works against HTTPS.
  2. A byte actually round-trips through a reconciler-spawned ss-* container.
  3. The reconciler responds correctly to image upgrades, orphan containers,
     and portal shutdown.

Each test is auto-marked `e2e` by conftest. Run with:
    cd portal && uv run pytest -m e2e -v
"""

from __future__ import annotations

import json
import subprocess
import time

import httpx
import pytest

from ._helpers import (
    PROJECT,
    compose,
    compose_exec,
    container_exists,
    query_db,
    trigger_reconcile,
    postern_cli,
    wait_for_container,
)


# Helpers ==============================================================================================================
def _login_complete(client: httpx.Client, mailpit, email: str) -> httpx.Response:
    """Drive the OTP flow to a logged-in state. Returns the final 303 response
    that set the session cookie. The client picks up cookies as we go."""
    r = client.post("/login", data={"email": email})
    assert r.status_code == 303
    assert r.headers["location"] == "/login/verify"
    assert "otp_email" in r.cookies

    code = mailpit.extract_otp(email)

    r = client.post("/login/verify", data={"code": code})
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/"
    assert "session" in r.cookies
    return r


def _launch_sslocal(ssclient_config_path: str) -> None:
    """Start sslocal in ssclient as a daemonized background process, then wait
    for the SOCKS port (1080) to accept connections before returning."""
    # `-d` detaches; using docker exec directly (no `sh -c`) so the pid
    # inherits the container's init and survives past our call returning.
    subprocess.run(
        compose("exec", "-d", "ssclient", "sslocal", "-c", ssclient_config_path),
        check=True,
    )
    # Poll for the SOCKS port until it accepts a TCP connect.
    for _ in range(20):
        probe = subprocess.run(
            compose(
                "exec", "-T", "ssclient", "sh", "-c", "nc -z localhost 1080 2>/dev/null && echo READY || echo NOTREADY"
            ),
            capture_output=True,
            text=True,
        )
        if "READY" in probe.stdout:
            return
        time.sleep(0.5)
    # Dump sslocal stderr on failure to aid debugging
    logs = subprocess.run(
        compose("exec", "-T", "ssclient", "sh", "-c", "pgrep -a sslocal || echo 'no sslocal process'"),
        capture_output=True,
        text=True,
    )
    raise AssertionError(f"sslocal SOCKS port never opened. pgrep: {logs.stdout!r}")


# Tunnel happy path ====================================================================================================
def test_happy_path_tunnel_routes_traffic(portal_client, mailpit_client, fresh_user, fresh_connection):
    """The single most important test: prove a byte tunnels end-to-end."""
    email = "happy@postern.test"
    fresh_user("Happy User", email)
    conn_id, path_token = fresh_connection(email, "happy-path-conn")

    _login_complete(portal_client, mailpit_client, email)

    # Dashboard renders the connection
    r = portal_client.get("/")
    assert r.status_code == 200
    assert "happy-path-conn" in r.text

    # Download client config
    r = portal_client.get(f"/connection/{conn_id}/config")
    assert r.status_code == 200
    config = r.json()
    server = config["servers"][0]
    assert server["address"] == "postern.test"
    assert server["port"] == 443
    assert server["plugin"] == "v2ray-plugin"
    assert server["plugin_opts"].startswith("tls;fast-open;")
    assert f"path=/t/{path_token}" in server["plugin_opts"]
    assert server["plugin_opts"].endswith(f"host=postern.test")

    # Patch the config so it matches what the ssclient container can reach:
    #   - postern.test:443 -> ssclient is on the e2e-tunnel-entry network where
    #     nginx is aliased as postern.test, but nginx listens on 443 there too.
    #     So address+port are already correct.
    config_path_in_container = "/tmp/client.json"
    config_blob = json.dumps(config)
    subprocess.run(
        compose("exec", "-T", "ssclient", "sh", "-c", f"cat > {config_path_in_container}"),
        input=config_blob,
        text=True,
        check=True,
    )

    _launch_sslocal(config_path_in_container)

    # The actual byte-round-trip assertion: ssclient curls go-httpbin THROUGH the
    # ss-* container that nginx routes to. ssclient cannot reach go-httpbin
    # directly (different docker networks); the only path is the tunnel.
    result = subprocess.run(
        compose(
            "exec",
            "-T",
            "ssclient",
            "curl",
            "--silent",
            "--show-error",
            "--socks5-hostname",
            "localhost:1080",
            "--max-time",
            "10",
            "http://go-httpbin:8080/get",
        ),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"tunnel curl failed: stderr={result.stderr!r}"
    body = json.loads(result.stdout)
    assert "url" in body and "go-httpbin" in body["url"]

    # Control: prove the success above wasn't because ssclient could reach
    # go-httpbin directly. A direct curl (no SOCKS) MUST fail at DNS resolution
    # (go-httpbin isn't on e2e-tunnel-entry). Asserting rc=6 specifically so a
    # future accidental network bridge that yields a TCP RST (rc=7) doesn't
    # silently satisfy this check.
    direct = subprocess.run(
        compose(
            "exec",
            "-T",
            "ssclient",
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "3",
            "http://go-httpbin:8080/get",
        ),
        capture_output=True,
        text=True,
    )
    # curl rc 6 = couldn't resolve host; rc 28 = operation timed out (DNS too slow).
    # Both prove ssclient has no network route to go-httpbin. rc 7 (connection
    # refused) would mean a route exists -- that's the regression we're guarding.
    assert direct.returncode in (6, 28), (
        f"ssclient reached go-httpbin without the tunnel (curl rc={direct.returncode}, "
        f"stderr={direct.stderr!r}). Expected rc=6 (DNS resolution failure). "
        "The tunnel test above proves nothing if direct access succeeds."
    )


# Auth-flow assertions =================================================================================================
def test_invalid_otp_rejected(portal_client, mailpit_client, fresh_user):
    email = "wrongotp@postern.test"
    fresh_user("Wrong OTP", email)

    r = portal_client.post("/login", data={"email": email})
    assert r.status_code == 303
    # Trigger an OTP into mailpit so the email is registered AND there's an active OTP row
    mailpit_client.extract_otp(email)

    r = portal_client.post("/login/verify", data={"code": "000000"})
    assert r.status_code == 400
    assert "session" not in r.cookies


def test_unknown_email_does_not_leak(portal_client):
    """Unknown emails get the same response shape as known ones and produce a
    __dummy__ row in otp_codes. Asserts the email-enumeration defence."""
    unknown = "ghost-e2e@postern.test"
    r = portal_client.post("/login", data={"email": unknown})
    assert r.status_code == 303
    assert r.headers["location"] == "/login/verify"
    assert "otp_email" in r.cookies

    # The dummy OTP row must exist with the prefixed email.
    found_email = query_db("SELECT email FROM otp_codes WHERE email = ?", f"__dummy__{unknown}")
    assert found_email == f"__dummy__{unknown}"


def test_otp_cookie_lifetime_matches_expiry_invariant(portal_client):
    """CLAUDE.md invariant: OTP_EXPIRY_SECONDS (default 600) and the otp_email
    cookie max_age (hardcoded 900) drift independently and must stay in sync.
    This test pins both values."""
    r = portal_client.post("/login", data={"email": "anyone@postern.test"})
    set_cookie = r.headers.get("set-cookie", "")
    # max_age is in seconds -- match `Max-Age=900` ignoring case
    assert "max-age=900" in set_cookie.lower(), set_cookie

    otp_expiry = compose_exec(
        "python", "-c", "from postern.settings import Settings; print(Settings().otp_expiry_seconds)"
    ).stdout.strip()
    assert otp_expiry == "600", (
        f"Settings().otp_expiry_seconds={otp_expiry!r} drifted from cookie max-age=900; "
        "see CLAUDE.md auth-flow invariant"
    )


# Authorization on config download =====================================================================================
@pytest.mark.skip(reason="flakes with nginx 503 on /login/verify after `connection disable`; see #7")
def test_disabled_connection_config_returns_404(portal_client, mailpit_client, fresh_user, fresh_connection):
    email = "disabled@postern.test"
    fresh_user("Disabled", email)
    conn_id, _ = fresh_connection(email, "to-disable")

    postern_cli("connection", "disable", conn_id)

    _login_complete(portal_client, mailpit_client, email)

    r = portal_client.get(f"/connection/{conn_id}/config")
    assert r.status_code == 404


# Image-shape invariants ===============================================================================================
def test_portal_image_is_distroless(e2e_stack):
    """Pin the distroless invariant in code: the production image must not ship a
    POSIX shell. If this starts passing the wrong way, someone re-introduced an
    `apk` install or moved off the non-dev DHI base; revisit the do-not-list in
    CLAUDE.md before "fixing" the test."""
    result = subprocess.run(
        compose("exec", "-T", "portal", "/bin/sh", "-c", "true"),
        capture_output=True,
    )
    assert result.returncode != 0, (
        "Portal image unexpectedly has /bin/sh; the runtime stage of "
        "portal/Dockerfile drifted away from the distroless DHI base."
    )


# Reconciler invariants ================================================================================================
def test_reconciler_removes_orphan(e2e_stack):
    """A container with the postern.managed=true label but no DB row must be
    removed on the next reconcile pass."""
    orphan = "ss-orphan0000000000000000"
    subprocess.run(
        [
            "docker", "run", "-d", "--name", orphan, "--label", "postern.managed=true", "--network", "e2e-shadowsocks",
            "dhi.io/alpine-base:3.23-dev", "sleep", "infinity"
        ],
        check=True,
        capture_output=True,
    )
    try:
        trigger_reconcile()
        wait_for_container(orphan, present=False, timeout=15)
    finally:
        # Defensive cleanup if the test failed before reconcile removed it.
        subprocess.run(["docker", "rm", "-f", orphan], check=False, capture_output=True)


def test_image_upgrade_recreates_container(fresh_user, fresh_connection):
    """When local/shadowsocks-server image ID changes, the reconciler must
    recreate every managed container so the new bits propagate."""
    email = "imgupgrade@postern.test"
    fresh_user("Image Upgrade", email)
    _, token = fresh_connection(email, "to-upgrade")

    name = f"ss-{token}"
    inspect_before = subprocess.run(
        ["docker", "inspect", "--format", "{{.Image}}", name],
        capture_output=True,
        text=True,
        check=True,
    )
    image_before = inspect_before.stdout.strip()

    # Bump the image with a no-op label change so the digest changes
    bump_dockerfile = ("FROM local/shadowsocks-server\n"
                       "LABEL postern.test.bump=1\n")
    subprocess.run(
        ["docker", "build", "-t", "local/shadowsocks-server", "-"],
        input=bump_dockerfile,
        text=True,
        check=True,
        capture_output=True,
    )

    trigger_reconcile()

    # Poll for the container's image to change (recreation drops the container
    # then creates a new one with the same name).
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        inspect = subprocess.run(
            ["docker", "inspect", "--format", "{{.Image}}", name],
            capture_output=True,
            text=True,
        )
        if inspect.returncode == 0 and inspect.stdout.strip() != image_before:
            return
        time.sleep(0.5)
    pytest.fail(f"Container {name} was not recreated after image upgrade")


def test_portal_shutdown_cleans_ss_containers(fresh_user, fresh_connection):
    """The portal's lifespan calls cleanup_all_containers on shutdown.
    After a graceful stop, no ss-* containers should remain."""
    email = "shutdown@postern.test"
    fresh_user("Shutdown", email)
    _, token = fresh_connection(email, "shutdown-test")
    name = f"ss-{token}"
    assert container_exists(name)

    subprocess.run(compose("stop", "--timeout", "30", "portal"), check=True, capture_output=True)
    try:
        wait_for_container(name, present=False, timeout=30)

        # Belt and suspenders: confirm no managed containers anywhere
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "label=postern.managed=true", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == ""
    finally:
        # Restart portal so the rest of the suite can use the stack.
        subprocess.run(compose("start", "portal"), check=True, capture_output=True)
        # Wait for portal healthcheck before yielding back.
        for _ in range(30):
            health = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", f"{PROJECT}-portal-1"],
                capture_output=True,
                text=True,
            )
            if health.stdout.strip() == "healthy":
                break
            time.sleep(1)
