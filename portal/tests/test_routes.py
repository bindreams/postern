"""Integration tests for the web routes."""

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from postern import db
from postern.app import PosternApp
from postern.models import Connection, Session, User
from postern.settings import Settings

from datetime import datetime, timedelta, timezone


def _expires_str(days=7):
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


@pytest.fixture
def app_settings(tmp_path):
    return Settings(database_path=str(tmp_path / "test.db"), secret_key="test-secret")


@pytest.fixture
def test_app(app_settings):
    app = PosternApp(app_settings)
    return app


@pytest_asyncio.fixture
async def client(test_app, app_settings):
    # Initialize DB without the reconciler
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        test_app.state.db = database

        transport = ASGITransport(app=test_app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


# Login page ===========================================================================================================
async def test_login_page_renders(client, app_settings):
    response = await client.get("/login")
    assert response.status_code == 200
    # Brand-string is whatever PRODUCT_NAME points at (default "Postern").
    assert app_settings.product_name in response.text


async def test_login_redirects_to_verify(client, app_settings):
    # Create a user first
    async with db.get_connection(app_settings.database_path) as database:
        await db.create_user(database, User(name="Alice", email="alice@example.com"))

    with patch("postern.routes.login.email.send_otp_email", new_callable=AsyncMock, return_value=True):
        response = await client.post(
            "/login",
            data={"email": "alice@example.com"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login/verify"


async def test_login_nonexistent_email_still_redirects(client):
    """Timing side-channel mitigation: same behavior for non-existent emails."""
    response = await client.post(
        "/login",
        data={"email": "nobody@example.com"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login/verify"


# OTP verification =====================================================================================================
async def test_verify_page_renders(client):
    response = await client.get("/login/verify")
    assert response.status_code == 200
    assert "6-digit code" in response.text


# Dashboard ============================================================================================================
async def test_dashboard_requires_auth(client):
    response = await client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_dashboard_with_valid_session(client, app_settings):
    async with db.get_connection(app_settings.database_path) as database:
        user = User(name="Alice", email="alice@example.com")
        await db.create_user(database, user)

        session = Session(token="test-session-token", user_id=user.id, expires_at=_expires_str())
        await db.create_session(database, session)

    client.cookies.set("session", "test-session-token")
    response = await client.get("/")
    assert response.status_code == 200
    # The dashboard user chip renders the email and the first-letter avatar.
    assert "alice@example.com" in response.text


# Config download ======================================================================================================
async def test_config_download_requires_auth(client):
    response = await client.get("/connection/fake-id/config", follow_redirects=False)
    assert response.status_code == 303


async def test_config_download_for_owned_connection(client, app_settings):
    async with db.get_connection(app_settings.database_path) as database:
        user = User(name="Alice", email="alice@example.com")
        await db.create_user(database, user)

        conn = Connection(
            user_id=user.id,
            path_token="abcdef123456789012345678",
            label="iPhone",
            password="dGVzdGtleQ==",
        )
        await db.create_connection(database, conn)

        session = Session(token="test-token", user_id=user.id, expires_at=_expires_str())
        await db.create_session(database, session)

    client.cookies.set("session", "test-token")
    response = await client.get(f"/connection/{conn.id}/config")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    data = response.json()
    assert data["servers"][0]["address"] == "postern.example.com"
    assert "path=/t/abcdef123456789012345678" in data["servers"][0]["plugin_opts"]


async def test_config_download_for_other_user_returns_404(client, app_settings):
    async with db.get_connection(app_settings.database_path) as database:
        alice = User(name="Alice", email="alice@example.com")
        bob = User(name="Bob", email="bob@example.com")
        await db.create_user(database, alice)
        await db.create_user(database, bob)

        conn = Connection(
            user_id=bob.id,
            label="X",
            password="k",
            path_token="abcdef123456789012345678",
        )
        await db.create_connection(database, conn)

        session = Session(token="alice-token", user_id=alice.id, expires_at=_expires_str())
        await db.create_session(database, session)

    client.cookies.set("session", "alice-token")
    response = await client.get(f"/connection/{conn.id}/config")
    assert response.status_code == 404


# Health check =========================================================================================================
async def test_healthz(client):
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# PRODUCT_NAME branding ================================================================================================
async def test_product_name_default(client):
    """Without PRODUCT_NAME set, login renders the default 'Postern' brand."""
    response = await client.get("/login")
    assert response.status_code == 200
    # The brand-name span (next to the header logo) carries the configured product name.
    assert '<span class="brand-name">Postern</span>' in response.text


async def test_product_name_override(tmp_path):
    """With PRODUCT_NAME=Foo, all brand surfaces use Foo."""
    settings = Settings(
        database_path=str(tmp_path / "test.db"),
        secret_key="test-secret",
        product_name="Foo",
    )
    app = PosternApp(settings)
    async with db.get_connection(settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database

        user = User(name="Alice", email="alice@example.com")
        await db.create_user(database, user)
        conn = Connection(
            user_id=user.id,
            path_token="abcdef123456789012345678",
            label="Laptop",
            password="k",
        )
        await db.create_connection(database, conn)
        session = Session(token="tok", user_id=user.id, expires_at=_expires_str())
        await db.create_session(database, session)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            login_resp = await c.get("/login")
            assert '<span class="brand-name">Foo</span>' in login_resp.text
            assert "Login — Foo" in login_resp.text

            c.cookies.set("session", "tok")
            cfg_resp = await c.get(f"/connection/{conn.id}/config")
            # PRODUCT_NAME is lowercased for the filename prefix.
            assert 'filename="foo-Laptop.json"' in cfg_resp.headers["content-disposition"]


def test_safe_filename_sanitization():
    """_safe_filename strips chars outside [A-Za-z0-9_-] from both inputs."""
    from postern.routes.dashboard import _safe_filename
    assert _safe_filename("Hole/Slash", "test") == "hole_slash-test.json"
    assert _safe_filename("Postern", "../etc/passwd") == "postern-___etc_passwd.json"
    assert _safe_filename("Foo Bar", "label with spaces") == "foo_bar-label_with_spaces.json"


async def test_otp_subject_uses_product_name(tmp_path):
    """email.send_otp_email subject is f'Your {product_name} login code'."""
    from postern import email
    settings = Settings(
        database_path=str(tmp_path / "x.db"),
        secret_key="test-secret",
        product_name="Hole",
    )
    captured: dict = {}

    async def fake_send(msg, **kwargs):
        captured["subject"] = msg["Subject"]

    with patch("postern.email.aiosmtplib.send", side_effect=fake_send):
        ok = await email.send_otp_email("a@b.example", "123456", settings)
    assert ok is True
    assert captured["subject"] == "Your Hole login code"


# Logout ===============================================================================================================
async def test_logout(client, app_settings):
    async with db.get_connection(app_settings.database_path) as database:
        user = User(name="Alice", email="alice@example.com")
        await db.create_user(database, user)

        session = Session(token="tok", user_id=user.id, expires_at=_expires_str())
        await db.create_session(database, session)

    client.cookies.set("session", "tok")
    response = await client.post("/logout", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# Edge cases ===========================================================================================================
async def test_login_page_redirects_when_logged_in(client, app_settings):
    async with db.get_connection(app_settings.database_path) as database:
        user = User(name="Alice", email="alice@example.com")
        await db.create_user(database, user)

        session = Session(token="active-tok", user_id=user.id, expires_at=_expires_str())
        await db.create_session(database, session)

    client.cookies.set("session", "active-tok")
    response = await client.get("/login", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"


async def test_download_disabled_connection_returns_404(client, app_settings):
    async with db.get_connection(app_settings.database_path) as database:
        user = User(name="Alice", email="alice@example.com")
        await db.create_user(database, user)

        conn = Connection(
            user_id=user.id,
            path_token="abcdef123456789012345678",
            label="Phone",
            password="k",
            enabled=False,
        )
        await db.create_connection(database, conn)

        session = Session(token="tok", user_id=user.id, expires_at=_expires_str())
        await db.create_session(database, session)

    client.cookies.set("session", "tok")
    response = await client.get(f"/connection/{conn.id}/config")
    assert response.status_code == 404


async def test_download_nonexistent_connection_returns_404(client, app_settings):
    async with db.get_connection(app_settings.database_path) as database:
        user = User(name="Alice", email="alice@example.com")
        await db.create_user(database, user)

        session = Session(token="tok", user_id=user.id, expires_at=_expires_str())
        await db.create_session(database, session)

    client.cookies.set("session", "tok")
    response = await client.get("/connection/nonexistent-uuid/config")
    assert response.status_code == 404


# Brand icon ===========================================================================================================
async def test_brand_icon_default(client):
    """No PRODUCT_ICON_PATH set -> serve the built-in gradient-square SVG."""
    response = await client.get("/brand-icon")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"
    # The shipped default begins with `<svg`. The OR-branch for `<?xml` was dead
    # code -- the file has no XML prologue. Pin the exact start so a future
    # accidental swap to a transparent placeholder is caught.
    assert response.text.lstrip().startswith("<svg")


async def test_brand_icon_custom_svg(tmp_path, app_settings):
    """PRODUCT_ICON_PATH pointing at an .svg file -> serve those bytes."""
    svg = tmp_path / "icon.svg"
    body = b"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1 1'><rect width='1' height='1'/></svg>"
    svg.write_bytes(body)
    app_settings.product_icon_path = str(svg)
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/brand-icon")
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("image/svg+xml")
            assert r.content == body


async def test_brand_icon_custom_png(tmp_path, app_settings):
    """PRODUCT_ICON_PATH pointing at a .png file -> serve those bytes with PNG MIME."""
    png = tmp_path / "icon.png"
    body = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32  # PNG magic + dummy bytes
    png.write_bytes(body)
    app_settings.product_icon_path = str(png)
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/brand-icon")
            assert r.status_code == 200
            assert r.headers["content-type"] == "image/png"
            assert r.content == body


async def test_brand_icon_missing_path_falls_back(tmp_path, app_settings):
    """PRODUCT_ICON_PATH pointing at a nonexistent file -> serve the default."""
    app_settings.product_icon_path = str(tmp_path / "does-not-exist.svg")
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/brand-icon")
            assert r.status_code == 200
            assert r.headers["content-type"] == "image/svg+xml"


async def test_brand_icon_oversized_falls_back(tmp_path, app_settings):
    """PRODUCT_ICON_PATH file > 256 KB -> serve the default (does not 413 or error)."""
    big = tmp_path / "huge.svg"
    big.write_bytes(b"<svg>" + b"x" * (300 * 1024) + b"</svg>")
    app_settings.product_icon_path = str(big)
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/brand-icon")
            assert r.status_code == 200
            assert r.headers["content-type"] == "image/svg+xml"
            # The default is much smaller than 300 KB.
            assert len(r.content) < 50 * 1024


async def test_brand_icon_disallowed_extension_falls_back(tmp_path, app_settings):
    """PRODUCT_ICON_PATH with a non-allowed suffix (.html, .json, etc.) -> default."""
    bad = tmp_path / "icon.html"
    bad.write_bytes(b"<svg/>")
    app_settings.product_icon_path = str(bad)
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/brand-icon")
            assert r.status_code == 200
            assert r.content != b"<svg/>"  # not the disallowed file


async def test_brand_icon_traversal_falls_back(tmp_path, app_settings):
    """PRODUCT_ICON_PATH that resolves to a path outside the allowlist (e.g. /etc/passwd)
    must never serve the resolved file.

    Asserts on the EXACT bytes of the built-in default rather than `status_code in
    (200, 404)`, which would let a 500 or a body containing the resolved file's
    content slip through unnoticed.
    """
    from postern.routes.brand_icon import _DEFAULT_BYTES
    # A relative path that, even if interpreted naively against the CWD, doesn't
    # exist or doesn't have an .svg/.png suffix on the resolved side.
    app_settings.product_icon_path = "../../../etc/passwd"
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/brand-icon")
            assert r.status_code == 200
            assert r.headers["content-type"] == "image/svg+xml"
            assert r.content == _DEFAULT_BYTES


async def test_brand_icon_relative_path_falls_back(tmp_path, app_settings):
    """Relative PRODUCT_ICON_PATH (not absolute) is rejected up front."""
    from postern.routes.brand_icon import _DEFAULT_BYTES
    # File exists with allowed suffix, but the path is relative -> reject.
    (tmp_path / "icon.svg").write_bytes(b"<svg xmlns='http://www.w3.org/2000/svg'/>")
    app_settings.product_icon_path = "icon.svg"  # bare relative name
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/brand-icon")
            assert r.status_code == 200
            assert r.content == _DEFAULT_BYTES


@pytest.mark.skipif(
    not hasattr(__import__("os"), "symlink"),
    reason="symlinks unavailable on this platform",
)
async def test_brand_icon_symlink_to_disallowed_target_falls_back(tmp_path, app_settings):
    """Symlink TOCTOU: /brand/icon.svg -> /etc/passwd must NOT serve the target.

    A naive implementation that checks the suffix only on the un-resolved path
    would happily follow this symlink and serve passwd contents with
    image/svg+xml. The route checks the suffix on the RESOLVED path too.
    """
    import os
    from postern.routes.brand_icon import _DEFAULT_BYTES
    target = tmp_path / "secret.txt"
    target.write_bytes(b"top-secret operator content\n")
    link = tmp_path / "icon.svg"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # Windows without dev-mode/admin
        pytest.skip(f"cannot create symlink in this environment: {exc}")
    app_settings.product_icon_path = str(link)
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/brand-icon")
            assert r.status_code == 200
            assert r.headers["content-type"] == "image/svg+xml"
            assert r.content == _DEFAULT_BYTES
            assert b"top-secret" not in r.content


# Static assets ========================================================================================================
async def test_static_assets_are_served(client):
    """The /static/ mount serves files from src/postern/static/."""
    r = await client.get("/static/brand-default.svg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")


# Redesigned templates =================================================================================================
async def test_login_renders_identity_card(client):
    """Login page renders the visitor identity panel ('You appear as') alongside the auth card."""
    r = await client.get("/login")
    assert r.status_code == 200
    assert 'class="ipc"' in r.text or "ipc" in r.text  # class lookup
    assert "You appear as" in r.text


async def test_dashboard_renders_connections_card(client, app_settings):
    """Dashboard renders the connections card and the user chip; identity card is dashboard-omitted."""
    async with db.get_connection(app_settings.database_path) as database:
        user = User(name="Alice", email="alice@example.com")
        await db.create_user(database, user)
        session = Session(token="dash-tok", user_id=user.id, expires_at=_expires_str())
        await db.create_session(database, session)

    client.cookies.set("session", "dash-tok")
    r = await client.get("/")
    assert r.status_code == 200
    assert 'class="cc"' in r.text or "cc-hdr" in r.text
    assert "user-chip" in r.text
    assert "Log out" in r.text


async def test_login_renders_brand_link(client):
    """The header brand mark references /brand-icon (never /static/brand-default.svg directly)."""
    r = await client.get("/login")
    assert r.status_code == 200
    assert '<img src="/brand-icon"' in r.text


# CSP enforcement scans ================================================================================================
# CSP for the portal is `default-src 'self'` -- no inline <style> blocks, inline
# <script> blocks, HTML event-handler attributes (`onclick=` etc.), or `style="..."`
# attributes. These scans are deliberately permissive about external <link>/<script
# src="...">, which are fine, and deliberately strict about everything else.

import re as _re


def _assert_no_inline_css_or_js(body: str, page: str) -> None:
    """Shared CSP scan applied per-template.

    Uses case-insensitive substring counts + DOTALL-aware regex so:
    - `<style` matches `<style>`, `<style type=...>`, `<STYLE` equally;
    - a stray `<styleguide>` element wouldn't false-positive;
    - multi-line `<script>...</script>` blocks are caught;
    - `<script src=...>` (with or without other attributes) is allowed;
    - `style="..."` attributes are caught case-insensitively.
    """
    lowered = body.lower()
    # `<style ` (with trailing space, `>` or `/`) -- never `<styleguide` or similar.
    style_open_count = len(_re.findall(r"<style[\s/>]", lowered))
    assert style_open_count == 0, f"unexpected inline <style> block in /{page}: count={style_open_count}"
    # Inline <script>...</script>: bare <script[> or <script ATTR> where ATTR set
    # contains no `src=`. DOTALL so the open-tag attribute list across newlines
    # is still matched.
    bare_scripts = _re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", body, _re.IGNORECASE | _re.DOTALL)
    assert not bare_scripts, f"unexpected inline <script> in /{page}: {bare_scripts}"
    # `style="..."` attribute on any tag, anywhere in the body. Case-insensitive
    # and tolerant of either quote style, single or double.
    style_attrs = _re.findall(r"""\sstyle\s*=\s*['"][^'"]*['"]""", body, _re.IGNORECASE)
    assert not style_attrs, f"unexpected inline style= attribute in /{page}: {style_attrs}"
    # HTML event-handler attributes (onclick=, onerror=, onload=, onsubmit=, etc.)
    # are CSP-blocked too.
    event_attrs = _re.findall(r"\s on[a-z]+\s*=", body, _re.IGNORECASE)
    assert not event_attrs, f"unexpected inline event handler attribute in /{page}: {event_attrs}"


async def test_login_uses_external_css_and_js(client):
    """CSP forbids inline. Pages must reference /static/postern.css and /static/postern.js."""
    r = await client.get("/login")
    assert r.status_code == 200
    assert "/static/postern.css" in r.text
    assert "/static/postern.js" in r.text
    _assert_no_inline_css_or_js(r.text, "login")


async def test_otp_uses_external_css_and_js(client):
    r = await client.get("/login/verify")
    assert r.status_code == 200
    assert "/static/postern.css" in r.text
    assert "/static/postern.js" in r.text
    _assert_no_inline_css_or_js(r.text, "login/verify")


async def test_dashboard_uses_external_css_and_js(client, app_settings):
    async with db.get_connection(app_settings.database_path) as database:
        user = User(name="Alice", email="alice@example.com")
        await db.create_user(database, user)
        session = Session(token="d2-tok", user_id=user.id, expires_at=_expires_str())
        await db.create_session(database, session)
    client.cookies.set("session", "d2-tok")
    r = await client.get("/")
    body = r.text
    assert "/static/postern.css" in body
    assert "/static/postern.js" in body
    _assert_no_inline_css_or_js(body, "")


async def test_login_has_no_inline_event_handlers(client):
    """CSP forbids onclick=, onerror= etc. attached as HTML attributes."""
    r = await client.get("/login")
    _assert_no_inline_css_or_js(r.text, "login")


async def test_login_identity_card_renders_ip_from_x_real_ip(app_settings, tmp_path):
    """When nginx forwards X-Real-IP, the rendered identity card surfaces it.

    Pin the ASGI client to a real RFC1918 IP (172.20.0.5) so the X-Real-IP guard
    actually fires: identity._client_ip only trusts the header when the direct
    socket peer is a private/loopback range. httpx's default ASGITransport client
    is ("testclient", 50000) -- "testclient" is not a parsable IP, which would
    let the test pass via the ValueError fall-through path instead of via the
    intended trusted-proxy-hop branch.
    """
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app, client=("172.20.0.5", 443))
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/login", headers={"X-Real-IP": "203.0.113.42"})
            assert r.status_code == 200
            assert "203.0.113.42" in r.text


async def test_login_identity_card_ignores_x_real_ip_from_public_peer(app_settings, tmp_path):
    """Spoofing guard: a public direct-hop IP must NOT cause X-Real-IP to be trusted.

    Mirrors test_lookup_ignores_x_real_ip_when_direct_is_public but exercised
    end-to-end through the rendered template, so a future refactor that bypasses
    identity._client_ip can't silently undo the protection.
    """
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app, client=("198.51.100.1", 443))
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/login", headers={"X-Real-IP": "203.0.113.42"})
            assert r.status_code == 200
            assert "198.51.100.1" in r.text
            assert "203.0.113.42" not in r.text
