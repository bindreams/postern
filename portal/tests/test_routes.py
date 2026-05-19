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
    assert "Alice" in response.text


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
    assert "<h1>Postern</h1>" in response.text


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
            assert "<h1>Foo</h1>" in login_resp.text
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
    assert response.text.lstrip().startswith("<svg") or response.text.lstrip().startswith("<?xml")


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
    must never serve the resolved file."""
    app_settings.product_icon_path = "../../../etc/passwd"
    app = PosternApp(app_settings)
    async with db.get_connection(app_settings.database_path) as database:
        await db.migrate(database)
        app.state.db = database
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/brand-icon")
            # Either falls back to the default SVG (preferred) or returns 404; never
            # serves /etc/passwd. Both outcomes are safe; both are tested via the
            # extension allowlist.
            assert r.status_code in (200, 404)
            if r.status_code == 200:
                assert r.headers["content-type"] == "image/svg+xml"


# Static assets ========================================================================================================
async def test_static_assets_are_served(client):
    """The /static/ mount serves files from src/postern/static/."""
    r = await client.get("/static/brand-default.svg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
