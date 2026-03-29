"""Integration tests for the web routes."""

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from voyager import db
from voyager.app import create_app
from voyager.models import Connection, Session, User
from voyager.settings import Settings

from datetime import datetime, timedelta, timezone


def _expires_str(days=7):
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


@pytest.fixture
def app_settings(tmp_path):
    return Settings(database_path=str(tmp_path / "test.db"), secret_key="test-secret")


@pytest.fixture
def test_app(app_settings):
    app = create_app(app_settings)
    return app


@pytest_asyncio.fixture
async def client(test_app, app_settings):
    # Initialize DB without the reconciler
    database = await db.get_connection(app_settings.database_path)
    await db.migrate(database)
    test_app.state.db = database

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    await database.close()



# Login page =====
async def test_login_page_renders(client):
    response = await client.get("/login")
    assert response.status_code == 200
    assert "Voyager VPN" in response.text


async def test_login_redirects_to_verify(client, app_settings):
    # Create a user first
    database = await db.get_connection(app_settings.database_path)
    await db.create_user(database, User(name="Alice", email="alice@example.com"))
    await database.close()

    with patch("voyager.routes.login.email.send_otp_email", new_callable=AsyncMock, return_value=True):
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


# OTP verification =====
async def test_verify_page_renders(client):
    response = await client.get("/login/verify")
    assert response.status_code == 200
    assert "6-digit code" in response.text


# Dashboard =====
async def test_dashboard_requires_auth(client):
    response = await client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_dashboard_with_valid_session(client, app_settings):
    database = await db.get_connection(app_settings.database_path)
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(database, user)

    session = Session(token="test-session-token", user_id=user.id, expires_at=_expires_str())
    await db.create_session(database, session)
    await database.close()

    response = await client.get(
        "/", cookies={"session": "test-session-token"}
    )
    assert response.status_code == 200
    assert "Alice" in response.text


# Config download =====
async def test_config_download_requires_auth(client):
    response = await client.get("/connection/fake-id/config", follow_redirects=False)
    assert response.status_code == 303


async def test_config_download_for_owned_connection(client, app_settings):
    database = await db.get_connection(app_settings.database_path)
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
    await database.close()

    response = await client.get(
        f"/connection/{conn.id}/config",
        cookies={"session": "test-token"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    data = response.json()
    assert data["servers"][0]["address"] == "voyager.binarydreams.me"
    assert "path=/t/abcdef123456789012345678" in data["servers"][0]["plugin_opts"]


async def test_config_download_for_other_user_returns_404(client, app_settings):
    database = await db.get_connection(app_settings.database_path)
    alice = User(name="Alice", email="alice@example.com")
    bob = User(name="Bob", email="bob@example.com")
    await db.create_user(database, alice)
    await db.create_user(database, bob)

    conn = Connection(
        user_id=bob.id, label="X", password="k",
        path_token="abcdef123456789012345678",
    )
    await db.create_connection(database, conn)

    session = Session(token="alice-token", user_id=alice.id, expires_at=_expires_str())
    await db.create_session(database, session)
    await database.close()

    response = await client.get(
        f"/connection/{conn.id}/config",
        cookies={"session": "alice-token"},
    )
    assert response.status_code == 404


# Health check =====
async def test_healthz(client):
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# Logout =====
async def test_logout(client, app_settings):
    database = await db.get_connection(app_settings.database_path)
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(database, user)

    session = Session(token="tok", user_id=user.id, expires_at=_expires_str())
    await db.create_session(database, session)
    await database.close()

    response = await client.post(
        "/logout",
        cookies={"session": "tok"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# Edge cases =====
async def test_login_page_redirects_when_logged_in(client, app_settings):
    database = await db.get_connection(app_settings.database_path)
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(database, user)

    session = Session(token="active-tok", user_id=user.id, expires_at=_expires_str())
    await db.create_session(database, session)
    await database.close()

    response = await client.get(
        "/login",
        cookies={"session": "active-tok"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


async def test_download_disabled_connection_returns_404(client, app_settings):
    database = await db.get_connection(app_settings.database_path)
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
    await database.close()

    response = await client.get(
        f"/connection/{conn.id}/config",
        cookies={"session": "tok"},
    )
    assert response.status_code == 404


async def test_download_nonexistent_connection_returns_404(client, app_settings):
    database = await db.get_connection(app_settings.database_path)
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(database, user)

    session = Session(token="tok", user_id=user.id, expires_at=_expires_str())
    await db.create_session(database, session)
    await database.close()

    response = await client.get(
        "/connection/nonexistent-uuid/config",
        cookies={"session": "tok"},
    )
    assert response.status_code == 404
