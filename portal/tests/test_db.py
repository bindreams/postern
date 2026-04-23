import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from voyager import db
from voyager.models import Connection, Session, User


# User CRUD ============================================================================================================
async def test_create_and_get_user(test_db):
    user = User(name="Alice", email="alice@example.com")
    created = await db.create_user(test_db, user)
    assert created.id == user.id

    fetched = await db.get_user_by_email(test_db, "alice@example.com")
    assert fetched is not None
    assert fetched.name == "Alice"
    assert fetched.id == user.id


async def test_get_user_not_found(test_db):
    assert await db.get_user_by_email(test_db, "nobody@example.com") is None


async def test_list_users(test_db):
    await db.create_user(test_db, User(name="Bob", email="bob@example.com"))
    await db.create_user(test_db, User(name="Alice", email="alice@example.com"))
    users = await db.list_users(test_db)
    assert len(users) == 2
    assert users[0].name == "Alice"  # sorted by name


async def test_delete_user_cascades_connections(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)
    conn = Connection(user_id=user.id, path_token="aabb112233445566aabb1122", label="Phone", password="key123")
    await db.create_connection(test_db, conn)

    await db.delete_user(test_db, user.id)
    assert await db.get_user_by_id(test_db, user.id) is None
    connections = await db.list_connections(test_db, user_id=user.id)
    assert connections == []


# Connection CRUD ======================================================================================================
async def test_create_connection(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    conn = Connection(
        user_id=user.id,
        path_token="abcdef123456789012345678",
        label="iPhone",
        password="base64key==",
    )
    await db.create_connection(test_db, conn)

    fetched = await db.get_connection_by_id(test_db, conn.id)
    assert fetched is not None
    assert fetched.path_token == "abcdef123456789012345678"
    assert fetched.enabled is True


async def test_list_connections_enabled_only(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    c1 = Connection(user_id=user.id, path_token="aa11bb22cc33dd44ee55ff66", label="A", password="k")
    c2 = Connection(user_id=user.id, path_token="ff66ee55dd44cc33bb22aa11", label="B", password="k", enabled=False)
    await db.create_connection(test_db, c1)
    await db.create_connection(test_db, c2)

    all_conns = await db.list_connections(test_db)
    assert len(all_conns) == 2

    enabled = await db.list_connections(test_db, enabled_only=True)
    assert len(enabled) == 1
    assert enabled[0].label == "A"


async def test_disable_and_enable_connection(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)
    conn = Connection(user_id=user.id, path_token="aa11bb22cc33dd44ee55ff66", label="X", password="k")
    await db.create_connection(test_db, conn)

    assert await db.set_connection_enabled(test_db, conn.id, False)
    fetched = await db.get_connection_by_id(test_db, conn.id)
    assert fetched is not None
    assert fetched.enabled is False

    assert await db.set_connection_enabled(test_db, conn.id, True)
    fetched = await db.get_connection_by_id(test_db, conn.id)
    assert fetched is not None
    assert fetched.enabled is True


# OTP ==================================================================================================================
async def test_create_and_verify_otp(test_db):
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    code_hash = hashlib.sha256(b"123456").hexdigest()

    await db.create_otp(test_db, "alice@example.com", code_hash, expires)
    assert await db.verify_otp(test_db, "alice@example.com", code_hash)


async def test_verify_wrong_otp(test_db):
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    code_hash = hashlib.sha256(b"123456").hexdigest()
    wrong_hash = hashlib.sha256(b"000000").hexdigest()

    await db.create_otp(test_db, "alice@example.com", code_hash, expires)
    assert not await db.verify_otp(test_db, "alice@example.com", wrong_hash)


async def test_otp_max_attempts(test_db):
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    code_hash = hashlib.sha256(b"123456").hexdigest()
    wrong_hash = hashlib.sha256(b"000000").hexdigest()

    await db.create_otp(test_db, "alice@example.com", code_hash, expires)

    # Exhaust attempts
    for _ in range(5):
        await db.verify_otp(test_db, "alice@example.com", wrong_hash)

    # Even correct code should fail now (OTP invalidated)
    assert not await db.verify_otp(test_db, "alice@example.com", code_hash)


async def test_otp_rate_limit(test_db):
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()

    for i in range(3):
        await db.create_otp(test_db, "alice@example.com", f"hash{i}", expires)

    with pytest.raises(ValueError, match="Rate limit"):
        await db.create_otp(test_db, "alice@example.com", "hash3", expires)


async def test_verify_otp_uses_constant_time_comparison(test_db):
    """Invariant: OTP verification must go through hmac.compare_digest, never ==.
    Guards against a reviewer simplifying the comparison. See CLAUDE.md.

    Covers BOTH accept and reject paths so compare_digest is pinned as the
    gatekeeper for the decision, not just called incidentally."""
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    code_hash = hashlib.sha256(b"123456").hexdigest()
    wrong_hash = hashlib.sha256(b"000000").hexdigest()

    await db.create_otp(test_db, "alice@example.com", code_hash, expires)

    # Reject path: compare called with (stored, provided), returns False.
    with patch("voyager.db.hmac.compare_digest", wraps=hmac.compare_digest) as mock_cmp:
        assert not await db.verify_otp(test_db, "alice@example.com", wrong_hash)
    mock_cmp.assert_called_once_with(code_hash, wrong_hash)

    # Accept path: compare_digest gates acceptance.
    with patch("voyager.db.hmac.compare_digest", wraps=hmac.compare_digest) as mock_cmp:
        assert await db.verify_otp(test_db, "alice@example.com", code_hash)
    mock_cmp.assert_called_once_with(code_hash, code_hash)


# Session ==============================================================================================================
async def test_create_and_get_session(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    expires = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    session = Session(token="tok123", user_id=user.id, expires_at=expires)
    await db.create_session(test_db, session)

    fetched = await db.get_valid_session(test_db, "tok123")
    assert fetched is not None
    assert fetched.user_id == user.id


async def test_expired_session_not_returned(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    expires = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    session = Session(token="expired", user_id=user.id, expires_at=expires)
    await db.create_session(test_db, session)

    assert await db.get_valid_session(test_db, "expired") is None


async def test_delete_session(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    expires = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    session = Session(token="tok123", user_id=user.id, expires_at=expires)
    await db.create_session(test_db, session)

    assert await db.delete_session(test_db, "tok123")
    assert await db.get_valid_session(test_db, "tok123") is None


# Cleanup ==============================================================================================================
async def test_cleanup_expired(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    # Expired session
    expired_session = Session(
        token="old",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    await db.create_session(test_db, expired_session)

    # Valid session
    valid_session = Session(
        token="current",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    await db.create_session(test_db, valid_session)

    await db.cleanup_expired(test_db)

    assert await db.get_valid_session(test_db, "old") is None
    assert await db.get_valid_session(test_db, "current") is not None


# Edge cases ===========================================================================================================
async def test_delete_connections_for_user(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)
    c1 = Connection(user_id=user.id, path_token="aa11bb22cc33dd44ee55ff66", label="A", password="k")
    c2 = Connection(user_id=user.id, path_token="ff66ee55dd44cc33bb22aa11", label="B", password="k")
    await db.create_connection(test_db, c1)
    await db.create_connection(test_db, c2)

    count = await db.delete_connections_for_user(test_db, user.id)
    assert count == 2
    assert await db.list_connections(test_db, user_id=user.id) == []


async def test_get_user_by_id_directly(test_db):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    fetched = await db.get_user_by_id(test_db, user.id)
    assert fetched is not None
    assert fetched.name == "Alice"

    assert await db.get_user_by_id(test_db, "nonexistent-uuid") is None


async def test_delete_nonexistent_user(test_db):
    assert not await db.delete_user(test_db, "nonexistent-uuid")


async def test_delete_nonexistent_session(test_db):
    assert not await db.delete_session(test_db, "nonexistent-token")


# Migration ============================================================================================================
async def test_migrate_is_idempotent(test_db):
    # test_db fixture already migrated; calling again should be a no-op
    await db.migrate(test_db)
    users = await db.list_users(test_db)
    assert users == []
