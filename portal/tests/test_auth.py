from voyager import db
from voyager.auth import (
    generate_otp_code,
    generate_session_token,
    hash_otp,
    request_otp,
    verify_otp_and_create_session,
)
from voyager.models import User
from voyager.settings import Settings


def test_generate_otp_code_is_6_digits():
    code = generate_otp_code()
    assert len(code) == 6
    assert code.isdigit()


def test_generate_otp_code_is_zero_padded():
    # Run many times to have a chance of hitting a small number
    codes = {generate_otp_code() for _ in range(100)}
    assert all(len(c) == 6 for c in codes)


def test_hash_otp_is_deterministic():
    assert hash_otp("123456") == hash_otp("123456")
    assert hash_otp("123456") != hash_otp("654321")


def test_generate_session_token_is_unique():
    tokens = {generate_session_token() for _ in range(100)}
    assert len(tokens) == 100


async def test_request_otp_for_existing_user(test_db, settings):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    code = await request_otp(test_db, "alice@example.com", settings)
    assert code is not None
    assert len(code) == 6


async def test_request_otp_for_nonexistent_user(test_db, settings):
    code = await request_otp(test_db, "nobody@example.com", settings)
    assert code is None


async def test_request_otp_creates_dummy_row_for_nonexistent_user(test_db, settings):
    """Invariant: unknown emails must still create an otp_codes row (under a
    __dummy__ prefix) so timing and rate-limit buckets don't leak existence.
    See CLAUDE.md "Email-enumeration defence"."""
    await request_otp(test_db, "ghost@example.com", settings)

    cursor = await test_db.execute("SELECT email FROM otp_codes")
    rows = await cursor.fetchall()
    assert len(rows) == 1
    assert rows[0]["email"] == "__dummy__ghost@example.com"


async def test_verify_otp_creates_session(test_db, settings):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    code = await request_otp(test_db, "alice@example.com", settings)
    assert code is not None

    session = await verify_otp_and_create_session(test_db, "alice@example.com", code, settings)
    assert session is not None
    assert session.user_id == user.id
    assert len(session.token) > 20


async def test_verify_wrong_otp_returns_none(test_db, settings):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    await request_otp(test_db, "alice@example.com", settings)

    session = await verify_otp_and_create_session(test_db, "alice@example.com", "000000", settings)
    assert session is None


async def test_otp_rate_limit_returns_none(test_db, settings):
    user = User(name="Alice", email="alice@example.com")
    await db.create_user(test_db, user)

    # Exhaust rate limit
    for _ in range(3):
        await request_otp(test_db, "alice@example.com", settings)

    # Fourth request should return None (rate limited)
    code = await request_otp(test_db, "alice@example.com", settings)
    assert code is None
