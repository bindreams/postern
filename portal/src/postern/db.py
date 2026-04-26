from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import aiosqlite

from postern.models import Connection, Session, User

# Schema versions ======================================================================================================
MIGRATIONS: dict[int, str] = {
    1: """
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE connections (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            path_token TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            password TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT NOT NULL,
            used BOOLEAN NOT NULL DEFAULT 0
        );

        CREATE TABLE sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL
        );
    """,
}


@asynccontextmanager
async def get_connection(path: str) -> AsyncIterator[aiosqlite.Connection]:
    """Open a DB connection with standard pragmas; auto-close on exit.

    Use as `async with db.get_connection(path) as conn:`. Closure on every
    exit path is load-bearing: the aiosqlite worker is a non-daemon Thread
    and a missed close() hangs interpreter exit forever (see CLAUDE.md
    `Do-not list`).
    """
    async with aiosqlite.connect(path) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute("PRAGMA busy_timeout=5000")
        yield conn


async def migrate(db: aiosqlite.Connection) -> None:
    """Apply any pending schema migrations."""
    await db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
    cursor = await db.execute("SELECT MAX(version) FROM schema_version")
    row = await cursor.fetchone()
    current_version = (row[0] if row else None) or 0

    for version in sorted(MIGRATIONS):
        if version > current_version:
            for statement in MIGRATIONS[version].split(";"):
                statement = statement.strip()
                if statement:
                    await db.execute(statement)
            await db.execute("INSERT INTO schema_version (version) VALUES (?)", (version, ))
            await db.commit()


# User queries =========================================================================================================
async def create_user(db: aiosqlite.Connection, user: User) -> User:
    await db.execute(
        "INSERT INTO users (id, name, email) VALUES (?, ?, ?)",
        (user.id, user.name, user.email),
    )
    await db.commit()
    return user


async def get_user_by_email(db: aiosqlite.Connection, email: str) -> User | None:
    cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email, ))
    row = await cursor.fetchone()
    if row is None:
        return None
    return User(**dict(row))


async def get_user_by_id(db: aiosqlite.Connection, user_id: str) -> User | None:
    cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id, ))
    row = await cursor.fetchone()
    if row is None:
        return None
    return User(**dict(row))


async def list_users(db: aiosqlite.Connection) -> list[User]:
    cursor = await db.execute("SELECT * FROM users ORDER BY name")
    rows = await cursor.fetchall()
    return [User(**dict(row)) for row in rows]


async def delete_user(db: aiosqlite.Connection, user_id: str) -> bool:
    cursor = await db.execute("DELETE FROM users WHERE id = ?", (user_id, ))
    await db.commit()
    return cursor.rowcount > 0


# Connection queries ===================================================================================================
async def create_connection(db: aiosqlite.Connection, conn: Connection) -> Connection:
    await db.execute(
        """INSERT INTO connections (id, user_id, path_token, label, password, enabled)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            conn.id,
            conn.user_id,
            conn.path_token,
            conn.label,
            conn.password,
            conn.enabled,
        ),
    )
    await db.commit()
    return conn


async def get_connection_by_id(db: aiosqlite.Connection, connection_id: str) -> Connection | None:
    cursor = await db.execute("SELECT * FROM connections WHERE id = ?", (connection_id, ))
    row = await cursor.fetchone()
    if row is None:
        return None
    return Connection(**dict(row))


async def list_connections(db: aiosqlite.Connection,
                           *,
                           user_id: str | None = None,
                           enabled_only: bool = False) -> list[Connection]:
    query = "SELECT * FROM connections WHERE 1=1"
    params: list[object] = []
    if user_id is not None:
        query += " AND user_id = ?"
        params.append(user_id)
    if enabled_only:
        query += " AND enabled = 1"
    query += " ORDER BY created_at"
    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()
    return [Connection(**dict(row)) for row in rows]


async def set_connection_enabled(db: aiosqlite.Connection, connection_id: str, enabled: bool) -> bool:
    cursor = await db.execute(
        "UPDATE connections SET enabled = ? WHERE id = ?",
        (enabled, connection_id),
    )
    await db.commit()
    return cursor.rowcount > 0


async def delete_connections_for_user(db: aiosqlite.Connection, user_id: str) -> int:
    cursor = await db.execute("DELETE FROM connections WHERE user_id = ?", (user_id, ))
    await db.commit()
    return cursor.rowcount


# OTP queries ==========================================================================================================
async def create_otp(
    db: aiosqlite.Connection,
    email: str,
    code_hash: str,
    expires_at: str,
    max_per_window: int = 3,
) -> None:
    """Insert an OTP. Rate limit check + insert in a single transaction."""
    cursor = await db.execute(
        """SELECT COUNT(*) FROM otp_codes
           WHERE email = ? AND used = 0
             AND datetime('now') < datetime(expires_at)""",
        (email, ),
    )
    row = await cursor.fetchone()
    count = row[0] if row else 0

    if count >= max_per_window:
        raise ValueError("Rate limit exceeded")

    await db.execute(
        "INSERT INTO otp_codes (email, code_hash, expires_at) VALUES (?, ?, ?)",
        (email, code_hash, expires_at),
    )
    await db.commit()


async def verify_otp(db: aiosqlite.Connection, email: str, code_hash: str, max_attempts: int = 5) -> bool:
    """Check OTP validity. Returns True if valid, False otherwise.
    Increments attempt count on failure; marks as used on success.
    Uses constant-time comparison to prevent timing side-channels."""
    cursor = await db.execute(
        """SELECT id, code_hash, attempts FROM otp_codes
           WHERE email = ? AND used = 0 AND datetime(expires_at) > datetime('now')
           ORDER BY id DESC LIMIT 1""",
        (email, ),
    )
    row = await cursor.fetchone()
    if row is None:
        return False

    otp_id, stored_hash, attempts = row["id"], row["code_hash"], row["attempts"]

    if attempts >= max_attempts:
        await db.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_id, ))
        await db.commit()
        return False

    if not hmac.compare_digest(stored_hash, code_hash):
        await db.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?", (otp_id, ))
        await db.commit()
        return False

    await db.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_id, ))
    await db.commit()
    return True


# Session queries ======================================================================================================
async def create_session(db: aiosqlite.Connection, session: Session) -> Session:
    await db.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (session.token, session.user_id, session.expires_at),
    )
    await db.commit()
    return session


async def get_valid_session(db: aiosqlite.Connection, token: str) -> Session | None:
    cursor = await db.execute(
        """SELECT * FROM sessions
           WHERE token = ? AND datetime(expires_at) > datetime('now')""",
        (token, ),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return Session(**dict(row))


async def delete_session(db: aiosqlite.Connection, token: str) -> bool:
    cursor = await db.execute("DELETE FROM sessions WHERE token = ?", (token, ))
    await db.commit()
    return cursor.rowcount > 0


# Cleanup ==============================================================================================================
async def cleanup_expired(db: aiosqlite.Connection) -> None:
    """Remove expired sessions and used/expired OTP codes."""
    await db.execute("DELETE FROM sessions WHERE datetime(expires_at) <= datetime('now')")
    await db.execute("""DELETE FROM otp_codes
           WHERE used = 1 OR datetime(expires_at) <= datetime('now')""")
    await db.commit()
