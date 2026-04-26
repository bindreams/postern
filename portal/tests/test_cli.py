"""Tests for the admin CLI commands."""

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from postern.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def cli_env(tmp_path, monkeypatch):
    """Set environment variables for CLI commands."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("DATABASE_PATH", db_path)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    return db_path


# User commands ========================================================================================================
def test_user_add(cli_env):
    result = runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    assert result.exit_code == 0
    assert "Created user Alice" in result.output


def test_user_add_duplicate_email(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["user", "add", "Alice2", "alice@example.com"])
    assert result.exit_code != 0


def test_cli_does_not_leak_aiosqlite_workers_on_error(cli_env):
    """Regression: every cli command must close its DB connection on every
    path. The aiosqlite worker is a non-daemon Thread; a missed close() means
    the thread blocks interpreter exit forever after pytest finishes.

    The duplicate-email path is the canonical trigger: the second `user add`
    raises sqlite3.IntegrityError before close()."""
    import threading

    def aiosqlite_workers() -> set[threading.Thread]:
        # Worker target is `aiosqlite.core._connection_worker_thread`; default
        # Thread name embeds the target on Python 3.10+ (e.g. "Thread-7
        # (_connection_worker_thread)").
        return {t for t in threading.enumerate() if t.is_alive() and "_connection_worker_thread" in (t.name or "")}

    # First invoke succeeds and runs close(); snapshot AFTER it so any
    # still-terminating worker from this success path is treated as
    # "pre-existing" and excluded from the leak count.
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    before = aiosqlite_workers()

    result = runner.invoke(app, ["user", "add", "Alice2", "alice@example.com"])
    assert result.exit_code != 0  # duplicate email -> IntegrityError

    leaked = aiosqlite_workers() - before
    assert not leaked, (
        f"CLI leaked aiosqlite worker thread(s) on error path: {leaked}. "
        f"Each leaked non-daemon thread will hang interpreter exit forever."
    )


def test_user_list(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    runner.invoke(app, ["user", "add", "Bob", "bob@example.com"])
    result = runner.invoke(app, ["user", "list"])
    assert result.exit_code == 0
    assert "Alice" in result.output
    assert "Bob" in result.output


def test_user_list_empty(cli_env):
    result = runner.invoke(app, ["user", "list"])
    assert result.exit_code == 0
    assert "No users" in result.output


def test_user_disable(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    result = runner.invoke(app, ["user", "disable", "alice@example.com"])
    assert result.exit_code == 0
    assert "Disabled 1 connection" in result.output


def test_user_disable_not_found(cli_env):
    result = runner.invoke(app, ["user", "disable", "nobody@example.com"])
    assert result.exit_code == 1


def test_user_delete(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["user", "delete", "alice@example.com"])
    assert result.exit_code == 0
    assert "Deleted user" in result.output


def test_user_delete_not_found(cli_env):
    result = runner.invoke(app, ["user", "delete", "nobody@example.com"])
    assert result.exit_code == 1


# Connection commands ==================================================================================================
def test_connection_add(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "iPhone"])
    assert result.exit_code == 0
    assert "Created connection" in result.output


def test_connection_add_user_not_found(cli_env):
    result = runner.invoke(app, ["connection", "add", "nobody@example.com", "Phone"])
    assert result.exit_code == 1


def test_connection_list(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    runner.invoke(app, ["connection", "add", "alice@example.com", "iPhone"])
    result = runner.invoke(app, ["connection", "list"])
    assert result.exit_code == 0
    assert "iPhone" in result.output


def test_connection_list_filter_by_user(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    runner.invoke(app, ["user", "add", "Bob", "bob@example.com"])
    runner.invoke(app, ["connection", "add", "alice@example.com", "Alice-Phone"])
    runner.invoke(app, ["connection", "add", "bob@example.com", "Bob-Phone"])

    result = runner.invoke(app, ["connection", "list", "--user-email", "alice@example.com"])
    assert result.exit_code == 0
    assert "Alice-Phone" in result.output
    assert "Bob-Phone" not in result.output


def test_connection_disable(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    conn_id = result.output.split("Created connection ")[1].strip()

    result = runner.invoke(app, ["connection", "disable", conn_id])
    assert result.exit_code == 0
    assert "Connection disabled" in result.output


def test_connection_enable(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    conn_id = result.output.split("Created connection ")[1].strip()

    runner.invoke(app, ["connection", "disable", conn_id])
    result = runner.invoke(app, ["connection", "enable", conn_id])
    assert result.exit_code == 0
    assert "Connection enabled" in result.output


def test_connection_disable_not_found(cli_env):
    result = runner.invoke(app, ["connection", "disable", "nonexistent-uuid"])
    assert result.exit_code == 1


def test_connection_list_user_not_found(cli_env):
    """The --user-email path raises typer.Exit(1) from inside an async with block;
    pin the user-facing message + exit code so the rewrite can't drift."""
    result = runner.invoke(app, ["connection", "list", "--user-email", "nobody@example.com"])
    assert result.exit_code == 1
    assert "User not found: nobody@example.com" in result.output


# Reconcile command ====================================================================================================
def test_reconcile_creates_trigger_file(cli_env, tmp_path):
    """`postern reconcile` is the operator-facing manual-reconcile trigger, used in
    place of `touch /data/.reconcile-now` since the production image is distroless
    and has no `touch` binary. It writes the same file the reconciler watches
    (next to the database) and prints the path so operators can grep logs."""
    trigger = tmp_path / ".reconcile-now"
    assert trigger.parent == Path(os.environ["DATABASE_PATH"]).parent  # invariant pin
    assert not trigger.exists()

    result = runner.invoke(app, ["reconcile"])
    assert result.exit_code == 0
    assert trigger.exists()
    assert "Reconcile triggered" in result.output
    assert str(trigger) in result.output

    # Idempotent: a second call must succeed without error or extra side-effects
    result2 = runner.invoke(app, ["reconcile"])
    assert result2.exit_code == 0
    assert trigger.exists()
