"""Tests for the admin CLI commands."""

import pytest
from typer.testing import CliRunner

from voyager.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def cli_env(tmp_path, monkeypatch):
    """Set environment variables for CLI commands."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("DATABASE_PATH", db_path)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    return db_path


# User commands =====
def test_user_add(cli_env):
    result = runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    assert result.exit_code == 0
    assert "Created user Alice" in result.output


def test_user_add_duplicate_email(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["user", "add", "Alice2", "alice@example.com"])
    assert result.exit_code != 0


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


# Connection commands =====
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
