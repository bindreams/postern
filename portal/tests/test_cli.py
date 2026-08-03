"""Tests for the admin CLI commands."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    # Resolved by default -- most tests aren't about instance-identity
    # warnings and shouldn't have to think about this. Tests that DO care
    # use _unresolve_identity() below to unset it.
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "postern-test")
    return db_path


def _unresolve_identity(monkeypatch):
    """Make resolve_instance_id() return None for the rest of this test --
    neither env var set. Used by the instance-identity-warning tests below;
    kept as a shared helper since 5+ tests need it applied identically."""
    monkeypatch.delenv("COMPOSE_PROJECT_NAME", raising=False)
    monkeypatch.delenv("INSTANCE_ID", raising=False)


@pytest.fixture(autouse=True)
def _mock_docker_client(monkeypatch):
    """`connection disable` and `user delete` both construct a real
    docker.DockerClient.from_env() (the disabled/deleted-connection legacy-
    container check) -- CLAUDE.md pins that tests never need a real Docker
    daemon. Without this, any test invoking either command depends on the
    ambient DOCKER_HOST: on a host where it points at an unreachable (not
    refusing) endpoint, docker-py's default 60s connect timeout would hang
    the whole suite with no obvious cause.

    Default: no container found (the common case, and harmless even for
    tests that never look at Docker at all). Tests that need different
    container-lookup behavior use `patch("docker.DockerClient.from_env",
    ...)` in their own scope, which takes precedence for its duration.
    """
    import docker.errors
    mock_client = MagicMock()
    mock_client.containers.get.side_effect = docker.errors.NotFound("no such container")
    monkeypatch.setattr("docker.DockerClient.from_env", MagicMock(return_value=mock_client))
    return mock_client


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


def test_user_disable_warns_when_legacy_container_still_running(cli_env):
    """`user disable` is the revoke-this-person's-access command -- it must
    get the identical proactive legacy-container warning `connection
    disable` and `user delete` do, not leave the operator to discover a
    still-running pre-upgrade tunnel only via the reconciler's own
    periodic log line."""
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])

    import sqlite3
    with sqlite3.connect(cli_env) as raw:
        path_token = raw.execute("SELECT path_token FROM connections WHERE label='Phone'").fetchone()[0]

    container = MagicMock()
    container.labels = {"postern.managed": "true"}  # legacy: no instance label
    container.status = "running"
    mock_client = MagicMock()
    mock_client.containers.get.return_value = container

    with patch("docker.DockerClient.from_env", return_value=mock_client):
        result = runner.invoke(app, ["user", "disable", "alice@example.com"])

    assert result.exit_code == 0
    assert f"ss-{path_token}" in result.output
    assert "docker rm -f" in result.output


def test_user_delete(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["user", "delete", "alice@example.com"])
    assert result.exit_code == 0
    assert "Deleted user" in result.output


def test_user_delete_not_found(cli_env):
    result = runner.invoke(app, ["user", "delete", "nobody@example.com"])
    assert result.exit_code == 1


def test_user_delete_warns_when_legacy_container_still_running(cli_env):
    """`user delete` cascades the connection row away at the database level
    -- unlike `connection disable`, there is no surviving row for the
    reconciler's own periodic check to ever match a legacy container
    against afterward. This is the ONLY place that check can still happen,
    so it must run before (or as part of) the delete, using the
    still-known path_token."""
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    path_token_label = result.output  # "Created connection <id> (<plugin>, ech=<mode>)"
    assert "Created connection" in path_token_label

    import sqlite3
    with sqlite3.connect(cli_env) as raw:
        path_token = raw.execute("SELECT path_token FROM connections WHERE label='Phone'").fetchone()[0]

    container = MagicMock()
    container.labels = {"postern.managed": "true"}  # legacy: no instance label
    container.status = "running"
    mock_client = MagicMock()
    mock_client.containers.get.return_value = container

    with patch("docker.DockerClient.from_env", return_value=mock_client):
        result = runner.invoke(app, ["user", "delete", "alice@example.com"])

    assert result.exit_code == 0
    assert f"ss-{path_token}" in result.output
    assert "docker rm -f" in result.output


def test_user_delete_does_not_warn_when_no_connections(cli_env):
    """A user with zero connections must not trigger any Docker lookup at
    all -- the common case for `user add` immediately followed by `user
    delete`."""
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])

    with patch("docker.DockerClient.from_env") as mock_from_env:
        result = runner.invoke(app, ["user", "delete", "alice@example.com"])

    assert result.exit_code == 0
    mock_from_env.assert_not_called()


# Connection commands ==================================================================================================
def test_connection_add(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "iPhone"])
    assert result.exit_code == 0
    assert "Created connection" in result.output


def test_connection_add_user_not_found(cli_env):
    result = runner.invoke(app, ["connection", "add", "nobody@example.com", "Phone"])
    assert result.exit_code == 1


# Connection plugin flag ===============================================================================================
def test_connection_add_default_plugin_is_v2ray(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "iPhone"])
    assert result.exit_code == 0
    import sqlite3
    with sqlite3.connect(cli_env) as raw:
        row = raw.execute("SELECT plugin FROM connections WHERE label='iPhone'").fetchone()
    assert row is not None and row[0] == "v2ray-plugin"


def test_connection_add_plugin_galoshes(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "iPad", "--plugin", "galoshes"])
    assert result.exit_code == 0, result.output
    import sqlite3
    with sqlite3.connect(cli_env) as raw:
        row = raw.execute("SELECT plugin FROM connections WHERE label='iPad'").fetchone()
    assert row is not None and row[0] == "galoshes"


def test_connection_add_explicit_v2ray_plugin_value(cli_env):
    """Pins the --plugin v2ray-plugin form against any Typer-Enum
    value-vs-name rendering regression. PluginChoice.v2ray = "v2ray-plugin";
    Typer should accept the *value* on the CLI, not the *name*."""
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Mac", "--plugin", "v2ray-plugin"])
    assert result.exit_code == 0, result.output
    import sqlite3
    with sqlite3.connect(cli_env) as raw:
        row = raw.execute("SELECT plugin FROM connections WHERE label='Mac'").fetchone()
    assert row is not None and row[0] == "v2ray-plugin"


def test_connection_add_invalid_plugin_rejected(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "X", "--plugin", "bogus"])
    assert result.exit_code != 0


def test_connection_list_shows_plugin(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    runner.invoke(app, ["connection", "add", "alice@example.com", "iPhone"])
    runner.invoke(app, ["connection", "add", "alice@example.com", "iPad", "--plugin", "galoshes"])
    result = runner.invoke(app, ["connection", "list"])
    assert result.exit_code == 0
    assert "[v2ray-plugin]" in result.output
    assert "[galoshes]" in result.output


# Connection ech flag ==================================================================================================
def _stored_ech(db_path, label):
    import sqlite3
    with sqlite3.connect(db_path) as raw:
        row = raw.execute("SELECT ech FROM connections WHERE label=?", (label, )).fetchone()
    return row[0] if row else "<missing>"


def test_connection_add_default_ech_is_auto(cli_env, monkeypatch):
    # auto must NOT trigger the front self-check; make check_apex_ech explode so an
    # accidental widening of the `if ech is EchChoice.always` gate fails here,
    # deterministically, instead of making a real network call.
    def _boom(*a, **k):
        raise AssertionError("check_apex_ech must not run for --ech auto")

    monkeypatch.setattr("postern.ech.check_apex_ech", _boom)
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    runner.invoke(app, ["connection", "add", "alice@example.com", "iPhone"])
    assert _stored_ech(cli_env, "iPhone") == "auto"


def test_connection_add_explicit_never(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "iPad", "--ech", "never"])
    assert result.exit_code == 0, result.output
    assert _stored_ech(cli_env, "iPad") == "never"


def test_connection_add_invalid_ech_rejected(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "X", "--ech", "sometimes"])
    assert result.exit_code != 0


def test_connection_add_always_allowed_when_front_present(cli_env, monkeypatch):
    monkeypatch.setattr("postern.ech.check_apex_ech", lambda *a, **k: "present")
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Mac", "--ech", "always"])
    assert result.exit_code == 0, result.output
    assert _stored_ech(cli_env, "Mac") == "always"


def test_connection_add_always_refused_when_front_absent(cli_env, monkeypatch):
    monkeypatch.setattr("postern.ech.check_apex_ech", lambda *a, **k: "absent")
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "X", "--ech", "always"])
    assert result.exit_code == 1
    assert "not serving ECH" in result.output


def test_connection_add_always_warns_when_inconclusive(cli_env, monkeypatch):
    monkeypatch.setattr("postern.ech.check_apex_ech", lambda *a, **k: "inconclusive")
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone", "--ech", "always"])
    assert result.exit_code == 0, result.output
    assert "could not confirm" in result.output
    assert _stored_ech(cli_env, "Phone") == "always"


def test_connection_add_always_requires_doh(cli_env, monkeypatch):
    # Blank DoH short-circuits before check_apex_ech, so no mock is needed here.
    monkeypatch.setenv("ECH_DOH_URL", "")
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "X", "--ech", "always"])
    assert result.exit_code == 1
    assert "ECH_DOH_URL" in result.output


def test_connection_add_auto_survives_blank_doh(cli_env, monkeypatch):
    monkeypatch.setenv("ECH_DOH_URL", "")
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Tab", "--ech", "auto"])
    assert result.exit_code == 0, result.output
    assert _stored_ech(cli_env, "Tab") == "auto"


def test_connection_list_shows_ech(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    runner.invoke(app, ["connection", "add", "alice@example.com", "iPhone", "--ech", "never"])
    result = runner.invoke(app, ["connection", "list"])
    assert result.exit_code == 0
    assert "ech:never" in result.output


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
    # Output is "Created connection <uuid> (<plugin>)"; take the UUID only.
    conn_id = result.output.split("Created connection ")[1].split()[0]

    result = runner.invoke(app, ["connection", "disable", conn_id])
    assert result.exit_code == 0
    assert "Connection disabled" in result.output


def test_connection_enable(cli_env):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    # Output is "Created connection <uuid> (<plugin>)"; take the UUID only.
    conn_id = result.output.split("Created connection ")[1].split()[0]

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


def test_reconcile_fails_when_identity_unresolved(cli_env, monkeypatch):
    """`postern reconcile` still writes the trigger file (harmless), but must
    exit nonzero and warn -- silently reporting success while the reconciler
    is about to no-op on every container would hide the misconfiguration."""
    _unresolve_identity(monkeypatch)

    result = runner.invoke(app, ["reconcile"])

    assert result.exit_code == 1
    assert "WARNING: could not determine this deployment's instance id" in result.output


def test_reconcile_succeeds_when_identity_resolved(cli_env):
    result = runner.invoke(app, ["reconcile"])
    assert result.exit_code == 0
    assert "WARNING" not in result.output


# Instance identity warnings ===========================================================================================
def test_user_disable_warns_when_identity_unresolved(cli_env, monkeypatch):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    _unresolve_identity(monkeypatch)

    result = runner.invoke(app, ["user", "disable", "alice@example.com"])

    assert result.exit_code == 0  # the disable itself still succeeds
    assert "WARNING: could not determine this deployment's instance id" in result.output


def test_user_delete_warns_when_identity_unresolved(cli_env, monkeypatch):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    _unresolve_identity(monkeypatch)

    result = runner.invoke(app, ["user", "delete", "alice@example.com"])

    assert result.exit_code == 0
    assert "WARNING: could not determine this deployment's instance id" in result.output


def test_connection_add_warns_when_identity_unresolved(cli_env, monkeypatch):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    _unresolve_identity(monkeypatch)

    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])

    assert result.exit_code == 0
    assert "WARNING: could not determine this deployment's instance id" in result.output


def test_connection_disable_warns_when_identity_unresolved(cli_env, monkeypatch):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    conn_id = result.output.split("Created connection ")[1].split()[0]
    _unresolve_identity(monkeypatch)

    result = runner.invoke(app, ["connection", "disable", conn_id])

    assert result.exit_code == 0
    assert "WARNING: could not determine this deployment's instance id" in result.output


def test_connection_enable_warns_when_identity_unresolved(cli_env, monkeypatch):
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    conn_id = result.output.split("Created connection ")[1].split()[0]
    runner.invoke(app, ["connection", "disable", conn_id])
    _unresolve_identity(monkeypatch)

    result = runner.invoke(app, ["connection", "enable", conn_id])

    assert result.exit_code == 0
    assert "WARNING: could not determine this deployment's instance id" in result.output


def test_connection_add_does_not_warn_when_identity_resolved(cli_env):
    """The positive case: a correctly-configured deployment (the default
    cli_env fixture already sets COMPOSE_PROJECT_NAME) must never see this
    warning -- a regression here would false-positive-spam every ordinary
    invocation."""
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])

    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])

    assert result.exit_code == 0
    assert "WARNING" not in result.output


# Disabled-connection container survival warning =======================================================================
def test_connection_disable_warns_when_legacy_container_still_running(cli_env, monkeypatch):
    """The proactive, CLI-side counterpart to the reconciler's own
    _report_legacy_running_containers: `connection disable` immediately
    surfaces the same manual-remediation guidance instead of leaving the
    operator to notice only in the reconciler's logs on the next pass."""
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    conn_id = result.output.split("Created connection ")[1].split()[0]
    path_token = _connection_path_token(cli_env, conn_id)

    container = MagicMock()
    container.labels = {"postern.managed": "true"}  # legacy: no instance label
    container.status = "running"
    mock_client = MagicMock()
    mock_client.containers.get.return_value = container

    with patch("docker.DockerClient.from_env", return_value=mock_client):
        result = runner.invoke(app, ["connection", "disable", conn_id])

    assert result.exit_code == 0
    assert f"ss-{path_token}" in result.output
    assert "docker rm -f" in result.output


def test_connection_disable_does_not_warn_for_own_instance_container(cli_env):
    """A container already labelled for THIS instance is swept normally by
    the reconciler on its next pass -- no separate CLI warning needed."""
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    conn_id = result.output.split("Created connection ")[1].split()[0]

    container = MagicMock()
    container.labels = {"postern.managed": "true", "postern.instance": "postern-test"}
    container.status = "running"
    mock_client = MagicMock()
    mock_client.containers.get.return_value = container

    with patch("docker.DockerClient.from_env", return_value=mock_client):
        result = runner.invoke(app, ["connection", "disable", conn_id])

    assert result.exit_code == 0
    assert "docker rm -f" not in result.output


def test_connection_disable_does_not_warn_when_no_container_exists(cli_env):
    import docker.errors

    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    conn_id = result.output.split("Created connection ")[1].split()[0]

    mock_client = MagicMock()
    mock_client.containers.get.side_effect = docker.errors.NotFound("no such container")

    with patch("docker.DockerClient.from_env", return_value=mock_client):
        result = runner.invoke(app, ["connection", "disable", conn_id])

    assert result.exit_code == 0
    assert "docker rm -f" not in result.output


def test_connection_disable_reports_when_container_lookup_fails(cli_env):
    """A Docker-side failure (docker-proxy unreachable, an APIError, ...)
    other than a clean NotFound must not be silently discarded -- the
    disable itself already succeeded, so this stays advisory (exit 0), but
    the operator needs SOME signal that the safety check itself couldn't
    run, distinct from "checked, and nothing to worry about"."""
    runner.invoke(app, ["user", "add", "Alice", "alice@example.com"])
    result = runner.invoke(app, ["connection", "add", "alice@example.com", "Phone"])
    conn_id = result.output.split("Created connection ")[1].split()[0]

    with patch("docker.DockerClient.from_env", side_effect=RuntimeError("docker-proxy unreachable")):
        result = runner.invoke(app, ["connection", "disable", conn_id])

    assert result.exit_code == 0
    assert "NOTE: could not check" in result.output


def _connection_path_token(db_path, conn_id):
    import sqlite3
    with sqlite3.connect(db_path) as raw:
        row = raw.execute("SELECT path_token FROM connections WHERE id=?", (conn_id, )).fetchone()
    return row[0] if row else None


# Version ==============================================================================================================
def test_version_reports_the_baked_revision(monkeypatch):
    monkeypatch.setenv("POSTERN_REVISION", "a" * 40)
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "a" * 40 in result.output


def test_version_reports_unknown_when_unstamped(monkeypatch):
    monkeypatch.delenv("POSTERN_REVISION", raising=False)
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "unknown" in result.output


def test_version_json_shape(monkeypatch):
    import json
    monkeypatch.setenv("POSTERN_REVISION", "b" * 40)
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["revision"] == "b" * 40
    assert isinstance(payload["version"], str) and payload["version"]
