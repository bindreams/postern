import asyncio
import contextlib
import logging
import threading
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import docker.errors
import pytest

from postern import db, reconcile_wait
from postern.reconciler import (
    INSTANCE_LABEL,
    MANAGED_LABEL,
    MANAGED_VALUE,
    _container_name,
    _list_managed_containers,
    _reconcile_once,
    _reconcile_pass,
    _report_legacy_running_containers,
    resolve_instance_id,
    cleanup_all_containers,
    reconcile,
    reconciliation_loop,
)
from postern import reconciler
from postern.models import Connection
from postern.settings import Settings

INSTANCE_ID = "postern-test"


@pytest.fixture(autouse=True)
def _reset_reconciler_module_state():
    import postern.reconciler as reconciler_module
    reconciler_module._startup_identity_logged = False
    reconciler_module._inflight_reconcile_future = None
    reconciler_module._shutdown_requested.clear()
    yield
    reconciler_module._startup_identity_logged = False
    reconciler_module._inflight_reconcile_future = None
    reconciler_module._shutdown_requested.clear()


def _make_settings():
    return Settings(
        secret_key="test-secret",
        shadowsocks_image="local/shadowsocks-server",
        shadowsocks_network="shadowsocks",
        domain="postern.example.com",
        compose_project_name=INSTANCE_ID,
        instance_id="",
    )


def _make_connection(*, path_token="abcdef123456789012345678", enabled=True):
    return Connection(
        user_id="user-uuid",
        path_token=path_token,
        label="Test",
        password="dGVzdGtleQ==",
        enabled=enabled,
    )


def _make_mock_container(name, status="running", image_id="img1", network="shadowsocks"):
    """`network` defaults to `_make_settings()`'s own `shadowsocks_network`
    default so tests that don't care about network membership (most of them)
    don't accidentally trip the network-mismatch recreate check -- pass a
    different value to exercise that check on purpose."""
    container = MagicMock()
    container.name = name
    container.status = status
    container.attrs = {"Image": image_id, "NetworkSettings": {"Networks": {network: {}}}}
    return container


def _assert_init_passed(client):
    """Reconciler must always pass init=True to docker (tini at PID 1)."""
    call_kwargs = client.containers.run.call_args.kwargs
    assert call_kwargs["init"] is True


# Container naming =====================================================================================================
def test_container_name():
    conn = _make_connection(path_token="abcdef123456789012345678")
    assert _container_name(conn) == "ss-abcdef123456789012345678"


# Instance identity resolution =========================================================================================
def test_resolve_instance_id_prefers_explicit_override():
    settings = Settings(secret_key="test-secret", instance_id="pinned-instance", compose_project_name="postern-e2e")
    assert resolve_instance_id(settings) == "pinned-instance"


def test_resolve_instance_id_falls_back_to_compose_project_name():
    settings = Settings(secret_key="test-secret", instance_id="", compose_project_name="postern-e2e")
    assert resolve_instance_id(settings) == "postern-e2e"


def test_resolve_instance_id_returns_none_when_neither_is_set():
    """Not started via an up-to-date `docker compose` (or the environment
    block was stripped) -- fail safe rather than guessing."""
    settings = Settings(secret_key="test-secret", instance_id="", compose_project_name="")
    assert resolve_instance_id(settings) is None


def test_resolve_instance_id_strips_whitespace():
    settings = Settings(secret_key="test-secret", instance_id="  ", compose_project_name="postern-e2e")
    # A whitespace-only override must not shadow a real compose_project_name.
    assert resolve_instance_id(settings) == "postern-e2e"


def test_resolve_instance_id_treats_whitespace_only_compose_project_name_as_unset():
    """Symmetric with the override case above: a whitespace-only
    COMPOSE_PROJECT_NAME (e.g. a Compose interpolation quirk yielding
    spaces instead of a true empty string) must not be treated as
    resolved."""
    settings = Settings(secret_key="test-secret", instance_id="", compose_project_name="   ")
    assert resolve_instance_id(settings) is None


def test_list_managed_containers_filters_on_managed_and_instance_labels():
    client = MagicMock()
    client.containers.list.return_value = []

    _list_managed_containers(client, INSTANCE_ID)

    client.containers.list.assert_called_once_with(
        all=True,
        ignore_removed=True,
        filters={"label": [f"{MANAGED_LABEL}={MANAGED_VALUE}", f"{INSTANCE_LABEL}={INSTANCE_ID}"]},
    )


# Reconciliation logic =================================================================================================
def test_creates_missing_container():
    conn = _make_connection()
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    client.containers.run.assert_called_once()
    call_kwargs = client.containers.run.call_args.kwargs
    assert call_kwargs["name"] == "ss-abcdef123456789012345678"
    assert call_kwargs["network"] == "shadowsocks"
    assert "SS_CONFIG" in call_kwargs["environment"]
    _assert_init_passed(client)


def test_creates_missing_container_stamps_instance_label():
    conn = _make_connection()
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    call_kwargs = client.containers.run.call_args.kwargs
    assert call_kwargs["labels"] == {MANAGED_LABEL: MANAGED_VALUE, INSTANCE_LABEL: INSTANCE_ID}


def test_removes_orphan_container():
    settings = _make_settings()

    orphan = _make_mock_container("ss-orphantoken123456789012")
    client = MagicMock()
    client.containers.list.return_value = [orphan]
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [], settings, INSTANCE_ID)

    orphan.stop.assert_called_once()
    orphan.remove.assert_called_once()


def test_does_not_touch_existing_healthy_container():
    conn = _make_connection()
    settings = _make_settings()

    existing = _make_mock_container("ss-abcdef123456789012345678")
    client = MagicMock()
    client.containers.list.return_value = [existing]
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    client.containers.run.assert_not_called()
    existing.stop.assert_not_called()
    existing.remove.assert_not_called()


def test_restarts_exited_container():
    conn = _make_connection()
    settings = _make_settings()

    exited = _make_mock_container("ss-abcdef123456789012345678", status="exited")
    client = MagicMock()
    client.containers.list.return_value = [exited]
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    exited.start.assert_called_once()


def test_starts_container_stuck_in_created_state():
    """docker-py's containers.run() is create-then-start with no rollback:
    if start() raises, the container is left behind already labelled, in
    Docker's `created` state. It must be recovered the same way an
    `exited` container is -- container.start() behaves identically for
    both -- instead of being permanently invisible to every other code
    path (its name is desired, so it's not swept; its image already
    matches, so it's not recreated)."""
    conn = _make_connection()
    settings = _make_settings()

    stuck = _make_mock_container("ss-abcdef123456789012345678", status="created")
    client = MagicMock()
    client.containers.list.return_value = [stuck]
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    stuck.start.assert_called_once()
    client.containers.run.assert_not_called()  # not swept-and-recreated, just started


def test_reconcile_once_stops_early_when_shutdown_requested(caplog):
    """The cooperative-abort checkpoint: once _shutdown_requested is set, a
    pass must not start any further container operations -- an in-flight
    connection is left for the next pass (idempotent) rather than the
    current one grinding through a potentially-long queue of stop() calls
    during shutdown."""
    import postern.reconciler as reconciler_module

    conn = _make_connection()
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")

    reconciler_module._shutdown_requested.set()
    try:
        with caplog.at_level(logging.INFO, logger="postern.reconciler"):
            _reconcile_once(client, [conn], settings, INSTANCE_ID)
    finally:
        reconciler_module._shutdown_requested.clear()

    client.containers.run.assert_not_called()  # never reached the create loop's body
    assert "Shutdown requested" in caplog.text


async def test_reconciliation_loop_clears_shutdown_flag_on_start(tmp_path):
    """_shutdown_requested is otherwise a permanent one-way flag: a SECOND
    reconciliation_loop() call in the same process (every PosternApp/
    lifespan cycle in the test suite; conceivably a future embedded/reload
    scenario) must not silently inherit a stuck flag from a PRIOR
    lifespan's shutdown and make every pass a permanent no-op."""
    import postern.reconciler as reconciler_module
    reconciler_module._shutdown_requested.set()  # simulate: a prior lifespan already shut down in this process

    db_path = tmp_path / "postern.db"
    settings = Settings(secret_key="test-secret", database_path=str(db_path), reconcile_interval_seconds=3600)

    call_event = asyncio.Event()

    async def fake_reconcile(*args, **kwargs):
        call_event.set()

    with patch("postern.reconciler.reconcile", side_effect=fake_reconcile):
        task = asyncio.create_task(reconciliation_loop(str(db_path), settings))
        try:
            # A real synchronization point, matching this file's existing
            # test_reconciliation_loop_responds_to_trigger_file pattern:
            # reconciliation_loop's _shutdown_requested.clear() is its very
            # first statement, strictly before the loop's first `await
            # reconcile(...)` call -- observing that call happened (via the
            # event fake_reconcile sets) proves the clear() already ran.
            await call_event.wait()
            assert not reconciler_module._shutdown_requested.is_set()
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


def test_reconcile_pass_skips_legacy_scan_when_shutdown_requested():
    """_report_legacy_running_containers is an unbounded, daemon-wide Docker
    inspect scan (see its own docstring) that the cooperative-abort
    checkpoints inside _reconcile_once do nothing to bound -- it must be
    skipped once shutdown has been requested, or it can burn through
    stop_grace_period and get the portal SIGKILLed before
    cleanup_all_containers ever runs."""
    import postern.reconciler as reconciler_module

    conn = _make_connection()
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")

    reconciler_module._shutdown_requested.set()
    try:
        _reconcile_pass(client, [conn], [conn], settings, INSTANCE_ID)
    finally:
        reconciler_module._shutdown_requested.clear()

    # _reconcile_once itself makes exactly one containers.list() call
    # (_list_managed_containers) before its own first checkpoint bails out.
    # If the legacy scan's SEPARATE containers.list() call also fired, this
    # would be 2 -- it must stay 1.
    assert client.containers.list.call_count == 1


def test_recreates_container_on_image_change():
    conn = _make_connection()
    settings = _make_settings()

    old_container = _make_mock_container("ss-abcdef123456789012345678", image_id="old_img")
    client = MagicMock()
    client.containers.list.return_value = [old_container]
    client.images.get.return_value = MagicMock(id="new_img")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    old_container.stop.assert_called()
    old_container.remove.assert_called()
    client.containers.run.assert_called_once()
    _assert_init_passed(client)


# Recreate on network mismatch (issue #202: SHADOWSOCKS_NETWORK changed on a live deployment) ==========================
def test_container_networks_reads_networksettings():
    container = MagicMock()
    container.attrs = {"NetworkSettings": {"Networks": {"shadowsocks": {}, "other": {}}}}
    assert reconciler._container_networks(container) == {"shadowsocks", "other"}


def test_container_networks_empty_when_missing():
    """A container whose inspect payload carries no NetworkSettings at all
    (never happens for a real Docker container, but must not crash) counts
    as attached to no network -- i.e. a mismatch against any configured
    settings.shadowsocks_network, which is the conservative (recreate) side."""
    container = MagicMock()
    container.attrs = {}
    assert reconciler._container_networks(container) == set()


def test_recreates_container_on_network_change():
    """A container still on the OLD SHADOWSOCKS_NETWORK value must be
    recreated even though its image is current -- this is what makes a live
    SHADOWSOCKS_NETWORK change self-heal without a manual `docker rm -f`,
    even when the shutdown wipe is skipped or fails (docker-proxy
    unreachable, or instance identity unresolvable at that moment)."""
    conn = _make_connection()
    settings = _make_settings()

    old_container = _make_mock_container("ss-abcdef123456789012345678", network="old-network")
    client = MagicMock()
    client.containers.list.return_value = [old_container]
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    old_container.stop.assert_called()
    old_container.remove.assert_called()
    client.containers.run.assert_called_once()
    _assert_init_passed(client)


def test_recreates_container_on_image_and_network_change():
    """Both stale at once must still recreate exactly once, not twice."""
    conn = _make_connection()
    settings = _make_settings()

    old_container = _make_mock_container("ss-abcdef123456789012345678", image_id="old_img", network="old-network")
    client = MagicMock()
    client.containers.list.return_value = [old_container]
    client.images.get.return_value = MagicMock(id="new_img")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    old_container.stop.assert_called_once()
    old_container.remove.assert_called_once()
    client.containers.run.assert_called_once()


def test_network_upgrade_skips_recreate_when_removal_fails(caplog):
    """Mirrors test_image_upgrade_skips_recreate_when_removal_fails: if
    removing the stale-network container fails, recreating anyway would just
    409 -- skip it and escalate once, naming the network (not the image) as
    what's stale, so an operator isn't misdirected."""
    conn = _make_connection()
    settings = _make_settings()

    old_container = _make_mock_container("ss-abcdef123456789012345678", network="old-network")
    old_container.remove.side_effect = RuntimeError("removal failed")
    client = MagicMock()
    client.containers.list.return_value = [old_container]
    client.images.get.return_value = MagicMock(id="img1")

    with caplog.at_level(logging.ERROR, logger="postern.reconciler"):
        _reconcile_once(client, [conn], settings, INSTANCE_ID)

    client.containers.run.assert_not_called()
    assert "still serves the OLD network" in caplog.text
    assert "still serves the OLD image" not in caplog.text


# Name conflicts on create (pre-fix / legacy / cross-deployment containers) ============================================
def _conflict_error():
    response = MagicMock(status_code=409)
    return docker.errors.APIError("conflict", response=response)


def _server_error():
    response = MagicMock(status_code=500)
    return docker.errors.APIError("server error", response=response)


def test_create_logs_name_conflict_and_never_touches_a_foreign_squatter(caplog):
    """A 409 on create must NEVER trigger an automatic removal of a squatter
    that isn't labelled for this instance -- ownership can't be proven
    safely (a cloned database makes two independent deployments generate
    the identical desired name). It gets the manual-remediation message,
    and the reconciler must not retry create() itself this pass."""
    conn = _make_connection()
    settings = _make_settings()
    name = _container_name(conn)

    squatter = MagicMock()
    squatter.name = name
    squatter.labels = {MANAGED_LABEL: MANAGED_VALUE}  # no instance label: legacy
    squatter.stop = MagicMock()
    squatter.remove = MagicMock()

    client = MagicMock()
    client.containers.list.return_value = []  # not in the instance-scoped managed set
    client.images.get.return_value = MagicMock(id="img1")
    client.containers.run.side_effect = _conflict_error()
    client.containers.get.return_value = squatter

    with caplog.at_level(logging.ERROR, logger="postern.reconciler"):
        _reconcile_once(client, [conn], settings, INSTANCE_ID)

    squatter.stop.assert_not_called()
    squatter.remove.assert_not_called()
    assert client.containers.run.call_count == 1
    assert name in caplog.text
    assert "docker rm -f" in caplog.text


def test_create_logs_distinctly_when_squatter_is_this_instances_own(caplog):
    """When the squatter already carries THIS instance's own instance
    label, it's a prior removal (orphan sweep / image-upgrade recreate)
    that silently failed, not a foreign container -- the message must say
    so distinctly and NOT suggest manual removal, since the next pass
    retries on its own."""
    conn = _make_connection()
    settings = _make_settings()
    name = _container_name(conn)

    squatter = MagicMock()
    squatter.name = name
    squatter.labels = {MANAGED_LABEL: MANAGED_VALUE, INSTANCE_LABEL: INSTANCE_ID}
    squatter.stop = MagicMock()
    squatter.remove = MagicMock()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")
    client.containers.run.side_effect = _conflict_error()
    client.containers.get.return_value = squatter

    with caplog.at_level(logging.WARNING, logger="postern.reconciler"):
        _reconcile_once(client, [conn], settings, INSTANCE_ID)

    squatter.stop.assert_not_called()
    squatter.remove.assert_not_called()
    assert client.containers.run.call_count == 1
    assert "own container" in caplog.text
    assert "docker rm -f" not in caplog.text


def test_log_name_conflict_logs_distinctly_when_squatter_lookup_fails(caplog):
    """If the squatter itself can't even be inspected (e.g. a docker-proxy
    hiccup or generic API error, NOT a clean NotFound -- see the dedicated
    NotFound test below), that's a DIFFERENT, unconfirmed condition from
    "definitely a foreign container" -- it must get its own honest
    ERROR-level disposition, not silently reuse the confirmed-foreign
    message with labels=None (which would tell an operator to `docker rm
    -f` a container whose ownership was never actually established)."""
    conn = _make_connection()
    settings = _make_settings()
    name = _container_name(conn)

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")
    client.containers.run.side_effect = _conflict_error()
    client.containers.get.side_effect = RuntimeError("container vanished")

    with caplog.at_level(logging.ERROR, logger="postern.reconciler"):
        _reconcile_once(client, [conn], settings, INSTANCE_ID)

    assert "could not be inspected" in caplog.text
    assert "docker rm -f" not in caplog.text
    assert name in caplog.text


def test_log_name_conflict_resolves_itself_when_squatter_vanishes_before_inspection(caplog):
    """The 409-then-inspect sequence is racy: the squatter can be removed
    between containers.run()'s 409 and this containers.get() -- most
    plausibly an operator following this function's own `docker rm -f`
    remediation advice. That's docker.errors.NotFound, a benign and
    self-healing outcome (the name is free again), and must NOT get the
    same "docker-proxy issue?" ERROR a genuine inspection failure gets --
    that would read as "the remediation didn't work" at the exact moment
    it did."""
    conn = _make_connection()
    settings = _make_settings()
    name = _container_name(conn)

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")
    client.containers.run.side_effect = _conflict_error()
    client.containers.get.side_effect = docker.errors.NotFound("no such container")

    with caplog.at_level(logging.INFO, logger="postern.reconciler"):
        _reconcile_once(client, [conn], settings, INSTANCE_ID)

    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    assert "resolved itself" in caplog.text
    assert name in caplog.text


def test_create_logs_generically_on_non_conflict_api_error(caplog):
    """A non-409 API error (e.g. a 500) is a different failure mode and must
    get the ordinary generic disposition, not the name-conflict message --
    and must not attempt to inspect a squatter that may not exist."""
    conn = _make_connection()
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")
    client.containers.run.side_effect = _server_error()

    with caplog.at_level(logging.ERROR, logger="postern.reconciler"):
        _reconcile_once(client, [conn], settings, INSTANCE_ID)

    client.containers.get.assert_not_called()
    assert "Failed to create container" in caplog.text
    assert "docker rm -f" not in caplog.text


def test_create_logs_generically_on_non_api_error(caplog):
    """A plain (non-docker.errors) exception from containers.run must also
    get the generic disposition and must not propagate out of
    _reconcile_once."""
    conn = _make_connection()
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")
    client.containers.run.side_effect = ConnectionError("docker-proxy unreachable")

    with caplog.at_level(logging.ERROR, logger="postern.reconciler"):
        _reconcile_once(client, [conn], settings, INSTANCE_ID)  # must not raise

    assert "Failed to create container" in caplog.text


def test_image_upgrade_skips_recreate_when_removal_fails(caplog):
    """If removing the old-image container fails, recreating anyway would
    just 409 against the container still occupying the name -- and get
    logged every pass forever as a harmless-sounding 'will retry' with no
    escalation, while the tunnel keeps serving the OLD image indefinitely.
    Recreate must be skipped, and this specific failure escalated once,
    when it's actually known to have happened."""
    conn = _make_connection()
    settings = _make_settings()

    old_container = _make_mock_container("ss-abcdef123456789012345678", image_id="old_img")
    old_container.remove.side_effect = RuntimeError("removal failed")
    client = MagicMock()
    client.containers.list.return_value = [old_container]
    client.images.get.return_value = MagicMock(id="new_img")

    with caplog.at_level(logging.ERROR, logger="postern.reconciler"):
        _reconcile_once(client, [conn], settings, INSTANCE_ID)

    client.containers.run.assert_not_called()  # no recreate attempted
    assert "still serves the OLD image" in caplog.text


def test_image_upgrade_recreates_when_removal_target_already_gone():
    """docker.errors.NotFound from remove() means the container is already
    gone (removed concurrently, or a stray --rm auto-removal) -- the
    postcondition _remove_container exists to guarantee already holds, so
    this must be treated as success, not failure: the recreate should still
    happen, not be skipped with a misleading 'still serves the OLD image'
    error about a container that no longer exists."""
    conn = _make_connection()
    settings = _make_settings()

    old_container = _make_mock_container("ss-abcdef123456789012345678", image_id="old_img")
    old_container.remove.side_effect = docker.errors.NotFound("no such container")
    client = MagicMock()
    client.containers.list.return_value = [old_container]
    client.images.get.return_value = MagicMock(id="new_img")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    client.containers.run.assert_called_once()  # recreate DID happen


# Visibility for legacy containers outside the desired (enabled) set ===================================================
def _make_disabled_squatter(name, labels, status="running"):
    squatter = MagicMock()
    squatter.name = name
    squatter.labels = labels
    squatter.status = status
    return squatter


def test_reports_legacy_container_for_disabled_connection(caplog):
    """A disabled connection is never the target of a create() call, so
    _log_name_conflict's 409-triggered logging never fires for it -- this
    is the only other place the equivalent visibility exists. Its DB row
    still exists (disabled, not deleted), so the message can cite the
    connection id."""
    conn = _make_connection()
    name = _container_name(conn)
    squatter = _make_disabled_squatter(name, {MANAGED_LABEL: MANAGED_VALUE})  # no instance label

    client = MagicMock()
    client.containers.list.return_value = [squatter]

    with caplog.at_level(logging.WARNING, logger="postern.reconciler"):
        _report_legacy_running_containers(client, desired_names=set(), connections_by_name={name: conn})

    assert name in caplog.text
    assert "docker rm -f" in caplog.text
    assert conn.id in caplog.text


def test_reports_legacy_container_for_deleted_connection(caplog):
    """`postern user delete` cascades the connection row away entirely --
    connections_by_name has no entry for it -- but a still-running legacy
    container for that connection must still be flagged. The message can't
    cite a connection id it doesn't have, so it must say so instead of
    guessing or silently dropping the report."""
    name = "ss-deletedtoken123456789012"
    squatter = _make_disabled_squatter(name, {MANAGED_LABEL: MANAGED_VALUE})

    client = MagicMock()
    client.containers.list.return_value = [squatter]

    with caplog.at_level(logging.WARNING, logger="postern.reconciler"):
        _report_legacy_running_containers(client, desired_names=set(), connections_by_name={})

    assert name in caplog.text
    assert "docker rm -f" in caplog.text
    assert "no connection" in caplog.text.lower()


def test_report_legacy_running_skips_container_in_desired_set():
    """A container whose name IS in desired_names (an enabled connection)
    is left to the ordinary create-sweep's own 409 handling
    (_log_name_conflict) -- this function must not ALSO warn about it."""
    conn = _make_connection()
    name = _container_name(conn)
    squatter = _make_disabled_squatter(name, {MANAGED_LABEL: MANAGED_VALUE})

    client = MagicMock()
    client.containers.list.return_value = [squatter]

    with patch("postern.reconciler.logger") as mock_logger:
        _report_legacy_running_containers(client, desired_names={name}, connections_by_name={name: conn})
        mock_logger.warning.assert_not_called()


def test_report_legacy_running_skips_own_instance_container():
    """Already in this instance's own managed set -- the ordinary sweep
    handles it; no separate warning needed here."""
    conn = _make_connection()
    name = _container_name(conn)
    squatter = _make_disabled_squatter(name, {MANAGED_LABEL: MANAGED_VALUE, INSTANCE_LABEL: INSTANCE_ID})

    client = MagicMock()
    client.containers.list.return_value = [squatter]

    with patch("postern.reconciler.logger") as mock_logger:
        _report_legacy_running_containers(client, desired_names=set(), connections_by_name={name: conn})
        mock_logger.warning.assert_not_called()


def test_report_legacy_running_skips_foreign_instance_container():
    """A container labelled for a DIFFERENT, live deployment must never be
    flagged, even if its name happens to match one of THIS instance's
    disabled connections (a cloned database makes that collision possible,
    not just theoretical) -- suggesting `docker rm -f` against a live
    foreign tunnel would be exactly the destructive mistake this whole
    design exists to avoid."""
    conn = _make_connection()
    name = _container_name(conn)
    squatter = _make_disabled_squatter(name, {MANAGED_LABEL: MANAGED_VALUE, INSTANCE_LABEL: "some-other-deployment"})

    client = MagicMock()
    client.containers.list.return_value = [squatter]

    with patch("postern.reconciler.logger") as mock_logger:
        _report_legacy_running_containers(client, desired_names=set(), connections_by_name={name: conn})
        mock_logger.warning.assert_not_called()


def test_report_legacy_running_skips_non_running_container():
    """A claim of 'still running' must actually be verified -- an exited
    or created (never-running) container isn't serving traffic, so there's
    nothing urgent to tell the operator about."""
    conn = _make_connection()
    name = _container_name(conn)
    squatter = _make_disabled_squatter(name, {MANAGED_LABEL: MANAGED_VALUE}, status="exited")

    client = MagicMock()
    client.containers.list.return_value = [squatter]

    with patch("postern.reconciler.logger") as mock_logger:
        _report_legacy_running_containers(client, desired_names=set(), connections_by_name={name: conn})
        mock_logger.warning.assert_not_called()


def test_report_legacy_running_skips_when_no_container_exists():
    client = MagicMock()
    client.containers.list.return_value = []

    with patch("postern.reconciler.logger") as mock_logger:
        _report_legacy_running_containers(client, desired_names=set(), connections_by_name={})
        mock_logger.warning.assert_not_called()


def test_report_legacy_running_makes_one_list_call():
    """O(1) Docker API calls per pass, not O(N) -- this runs every pass."""
    client = MagicMock()
    client.containers.list.return_value = []

    _report_legacy_running_containers(client, desired_names=set(), connections_by_name={})

    client.containers.list.assert_called_once()


def test_report_legacy_running_passes_ignore_removed():
    """Same ask-forgiveness listing as _list_managed_containers -- a
    container vanishing between the initial list and docker-py's per-id
    inspect must not abort the whole check."""
    client = MagicMock()
    client.containers.list.return_value = []

    _report_legacy_running_containers(client, desired_names=set(), connections_by_name={})

    call_kwargs = client.containers.list.call_args.kwargs
    assert call_kwargs.get("ignore_removed") is True


def test_report_legacy_running_logs_and_swallows_listing_failure(caplog):
    client = MagicMock()
    client.containers.list.side_effect = RuntimeError("docker-proxy blip")

    with caplog.at_level(logging.WARNING, logger="postern.reconciler"):
        _report_legacy_running_containers(client, desired_names=set(), connections_by_name={})  # must not raise

    assert "Could not check for legacy containers" in caplog.text


# Cross-instance sweep isolation =======================================================================================
class _LabelledContainer:
    """A container stand-in with a real `.labels` dict, used with
    _filtering_containers_list below to exercise actual label-filter
    semantics. A plain MagicMock's `.list()` ignores the `filters` kwarg
    entirely, which would hide a regression where the filter construction
    stops including the instance label."""

    def __init__(self, name, labels, status="running", image_id="img1"):
        self.name = name
        self.labels = dict(labels)
        self.status = status
        self.attrs = {"Image": image_id}
        self.stop = MagicMock()
        self.remove = MagicMock()
        self.start = MagicMock()


def _filtering_containers_list(containers):
    """A `containers.list(all=True, filters={"label": [...]})` stand-in that
    actually applies the label filters (AND semantics), mirroring the real
    Docker daemon's behavior for `filters={"label": [...]}`."""

    def _list(all=True, ignore_removed=False, filters=None):
        label_filters = (filters or {}).get("label", [])
        if isinstance(label_filters, str):
            label_filters = [label_filters]
        matched = []
        for c in containers:
            keep = True
            for lf in label_filters:
                key, _, value = lf.partition("=")
                if c.labels.get(key) != value:
                    keep = False
                    break
            if keep:
                matched.append(c)
        return matched

    return _list


def test_ignores_container_from_different_instance():
    """A managed container carrying a DIFFERENT instance label must survive
    a reconcile pass untouched, even though it's absent from this
    instance's desired set."""
    conn = _make_connection()
    settings = _make_settings()

    foreign = _LabelledContainer(
        "ss-foreigntoken1234567890",
        labels={MANAGED_LABEL: MANAGED_VALUE, INSTANCE_LABEL: "postern-prod"},
    )
    client = MagicMock()
    client.containers.list.side_effect = _filtering_containers_list([foreign])
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings, "postern-e2e")

    foreign.stop.assert_not_called()
    foreign.remove.assert_not_called()
    # This instance's own missing container is still created normally.
    client.containers.run.assert_called_once()


def test_ignores_legacy_container_without_instance_label():
    """A managed container carrying only MANAGED_LABEL (no INSTANCE_LABEL)
    predates the instance label and is never swept by a bare listing when
    it doesn't correspond to a desired connection -- it's simply invisible
    to this instance's reconciler, the same as a container belonging to a
    genuinely different deployment."""
    legacy = _LabelledContainer("ss-legacytoken1234567890a", labels={MANAGED_LABEL: MANAGED_VALUE})
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.side_effect = _filtering_containers_list([legacy])
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [], settings, "postern-e2e")

    legacy.stop.assert_not_called()
    legacy.remove.assert_not_called()


# Async functions ======================================================================================================
async def test_reconciliation_loop_responds_to_trigger_file(tmp_path):
    """The loop sleeps for reconcile_interval_seconds but wakes early when the
    .reconcile-now trigger file appears. Invariant documented in CLAUDE.md."""
    db_path = tmp_path / "postern.db"
    trigger_path = tmp_path / ".reconcile-now"
    settings = Settings(
        secret_key="test-secret",
        database_path=str(db_path),
        reconcile_interval_seconds=3600,  # long enough that the trigger file must be what wakes us
    )

    call_event = asyncio.Event()
    calls = 0

    async def fake_reconcile(*args, **kwargs):
        nonlocal calls
        calls += 1
        call_event.set()

    with patch("postern.reconciler.reconcile", side_effect=fake_reconcile):
        task = asyncio.create_task(reconciliation_loop(str(db_path), settings))
        try:
            # Wait for the first reconcile (happens before the sleep)
            await asyncio.wait_for(call_event.wait(), timeout=3)
            assert calls == 1

            # Reset event and drop the trigger file
            call_event.clear()
            trigger_path.touch()

            # Expect a second reconcile within a couple of poll ticks
            await asyncio.wait_for(call_event.wait(), timeout=3)
            assert calls == 2

            # Trigger file must be consumed
            assert not trigger_path.exists()
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


# Fail-safe on unknown identity ========================================================================================
async def test_reconcile_skips_container_ops_when_identity_unknown(tmp_path):
    """When this portal cannot determine its own instance identity, it must
    not touch any container -- but unrelated cleanup (expired
    sessions/OTPs) still runs."""
    db_path = tmp_path / "postern.db"
    async with db.get_connection(str(db_path)) as conn:
        await db.migrate(conn)

    settings = Settings(secret_key="test-secret", database_path=str(db_path), instance_id="", compose_project_name="")

    client = MagicMock()
    client.images.get.return_value = MagicMock(id="img1")

    with patch("postern.reconciler._get_docker_client", return_value=client), \
         patch("postern.reconciler.db.cleanup_expired", new_callable=AsyncMock) as mock_cleanup:
        await reconcile(str(db_path), settings)

    client.containers.list.assert_not_called()
    client.containers.run.assert_not_called()
    mock_cleanup.assert_awaited_once()
    client.close.assert_called_once()


async def test_reconcile_runs_cleanup_expired_even_if_container_reconcile_raises(tmp_path):
    """cleanup_expired must run even when the container-reconcile branch
    raises for a reason OTHER than unresolved identity (e.g. an unexpected
    error inside _reconcile_once) -- the exception must still propagate
    afterward (not be silently swallowed), and the docker client must still
    be closed."""
    db_path = tmp_path / "postern.db"
    async with db.get_connection(str(db_path)) as conn:
        await db.migrate(conn)

    settings = Settings(
        secret_key="test-secret", database_path=str(db_path), instance_id="", compose_project_name="postern-test"
    )

    client = MagicMock()
    client.images.get.return_value = MagicMock(id="img1")

    with patch("postern.reconciler._get_docker_client", return_value=client), \
         patch("postern.reconciler._reconcile_once", side_effect=RuntimeError("boom")), \
         patch("postern.reconciler.db.cleanup_expired", new_callable=AsyncMock) as mock_cleanup:
        with pytest.raises(RuntimeError):
            await reconcile(str(db_path), settings)

    mock_cleanup.assert_awaited_once()
    client.close.assert_called_once()


async def test_reconcile_closes_client_when_image_check_raises_unexpectedly(tmp_path):
    """A DIFFERENT client-leak path from the one above: something raises
    BEFORE the pass is ever dispatched to the executor (so _reconcile_pass's
    own client.close() never gets a chance to run). client must still be
    closed by reconcile() itself in this case -- and cleanup_expired must
    still run."""
    db_path = tmp_path / "postern.db"
    async with db.get_connection(str(db_path)) as conn:
        await db.migrate(conn)

    settings = Settings(
        secret_key="test-secret", database_path=str(db_path), instance_id="", compose_project_name="postern-test"
    )

    client = MagicMock()
    client.images.get.side_effect = RuntimeError("docker-proxy connection reset")

    with patch("postern.reconciler._get_docker_client", return_value=client), \
         patch("postern.reconciler.db.cleanup_expired", new_callable=AsyncMock) as mock_cleanup:
        with pytest.raises(RuntimeError):
            await reconcile(str(db_path), settings)

    mock_cleanup.assert_awaited_once()
    client.close.assert_called_once()
    client.containers.list.assert_not_called()  # never reached dispatch


# Resolved-identity provenance logging =================================================================================
async def test_reconcile_logs_resolved_instance_id_once_at_startup(tmp_path, caplog):
    db_path = tmp_path / "postern.db"
    async with db.get_connection(str(db_path)) as conn:
        await db.migrate(conn)
    settings = Settings(
        secret_key="test-secret", database_path=str(db_path), instance_id="", compose_project_name="postern-test"
    )

    client = MagicMock()
    client.images.get.return_value = MagicMock(id="img1")
    client.containers.list.return_value = []

    with patch("postern.reconciler._get_docker_client", return_value=client), \
         caplog.at_level(logging.INFO, logger="postern.reconciler"):
        await reconcile(str(db_path), settings)
        await reconcile(str(db_path), settings)

    assert caplog.text.count("Resolved own instance id") == 1  # logged once per process, not every pass


async def test_reconcile_logs_provenance_on_delayed_identity_resolution(tmp_path, caplog):
    """The startup log must fire on the FIRST pass that actually resolves
    identity, even if earlier passes failed to -- the one-shot flag guards
    against DUPLICATE logs, not against ever logging at all."""
    db_path = tmp_path / "postern.db"
    async with db.get_connection(str(db_path)) as conn:
        await db.migrate(conn)
    settings = Settings(secret_key="test-secret", database_path=str(db_path), instance_id="", compose_project_name="")

    client = MagicMock()
    client.images.get.return_value = MagicMock(id="img1")

    with patch("postern.reconciler._get_docker_client", return_value=client), \
         caplog.at_level(logging.INFO, logger="postern.reconciler"):
        await reconcile(str(db_path), settings)  # identity unknown: no log expected

    assert "Resolved own instance id" not in caplog.text

    settings2 = Settings(
        secret_key="test-secret", database_path=str(db_path), instance_id="", compose_project_name="postern-test"
    )
    client.containers.list.return_value = []
    with patch("postern.reconciler._get_docker_client", return_value=client), \
         caplog.at_level(logging.INFO, logger="postern.reconciler"):
        await reconcile(str(db_path), settings2)  # identity now resolves: log expected

    assert caplog.text.count("Resolved own instance id") == 1


async def test_reconcile_logs_both_values_at_info_when_instance_id_override_differs_from_compose_project(
    tmp_path, caplog
):
    """An override differing from compose_project_name is the shape of both
    the one legitimate documented use (disambiguating two checkouts whose
    directory basenames collide) AND an accidentally-copied .env -- the two
    are indistinguishable from inside this one process, so this must log
    both values at INFO (for an operator who suspects a collision to
    inspect), never as an alarming WARNING that would fire on every
    correctly configured override deployment."""
    db_path = tmp_path / "postern.db"
    async with db.get_connection(str(db_path)) as conn:
        await db.migrate(conn)
    settings = Settings(
        secret_key="test-secret",
        database_path=str(db_path),
        instance_id="pinned",
        compose_project_name="postern-test",  # differs from "pinned"
    )

    client = MagicMock()
    client.images.get.return_value = MagicMock(id="img1")
    client.containers.list.return_value = []

    with patch("postern.reconciler._get_docker_client", return_value=client), \
         caplog.at_level(logging.INFO, logger="postern.reconciler"):
        await reconcile(str(db_path), settings)

    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    assert "'pinned'" in caplog.text
    assert "'postern-test'" in caplog.text


async def test_reconcile_does_not_warn_when_instance_id_override_matches_compose_project(tmp_path, caplog):
    """The negative case: a correctly-configured explicit INSTANCE_ID that
    happens to equal compose_project_name must not produce any WARNING --
    a regression here would false-positive-spam every legitimately
    configured deployment."""
    db_path = tmp_path / "postern.db"
    async with db.get_connection(str(db_path)) as conn:
        await db.migrate(conn)
    settings = Settings(
        secret_key="test-secret",
        database_path=str(db_path),
        instance_id="postern-test",
        compose_project_name="postern-test",  # matches
    )

    client = MagicMock()
    client.images.get.return_value = MagicMock(id="img1")
    client.containers.list.return_value = []

    with patch("postern.reconciler._get_docker_client", return_value=client), \
         caplog.at_level(logging.WARNING, logger="postern.reconciler"):
        await reconcile(str(db_path), settings)

    assert not any(r.levelno >= logging.WARNING for r in caplog.records)


# Shutdown race: wait_for_inflight_reconcile ===========================================================================
async def test_wait_for_inflight_reconcile_blocks_until_pass_actually_finishes(tmp_path):
    """The exact race the fix closes: a reconcile pass is cancelled
    mid-flight (its awaiting task raises CancelledError immediately), but
    the underlying executor thread keeps running. wait_for_inflight_reconcile()
    must not return until that thread has genuinely finished."""
    import postern.reconciler as reconciler_module

    db_path = tmp_path / "postern.db"
    async with db.get_connection(str(db_path)) as conn:
        await db.migrate(conn)
    settings = Settings(
        secret_key="test-secret", database_path=str(db_path), instance_id="", compose_project_name="postern-test"
    )

    started = threading.Event()
    finish = threading.Event()

    def slow_reconcile_once(*args, **kwargs):
        started.set()
        finish.wait()  # unbounded: released explicitly below, this is code we fully control

    client = MagicMock()
    client.images.get.return_value = MagicMock(id="img1")

    try:
        with patch("postern.reconciler._get_docker_client", return_value=client), \
             patch("postern.reconciler._reconcile_once", side_effect=slow_reconcile_once):
            task = asyncio.create_task(reconcile(str(db_path), settings))
            await asyncio.to_thread(started.wait)  # blocks until the pass is genuinely running in its worker thread

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            # The task has unwound, but the underlying thread is still running --
            # structurally guaranteed, not a timing bet: slow_reconcile_once
            # cannot return until finish.set() below, so wait_task cannot
            # possibly be done yet no matter how long we yield for.
            # asyncio.sleep(0) is a single event-loop tick (not a duration
            # chosen to be "long enough"), just enough for wait_task to reach
            # its first await point.
            wait_task = asyncio.create_task(reconciler_module.wait_for_inflight_reconcile())
            await asyncio.sleep(0)
            assert not wait_task.done()

            finish.set()
            # No numeric timeout here either: both sides are this test's own
            # code, released deterministically by finish.set() above -- a
            # chosen "long enough" bound would be exactly the pattern this
            # whole fix exists to avoid. A genuine external hang bound (if
            # ever wanted) belongs at the CI-job level (e.g. a pytest-timeout
            # plugin), not as a per-test guess.
            await wait_task
    finally:
        finish.set()  # release the worker thread even if an assertion above failed


# cleanup_all_containers ===============================================================================================
async def test_cleanup_all_containers():
    c1 = _make_mock_container("ss-aaa111bbb222ccc333ddd444")
    c2 = _make_mock_container("ss-eee555fff666ggg777hhh888")

    client = MagicMock()
    client.containers.list.return_value = [c1, c2]

    with patch("postern.reconciler._get_docker_client", return_value=client):
        await cleanup_all_containers(_make_settings())

    c1.stop.assert_called_once()
    c1.remove.assert_called_once()
    c2.stop.assert_called_once()
    c2.remove.assert_called_once()
    client.close.assert_called_once()


async def test_cleanup_all_containers_skips_when_identity_unknown():
    """Shutdown cleanup must not remove ANY container -- or even talk to
    Docker at all -- when this instance's identity can't be determined."""
    settings = Settings(secret_key="test-secret", instance_id="", compose_project_name="")

    with patch("postern.reconciler._get_docker_client") as mock_get_client:
        await cleanup_all_containers(settings)

    mock_get_client.assert_not_called()


async def test_cleanup_all_containers_ignores_container_from_different_instance():
    """Same cross-instance isolation as the reconcile sweep, applied to the
    shutdown-cleanup wipe -- the single most destructive operation in the
    codebase."""
    foreign = _LabelledContainer(
        "ss-foreigntoken1234567890",
        labels={MANAGED_LABEL: MANAGED_VALUE, INSTANCE_LABEL: "postern-prod"},
    )
    client = MagicMock()
    client.containers.list.side_effect = _filtering_containers_list([foreign])

    with patch("postern.reconciler._get_docker_client", return_value=client):
        await cleanup_all_containers(_make_settings())

    foreign.stop.assert_not_called()
    foreign.remove.assert_not_called()


async def test_cleanup_all_containers_ignores_legacy_container_without_instance_label():
    """Same as above, for a container that predates the instance label
    entirely -- the exact shape of every container the mandatory post-upgrade
    migration note is about."""
    legacy = _LabelledContainer("ss-legacytoken1234567890a", labels={MANAGED_LABEL: MANAGED_VALUE})
    client = MagicMock()
    client.containers.list.side_effect = _filtering_containers_list([legacy])

    with patch("postern.reconciler._get_docker_client", return_value=client):
        await cleanup_all_containers(_make_settings())

    legacy.stop.assert_not_called()
    legacy.remove.assert_not_called()


async def test_cleanup_all_containers_closes_client_even_if_listing_raises():
    """client.close() must run even when something after client acquisition
    raises -- mirroring reconcile()'s try/finally pattern."""
    client = MagicMock()
    client.containers.list.side_effect = RuntimeError("docker-proxy blip")

    with patch("postern.reconciler._get_docker_client", return_value=client):
        await cleanup_all_containers(_make_settings())  # the outer except must swallow this

    client.close.assert_called_once()


# Per-connection plugin in SS_CONFIG ===================================================================================
def test_v2ray_connection_passes_v2ray_plugin_in_ss_config():
    import base64
    import json as _json

    conn = _make_connection()  # default plugin
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    call_kwargs = client.containers.run.call_args.kwargs
    cfg = _json.loads(base64.b64decode(call_kwargs["environment"]["SS_CONFIG"]))
    assert cfg["servers"][0]["plugin"] == "v2ray-plugin"


def test_galoshes_connection_passes_galoshes_in_ss_config():
    import base64
    import json as _json

    conn = _make_connection().model_copy(update={"plugin": "galoshes"})
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings, INSTANCE_ID)

    call_kwargs = client.containers.run.call_args.kwargs
    cfg = _json.loads(base64.b64decode(call_kwargs["environment"]["SS_CONFIG"]))
    assert cfg["servers"][0]["plugin"] == "galoshes"


# Waiter notification from the loop (issue #196) =======================================================================
def _record_notifications(monkeypatch) -> tuple[list[tuple[list[Path], bool]], asyncio.Event]:
    """Intercept notify_waiters; return the recorded calls and an Event set on first call."""
    notified: list[tuple[list[Path], bool]] = []
    done = asyncio.Event()

    def record(paths, *, ok):
        notified.append((list(paths), ok))
        done.set()

    monkeypatch.setattr(reconcile_wait, "notify_waiters", record)
    return notified, done


async def test_loop_reports_a_successful_pass_to_waiters(tmp_path, monkeypatch):
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    notified, done = _record_notifications(monkeypatch)

    async def fake_reconcile(_db, _settings):
        pass

    monkeypatch.setattr(reconciler, "reconcile", fake_reconcile)
    task = asyncio.create_task(reconciliation_loop(db_path, _make_settings()))
    try:
        await done.wait()
        assert notified[0] == ([waiter.path], True)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        reconcile_wait.close_waiter(waiter)


async def test_loop_reports_a_raising_pass_as_failed(tmp_path, monkeypatch):
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    notified, done = _record_notifications(monkeypatch)

    async def boom(_db, _settings):
        raise RuntimeError("docker is down")

    monkeypatch.setattr(reconciler, "reconcile", boom)
    task = asyncio.create_task(reconciliation_loop(db_path, _make_settings()))
    try:
        await done.wait()
        assert notified[0] == ([waiter.path], False)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        reconcile_wait.close_waiter(waiter)


async def test_loop_reports_a_cancelled_pass_as_failed(tmp_path, monkeypatch):
    """Shutdown cancels the loop and then deletes every ss-* container (`app.py`).
    A waiter told "ok" there would send a deploy on to verification believing its
    tunnels had just been reconciled, seconds before they are all removed."""
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    notified, done = _record_notifications(monkeypatch)
    entered = asyncio.Event()

    async def hang(_db, _settings):
        entered.set()
        await asyncio.Event().wait()  # only cancellation ends this

    monkeypatch.setattr(reconciler, "reconcile", hang)
    task = asyncio.create_task(reconciliation_loop(db_path, _make_settings()))
    try:
        await entered.wait()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert done.is_set()
        assert notified[0] == ([waiter.path], False)
    finally:
        reconcile_wait.close_waiter(waiter)


async def test_loop_reports_a_non_exception_baseexception_escape_as_failed(tmp_path, monkeypatch):
    """`passed` must not default to True: anything escaping `await reconcile(...)`
    other than asyncio.CancelledError or Exception (e.g. a bare BaseException) has
    to notify ok=False too. A waiter told "ok" here would be told a pass completed
    when it never did."""
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    notified, done = _record_notifications(monkeypatch)

    class _WeirdEscape(BaseException):
        pass

    async def boom(_db, _settings):
        raise _WeirdEscape("simulated exotic escape")

    monkeypatch.setattr(reconciler, "reconcile", boom)
    task = asyncio.create_task(reconciliation_loop(db_path, _make_settings()))
    try:
        await done.wait()
        assert notified[0] == ([waiter.path], False)
    finally:
        with contextlib.suppress(_WeirdEscape):
            await task
        reconcile_wait.close_waiter(waiter)


async def test_loop_notifies_a_waiter_registered_during_the_interval_wait_on_shutdown(tmp_path, monkeypatch):
    """A waiter can register after the current pass's snapshot was already taken --
    e.g. while the loop is parked in its interval-wait sleep between passes. If
    shutdown cancels the loop right then, there is no "next pass" to snapshot and
    notify it: it must still get a verdict here, or `postern reconcile --wait`
    (unbounded by default) hangs forever."""
    db_path = str(tmp_path / "postern.db")
    settings = Settings(
        secret_key="test-secret",
        database_path=db_path,
        reconcile_interval_seconds=3600,
        compose_project_name=INSTANCE_ID,
    )

    sleep_entered = asyncio.Event()
    release_sleep = asyncio.Event()

    async def fake_sleep(_seconds):
        sleep_entered.set()
        await release_sleep.wait()

    async def fake_reconcile(_db, _settings):
        pass

    monkeypatch.setattr(reconciler, "reconcile", fake_reconcile)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    task = asyncio.create_task(reconciliation_loop(db_path, settings))
    try:
        # The first pass has completed (no waiters were registered for it) and the
        # loop is now blocked in the interval-wait's `await asyncio.sleep(1)`.
        await sleep_entered.wait()

        waiter = reconcile_wait.register_waiter(db_path)
        try:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            assert reconcile_wait.wait_for_notify(waiter, timeout=0) == "failed"
        finally:
            reconcile_wait.close_waiter(waiter)
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
