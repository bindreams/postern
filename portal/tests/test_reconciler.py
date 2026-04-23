import asyncio
from unittest.mock import MagicMock, patch

from voyager.models import Connection
from voyager.reconciler import (
    _container_name,
    _reconcile_once,
    cleanup_all_containers,
    reconciliation_loop,
)
from voyager.settings import Settings


def _make_settings():
    return Settings(
        secret_key="test-secret",
        shadowsocks_image="local/shadowsocks-server",
        shadowsocks_network="shadowsocks",
        domain="voyager.binarydreams.me",
    )


def _make_connection(*, path_token="abcdef123456789012345678", enabled=True):
    return Connection(
        user_id="user-uuid",
        path_token=path_token,
        label="Test",
        password="dGVzdGtleQ==",
        enabled=enabled,
    )


def _make_mock_container(name, status="running", image_id="img1"):
    container = MagicMock()
    container.name = name
    container.status = status
    container.attrs = {"Image": image_id}
    return container


# Container naming =====================================================================================================
def test_container_name():
    conn = _make_connection(path_token="abcdef123456789012345678")
    assert _container_name(conn) == "ss-abcdef123456789012345678"


# Reconciliation logic =================================================================================================
def test_creates_missing_container():
    conn = _make_connection()
    settings = _make_settings()

    client = MagicMock()
    client.containers.list.return_value = []
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings)

    client.containers.run.assert_called_once()
    call_kwargs = client.containers.run.call_args.kwargs
    assert call_kwargs["name"] == "ss-abcdef123456789012345678"
    assert call_kwargs["network"] == "shadowsocks"
    assert "SS_CONFIG" in call_kwargs["environment"]


def test_removes_orphan_container():
    settings = _make_settings()

    orphan = _make_mock_container("ss-orphantoken123456789012")
    client = MagicMock()
    client.containers.list.return_value = [orphan]
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [], settings)

    orphan.stop.assert_called_once()
    orphan.remove.assert_called_once()


def test_does_not_touch_existing_healthy_container():
    conn = _make_connection()
    settings = _make_settings()

    existing = _make_mock_container("ss-abcdef123456789012345678")
    client = MagicMock()
    client.containers.list.return_value = [existing]
    client.images.get.return_value = MagicMock(id="img1")

    _reconcile_once(client, [conn], settings)

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

    _reconcile_once(client, [conn], settings)

    exited.start.assert_called_once()


def test_recreates_container_on_image_change():
    conn = _make_connection()
    settings = _make_settings()

    old_container = _make_mock_container("ss-abcdef123456789012345678", image_id="old_img")
    client = MagicMock()
    client.containers.list.return_value = [old_container]
    client.images.get.return_value = MagicMock(id="new_img")

    _reconcile_once(client, [conn], settings)

    old_container.stop.assert_called()
    old_container.remove.assert_called()
    client.containers.run.assert_called_once()


# Async functions ======================================================================================================
async def test_reconciliation_loop_responds_to_trigger_file(tmp_path):
    """The loop sleeps for reconcile_interval_seconds but wakes early when the
    .reconcile-now trigger file appears. Invariant documented in CLAUDE.md."""
    db_path = tmp_path / "voyager.db"
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

    with patch("voyager.reconciler.reconcile", side_effect=fake_reconcile):
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


@patch("voyager.reconciler._get_docker_client")
async def test_cleanup_all_containers(mock_get_client):
    c1 = _make_mock_container("ss-aaa111bbb222ccc333ddd444")
    c2 = _make_mock_container("ss-eee555fff666ggg777hhh888")
    client = MagicMock()
    client.containers.list.return_value = [c1, c2]
    mock_get_client.return_value = client

    await cleanup_all_containers()

    c1.stop.assert_called_once()
    c1.remove.assert_called_once()
    c2.stop.assert_called_once()
    c2.remove.assert_called_once()
    client.close.assert_called_once()
