"""Tests for the FastAPI lifespan: reconciler startup + cleanup on shutdown."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from asgi_lifespan import LifespanManager

from postern.app import PosternApp
from postern.settings import Settings


async def test_lifespan_starts_and_stops_reconciler(tmp_path):
    settings = Settings(database_path=str(tmp_path / "lifespan.db"), secret_key="test-secret")
    app = PosternApp(settings)

    loop_calls: list[tuple] = []
    loop_started = asyncio.Event()

    async def fake_loop(*args, **kwargs):
        loop_calls.append((args, kwargs))
        loop_started.set()
        await asyncio.Event().wait()  # block until cancelled

    with (
        patch("postern.app.reconciliation_loop", new=fake_loop),
        patch("postern.app.cleanup_all_containers", new_callable=AsyncMock) as mock_cleanup,
    ):
        async with LifespanManager(app):
            # Startup: wait on the event (don't rely on sleep(0) yielding far enough)
            await asyncio.wait_for(loop_started.wait(), timeout=3)
            assert len(loop_calls) == 1
            assert loop_calls[0][0][0] == str(tmp_path / "lifespan.db")
            assert loop_calls[0][0][1] is settings
            mock_cleanup.assert_not_called()

        # Shutdown: cleanup_all_containers was awaited
        mock_cleanup.assert_awaited_once()


async def test_lifespan_closes_db_when_migrate_fails(tmp_path):
    """Regression: the lifespan opens the DB connection BEFORE migrate runs.
    If migrate raises, the connection (and its non-daemon aiosqlite worker
    thread) must still be closed."""
    import threading

    settings = Settings(database_path=str(tmp_path / "lifespan-fail.db"), secret_key="test-secret")
    application = PosternApp(settings)

    def aiosqlite_workers() -> set[threading.Thread]:
        return {t for t in threading.enumerate() if t.is_alive() and "_connection_worker_thread" in (t.name or "")}

    before = aiosqlite_workers()

    # Force migrate to fail; the connection it was given must still be closed.
    with patch("postern.app.db.migrate", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError, match="boom"):
            async with LifespanManager(application):
                pass  # should not reach here

    leaked = aiosqlite_workers() - before
    assert not leaked, f"Lifespan leaked aiosqlite worker on migrate failure: {leaked}"


async def test_lifespan_shutdown_passes_settings_to_cleanup_all_containers(tmp_path):
    """cleanup_all_containers needs settings to scope its container sweep to
    this instance (see reconciler.resolve_instance_id) -- pin that the
    lifespan passes it, not just that it's called."""
    settings = Settings(database_path=str(tmp_path / "lifespan-settings.db"), secret_key="test-secret")
    app = PosternApp(settings)

    loop_started = asyncio.Event()

    async def fake_loop(*args, **kwargs):
        loop_started.set()
        await asyncio.Event().wait()  # block until cancelled

    with (
        patch("postern.app.reconciliation_loop", new=fake_loop),
        patch("postern.app.cleanup_all_containers", new_callable=AsyncMock) as mock_cleanup,
    ):
        async with LifespanManager(app):
            await loop_started.wait()  # structurally guaranteed by fake_loop's own event, no timing bet

    mock_cleanup.assert_awaited_once_with(settings)


async def test_lifespan_shutdown_waits_for_inflight_reconcile_before_cleanup(tmp_path):
    """The shutdown sequence must be: request_reconcile_shutdown -> cancel the
    loop task -> wait_for_inflight_reconcile -> cleanup_all_containers, in
    that exact order. wait_for_inflight_reconcile between the cancel and the
    cleanup is what closes the race where a straggler create() from an
    in-flight pass could run concurrently with (or even after) the shutdown
    sweep."""
    settings = Settings(database_path=str(tmp_path / "lifespan-order.db"), secret_key="test-secret")
    app = PosternApp(settings)

    loop_started = asyncio.Event()

    async def fake_loop(*args, **kwargs):
        loop_started.set()
        await asyncio.Event().wait()  # block until cancelled

    order_tracker = Mock()

    def sync_request_reconcile_shutdown(*args, **kwargs):
        # request_reconcile_shutdown is synchronous in the real module.
        order_tracker.request_reconcile_shutdown()

    async def fake_wait_for_inflight_reconcile(*args, **kwargs):
        order_tracker.wait_for_inflight_reconcile()

    async def fake_cleanup_all_containers(*args, **kwargs):
        order_tracker.cleanup_all_containers()

    with (
        patch("postern.app.reconciliation_loop", new=fake_loop),
        patch("postern.app.request_reconcile_shutdown", new=sync_request_reconcile_shutdown),
        patch("postern.app.wait_for_inflight_reconcile", new=fake_wait_for_inflight_reconcile),
        patch("postern.app.cleanup_all_containers", new=fake_cleanup_all_containers),
    ):
        async with LifespanManager(app):
            await loop_started.wait()  # structurally guaranteed by fake_loop's own event, no timing bet

    assert [c[0] for c in order_tracker.mock_calls] == [
        "request_reconcile_shutdown",
        "wait_for_inflight_reconcile",
        "cleanup_all_containers",
    ]
