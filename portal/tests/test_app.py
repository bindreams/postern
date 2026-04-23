"""Tests for the FastAPI lifespan: reconciler startup + cleanup on shutdown."""

import asyncio
from unittest.mock import AsyncMock, patch

from asgi_lifespan import LifespanManager

from voyager.app import create_app
from voyager.settings import Settings


async def test_lifespan_starts_and_stops_reconciler(tmp_path):
    settings = Settings(database_path=str(tmp_path / "lifespan.db"), secret_key="test-secret")
    app = create_app(settings)

    loop_calls: list[tuple] = []
    loop_started = asyncio.Event()

    async def fake_loop(*args, **kwargs):
        loop_calls.append((args, kwargs))
        loop_started.set()
        await asyncio.Event().wait()  # block until cancelled

    with (
        patch("voyager.app.reconciliation_loop", new=fake_loop),
        patch("voyager.app.cleanup_all_containers", new_callable=AsyncMock) as mock_cleanup,
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
