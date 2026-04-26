"""FastAPI application with lifespan for the reconciliation loop."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from postern import db
from postern.reconciler import cleanup_all_containers, reconciliation_loop
from postern.routes import dashboard, login
from postern.settings import Settings

logger = logging.getLogger(__name__)


class PosternApp(FastAPI):

    def __init__(self, settings: Settings | None = None):
        super().__init__(lifespan=type(self)._lifespan, docs_url=None, redoc_url=None, openapi_url=None)
        self.state.settings = settings or Settings()

        @self.middleware("http")
        async def _inject_db(request: Request, call_next):
            request.state.db = self.state.db
            return await call_next(request)

        self.include_router(login.router)
        self.include_router(dashboard.router)

    @classmethod
    @asynccontextmanager
    async def _lifespan(cls, app: FastAPI):
        settings: Settings = app.state.settings
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            app.state.db = database

            # Start reconciliation loop --------------------------------------------------------------------------------
            reconciler_task = asyncio.create_task(reconciliation_loop(settings.database_path, settings))
            logger.info("Reconciliation loop started")

            try:
                yield
            finally:
                # Shutdown ---------------------------------------------------------------------------------------------
                reconciler_task.cancel()
                try:
                    await reconciler_task
                except asyncio.CancelledError:
                    pass
                await cleanup_all_containers()

            logger.info("Shutdown complete")
