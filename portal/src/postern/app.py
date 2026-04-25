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


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    database = await db.get_connection(settings.database_path)
    await db.migrate(database)
    app.state.db = database

    # Start reconciliation loop ----------------------------------------------------------------------------------------
    reconciler_task = asyncio.create_task(reconciliation_loop(settings.database_path, settings))
    logger.info("Reconciliation loop started")

    yield

    # Shutdown ---------------------------------------------------------------------------------------------------------
    reconciler_task.cancel()
    try:
        await reconciler_task
    except asyncio.CancelledError:
        pass

    await cleanup_all_containers()
    await database.close()
    logger.info("Shutdown complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = Settings()

    application = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    application.state.settings = settings

    # Middleware: inject DB connection into request state --------------------------------------------------------------
    @application.middleware("http")
    async def inject_db(request: Request, call_next):
        request.state.db = application.state.db
        return await call_next(request)

    # Include routers --------------------------------------------------------------------------------------------------
    application.include_router(login.router)
    application.include_router(dashboard.router)

    return application


def _get_app() -> FastAPI:
    """Lazy app factory for uvicorn. Only called when actually serving."""
    return create_app()


app = _get_app
