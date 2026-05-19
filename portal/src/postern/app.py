"""FastAPI application with lifespan for the reconciliation loop."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from postern import db, identity
from postern.reconciler import cleanup_all_containers, reconciliation_loop
from postern.routes import dashboard, login
from postern.settings import Settings

logger = logging.getLogger(__name__)


class PosternApp(FastAPI):

    def __init__(self, settings: Settings | None = None):
        super().__init__(lifespan=type(self)._lifespan, docs_url=None, redoc_url=None, openapi_url=None)
        self.state.settings = settings or Settings()

        # Brand display string surfaced via Jinja `{{ product_name }}` -- registered on each
        # router's Jinja2Templates env so templates don't have to thread it through every
        # context dict. Routers create their templates instance at module import; we patch
        # the env globals here at app construction (settings now exist). Use `update` (not
        # subscript) because `Environment.globals` is typed as a heterogeneous dict whose
        # value type union doesn't include plain `str`; `update` is permissive enough.
        for tpls in (login.templates, dashboard.templates):
            tpls.env.globals.update(product_name=self.state.settings.product_name)

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
            # GeoIP readers are lazy: GeoIPReaders("") is a no-op constructor and never
            # opens a file. The login page calls .city() / .asn() on demand; missing or
            # absent DBs are treated as "no enrichment" without raising.
            app.state.geoip_readers = identity.GeoIPReaders(settings.geoip_db_dir)

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
                app.state.geoip_readers.close()

            logger.info("Shutdown complete")
