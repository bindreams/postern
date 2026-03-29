import pytest
import pytest_asyncio

import aiosqlite

from voyager import db
from voyager.settings import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(database_path=str(tmp_path / "test.db"), secret_key="test-secret")


@pytest_asyncio.fixture
async def test_db(settings):
    conn = await db.get_connection(settings.database_path)
    await db.migrate(conn)
    yield conn
    await conn.close()
