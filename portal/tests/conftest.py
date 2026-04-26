import pytest
import pytest_asyncio

from postern import db
from postern.settings import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(database_path=str(tmp_path / "test.db"), secret_key="test-secret")


@pytest_asyncio.fixture
async def test_db(settings):
    async with db.get_connection(settings.database_path) as conn:
        await db.migrate(conn)
        yield conn
