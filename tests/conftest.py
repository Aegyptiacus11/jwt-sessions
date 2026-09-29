from __future__ import annotations

import pytest
from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from jwt_sessions import InMemoryRefreshStore
from jwt_sessions.sqlalchemy_store import SQLAlchemyRefreshStore, refresh_tables

SECRET = "test-secret-that-is-comfortably-over-32-bytes"


@pytest.fixture(params=["memory", "sqlalchemy"])
async def store(request, tmp_path):
    """Every refresh behaviour is checked against both stores: they are two
    implementations of one contract, and the SQL one is what an app runs."""
    if request.param == "memory":
        yield InMemoryRefreshStore()
        return
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}")
    metadata = MetaData()
    families, tokens = refresh_tables(metadata)
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    yield SQLAlchemyRefreshStore(async_sessionmaker(engine), families, tokens)
    await engine.dispose()
