from __future__ import annotations

from pathlib import Path

from sqlalchemy import event
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import BASE_DIR, settings


def get_database_url() -> str:
    """Return the configured URL, resolving relative SQLite paths.

    ``DATABASE_URL`` is honoured, including a custom file name. Relative
    SQLite paths are resolved against ``backend/`` so the database lands in
    the same place regardless of the current working directory.
    """
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite":
        return settings.database_url

    database = url.database
    if not database or database == ":memory:":
        return settings.database_url

    db_path = Path(database)
    if not db_path.is_absolute():
        db_path = (BASE_DIR / db_path).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    return url.set(database=db_path.as_posix()).render_as_string(hide_password=False)


_url = get_database_url()
_engine_kwargs: dict = {"echo": settings.database_echo}
if not _url.startswith("sqlite"):
    _engine_kwargs["pool_size"] = settings.database_pool_size
    _engine_kwargs["max_overflow"] = settings.database_max_overflow

engine = create_async_engine(_url, **_engine_kwargs)

if _url.startswith("sqlite"):

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi, _):
        cursor = dbapi.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()


async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db() -> None:
    import app.models.insight  # noqa: F401 - register ScanInsight table
    from app.models.base import BaseModel  # noqa: F401 - register all models

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
