"""
Async SQLAlchemy engine, session factory, and declarative base.

Provides:
- ``engine``  -- the async engine bound to the configured ``DATABASE_URL``.
- ``async_session_factory`` -- a session-maker that produces ``AsyncSession`` instances.
- ``Base`` -- the declarative base class for all ORM models.
- ``get_db_session`` -- an async generator suitable for FastAPI ``Depends()``.
"""

from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

# ── Constants ────────────────────────────────────────────────────────────────

_POOL_SIZE: int = 20
_MAX_OVERFLOW: int = 10
_POOL_TIMEOUT_SECONDS: int = 30
_POOL_RECYCLE_SECONDS: int = 1800  # 30 minutes


# ── Declarative Base ─────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models in the project."""


# ── Engine & Session Factory ─────────────────────────────────────────────────

def _build_engine() -> AsyncEngine:
    """Create and return a new async engine using current settings."""
    settings = get_settings()
    return create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        pool_size=_POOL_SIZE,
        max_overflow=_MAX_OVERFLOW,
        pool_timeout=_POOL_TIMEOUT_SECONDS,
        pool_recycle=_POOL_RECYCLE_SECONDS,
        pool_pre_ping=True,
    )


engine: AsyncEngine = _build_engine()

async_session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


# ── Dependency Injection Helper ──────────────────────────────────────────────

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an ``AsyncSession`` and guarantee cleanup on exit.

    Intended for use with FastAPI's dependency injection system::

        @router.get("/items")
        async def list_items(db: AsyncSession = Depends(get_db_session)):
            ...

    The session is committed if no exception occurs; otherwise it is rolled
    back.  In both cases the session is closed at the end.
    """
    session = async_session_factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()
