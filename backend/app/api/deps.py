"""
Shared FastAPI dependency functions for the ReconScope API.

Provides database session injection and common validation helpers that are
reused across multiple endpoint modules.
"""

from __future__ import annotations

from typing import AsyncGenerator
from uuid import UUID

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import async_session_factory
from app.models.scan import Scan


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session and guarantee cleanup on exit.

    The session is committed automatically when the request handler finishes
    without raising an exception.  On failure the transaction is rolled back.
    In both cases the session is closed.

    Usage::

        @router.get("/items")
        async def list_items(
            db: AsyncSession = Depends(get_db_session),
        ) -> list[Item]:
            ...

    Yields:
        An :class:`~sqlalchemy.ext.asyncio.AsyncSession` bound to the
        application engine.
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


async def validate_scan_exists(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> Scan:
    """Load a :class:`~app.models.scan.Scan` by its primary key or raise 404.

    This dependency eagerly loads all first-level relationships
    (``target``, ``subdomains``, ``findings``, ``attack_paths``,
    ``correlations``) so that downstream handlers can access them without
    additional queries.

    Args:
        scan_id: The UUID primary key of the scan to load.
        db: The database session (injected automatically).

    Returns:
        The fully-loaded :class:`Scan` instance.

    Raises:
        HTTPException: *404 Not Found* if no scan with the given ID exists.
    """
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.subdomains),
            selectinload(Scan.findings),
            selectinload(Scan.attack_paths),
            selectinload(Scan.correlations),
        )
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with id '{scan_id}' not found.",
        )

    return scan
