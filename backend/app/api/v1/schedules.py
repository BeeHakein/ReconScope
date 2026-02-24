"""
Schedule CRUD endpoints for recurring scan management.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.api.schemas.schedule import ScheduleCreate, ScheduleResponse, ScheduleUpdate
from app.models.schedule import ScanSchedule

logger = logging.getLogger(__name__)
router = APIRouter()


def _compute_next_run(cron_expr: str) -> datetime | None:
    """Compute the next run timestamp from a cron expression.

    Uses a simple heuristic if croniter is not available.
    """
    try:
        from croniter import croniter
        return croniter(cron_expr, datetime.now(timezone.utc)).get_next(datetime)
    except ImportError:
        # Fallback: just return tomorrow at midnight UTC
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        return now.replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(days=1)
    except Exception:
        return None


@router.get(
    "",
    response_model=list[ScheduleResponse],
    summary="List all scan schedules",
)
async def list_schedules(
    db: AsyncSession = Depends(get_db_session),
) -> list[ScheduleResponse]:
    """Retrieve all scan schedules."""
    stmt = select(ScanSchedule).order_by(ScanSchedule.created_at.desc())
    result = await db.execute(stmt)
    schedules = result.scalars().all()
    return [ScheduleResponse.model_validate(s) for s in schedules]


@router.post(
    "",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan schedule",
)
async def create_schedule(
    body: ScheduleCreate,
    db: AsyncSession = Depends(get_db_session),
) -> ScheduleResponse:
    """Create a new recurring scan schedule."""
    next_run = _compute_next_run(body.cron_expression)

    schedule = ScanSchedule(
        target=body.target.strip().lower(),
        modules=body.modules if body.modules else None,
        cron_expression=body.cron_expression,
        is_active=True,
        next_run_at=next_run,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)

    return ScheduleResponse.model_validate(schedule)


@router.patch(
    "/{schedule_id}",
    response_model=ScheduleResponse,
    summary="Update a scan schedule",
)
async def update_schedule(
    schedule_id: UUID,
    body: ScheduleUpdate,
    db: AsyncSession = Depends(get_db_session),
) -> ScheduleResponse:
    """Toggle active state or update cron expression of a schedule."""
    schedule = await db.get(ScanSchedule, schedule_id)
    if schedule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule '{schedule_id}' not found.",
        )

    if body.is_active is not None:
        schedule.is_active = body.is_active
    if body.cron_expression is not None:
        schedule.cron_expression = body.cron_expression
        schedule.next_run_at = _compute_next_run(body.cron_expression)
    if body.modules is not None:
        schedule.modules = body.modules if body.modules else None

    await db.flush()
    await db.refresh(schedule)

    return ScheduleResponse.model_validate(schedule)


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan schedule",
)
async def delete_schedule(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Remove a scan schedule permanently."""
    schedule = await db.get(ScanSchedule, schedule_id)
    if schedule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule '{schedule_id}' not found.",
        )
    await db.delete(schedule)
