"""
Celery Beat periodic task for processing scan schedules.

Checks the ``scan_schedules`` table every 60 seconds and triggers
scans for any schedule whose ``next_run_at`` is in the past.
"""

from __future__ import annotations

import asyncio
import uuid
import logging
from datetime import datetime, timezone
from typing import Any

from app.core.celery_app import celery

logger = logging.getLogger(__name__)


async def _process_schedules() -> int:
    """Check for due schedules and dispatch scan tasks.

    Returns:
        Number of scans triggered.
    """
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from app.config import get_settings
    from app.models.schedule import ScanSchedule
    from app.models.scan import Scan, ScanStatus, Target
    from app.api.schemas.scan import ALL_MODULES

    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    session_factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    triggered = 0
    now = datetime.now(timezone.utc)

    try:
        async with session_factory() as db:
            try:
                # Find active schedules that are due
                stmt = (
                    select(ScanSchedule)
                    .where(ScanSchedule.is_active.is_(True))
                    .where(ScanSchedule.next_run_at <= now)
                )
                result = await db.execute(stmt)
                due_schedules = result.scalars().all()

                for schedule in due_schedules:
                    try:
                        # Get or create target
                        target_stmt = select(Target).where(Target.domain == schedule.target)
                        target_result = await db.execute(target_stmt)
                        target = target_result.scalar_one_or_none()

                        if target is None:
                            target = Target(domain=schedule.target)
                            db.add(target)
                            await db.flush()

                        # Create a new scan
                        modules = schedule.modules or list(ALL_MODULES)
                        scan = Scan(
                            target_id=target.id,
                            status=ScanStatus.QUEUED,
                            modules=modules,
                            scope_confirmed=True,
                        )
                        db.add(scan)
                        await db.flush()

                        # Dispatch the Celery task
                        from app.tasks.scan_tasks import run_scan
                        run_scan.delay(str(scan.id))

                        # Update schedule timestamps
                        schedule.last_run_at = now
                        try:
                            from croniter import croniter
                            schedule.next_run_at = croniter(
                                schedule.cron_expression, now
                            ).get_next(datetime)
                        except ImportError:
                            from datetime import timedelta
                            schedule.next_run_at = now + timedelta(days=1)

                        triggered += 1
                        logger.info(
                            "Scheduled scan triggered for %s (schedule %s, scan %s)",
                            schedule.target,
                            schedule.id,
                            scan.id,
                        )

                    except Exception as exc:
                        logger.exception(
                            "Failed to trigger scheduled scan for %s: %s",
                            schedule.target,
                            exc,
                        )

                await db.commit()
            except Exception:
                await db.rollback()
                raise
    finally:
        await engine.dispose()

    return triggered


@celery.task(
    name="reconscope.process_schedules",
    bind=True,
    max_retries=0,
)
def process_schedules(self: Any) -> dict[str, Any]:
    """Celery task that checks and triggers due scan schedules.

    Called periodically by Celery Beat (every 60 seconds).
    """
    loop = asyncio.new_event_loop()
    try:
        triggered = loop.run_until_complete(_process_schedules())
        return {"status": "ok", "triggered": triggered}
    except Exception as exc:
        logger.exception("Schedule processing failed: %s", exc)
        return {"status": "error", "error": str(exc)}
    finally:
        loop.close()
