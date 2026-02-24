"""
Celery task definitions for ReconScope scan execution.

This module registers Celery tasks that bridge the synchronous Celery
worker environment with the async :class:`~app.engine.orchestrator.ScanOrchestrator`.

The main task :func:`run_scan` creates a fresh async event loop, opens a
database session, and delegates the entire scan lifecycle to the
orchestrator.  On failure the scan status is updated to ``FAILED`` and
a failure event is published via Redis Pub/Sub.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from app.core.celery_app import celery
from app.core.logging import get_logger

logger = get_logger(__name__)


async def _execute_scan(scan_id: str) -> None:
    """Async entry point that creates a DB session and runs the orchestrator.

    This coroutine is called from inside the synchronous Celery task via
    :func:`asyncio.run`.  It manages the database session lifecycle and
    delegates to :meth:`ScanOrchestrator.run_scan`.

    On any exception the scan is marked as ``FAILED`` in the database and
    a ``scan_failed`` event is published to Redis.

    Args:
        scan_id: The UUID of the scan to execute (as a string).
    """
    # Late imports to avoid circular dependency at module load time.
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from app.config import get_settings
    from app.engine.orchestrator import ScanOrchestrator
    from app.models.scan import Scan, ScanStatus

    # Create a fresh engine bound to the current event loop (Celery workers
    # spin up a new loop per task, so the module-level engine cannot be reused).
    settings = get_settings()
    task_engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        pool_pre_ping=True,
    )
    task_session_factory = async_sessionmaker(
        bind=task_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    try:
        async with task_session_factory() as db_session:
            try:
                orchestrator = ScanOrchestrator()
                await orchestrator.run_scan(scan_id=scan_id, db_session=db_session)
            except Exception as exc:
                logger.exception(
                    "Scan %s failed: %s",
                    scan_id,
                    exc,
                    extra={"action": "scan_failed", "target": scan_id},
                )

                # Attempt to mark the scan as FAILED.
                try:
                    scan: Scan | None = await db_session.get(
                        Scan, uuid.UUID(scan_id)
                    )
                    if scan is not None:
                        scan.status = ScanStatus.FAILED
                        scan.completed_at = datetime.now(timezone.utc)
                        if scan.started_at:
                            scan.duration_seconds = (
                                scan.completed_at - scan.started_at
                            ).total_seconds()
                        await db_session.commit()
                except Exception as db_exc:
                    logger.error(
                        "Could not update scan status to FAILED: %s",
                        db_exc,
                        extra={"action": "scan_status_update_error", "target": scan_id},
                    )

                # Attempt to publish a failure event.
                try:
                    await _publish_failure_event(scan_id, str(exc))
                except Exception as pub_exc:
                    logger.warning(
                        "Could not publish scan failure event: %s",
                        pub_exc,
                        extra={"action": "redis_publish_error", "target": scan_id},
                    )

                raise
    finally:
        await task_engine.dispose()


async def _publish_failure_event(scan_id: str, error_message: str) -> None:
    """Publish a ``scan_failed`` event via Redis Pub/Sub.

    Args:
        scan_id: The scan UUID string.
        error_message: A description of the failure.
    """
    import redis.asyncio as aioredis
    from app.config import get_settings

    settings = get_settings()
    channel: str = f"scan:{scan_id}"
    message: str = json.dumps(
        {
            "event": "scan_failed",
            "module": None,
            "data": {"error": error_message},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        default=str,
    )

    redis_client = aioredis.from_url(settings.REDIS_URL)
    async with redis_client:
        await redis_client.publish(channel, message)


@celery.task(
    name="reconscope.run_scan",
    bind=True,
    max_retries=0,
    acks_late=True,
    reject_on_worker_lost=True,
    track_started=True,
)
def run_scan(self: Any, scan_id: str) -> dict[str, str]:
    """Celery task that executes a full reconnaissance scan.

    Creates a new async event loop, runs the scan orchestrator inside it,
    and returns a summary dict.  The task is deliberately non-retryable
    (``max_retries=0``) because partial scan results would be confusing.

    Args:
        self: The Celery task instance (bound via ``bind=True``).
        scan_id: UUID of the :class:`~app.models.scan.Scan` to execute.

    Returns:
        A dictionary with ``scan_id`` and ``status`` keys.

    Raises:
        Exception: Propagated from the orchestrator if the scan fails.
    """
    logger.info(
        "Celery task received for scan %s",
        scan_id,
        extra={"action": "task_received", "target": scan_id},
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_execute_scan(scan_id))
    finally:
        loop.close()

    logger.info(
        "Celery task completed for scan %s",
        scan_id,
        extra={"action": "task_completed", "target": scan_id},
    )

    return {"scan_id": scan_id, "status": "completed"}
