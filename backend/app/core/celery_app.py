"""
Celery application instance and configuration.

The Celery app uses Redis as both broker and result backend, configured from
the application settings.  Task modules are auto-discovered under
``app.tasks``.
"""

from __future__ import annotations

from celery import Celery

from app.config import get_settings

# ── Constants ────────────────────────────────────────────────────────────────

_TASK_SOFT_TIME_LIMIT_SECONDS: int = 1800   # 30 minutes
_TASK_HARD_TIME_LIMIT_SECONDS: int = 2100   # 35 minutes
_TASK_DEFAULT_RATE_LIMIT: str = "10/m"
_RESULT_EXPIRES_SECONDS: int = 3600        # 1 hour
_WORKER_PREFETCH_MULTIPLIER: int = 1


def _create_celery_app() -> Celery:
    """Build and configure the Celery application instance.

    Returns:
        A fully configured ``Celery`` application ready to be used by workers
        and by the FastAPI backend to dispatch tasks.
    """
    settings = get_settings()

    app = Celery(
        "reconscope",
        broker=settings.REDIS_URL,
        backend=settings.REDIS_URL,
        include=["app.tasks.scan_tasks", "app.tasks.scheduler"],
    )

    app.conf.update(
        # ── Serialization ────────────────────────────────────────────────
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",

        # ── Time Zones ───────────────────────────────────────────────────
        timezone="UTC",
        enable_utc=True,

        # ── Task Execution ───────────────────────────────────────────────
        task_soft_time_limit=_TASK_SOFT_TIME_LIMIT_SECONDS,
        task_time_limit=_TASK_HARD_TIME_LIMIT_SECONDS,
        task_default_rate_limit=_TASK_DEFAULT_RATE_LIMIT,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_track_started=True,

        # ── Result Backend ───────────────────────────────────────────────
        result_expires=_RESULT_EXPIRES_SECONDS,

        # ── Worker ───────────────────────────────────────────────────────
        worker_prefetch_multiplier=_WORKER_PREFETCH_MULTIPLIER,
        worker_max_tasks_per_child=200,
        worker_hijack_root_logger=False,

        # ── Broker ───────────────────────────────────────────────────────
        broker_connection_retry_on_startup=True,

        # ── Beat Schedule ────────────────────────────────────────────────
        beat_schedule={
            "process-scan-schedules": {
                "task": "reconscope.process_schedules",
                "schedule": 60.0,
            },
        },
    )

    # Auto-discover task modules inside the ``app.tasks`` package.
    app.autodiscover_tasks(["app.tasks"], related_name="scan_tasks")

    return app


celery: Celery = _create_celery_app()
