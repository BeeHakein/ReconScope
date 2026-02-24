"""ReconScope Celery task definitions."""

from app.tasks.scan_tasks import run_scan  # noqa: F401 – register task with Celery
