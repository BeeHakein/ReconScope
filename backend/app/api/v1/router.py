"""
Aggregated APIRouter for API version 1.

All v1 endpoint routers are included here and exposed as a single ``router``
instance that is mounted by the FastAPI application in ``app.main``.  The
prefix ``/api/v1`` is applied by the application, so sub-routers only declare
their own resource prefix (e.g. ``/scans``, ``/targets``).
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import scans, targets, export, schedules

router = APIRouter()

router.include_router(
    scans.router,
    prefix="/scans",
    tags=["scans"],
)
router.include_router(
    targets.router,
    prefix="/targets",
    tags=["targets"],
)
router.include_router(
    export.router,
    prefix="/scans",
    tags=["export"],
)
router.include_router(
    schedules.router,
    prefix="/schedules",
    tags=["schedules"],
)
