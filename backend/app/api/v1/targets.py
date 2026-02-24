"""
Target and scan-history endpoints.

Provides read-only access to the inventory of scanned domains and the
historical scan records for each domain.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db_session
from app.models.scan import Scan, Target

router = APIRouter()

# ---------------------------------------------------------------------------
# Response schemas (local to this module)
# ---------------------------------------------------------------------------


class TargetListItem(BaseModel):
    """Compact target representation for the listing endpoint.

    Attributes:
        id: Target UUID.
        domain: The fully-qualified domain name.
        created_at: When the target was first registered.
        scan_count: How many scans have been executed against this target.
    """

    id: UUID
    domain: str
    created_at: datetime
    scan_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class ScanHistoryItem(BaseModel):
    """A scan entry within a target's history timeline.

    Attributes:
        scan_id: UUID of the scan.
        status: Final or current status string.
        created_at: When the scan was queued.
        completed_at: When the scan finished (``None`` if still running).
        duration_seconds: Wall-clock execution time in seconds.
        total_subdomains: Number of subdomains discovered.
        total_services: Number of services detected.
        total_cves: Number of CVEs matched.
        overall_risk: Computed risk level.
    """

    scan_id: UUID
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    total_subdomains: int = 0
    total_services: int = 0
    total_cves: int = 0
    overall_risk: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# GET /targets/
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=list[TargetListItem],
    summary="List all scanned targets",
)
async def list_targets(
    skip: int = Query(0, ge=0, description="Number of records to skip."),
    limit: int = Query(50, ge=1, le=200, description="Max records to return."),
    db: AsyncSession = Depends(get_db_session),
) -> list[TargetListItem]:
    """Return a paginated list of all domains that have been scanned.

    Each item includes the total number of scans executed against the
    target, enabling the caller to identify domains with extensive scan
    history.

    Args:
        skip: Offset for pagination.
        limit: Maximum number of targets to return (1--200).
        db: The database session (injected).

    Returns:
        A list of :class:`TargetListItem` instances ordered by creation
        date descending.
    """
    stmt = (
        select(Target)
        .options(selectinload(Target.scans))
        .order_by(Target.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(stmt)
    targets = result.scalars().all()

    return [
        TargetListItem(
            id=t.id,
            domain=t.domain,
            created_at=t.created_at,
            scan_count=len(t.scans),
        )
        for t in targets
    ]


# ---------------------------------------------------------------------------
# GET /targets/{domain}/history
# ---------------------------------------------------------------------------


@router.get(
    "/{domain}/history",
    response_model=list[ScanHistoryItem],
    summary="Get scan history for a domain",
)
async def get_target_history(
    domain: str,
    skip: int = Query(0, ge=0, description="Number of records to skip."),
    limit: int = Query(50, ge=1, le=200, description="Max records to return."),
    db: AsyncSession = Depends(get_db_session),
) -> list[ScanHistoryItem]:
    """Return the chronological scan history for the specified domain.

    Scans are ordered by creation date descending so the most recent scan
    appears first.

    Args:
        domain: The fully-qualified domain name to look up.
        skip: Offset for pagination.
        limit: Maximum number of scan records to return (1--200).
        db: The database session (injected).

    Returns:
        A list of :class:`ScanHistoryItem` instances.

    Raises:
        HTTPException: *404 Not Found* when the domain has never been
            scanned.
    """
    normalised_domain = domain.strip().lower().rstrip(".")

    stmt = select(Target).where(Target.domain == normalised_domain)
    result = await db.execute(stmt)
    target = result.scalar_one_or_none()

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No target found for domain '{normalised_domain}'.",
        )

    scans_stmt = (
        select(Scan)
        .where(Scan.target_id == target.id)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    scans_result = await db.execute(scans_stmt)
    scans = scans_result.scalars().all()

    return [
        ScanHistoryItem(
            scan_id=s.id,
            status=s.status.value,
            created_at=s.created_at,
            completed_at=s.completed_at,
            duration_seconds=s.duration_seconds,
            total_subdomains=s.total_subdomains,
            total_services=s.total_services,
            total_cves=s.total_cves,
            overall_risk=s.overall_risk,
        )
        for s in scans
    ]
