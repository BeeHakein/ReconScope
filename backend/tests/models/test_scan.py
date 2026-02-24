"""
Tests for Target, Scan, and ScanStatus ORM models.

Validates default values, nullable constraints, enum completeness,
and foreign-key relationships using an in-memory SQLite test database.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Target, Scan, ScanStatus


@pytest.mark.asyncio
async def test_target_creation_sets_defaults(db_session: AsyncSession) -> None:
    """Creating a Target should auto-generate an id and set created_at."""
    target = Target(domain="defaults-test.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    assert target.id is not None, "Target id must be auto-generated"
    assert isinstance(target.id, uuid.UUID), "Target id must be a UUID"
    assert target.domain == "defaults-test.com"
    assert target.created_at is not None, "created_at must be set automatically"
    assert isinstance(target.created_at, datetime)


@pytest.mark.asyncio
async def test_target_domain_is_required(db_session: AsyncSession) -> None:
    """A Target with domain=None must be rejected by the database."""
    target = Target(domain=None)  # type: ignore[arg-type]
    db_session.add(target)
    with pytest.raises(Exception):
        await db_session.commit()


@pytest.mark.asyncio
async def test_scan_creation_with_defaults(
    db_session: AsyncSession, sample_target: Target
) -> None:
    """Creating a Scan should default status to QUEUED and set created_at."""
    scan = Scan(target_id=sample_target.id)
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    assert scan.id is not None, "Scan id must be auto-generated"
    assert isinstance(scan.id, uuid.UUID)
    assert scan.status == ScanStatus.QUEUED, "Default status must be QUEUED"
    assert scan.created_at is not None, "created_at must be set automatically"
    assert scan.total_subdomains == 0
    assert scan.total_services == 0
    assert scan.total_cves == 0


@pytest.mark.asyncio
async def test_scan_status_enum_values() -> None:
    """ScanStatus must contain all five lifecycle states."""
    expected = {"queued", "running", "post_processing", "completed", "failed"}
    actual = {status.value for status in ScanStatus}
    assert actual == expected, f"ScanStatus values mismatch: {actual} != {expected}"


@pytest.mark.asyncio
async def test_scan_target_relationship(
    db_session: AsyncSession, sample_target: Target
) -> None:
    """A Scan's target relationship must resolve to the parent Target."""
    scan = Scan(
        id=uuid.uuid4(),
        target_id=sample_target.id,
        status=ScanStatus.RUNNING,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    assert scan.target_id == sample_target.id
    assert scan.target is not None, "Scan.target relationship must be populated"
    assert scan.target.domain == sample_target.domain
