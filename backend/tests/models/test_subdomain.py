"""
Tests for the Subdomain ORM model.

Validates field assignment, foreign-key relationships to Scan, and
cascade behavior with child Service records.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.scan import Target, Scan, ScanStatus
from app.models.subdomain import Subdomain
from app.models.service import Service


@pytest.mark.asyncio
async def test_subdomain_creation(
    db_session: AsyncSession, sample_scan: Scan
) -> None:
    """Creating a Subdomain should persist all fields correctly."""
    subdomain = Subdomain(
        id=uuid.uuid4(),
        scan_id=sample_scan.id,
        name="mail.example.com",
        ip_address="93.184.216.35",
        source="dns",
        is_alive=True,
        dns_records={"A": ["93.184.216.35"], "MX": ["10 mail.example.com"]},
        whois_data={"registrar": "Test Registrar"},
        discovered_at=datetime.now(timezone.utc),
    )
    db_session.add(subdomain)
    await db_session.commit()
    await db_session.refresh(subdomain)

    assert subdomain.id is not None
    assert subdomain.name == "mail.example.com"
    assert subdomain.ip_address == "93.184.216.35"
    assert subdomain.source == "dns"
    assert subdomain.is_alive is True
    assert "A" in subdomain.dns_records
    assert subdomain.whois_data["registrar"] == "Test Registrar"
    assert subdomain.discovered_at is not None


@pytest.mark.asyncio
async def test_subdomain_scan_relationship(
    db_session: AsyncSession, sample_scan: Scan
) -> None:
    """The Subdomain.scan relationship must resolve to the parent Scan."""
    subdomain = Subdomain(
        id=uuid.uuid4(),
        scan_id=sample_scan.id,
        name="api.example.com",
        discovered_at=datetime.now(timezone.utc),
    )
    db_session.add(subdomain)
    await db_session.commit()
    await db_session.refresh(subdomain)

    assert subdomain.scan_id == sample_scan.id
    assert subdomain.scan is not None, "Subdomain.scan relationship must be populated"
    assert subdomain.scan.id == sample_scan.id


@pytest.mark.asyncio
async def test_subdomain_services_relationship(
    db_session: AsyncSession, sample_scan: Scan
) -> None:
    """Deleting a Subdomain must cascade-delete its child Service records."""
    subdomain = Subdomain(
        id=uuid.uuid4(),
        scan_id=sample_scan.id,
        name="services-test.example.com",
        discovered_at=datetime.now(timezone.utc),
    )
    db_session.add(subdomain)
    await db_session.commit()
    await db_session.refresh(subdomain)

    service_1 = Service(
        id=uuid.uuid4(),
        subdomain_id=subdomain.id,
        port=80,
        protocol="tcp",
        service_name="http",
    )
    service_2 = Service(
        id=uuid.uuid4(),
        subdomain_id=subdomain.id,
        port=443,
        protocol="tcp",
        service_name="https",
    )
    db_session.add_all([service_1, service_2])
    await db_session.commit()

    # Reload subdomain with services eagerly loaded.
    stmt = (
        select(Subdomain)
        .options(selectinload(Subdomain.services))
        .where(Subdomain.id == subdomain.id)
    )
    result = await db_session.execute(stmt)
    loaded = result.scalar_one()

    assert len(loaded.services) == 2, "Subdomain should have 2 child services"
    port_set = {svc.port for svc in loaded.services}
    assert port_set == {80, 443}

    # Verify cascade: deleting subdomain removes services.
    await db_session.delete(loaded)
    await db_session.commit()

    svc_result = await db_session.execute(
        select(Service).where(Service.subdomain_id == subdomain.id)
    )
    remaining = svc_result.scalars().all()
    assert len(remaining) == 0, "Services must be cascade-deleted with their Subdomain"
