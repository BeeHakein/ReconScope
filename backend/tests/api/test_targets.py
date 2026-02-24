"""
Tests for the target listing and history API endpoints.

Covers the ``/api/v1/targets`` routes including empty listing, populated
listing, and scan history retrieval for a specific domain.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus, Target


@pytest.mark.asyncio
async def test_list_targets_empty(client: AsyncClient) -> None:
    """GET /api/v1/targets/ with no targets in the database returns an empty list."""
    response = await client.get("/api/v1/targets/")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_list_targets_with_results(
    client: AsyncClient,
    test_engine,
) -> None:
    """GET /api/v1/targets/ returns all registered targets with scan counts."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession as AS

    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AS,
        expire_on_commit=False,
    )
    async with session_factory() as sess:
        target_1 = Target(domain="alpha.com", created_at=datetime.now(timezone.utc))
        target_2 = Target(domain="bravo.com", created_at=datetime.now(timezone.utc))
        sess.add_all([target_1, target_2])
        await sess.flush()

        scan = Scan(
            target_id=target_1.id,
            status=ScanStatus.COMPLETED,
            config={},
            created_at=datetime.now(timezone.utc),
        )
        sess.add(scan)
        await sess.commit()

    response = await client.get("/api/v1/targets/")

    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2

    domains = {item["domain"] for item in data}
    assert "alpha.com" in domains
    assert "bravo.com" in domains

    # alpha.com should have scan_count >= 1.
    alpha_item = next(item for item in data if item["domain"] == "alpha.com")
    assert alpha_item["scan_count"] >= 1


@pytest.mark.asyncio
async def test_get_target_history(
    client: AsyncClient,
    test_engine,
) -> None:
    """GET /api/v1/targets/{domain}/history returns the scan timeline for a domain."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession as AS

    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AS,
        expire_on_commit=False,
    )
    async with session_factory() as sess:
        target = Target(domain="history-test.com", created_at=datetime.now(timezone.utc))
        sess.add(target)
        await sess.flush()

        scan_1 = Scan(
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            config={"modules": ["crtsh"]},
            created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2025, 1, 1, 0, 5, tzinfo=timezone.utc),
            duration_seconds=300.0,
            total_subdomains=10,
            total_services=5,
            total_cves=3,
            overall_risk="high",
        )
        scan_2 = Scan(
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            config={"modules": ["crtsh", "dns"]},
            created_at=datetime(2025, 2, 1, tzinfo=timezone.utc),
            completed_at=datetime(2025, 2, 1, 0, 10, tzinfo=timezone.utc),
            duration_seconds=600.0,
            total_subdomains=15,
            total_services=8,
            total_cves=5,
            overall_risk="critical",
        )
        sess.add_all([scan_1, scan_2])
        await sess.commit()

    response = await client.get("/api/v1/targets/history-test.com/history")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2

    # Most recent scan should be first (ordered by created_at desc).
    assert data[0]["overall_risk"] == "critical"
    assert data[0]["total_subdomains"] == 15
    assert data[1]["overall_risk"] == "high"
    assert data[1]["total_subdomains"] == 10

    # Verify response structure.
    for item in data:
        assert "scan_id" in item
        assert "status" in item
        assert "created_at" in item
        assert "total_cves" in item
