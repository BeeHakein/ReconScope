"""
Tests for the scan CRUD API endpoints.

Covers scan creation with and without scope confirmation, domain
validation, retrieval (single, list, detail), and deletion via the
``/api/v1/scans`` routes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus, Target


@pytest.mark.asyncio
async def test_create_scan_success(client: AsyncClient, db_session: AsyncSession) -> None:
    """POST /api/v1/scans/ with valid data and scope_confirmed=true returns 201."""
    with patch("app.api.v1.scans.run_scan") as mock_task:
        mock_task.delay = AsyncMock()
        response = await client.post(
            "/api/v1/scans/",
            json={
                "target": "acme-corp.de",
                "modules": ["crtsh", "dns"],
                "scope_confirmed": True,
            },
        )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["target"] == "acme-corp.de"
    assert data["status"] == "queued"
    assert "scan_id" in data
    assert data["modules"] == ["crtsh", "dns"]
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_scan_without_scope_confirmation_fails(
    client: AsyncClient,
) -> None:
    """POST /api/v1/scans/ with scope_confirmed=false returns 403 Forbidden."""
    response = await client.post(
        "/api/v1/scans/",
        json={
            "target": "acme-corp.de",
            "modules": ["crtsh"],
            "scope_confirmed": False,
        },
    )

    assert response.status_code == 403
    assert "scope" in response.json()["detail"].lower() or "confirm" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_create_scan_invalid_domain_fails(client: AsyncClient) -> None:
    """POST /api/v1/scans/ with an invalid domain returns 422 Unprocessable Entity."""
    response = await client.post(
        "/api/v1/scans/",
        json={
            "target": "not_a_valid_domain!!!",
            "modules": ["crtsh"],
            "scope_confirmed": True,
        },
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_scan_not_found(client: AsyncClient) -> None:
    """GET /api/v1/scans/{id} for a non-existent UUID returns 404."""
    fake_id = str(uuid.uuid4())
    response = await client.get(f"/api/v1/scans/{fake_id}")

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_list_scans_empty(client: AsyncClient) -> None:
    """GET /api/v1/scans/ with an empty database returns an empty list."""
    response = await client.get("/api/v1/scans/")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_list_scans_with_results(
    client: AsyncClient,
    db_session: AsyncSession,
    test_engine,
) -> None:
    """GET /api/v1/scans/ returns a populated list when scans exist."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession as AS

    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AS,
        expire_on_commit=False,
    )
    async with session_factory() as sess:
        target = Target(domain="list-test.com")
        sess.add(target)
        await sess.flush()
        scan_1 = Scan(
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            config={"modules": ["crtsh"]},
            created_at=datetime.now(timezone.utc),
        )
        scan_2 = Scan(
            target_id=target.id,
            status=ScanStatus.QUEUED,
            config={"modules": ["dns"]},
            created_at=datetime.now(timezone.utc),
        )
        sess.add_all([scan_1, scan_2])
        await sess.commit()

    response = await client.get("/api/v1/scans/")

    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2
    domains = {item["target"] for item in data}
    assert "list-test.com" in domains


@pytest.mark.asyncio
async def test_delete_scan_success(
    client: AsyncClient,
    db_session: AsyncSession,
    test_engine,
) -> None:
    """DELETE /api/v1/scans/{id} removes the scan and returns 204."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession as AS

    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AS,
        expire_on_commit=False,
    )
    async with session_factory() as sess:
        target = Target(domain="delete-test.com")
        sess.add(target)
        await sess.flush()
        scan = Scan(
            target_id=target.id,
            status=ScanStatus.QUEUED,
            config={},
            created_at=datetime.now(timezone.utc),
        )
        sess.add(scan)
        await sess.commit()
        scan_id = scan.id

    response = await client.delete(f"/api/v1/scans/{scan_id}")

    assert response.status_code == 204

    # Verify the scan is gone.
    get_response = await client.get(f"/api/v1/scans/{scan_id}")
    assert get_response.status_code == 404


@pytest.mark.asyncio
async def test_get_scan_detail(
    client: AsyncClient,
    db_session: AsyncSession,
    test_engine,
) -> None:
    """GET /api/v1/scans/{id} returns detailed scan information with progress and stats."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession as AS

    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AS,
        expire_on_commit=False,
    )
    async with session_factory() as sess:
        target = Target(domain="detail-test.com")
        sess.add(target)
        await sess.flush()
        scan = Scan(
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            config={"modules": ["crtsh", "dns"]},
            progress={
                "current_module": None,
                "modules_completed": ["crtsh", "dns"],
                "modules_pending": [],
                "percentage": 100,
            },
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_seconds=12.5,
            total_subdomains=5,
            total_services=3,
            total_cves=2,
            overall_risk="high",
        )
        sess.add(scan)
        await sess.commit()
        scan_id = scan.id

    response = await client.get(f"/api/v1/scans/{scan_id}")

    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == str(scan_id)
    assert data["target"] == "detail-test.com"
    assert data["status"] == "completed"
    assert data["overall_risk"] == "high"
    assert data["duration_seconds"] == 12.5
    assert "progress" in data
    assert data["progress"]["percentage"] == 100
    assert "stats" in data
    assert data["stats"]["subdomains_found"] == 5
    assert data["stats"]["services_found"] == 3
    assert data["stats"]["cves_found"] == 2
