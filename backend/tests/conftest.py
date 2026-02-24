"""
Shared pytest fixtures for the ReconScope test suite.

Provides an in-memory SQLite database (via aiosqlite), async session
management, a FastAPI test application with dependency overrides, and
factory fixtures for common ORM entities.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.database import Base
from app.models.scan import Target, Scan, ScanStatus
from app.models.subdomain import Subdomain
from app.models.service import Service
from app.models.technology import Technology
from app.models.cve import CVEMatch
from app.models.finding import Finding
from app.models.attack_path import AttackPath
from app.models.correlation import Correlation


# ---------------------------------------------------------------------------
# Database engine and session fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture()
async def test_engine() -> AsyncGenerator[AsyncEngine, None]:
    """Create an async in-memory SQLite engine and provision all tables.

    Yields the engine and disposes it after the test.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture()
async def db_session(test_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Yield an AsyncSession bound to the in-memory test database.

    Each test receives a fresh session; the transaction is rolled back
    after the test to keep test isolation.
    """
    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    async with session_factory() as session:
        yield session
        await session.rollback()


# ---------------------------------------------------------------------------
# FastAPI application with DB override
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture()
async def test_app(test_engine: AsyncEngine):
    """Return a FastAPI application with the DB dependency overridden.

    The override replaces the production ``get_db_session`` dependency with
    one that uses the in-memory SQLite test engine.
    """
    from fastapi import FastAPI
    from app.api.v1.router import router as v1_router
    from app.api.deps import get_db_session

    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    async def _override_get_db_session() -> AsyncGenerator[AsyncSession, None]:
        """Provide a test database session for dependency injection."""
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app = FastAPI()
    app.include_router(v1_router, prefix="/api/v1")
    app.dependency_overrides[get_db_session] = _override_get_db_session

    yield app

    app.dependency_overrides.clear()


@pytest_asyncio.fixture()
async def client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """Yield an httpx.AsyncClient wired to the test FastAPI app."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# ORM factory fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture()
async def sample_target(db_session: AsyncSession) -> Target:
    """Create and persist a sample Target with domain 'example.com'."""
    target = Target(
        id=uuid.uuid4(),
        domain="example.com",
        created_at=datetime.now(timezone.utc),
        notes="Test target",
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)
    return target


@pytest_asyncio.fixture()
async def sample_scan(db_session: AsyncSession, sample_target: Target) -> Scan:
    """Create and persist a sample Scan linked to sample_target."""
    scan = Scan(
        id=uuid.uuid4(),
        target_id=sample_target.id,
        status=ScanStatus.QUEUED,
        config={"modules": ["crtsh", "dns"]},
        progress={},
        created_at=datetime.now(timezone.utc),
        total_subdomains=0,
        total_services=0,
        total_cves=0,
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    return scan


@pytest_asyncio.fixture()
async def sample_subdomain(db_session: AsyncSession, sample_scan: Scan) -> Subdomain:
    """Create and persist a sample Subdomain linked to sample_scan."""
    subdomain = Subdomain(
        id=uuid.uuid4(),
        scan_id=sample_scan.id,
        name="www.example.com",
        ip_address="93.184.216.34",
        source="crtsh",
        is_alive=True,
        dns_records={"A": ["93.184.216.34"]},
        discovered_at=datetime.now(timezone.utc),
    )
    db_session.add(subdomain)
    await db_session.commit()
    await db_session.refresh(subdomain)
    return subdomain


# ---------------------------------------------------------------------------
# Engine test data fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_scan_data() -> dict:
    """Return a realistic scan data dictionary for engine tests.

    The structure mirrors what the scan orchestrator produces after
    running all modules and aggregating their results.
    """
    return {
        "subdomains": [
            {
                "name": "www.example.com",
                "ip_address": "185.23.45.10",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.21.0",
                        "technologies": [
                            {
                                "name": "Nginx",
                                "version": "1.21.0",
                                "category": "web_server",
                            }
                        ],
                        "cves": [],
                    }
                ],
            },
            {
                "name": "api.example.com",
                "ip_address": "185.23.45.11",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.24.0",
                        "technologies": [
                            {
                                "name": "Nginx",
                                "version": "1.24.0",
                                "category": "web_server",
                            }
                        ],
                        "cves": [],
                    }
                ],
            },
            {
                "name": "staging.example.com",
                "ip_address": "185.23.45.20",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [
                            {
                                "name": "Nginx",
                                "version": "1.18.0",
                                "category": "web_server",
                            }
                        ],
                        "cves": [
                            {
                                "cve_id": "CVE-2021-23017",
                                "cvss_score": 9.8,
                                "severity": "critical",
                                "description": "1-byte memory overwrite in resolver",
                            }
                        ],
                    },
                    {
                        "port": 3306,
                        "service_name": "mysql",
                        "version": "5.7.38",
                        "technologies": [],
                        "cves": [],
                    },
                ],
            },
            {
                "name": "mail.example.com",
                "ip_address": "185.23.45.30",
                "services": [
                    {
                        "port": 25,
                        "service_name": "postfix",
                        "version": "3.5.6",
                        "technologies": [],
                        "cves": [],
                    }
                ],
            },
        ]
    }
