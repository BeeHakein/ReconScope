"""
Scan CRUD and result query endpoints.

Provides the full lifecycle for reconnaissance scans: creation, listing,
detail retrieval, deletion, and granular result queries (subdomains, services,
technologies, CVEs, findings, attack paths, correlations, graph data, and
delta comparison between two scans).
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db_session, validate_scan_exists
from app.api.schemas.finding import (
    AttackPathResponse,
    AttackPathStepSchema,
    CorrelationResponse,
    FindingResponse,
)
from app.api.schemas.graph import GraphData, GraphEdge, GraphNode
from app.api.schemas.scan import (
    CVEResponse,
    DeltaResponse,
    ScanCreate,
    ScanDetail,
    ScanListItem,
    ScanProgress,
    ScanResponse,
    ScanStats,
    ServiceResponse,
    SubdomainResponse,
    TechnologyResponse,
)
from app.models.scan import Scan, ScanStatus, Target
from app.models.subdomain import Subdomain
from app.models.service import Service
from app.models.technology import Technology
from app.models.cve import CVEMatch
from app.models.finding import Finding
from app.models.attack_path import AttackPath
from app.models.correlation import Correlation

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_progress(scan: Scan) -> ScanProgress:
    """Construct a :class:`ScanProgress` from the scan's JSON progress blob.

    The ``progress`` column stores a dict with keys ``current_module``,
    ``modules_completed``, ``modules_pending``, and ``percentage``.  If the
    column is empty or the scan is in a terminal state sensible defaults are
    returned.

    Args:
        scan: The ORM scan instance.

    Returns:
        A fully populated :class:`ScanProgress`.
    """
    raw: dict[str, Any] = scan.progress or {}
    modules: list[str] = (scan.config or {}).get("modules", [])
    completed: list[str] = raw.get("modules_completed", [])
    pending: list[str] = raw.get(
        "modules_pending",
        [m for m in modules if m not in completed],
    )

    if scan.status == ScanStatus.COMPLETED:
        percentage = 100
        current_module = None
        pending = []
        completed = modules
    elif scan.status == ScanStatus.FAILED:
        percentage = raw.get("percentage", 0)
        current_module = None
    else:
        percentage = raw.get("percentage", 0)
        current_module = raw.get("current_module")

    return ScanProgress(
        current_module=current_module,
        modules_completed=completed,
        modules_pending=pending,
        percentage=percentage,
    )


def _build_stats(scan: Scan) -> ScanStats:
    """Construct a :class:`ScanStats` from the scan's aggregate columns.

    Args:
        scan: The ORM scan instance.

    Returns:
        A fully populated :class:`ScanStats`.
    """
    return ScanStats(
        subdomains_found=scan.total_subdomains,
        services_found=scan.total_services,
        cves_found=scan.total_cves,
    )


def _risk_level_for_score(score: float) -> str:
    """Map a numeric risk score (0--100) to a qualitative level string.

    Args:
        score: Numeric risk score.

    Returns:
        One of ``critical``, ``high``, ``medium``, ``low``, or ``info``.
    """
    if score >= 80.0:
        return "critical"
    if score >= 60.0:
        return "high"
    if score >= 40.0:
        return "medium"
    if score >= 20.0:
        return "low"
    return "info"


async def _load_scan_with_full_tree(
    scan_id: UUID,
    db: AsyncSession,
) -> Scan:
    """Load a scan with all nested relationships eagerly loaded.

    Loads subdomains -> services -> technologies and cves, plus findings,
    attack_paths, and correlations.

    Args:
        scan_id: The primary key of the scan.
        db: The active database session.

    Returns:
        The fully-loaded :class:`Scan`.

    Raises:
        HTTPException: *404 Not Found* when no matching scan exists.
    """
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.subdomains).selectinload(
                Subdomain.services
            ).selectinload(Service.technologies),
            selectinload(Scan.subdomains).selectinload(
                Subdomain.services
            ).selectinload(Service.cves),
            selectinload(Scan.findings),
            selectinload(Scan.attack_paths),
            selectinload(Scan.correlations),
        )
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with id '{scan_id}' not found.",
        )
    return scan


# ---------------------------------------------------------------------------
# POST /scans/
# ---------------------------------------------------------------------------


@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start a new reconnaissance scan",
)
async def create_scan(
    body: ScanCreate,
    db: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    """Create a new scan for the given domain.

    The caller **must** set ``scope_confirmed`` to ``true`` to acknowledge
    that they are authorised to scan the target domain.  A request with
    ``scope_confirmed=false`` is rejected with *403 Forbidden*.

    If the target domain has not been scanned before a new
    :class:`~app.models.scan.Target` record is created automatically.

    After persisting the scan a Celery task is dispatched to start the
    reconnaissance pipeline asynchronously.

    Args:
        body: The validated scan creation payload.
        db: The database session (injected).

    Returns:
        A :class:`ScanResponse` with the new scan's metadata.

    Raises:
        HTTPException: *403 Forbidden* when ``scope_confirmed`` is ``false``.
    """
    if not body.scope_confirmed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Scope confirmation required. You must confirm that you are "
                "authorised to scan the target domain."
            ),
        )

    # Upsert target --------------------------------------------------------
    stmt = select(Target).where(Target.domain == body.target)
    result = await db.execute(stmt)
    target = result.scalar_one_or_none()

    if target is None:
        target = Target(domain=body.target)
        db.add(target)
        await db.flush()

    # Create scan ----------------------------------------------------------
    scan = Scan(
        target_id=target.id,
        status=ScanStatus.QUEUED,
        config={"modules": body.modules, "scan_mode": body.scan_mode},
        progress={
            "current_module": None,
            "modules_completed": [],
            "modules_pending": body.modules,
            "percentage": 0,
        },
    )
    db.add(scan)
    await db.flush()

    # Trigger async pipeline -----------------------------------------------
    from app.tasks.scan_tasks import run_scan  # noqa: WPS433 (local import)

    run_scan.delay(str(scan.id))

    logger.info(
        "Scan %s created for target %s with modules %s",
        scan.id,
        body.target,
        body.modules,
    )

    return ScanResponse(
        scan_id=scan.id,
        target=target.domain,
        status=scan.status.value,
        created_at=scan.created_at,
        modules=body.modules,
    )


# ---------------------------------------------------------------------------
# GET /scans/
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=list[ScanListItem],
    summary="List all scans",
)
async def list_scans(
    skip: int = Query(0, ge=0, description="Number of records to skip."),
    limit: int = Query(50, ge=1, le=200, description="Max records to return."),
    db: AsyncSession = Depends(get_db_session),
) -> list[ScanListItem]:
    """Return a paginated list of scans ordered by creation date descending.

    Args:
        skip: Offset for pagination.
        limit: Maximum number of scans to return (1--200).
        db: The database session (injected).

    Returns:
        A list of :class:`ScanListItem` instances.
    """
    stmt = (
        select(Scan)
        .options(selectinload(Scan.target))
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(stmt)
    scans = result.scalars().all()

    return [
        ScanListItem(
            scan_id=s.id,
            target=s.target.domain,
            status=s.status.value,
            created_at=s.created_at,
            total_subdomains=s.total_subdomains,
            total_services=s.total_services,
            total_cves=s.total_cves,
            overall_risk=s.overall_risk,
            duration_seconds=s.duration_seconds,
        )
        for s in scans
    ]


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}",
    response_model=ScanDetail,
    summary="Get scan details with progress and stats",
)
async def get_scan(
    scan: Scan = Depends(validate_scan_exists),
) -> ScanDetail:
    """Return detailed information about a single scan including real-time
    progress and aggregate statistics.

    Args:
        scan: The validated scan instance (injected via dependency).

    Returns:
        A :class:`ScanDetail` instance.
    """
    return ScanDetail(
        scan_id=scan.id,
        target=scan.target.domain,
        status=scan.status.value,
        progress=_build_progress(scan),
        stats=_build_stats(scan),
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        duration_seconds=scan.duration_seconds,
        overall_risk=scan.overall_risk,
    )


# ---------------------------------------------------------------------------
# DELETE /scans/{scan_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan and all associated data",
)
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Permanently delete a scan together with all child records.

    The ORM cascade configuration ensures that subdomains, services,
    technologies, CVEs, findings, attack paths, and correlations are
    removed as well.

    Args:
        scan_id: The UUID of the scan to delete.
        db: The database session (injected).

    Raises:
        HTTPException: *404 Not Found* when no matching scan exists.
    """
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with id '{scan_id}' not found.",
        )

    await db.delete(scan)
    logger.info("Scan %s deleted.", scan_id)


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/results
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/results",
    summary="Get full scan results",
)
async def get_scan_results(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Return the complete result set for a scan.

    Includes subdomains, services, technologies, CVEs, and findings in a
    single response payload.  This endpoint eagerly loads the entire object
    tree in one round-trip.

    Args:
        scan_id: The UUID of the scan.
        db: The database session (injected).

    Returns:
        A dictionary with keys ``subdomains``, ``services``,
        ``technologies``, ``cves``, and ``findings``.
    """
    scan = await _load_scan_with_full_tree(scan_id, db)

    subdomains: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []
    cves: list[dict[str, Any]] = []

    for sub in scan.subdomains:
        subdomains.append(
            SubdomainResponse.model_validate(sub).model_dump()
        )
        for svc in sub.services:
            services.append(
                ServiceResponse.model_validate(svc).model_dump()
            )
            for tech in svc.technologies:
                technologies.append(
                    TechnologyResponse.model_validate(tech).model_dump()
                )
            for cve in svc.cves:
                cve_resp = CVEResponse(
                    id=cve.id,
                    cve_id=cve.cve_id,
                    cvss_score=cve.cvss_score,
                    severity=cve.severity,
                    description=cve.description,
                    affected_domain=sub.name,
                )
                cves.append(cve_resp.model_dump())

    findings = [
        FindingResponse.model_validate(f).model_dump()
        for f in scan.findings
    ]

    return {
        "subdomains": subdomains,
        "services": services,
        "technologies": technologies,
        "cves": cves,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/subdomains
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/subdomains",
    response_model=list[SubdomainResponse],
    summary="List subdomains for a scan",
)
async def list_subdomains(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[SubdomainResponse]:
    """Return all subdomains discovered during the given scan.

    Args:
        scan_id: The UUID of the parent scan.
        db: The database session (injected).

    Returns:
        A list of :class:`SubdomainResponse` instances.
    """
    await _ensure_scan_exists(scan_id, db)
    stmt = (
        select(Subdomain)
        .where(Subdomain.scan_id == scan_id)
        .order_by(Subdomain.name)
    )
    result = await db.execute(stmt)
    return [
        SubdomainResponse.model_validate(s)
        for s in result.scalars().all()
    ]


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/services
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/services",
    response_model=list[ServiceResponse],
    summary="List services for a scan",
)
async def list_services(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[ServiceResponse]:
    """Return all services detected across every subdomain in the scan.

    Args:
        scan_id: The UUID of the parent scan.
        db: The database session (injected).

    Returns:
        A list of :class:`ServiceResponse` instances.
    """
    await _ensure_scan_exists(scan_id, db)
    stmt = (
        select(Service)
        .join(Subdomain, Service.subdomain_id == Subdomain.id)
        .where(Subdomain.scan_id == scan_id)
        .order_by(Service.port)
    )
    result = await db.execute(stmt)
    return [
        ServiceResponse.model_validate(s)
        for s in result.scalars().all()
    ]


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/technologies
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/technologies",
    response_model=list[TechnologyResponse],
    summary="List technologies for a scan",
)
async def list_technologies(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[TechnologyResponse]:
    """Return all technologies detected across every service in the scan.

    Args:
        scan_id: The UUID of the parent scan.
        db: The database session (injected).

    Returns:
        A list of :class:`TechnologyResponse` instances.
    """
    await _ensure_scan_exists(scan_id, db)
    stmt = (
        select(Technology)
        .join(Service, Technology.service_id == Service.id)
        .join(Subdomain, Service.subdomain_id == Subdomain.id)
        .where(Subdomain.scan_id == scan_id)
        .order_by(Technology.name)
    )
    result = await db.execute(stmt)
    return [
        TechnologyResponse.model_validate(t)
        for t in result.scalars().all()
    ]


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/cves
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/cves",
    response_model=list[CVEResponse],
    summary="List CVEs for a scan",
)
async def list_cves(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[CVEResponse]:
    """Return all CVE matches found across every service in the scan.

    Each CVE response is enriched with the ``affected_domain`` derived
    from the parent subdomain.

    Args:
        scan_id: The UUID of the parent scan.
        db: The database session (injected).

    Returns:
        A list of :class:`CVEResponse` instances.
    """
    await _ensure_scan_exists(scan_id, db)
    stmt = (
        select(CVEMatch, Subdomain.name)
        .join(Service, CVEMatch.service_id == Service.id)
        .join(Subdomain, Service.subdomain_id == Subdomain.id)
        .where(Subdomain.scan_id == scan_id)
        .order_by(CVEMatch.cvss_score.desc().nullslast())
    )
    result = await db.execute(stmt)
    rows = result.all()

    return [
        CVEResponse(
            id=cve.id,
            cve_id=cve.cve_id,
            cvss_score=cve.cvss_score,
            severity=cve.severity,
            description=cve.description,
            affected_domain=subdomain_name,
        )
        for cve, subdomain_name in rows
    ]


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/findings
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/findings",
    response_model=list[FindingResponse],
    summary="List findings for a scan",
)
async def list_findings(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[FindingResponse]:
    """Return all prioritised findings generated by post-processing.

    Args:
        scan_id: The UUID of the parent scan.
        db: The database session (injected).

    Returns:
        A list of :class:`FindingResponse` instances sorted by risk score
        descending.
    """
    await _ensure_scan_exists(scan_id, db)
    stmt = (
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.risk_score.desc().nullslast())
    )
    result = await db.execute(stmt)
    return [
        FindingResponse.model_validate(f)
        for f in result.scalars().all()
    ]


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/attack-paths
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/attack-paths",
    response_model=list[AttackPathResponse],
    summary="List attack paths for a scan",
)
async def list_attack_paths(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[AttackPathResponse]:
    """Return all inferred attack paths for the scan.

    The ``steps`` JSON column is deserialised into a list of
    :class:`AttackPathStepSchema` instances.

    Args:
        scan_id: The UUID of the parent scan.
        db: The database session (injected).

    Returns:
        A list of :class:`AttackPathResponse` instances.
    """
    await _ensure_scan_exists(scan_id, db)
    stmt = (
        select(AttackPath)
        .where(AttackPath.scan_id == scan_id)
    )
    result = await db.execute(stmt)
    paths = result.scalars().all()

    responses: list[AttackPathResponse] = []
    for path in paths:
        steps = [
            AttackPathStepSchema(
                description=step.get("description", ""),
                node_id=step.get("node_id", ""),
                technique=step.get("technique", ""),
            )
            for step in (path.steps or [])
        ]
        responses.append(
            AttackPathResponse(
                id=path.id,
                severity=path.severity,
                title=path.title,
                steps=steps,
                affected_nodes=path.affected_nodes or [],
            )
        )

    return responses


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/correlations
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/correlations",
    response_model=list[CorrelationResponse],
    summary="List correlations for a scan",
)
async def list_correlations(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[CorrelationResponse]:
    """Return all correlation insights for the scan.

    Args:
        scan_id: The UUID of the parent scan.
        db: The database session (injected).

    Returns:
        A list of :class:`CorrelationResponse` instances.
    """
    await _ensure_scan_exists(scan_id, db)
    stmt = (
        select(Correlation)
        .where(Correlation.scan_id == scan_id)
    )
    result = await db.execute(stmt)
    return [
        CorrelationResponse.model_validate(c)
        for c in result.scalars().all()
    ]


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/graph
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/graph",
    response_model=GraphData,
    summary="Get graph data for visualisation",
)
async def get_graph_data(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> GraphData:
    """Build and return the complete node/edge graph for a scan.

    Node types:
        - ``domain`` -- the target domain itself
        - ``subdomain`` -- each discovered subdomain
        - ``service`` -- each network service
        - ``technology`` -- each detected technology stack component
        - ``cve`` -- each matched CVE

    Edge types:
        - ``resolves_to`` -- domain -> subdomain
        - ``runs_on`` -- subdomain -> service
        - ``uses_tech`` -- service -> technology
        - ``has_vuln`` -- service -> CVE

    Args:
        scan_id: The UUID of the scan.
        db: The database session (injected).

    Returns:
        A :class:`GraphData` with all nodes and edges.
    """
    scan = await _load_scan_with_full_tree(scan_id, db)

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    # -- Domain node -------------------------------------------------------
    domain_node_id = f"domain-{scan.target.domain}"
    nodes.append(
        GraphNode(
            id=domain_node_id,
            label=scan.target.domain,
            type="domain",
            risk_level=scan.overall_risk or "info",
            risk_score=0.0,
            metadata={"target_id": str(scan.target.id)},
        )
    )

    # -- Subdomain nodes ---------------------------------------------------
    for sub in scan.subdomains:
        sub_node_id = f"subdomain-{sub.id}"
        nodes.append(
            GraphNode(
                id=sub_node_id,
                label=sub.name,
                type="subdomain",
                risk_level="info",
                risk_score=0.0,
                metadata={
                    "ip": sub.ip_address or "",
                    "source": sub.source or "",
                    "is_alive": sub.is_alive,
                },
            )
        )
        edges.append(
            GraphEdge(
                source=domain_node_id,
                target=sub_node_id,
                type="resolves_to",
            )
        )

        # -- Service nodes -------------------------------------------------
        for svc in sub.services:
            svc_node_id = f"service-{svc.id}"
            nodes.append(
                GraphNode(
                    id=svc_node_id,
                    label=f"{svc.service_name or 'unknown'}:{svc.port}",
                    type="service",
                    risk_level="info",
                    risk_score=0.0,
                    metadata={
                        "port": svc.port,
                        "protocol": svc.protocol,
                        "version": svc.version or "",
                        "banner": svc.banner or "",
                    },
                )
            )
            edges.append(
                GraphEdge(
                    source=sub_node_id,
                    target=svc_node_id,
                    type="runs_on",
                )
            )

            # -- Technology nodes ------------------------------------------
            for tech in svc.technologies:
                tech_node_id = f"technology-{tech.id}"
                nodes.append(
                    GraphNode(
                        id=tech_node_id,
                        label=f"{tech.name} {tech.version or ''}".strip(),
                        type="technology",
                        risk_level="info",
                        risk_score=0.0,
                        metadata={
                            "category": tech.category or "",
                            "confidence": tech.confidence,
                        },
                    )
                )
                edges.append(
                    GraphEdge(
                        source=svc_node_id,
                        target=tech_node_id,
                        type="uses_tech",
                    )
                )

            # -- CVE nodes -------------------------------------------------
            for cve in svc.cves:
                cve_node_id = f"cve-{cve.id}"
                cve_score = cve.cvss_score or 0.0
                nodes.append(
                    GraphNode(
                        id=cve_node_id,
                        label=cve.cve_id,
                        type="cve",
                        risk_level=_risk_level_for_score(
                            cve_score * 10,
                        ),
                        risk_score=cve_score * 10,
                        metadata={
                            "cvss_score": cve_score,
                            "severity": cve.severity or "",
                            "description": (cve.description or "")[:200],
                        },
                    )
                )
                edges.append(
                    GraphEdge(
                        source=svc_node_id,
                        target=cve_node_id,
                        type="has_vuln",
                    )
                )

    return GraphData(nodes=nodes, edges=edges)


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/delta/{compare_scan_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}/delta/{compare_scan_id}",
    response_model=DeltaResponse,
    summary="Compare two scans",
)
async def get_delta(
    scan_id: UUID,
    compare_scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> DeltaResponse:
    """Compute the difference between two scans of the same target.

    The scan identified by *scan_id* is treated as the **old** (baseline)
    scan and *compare_scan_id* as the **new** scan.  The response
    highlights added, removed, and unchanged assets as well as newly
    appeared and resolved CVEs.

    Args:
        scan_id: UUID of the baseline (old) scan.
        compare_scan_id: UUID of the comparison (new) scan.
        db: The database session (injected).

    Returns:
        A :class:`DeltaResponse` with the computed differences.

    Raises:
        HTTPException: *404 Not Found* if either scan does not exist.
    """
    scan_old = await _load_scan_with_full_tree(scan_id, db)
    scan_new = await _load_scan_with_full_tree(compare_scan_id, db)

    from app.engine.delta import compute_delta  # noqa: WPS433 (local import)

    raw_delta: dict[str, Any] = compute_delta(scan_old, scan_new)

    return DeltaResponse(
        subdomains=raw_delta.get("subdomains", {}),
        services=raw_delta.get("services", {}),
        cves=raw_delta.get("cves", {}),
        risk_change=raw_delta.get("risk_change", {}),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _ensure_scan_exists(scan_id: UUID, db: AsyncSession) -> None:
    """Raise 404 if the given scan_id does not exist in the database.

    This is a lightweight check that avoids eagerly loading relationships.

    Args:
        scan_id: The UUID to verify.
        db: The active database session.

    Raises:
        HTTPException: *404 Not Found* when no scan matches.
    """
    stmt = select(Scan.id).where(Scan.id == scan_id)
    result = await db.execute(stmt)
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with id '{scan_id}' not found.",
        )
