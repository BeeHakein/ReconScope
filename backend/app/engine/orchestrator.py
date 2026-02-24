"""
Scan Orchestrator for ReconScope.

Coordinates the full lifecycle of a reconnaissance scan:

1. Load the scan from the database and mark it as RUNNING.
2. Resolve the module execution order from the registry.
3. Execute modules phase-by-phase (modules within a phase run in
   parallel via :func:`asyncio.gather`).
4. After all recon modules complete, run the post-processing pipeline:
   correlation analysis, risk scoring, and attack-path inference.
5. Persist every discovered asset, finding, and insight to the database.
6. Update aggregated scan statistics and mark the scan as COMPLETED.
7. Publish real-time WebSocket events via Redis Pub/Sub so the frontend
   can display live progress.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.logging import get_logger
from app.engine.attack_paths import AttackPathEngine, InferredAttackPath
from app.engine.correlation import CorrelationEngine, CorrelationInsight
from app.engine.risk_scoring import RiskScorer
from app.models.attack_path import AttackPath
from app.models.correlation import Correlation
from app.models.cve import CVEMatch
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.subdomain import Subdomain
from app.models.technology import Technology
from app.modules.base import ModuleResult
from app.modules.registry import ModuleRegistry

logger = get_logger(__name__)


class ScanOrchestrator:
    """Orchestrates a complete scan lifecycle.

    The orchestrator is instantiated per scan and driven by
    :meth:`run_scan`.  It uses async I/O throughout so that modules can
    issue concurrent HTTP requests while the database session remains on
    a single event-loop thread.

    Usage::

        orchestrator = ScanOrchestrator()
        await orchestrator.run_scan(scan_id="...", db_session=session)
    """

    def __init__(self) -> None:
        """Initialise internal components used across a scan run."""
        self._correlation_engine = CorrelationEngine()
        self._risk_scorer = RiskScorer()
        self._attack_path_engine = AttackPathEngine()

    # -- Public entry point ---------------------------------------------------

    async def run_scan(self, scan_id: str, db_session: AsyncSession) -> None:
        """Execute the full scan pipeline for *scan_id*.

        This is the main method called by the Celery task.  It manages
        the scan status transitions, module execution, post-processing,
        result persistence, and WebSocket event publishing.

        Args:
            scan_id: The UUID of the :class:`~app.models.scan.Scan` row.
            db_session: An active :class:`AsyncSession` for database I/O.

        Raises:
            Exception: Any unhandled error is propagated after the scan
                status has been set to ``FAILED`` and the failure event
                has been published.
        """
        scan: Scan | None = await db_session.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            logger.error(
                "Scan not found",
                extra={"action": "scan_not_found", "target": scan_id},
            )
            return

        target_domain: str = scan.target.domain

        logger.info(
            "Starting scan",
            extra={"action": "scan_start", "target": target_domain},
        )

        # ── Mark as RUNNING ────────────────────────────────────────────
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = {"current_module": None, "modules_completed": [], "modules_pending": [], "percentage": 0}
        await db_session.commit()
        await self._publish_event(scan_id, "scan_started", {"target": target_domain})

        # ── Resolve execution order ────────────────────────────────────
        selected_modules: list[str] | None = (scan.config or {}).get("modules")
        phases: list[list[Any]] = ModuleRegistry.get_execution_order(selected_modules)

        total_modules: int = sum(len(phase) for phase in phases)
        modules_completed: list[str] = []
        context: dict[str, Any] = {}

        # ── Execute phases sequentially ────────────────────────────────
        for phase in phases:
            module_names_in_phase: list[str] = [m.name for m in phase]

            # Update progress with pending modules.
            remaining: list[str] = [
                m.name
                for p in phases
                for m in p
                if m.name not in modules_completed and m.name not in module_names_in_phase
            ]
            scan.progress = {
                "current_module": ", ".join(module_names_in_phase),
                "modules_completed": list(modules_completed),
                "modules_pending": remaining,
                "percentage": int((len(modules_completed) / max(total_modules, 1)) * 100),
            }
            await db_session.commit()

            # Publish module_started events.
            for module in phase:
                await self._publish_event(
                    scan_id,
                    "module_started",
                    {"module": module.name},
                )

            # Run all modules in this phase concurrently.
            results: list[ModuleResult] = await asyncio.gather(
                *(module.execute(target_domain, context) for module in phase),
                return_exceptions=False,
            )

            # Merge results into the shared context.
            for module, result in zip(phase, results):
                logger.info(
                    "Module completed: %s (success=%s, duration=%.2fs)",
                    module.name,
                    result.success,
                    result.duration_seconds,
                    extra={"action": "module_completed", "target": target_domain},
                )

                # Merge list-valued outputs (subdomains, technologies, cves).
                for key, value in result.data.items():
                    if isinstance(value, list):
                        context.setdefault(key, []).extend(value)
                    elif isinstance(value, dict):
                        context.setdefault(key, {}).update(value)
                    else:
                        context[key] = value

                modules_completed.append(module.name)

                await self._publish_event(
                    scan_id,
                    "module_completed",
                    {
                        "module": module.name,
                        "success": result.success,
                        "duration": result.duration_seconds,
                        "summary": {
                            k: len(v) if isinstance(v, list) else "..."
                            for k, v in result.data.items()
                        },
                    },
                )

        # ── Post-processing ────────────────────────────────────────────
        scan.status = ScanStatus.POST_PROCESSING
        scan.progress = {
            "current_module": "post_processing",
            "modules_completed": modules_completed,
            "modules_pending": [],
            "percentage": 90,
        }
        await db_session.commit()
        await self._publish_event(scan_id, "post_processing_started", {})

        # Build the enriched scan_data dict expected by the engines.
        scan_data: dict[str, Any] = self._build_scan_data(context)

        # Correlation Engine.
        correlation_insights: list[CorrelationInsight] = (
            self._correlation_engine.analyze(scan_data)
        )
        logger.info(
            "Correlation engine produced %d insights",
            len(correlation_insights),
            extra={"action": "correlation_done", "target": target_domain},
        )

        # Attack Path Inference.
        attack_paths: list[InferredAttackPath] = (
            self._attack_path_engine.infer(scan_data)
        )
        logger.info(
            "Attack path engine produced %d paths",
            len(attack_paths),
            extra={"action": "attack_paths_done", "target": target_domain},
        )

        # ── Persist results ────────────────────────────────────────────
        subdomain_map: dict[str, Subdomain] = await self._save_subdomains(
            db_session, scan, context
        )
        service_index: dict[tuple[str, int], Service] = await self._save_technologies(
            db_session, subdomain_map, context
        )
        await self._save_cves(db_session, subdomain_map, service_index, context)

        findings_records: list[Finding] = await self._generate_findings(
            db_session, scan, context, correlation_insights
        )

        # Persist attack paths.
        for path in attack_paths:
            db_path = AttackPath(
                scan_id=scan.id,
                severity=path.severity,
                title=path.title,
                steps=[
                    {
                        "description": step.description,
                        "node_id": step.node_id,
                        "technique": step.technique,
                    }
                    for step in path.steps
                ],
                affected_nodes=path.affected_nodes,
            )
            db_session.add(db_path)

        # Persist correlations.
        for insight in correlation_insights:
            db_correlation = Correlation(
                scan_id=scan.id,
                correlation_type=insight.type,
                severity=insight.severity,
                message=insight.message,
                affected_assets=insight.affected_assets,
            )
            db_session.add(db_correlation)

        # ── Update scan statistics ─────────────────────────────────────
        scan.total_subdomains = len(subdomain_map)
        scan.total_services = len(service_index)
        scan.total_cves = len(context.get("cves", []))

        # Determine overall risk from finding scores.
        if findings_records:
            max_score: float = max(f.risk_score or 0.0 for f in findings_records)
            scan.overall_risk = self._risk_scorer.score_to_severity(max_score)
        else:
            scan.overall_risk = "info"

        # ── Mark as COMPLETED ──────────────────────────────────────────
        now = datetime.now(timezone.utc)
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = now
        scan.duration_seconds = (
            (now - scan.started_at).total_seconds() if scan.started_at else 0.0
        )
        scan.progress = {
            "current_module": None,
            "modules_completed": modules_completed,
            "modules_pending": [],
            "percentage": 100,
        }
        await db_session.commit()

        logger.info(
            "Scan completed in %.1fs",
            scan.duration_seconds,
            extra={"action": "scan_completed", "target": target_domain},
        )

        await self._publish_event(
            scan_id,
            "scan_completed",
            {
                "total_subdomains": scan.total_subdomains,
                "total_services": scan.total_services,
                "total_cves": scan.total_cves,
                "overall_risk": scan.overall_risk,
                "duration_seconds": scan.duration_seconds,
                "findings_count": len(findings_records),
                "attack_paths_count": len(attack_paths),
                "correlations_count": len(correlation_insights),
            },
        )

    # -- Redis Pub/Sub --------------------------------------------------------

    @staticmethod
    async def _publish_event(
        scan_id: str,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Publish a WebSocket-ready event to the Redis Pub/Sub channel.

        The WebSocket handler subscribes to ``scan:{scan_id}`` and
        forwards every message to the connected frontend client.

        Args:
            scan_id: The scan UUID (used as the channel suffix).
            event_type: Event name (``module_started``, ``scan_completed``,
                etc.).
            data: Arbitrary JSON-serialisable payload.
        """
        settings = get_settings()
        channel: str = f"scan:{scan_id}"
        message: str = json.dumps(
            {
                "event": event_type,
                "module": data.get("module"),
                "data": data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            default=str,
        )

        try:
            redis_client = aioredis.from_url(settings.REDIS_URL)
            async with redis_client:
                await redis_client.publish(channel, message)
        except Exception as exc:
            logger.warning(
                "Failed to publish Redis event: %s",
                exc,
                extra={"action": "redis_publish_error", "target": scan_id},
            )

    # -- Persistence helpers --------------------------------------------------

    @staticmethod
    async def _save_subdomains(
        db_session: AsyncSession,
        scan: Scan,
        context: dict[str, Any],
    ) -> dict[str, Subdomain]:
        """Create :class:`Subdomain` rows from context data.

        Deduplicates by subdomain name within the same scan.

        Args:
            db_session: Active database session.
            scan: The parent :class:`Scan` ORM instance.
            context: Module output context.

        Returns:
            A mapping of subdomain name to persisted :class:`Subdomain`.
        """
        subdomain_map: dict[str, Subdomain] = {}

        resolved_ips: dict[str, str] = context.get("resolved_ips", {})
        dns_records: dict[str, dict[str, Any]] = context.get("records", {})

        for sub_dict in context.get("subdomains", []):
            name: str = sub_dict["name"]
            if name in subdomain_map:
                continue

            ip_addr: str | None = resolved_ips.get(name) or sub_dict.get("ip_address")

            subdomain = Subdomain(
                scan_id=scan.id,
                name=name,
                ip_address=ip_addr,
                source=sub_dict.get("source"),
                is_alive=ip_addr is not None,
                dns_records=dns_records.get(name, {}),
            )
            db_session.add(subdomain)
            subdomain_map[name] = subdomain

        await db_session.flush()
        return subdomain_map

    @staticmethod
    async def _save_technologies(
        db_session: AsyncSession,
        subdomain_map: dict[str, Subdomain],
        context: dict[str, Any],
    ) -> dict[tuple[str, int], Service]:
        """Create :class:`Service` and :class:`Technology` rows.

        Technologies are grouped by domain.  For each domain a default
        HTTPS (port 443) :class:`Service` is created if no explicit
        service record exists yet.

        Args:
            db_session: Active database session.
            subdomain_map: Previously persisted subdomains.
            context: Module output context.

        Returns:
            A mapping of ``(subdomain_name, port)`` to persisted :class:`Service`.
        """
        # Index: (subdomain_name, port) -> Service
        service_index: dict[tuple[str, int], Service] = {}

        for tech_dict in context.get("technologies", []):
            domain_name: str = tech_dict.get("domain", "")
            subdomain: Subdomain | None = subdomain_map.get(domain_name)
            if subdomain is None:
                continue

            port: int = tech_dict.get("port", 443)
            svc_key = (domain_name, port)

            if svc_key not in service_index:
                service = Service(
                    subdomain_id=subdomain.id,
                    port=port,
                    protocol="tcp",
                    service_name=tech_dict.get("name"),
                    version=tech_dict.get("version"),
                )
                db_session.add(service)
                await db_session.flush()
                service_index[svc_key] = service

            target_service: Service = service_index[svc_key]

            technology = Technology(
                service_id=target_service.id,
                name=tech_dict["name"],
                version=tech_dict.get("version"),
                category=tech_dict.get("category"),
                confidence=tech_dict.get("confidence", 50),
            )
            db_session.add(technology)

        await db_session.flush()
        return service_index

    @staticmethod
    async def _save_cves(
        db_session: AsyncSession,
        subdomain_map: dict[str, Subdomain],
        service_index: dict[tuple[str, int], Service],
        context: dict[str, Any],
    ) -> None:
        """Create :class:`CVEMatch` rows.

        Each CVE from the context is linked to the :class:`Service` on
        the affected subdomain.  If no matching service exists, a default
        service entry is created.

        Args:
            db_session: Active database session.
            subdomain_map: Previously persisted subdomains.
            service_index: Previously persisted services keyed by ``(domain, port)``.
            context: Module output context.
        """
        for cve_dict in context.get("cves", []):
            domain_name: str = cve_dict.get("affected_domain", "")
            subdomain: Subdomain | None = subdomain_map.get(domain_name)
            if subdomain is None:
                continue

            # Find an existing service for this CVE from the index.
            target_service: Service | None = None
            for svc_key, svc in service_index.items():
                if svc_key[0] == domain_name and svc.service_name and cve_dict.get("affected_tech", "").lower() in (svc.service_name or "").lower():
                    target_service = svc
                    break

            if target_service is None:
                target_service = Service(
                    subdomain_id=subdomain.id,
                    port=443,
                    protocol="tcp",
                    service_name=cve_dict.get("affected_tech"),
                    version=cve_dict.get("affected_version"),
                )
                db_session.add(target_service)
                await db_session.flush()
                service_index[(domain_name, 443)] = target_service

            published_str: str | None = cve_dict.get("published")
            published_dt: datetime | None = None
            if published_str:
                try:
                    published_dt = datetime.fromisoformat(
                        published_str.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    published_dt = None

            cve_match = CVEMatch(
                service_id=target_service.id,
                cve_id=cve_dict["cve_id"],
                cvss_score=cve_dict.get("cvss_score"),
                cvss_vector=cve_dict.get("cvss_vector"),
                severity=cve_dict.get("severity"),
                description=cve_dict.get("description"),
                published_date=published_dt,
                epss_score=cve_dict.get("epss_score"),
                epss_percentile=cve_dict.get("epss_percentile"),
            )
            db_session.add(cve_match)

        await db_session.flush()

    async def _generate_findings(
        self,
        db_session: AsyncSession,
        scan: Scan,
        context: dict[str, Any],
        correlation_insights: list[CorrelationInsight],
    ) -> list[Finding]:
        """Generate :class:`Finding` rows from CVEs and correlations.

        Each CVE produces a finding scored by the :class:`RiskScorer`.
        Each correlation insight with severity ``high`` or ``critical``
        also produces a finding.

        Args:
            db_session: Active database session.
            scan: The parent :class:`Scan` ORM instance.
            context: Module output context.
            correlation_insights: Results from the correlation engine.

        Returns:
            A list of persisted :class:`Finding` instances.
        """
        findings: list[Finding] = []

        # Findings from CVEs.
        for cve_dict in context.get("cves", []):
            finding_input: dict[str, Any] = {
                "cvss_score": cve_dict.get("cvss_score"),
                "internet_facing": True,
                "asset": cve_dict.get("affected_domain", ""),
                "has_public_exploit": False,
                "service_type": cve_dict.get("affected_tech", ""),
            }
            risk_score: float = self._risk_scorer.calculate_score(finding_input)
            severity: str = self._risk_scorer.score_to_severity(risk_score)

            finding = Finding(
                scan_id=scan.id,
                severity=severity,
                title=f"{cve_dict['cve_id']} - {cve_dict.get('affected_tech', 'Unknown')} {cve_dict.get('affected_version', '')}",
                description=cve_dict.get("description", ""),
                asset=cve_dict.get("affected_domain", ""),
                risk_score=risk_score,
                cvss_score=cve_dict.get("cvss_score"),
                evidence={
                    "cve_id": cve_dict.get("cve_id"),
                    "cvss_vector": cve_dict.get("cvss_vector"),
                    "affected_version": cve_dict.get("affected_version"),
                },
            )
            db_session.add(finding)
            findings.append(finding)

        # Findings from correlation insights (high/critical only).
        for insight in correlation_insights:
            if insight.severity not in ("high", "critical"):
                continue

            finding_input = {
                "cvss_score": 0.0,
                "internet_facing": True,
                "asset": insight.affected_assets[0] if insight.affected_assets else "",
                "has_public_exploit": False,
                "service_type": insight.type,
            }
            risk_score = self._risk_scorer.calculate_score(finding_input)
            severity = self._risk_scorer.score_to_severity(risk_score)

            # Bump severity for critical correlation insights.
            if insight.severity == "critical" and severity not in ("critical",):
                severity = "high"
                risk_score = max(risk_score, 60.0)

            finding = Finding(
                scan_id=scan.id,
                severity=severity,
                title=f"Correlation: {insight.type.replace('_', ' ').title()}",
                description=insight.message,
                asset=", ".join(insight.affected_assets[:5]),
                risk_score=risk_score,
                cvss_score=None,
                evidence={
                    "correlation_type": insight.type,
                    "affected_assets": insight.affected_assets,
                },
            )
            db_session.add(finding)
            findings.append(finding)

        # Findings from discovered paths (active dirbuster module).
        _SENSITIVE_PATHS = {
            "/.git/HEAD", "/.git/config", "/.env", "/.env.local",
            "/.env.production", "/.env.backup", "/backup", "/backups",
            "/backup.zip", "/backup.tar.gz", "/dump.sql", "/data.sql",
            "/db", "/database", "/wp-config.php.bak",
            "/.htpasswd", "/.aws/credentials", "/.ssh/id_rsa",
            "/id_rsa", "/server-status", "/server-info",
            "/actuator/env", "/actuator/configprops",
            "/elmah.axd", "/trace.axd", "/phpinfo.php",
            "/secret", "/secrets", "/private",
        }
        for path_dict in context.get("discovered_paths", []):
            path = path_dict.get("path", "")
            status_code = path_dict.get("status_code", 0)
            domain = path_dict.get("domain", "")

            if path in _SENSITIVE_PATHS and status_code == 200:
                sev = "critical"
                score = 90.0
            elif path in _SENSITIVE_PATHS:
                sev = "high"
                score = 70.0
            elif status_code == 200:
                sev = "medium"
                score = 45.0
            else:
                continue

            finding = Finding(
                scan_id=scan.id,
                severity=sev,
                title=f"Exposed path: {path} ({status_code})",
                description=(
                    f"The path {path} on {domain} returned HTTP {status_code}. "
                    f"This may expose sensitive information or functionality."
                ),
                asset=domain,
                risk_score=score,
                cvss_score=None,
                evidence={
                    "path": path,
                    "status_code": status_code,
                    "content_length": path_dict.get("content_length"),
                    "source": "dirbuster",
                },
            )
            db_session.add(finding)
            findings.append(finding)

        # Findings from SSL audit (active sslaudit module).
        _SSL_SEVERITY_MAP = {
            "certificate_expired": ("critical", 95.0),
            "weak_protocol": ("high", 75.0),
            "certificate_validation_failed": ("high", 70.0),
            "hostname_mismatch": ("high", 70.0),
            "no_certificate": ("high", 70.0),
            "certificate_expiring_soon": ("medium", 50.0),
        }
        for ssl_dict in context.get("ssl_findings", []):
            issue = ssl_dict.get("issue", "")
            sev, score = _SSL_SEVERITY_MAP.get(issue, ("medium", 50.0))
            domain = ssl_dict.get("domain", "")

            finding = Finding(
                scan_id=scan.id,
                severity=sev,
                title=f"SSL/TLS: {issue.replace('_', ' ').title()}",
                description=ssl_dict.get("details", ""),
                asset=domain,
                risk_score=score,
                cvss_score=None,
                evidence={
                    "issue": issue,
                    "cert_expiry": ssl_dict.get("cert_expiry"),
                    "cert_issuer": ssl_dict.get("cert_issuer"),
                    "source": "sslaudit",
                },
            )
            db_session.add(finding)
            findings.append(finding)

        # Findings from header audit (active headeraudit module).
        _CRITICAL_HEADERS = {
            "Strict-Transport-Security",
            "Content-Security-Policy",
        }
        for hdr_dict in context.get("header_findings", []):
            header = hdr_dict.get("header", "")
            status = hdr_dict.get("status", "missing")
            domain = hdr_dict.get("domain", "")

            if header in _CRITICAL_HEADERS:
                sev = "medium"
                score = 45.0
            else:
                sev = "low"
                score = 25.0

            finding = Finding(
                scan_id=scan.id,
                severity=sev,
                title=f"Security header {status}: {header}",
                description=hdr_dict.get("recommendation", ""),
                asset=domain,
                risk_score=score,
                cvss_score=None,
                evidence={
                    "header": header,
                    "status": status,
                    "source": "headeraudit",
                },
            )
            db_session.add(finding)
            findings.append(finding)

        await db_session.flush()
        return findings

    # -- Data transformation --------------------------------------------------

    @staticmethod
    def _build_scan_data(context: dict[str, Any]) -> dict[str, Any]:
        """Reshape the module context into the structure expected by engines.

        The correlation and attack-path engines expect a nested dict::

            {
                "subdomains": [
                    {
                        "name": "...",
                        "ip_address": "...",
                        "dns_records": {...},
                        "services": [
                            {
                                "port": 443,
                                "service_name": "...",
                                "version": "...",
                                "technologies": [...],
                                "cves": [...]
                            }
                        ]
                    }
                ]
            }

        Args:
            context: Flat module output context.

        Returns:
            A nested dictionary suitable for engine consumption.
        """
        resolved_ips: dict[str, str] = context.get("resolved_ips", {})
        dns_records_map: dict[str, Any] = context.get("records", {})

        # Index technologies and CVEs by domain.
        techs_by_domain: dict[str, list[dict[str, Any]]] = {}
        for tech in context.get("technologies", []):
            domain = tech.get("domain", "")
            techs_by_domain.setdefault(domain, []).append(tech)

        cves_by_domain: dict[str, list[dict[str, Any]]] = {}
        for cve in context.get("cves", []):
            domain = cve.get("affected_domain", "")
            cves_by_domain.setdefault(domain, []).append(cve)

        enriched_subdomains: list[dict[str, Any]] = []
        seen_names: set[str] = set()

        for sub_dict in context.get("subdomains", []):
            name: str = sub_dict["name"]
            if name in seen_names:
                continue
            seen_names.add(name)

            domain_techs: list[dict[str, Any]] = techs_by_domain.get(name, [])
            domain_cves: list[dict[str, Any]] = cves_by_domain.get(name, [])

            # Group technologies into pseudo-services by port.
            service_map: dict[int, dict[str, Any]] = {}
            for tech in domain_techs:
                port: int = tech.get("port", 443)
                if port not in service_map:
                    service_map[port] = {
                        "port": port,
                        "service_name": tech.get("name"),
                        "version": tech.get("version"),
                        "technologies": [],
                        "cves": [],
                    }
                service_map[port]["technologies"].append(tech)

            # Assign CVEs to services by matching tech name.
            for cve in domain_cves:
                assigned = False
                for svc in service_map.values():
                    for tech in svc["technologies"]:
                        if tech.get("name", "").lower() == cve.get("affected_tech", "").lower():
                            svc["cves"].append(cve)
                            assigned = True
                            break
                    if assigned:
                        break
                if not assigned:
                    # Create a default service for unmatched CVEs.
                    default_port = 443
                    if default_port not in service_map:
                        service_map[default_port] = {
                            "port": default_port,
                            "service_name": cve.get("affected_tech"),
                            "version": cve.get("affected_version"),
                            "technologies": [],
                            "cves": [],
                        }
                    service_map[default_port]["cves"].append(cve)

            enriched_subdomains.append(
                {
                    "name": name,
                    "ip_address": resolved_ips.get(name) or sub_dict.get("ip_address"),
                    "is_alive": resolved_ips.get(name) is not None or sub_dict.get("is_alive", False),
                    "source": sub_dict.get("source"),
                    "dns_records": dns_records_map.get(name, {}),
                    "services": list(service_map.values()),
                }
            )

        scan_data: dict[str, Any] = {"subdomains": enriched_subdomains}

        # Pass through active module context for correlation/attack-path engines.
        if "discovered_paths" in context:
            scan_data["discovered_paths"] = context["discovered_paths"]
        if "ssl_findings" in context:
            scan_data["ssl_findings"] = context["ssl_findings"]
        if "header_findings" in context:
            scan_data["header_findings"] = context["header_findings"]

        return scan_data
