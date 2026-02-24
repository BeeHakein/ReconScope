"""
CVE Matching module for ReconScope.

Queries the NIST National Vulnerability Database (NVD) API v2.0 for
CVEs that match the technologies and versions detected by the upstream
``techdetect`` module.  Enriches results with EPSS (Exploit Prediction
Scoring System) data from FIRST.org.

Features:
- In-memory cache with 24h TTL to avoid redundant NVD queries
- Increased results per page (50) for better coverage
- EPSS score enrichment for exploit probability
- Supports optional NVD API key for higher rate limits
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

import httpx

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory NVD response cache (shared across module invocations)
# ---------------------------------------------------------------------------
# Key: "tech_name:version" -> (timestamp, list[cve_dict])
_nvd_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_CACHE_TTL: float = 86_400.0  # 24 hours


def _cache_get(key: str) -> list[dict[str, Any]] | None:
    """Return cached CVE results if they exist and haven't expired."""
    entry = _nvd_cache.get(key)
    if entry is None:
        return None
    cached_at, data = entry
    if time.monotonic() - cached_at > _CACHE_TTL:
        del _nvd_cache[key]
        return None
    return data


def _cache_set(key: str, data: list[dict[str, Any]]) -> None:
    """Store CVE results in the cache."""
    _nvd_cache[key] = (time.monotonic(), data)


@ModuleRegistry.register
class CveMatchModule(BaseReconModule):
    """CVE matching via the NIST NVD REST API v2.0 with EPSS enrichment.

    For every technology with a known (non-``"unknown"``) version found
    in the scan context, the module performs a keyword search against the
    NVD and extracts CVE identifiers, descriptions, CVSS scores (v3.1
    preferred, with v3.0 and v2 fallbacks), and severity ratings.

    Results are enriched with EPSS data (exploit probability and
    percentile) from FIRST.org.

    Rate-limiting is automatically adjusted based on whether an API key
    is available: **0.6 s** delay per request without a key, **0.1 s**
    with a key.
    """

    name: str = "cvematch"
    description: str = "CVE Matching via NVD API with EPSS Enrichment"
    phase: ModulePhase = ModulePhase.ANALYSIS
    depends_on: list[str] = ["techdetect"]
    requires_api_key: bool = True
    api_key_env_var: str = "NVD_API_KEY"
    rate_limit: int = 5

    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Query the NVD for CVEs matching detected technologies.

        Args:
            target:  Root domain of the scan (used for logging context).
            context: Must contain ``"technologies"`` -- a list of dicts
                     with at least ``"name"``, ``"version"``, and
                     ``"domain"`` keys as produced by :class:`TechDetectModule`.

        Returns:
            A :class:`ModuleResult` whose ``data["cves"]`` list contains
            dicts with keys ``cve_id``, ``description``, ``cvss_score``,
            ``cvss_vector``, ``severity``, ``affected_tech``,
            ``affected_version``, ``affected_domain``, ``published``,
            ``epss_score``, and ``epss_percentile``.
        """
        start: float = time.monotonic()
        cves: list[dict[str, Any]] = []
        errors: list[str] = []
        api_key: str | None = os.getenv(self.api_key_env_var)

        technologies: list[dict[str, Any]] = context.get("technologies", [])

        headers: dict[str, str] = {}
        if api_key:
            headers["apiKey"] = api_key

        request_delay: float = 0.1 if api_key else 0.6

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
        ) as client:
            for tech in technologies:
                version: str = tech.get("version", "unknown")
                if version == "unknown":
                    continue

                tech_name: str = tech.get("name", "")
                domain: str = tech.get("domain", "")
                cache_key = f"{tech_name.lower()}:{version}"

                # Check cache first
                cached = _cache_get(cache_key)
                if cached is not None:
                    logger.debug("Cache hit for %s", cache_key)
                    for cve_template in cached:
                        cve_entry = {**cve_template}
                        cve_entry["affected_domain"] = domain
                        cves.append(cve_entry)
                    continue

                keyword: str = f"{tech_name} {version}"
                tech_cves: list[dict[str, Any]] = []

                try:
                    response = await client.get(
                        self.NVD_API_URL,
                        params={
                            "keywordSearch": keyword,
                            "resultsPerPage": 50,
                        },
                        headers=headers,
                    )
                    response.raise_for_status()
                    nvd_data: dict[str, Any] = response.json()

                    for vuln in nvd_data.get("vulnerabilities", []):
                        cve_data: dict[str, Any] = vuln.get("cve", {})
                        metrics: dict[str, Any] = cve_data.get("metrics", {})

                        cvss_score: float | None = None
                        cvss_vector: str | None = None
                        for metric_version in (
                            "cvssMetricV31",
                            "cvssMetricV30",
                            "cvssMetricV2",
                        ):
                            metric_list = metrics.get(metric_version)
                            if metric_list:
                                cvss_payload = metric_list[0].get(
                                    "cvssData", {}
                                )
                                cvss_score = cvss_payload.get("baseScore")
                                cvss_vector = cvss_payload.get("vectorString")
                                break

                        descriptions: list[dict[str, str]] = cve_data.get(
                            "descriptions", []
                        )
                        description_text: str = ""
                        for desc in descriptions:
                            if desc.get("lang", "en") == "en":
                                description_text = desc.get("value", "")
                                break
                        if not description_text and descriptions:
                            description_text = descriptions[0].get("value", "")

                        cve_entry = {
                            "cve_id": cve_data.get("id"),
                            "description": description_text,
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "severity": self._score_to_severity(cvss_score),
                            "affected_tech": tech_name,
                            "affected_version": version,
                            "affected_domain": domain,
                            "published": cve_data.get("published"),
                            "epss_score": None,
                            "epss_percentile": None,
                        }
                        tech_cves.append(cve_entry)
                        cves.append(cve_entry)

                    # Cache the results (without domain, as that varies)
                    cache_entries = []
                    for c in tech_cves:
                        cache_entry = {**c}
                        cache_entry.pop("affected_domain", None)
                        cache_entries.append(cache_entry)
                    _cache_set(cache_key, cache_entries)

                except httpx.TimeoutException as exc:
                    error_msg = f"NVD request timed out for {keyword}: {exc}"
                    logger.warning(error_msg)
                    errors.append(error_msg)
                except httpx.HTTPStatusError as exc:
                    error_msg = (
                        f"NVD returned HTTP {exc.response.status_code} "
                        f"for {keyword}: {exc}"
                    )
                    logger.warning(error_msg)
                    errors.append(error_msg)
                except Exception as exc:  # noqa: BLE001
                    error_msg = f"NVD query for {keyword}: {exc}"
                    logger.exception(error_msg)
                    errors.append(error_msg)

                await asyncio.sleep(request_delay)

        # -- EPSS enrichment ---------------------------------------------------
        await self._enrich_epss(cves, errors)

        # -- De-duplicate CVEs by (cve_id, domain) ----------------------------
        seen: dict[tuple[str, str], dict[str, Any]] = {}
        for cve in cves:
            key = (cve.get("cve_id", ""), cve.get("affected_domain", ""))
            if key not in seen:
                seen[key] = cve
        cves = list(seen.values())

        duration: float = time.monotonic() - start

        return ModuleResult(
            module_name=self.name,
            success=True,
            data={"cves": cves},
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )

    # ------------------------------------------------------------------
    # EPSS enrichment
    # ------------------------------------------------------------------

    async def _enrich_epss(
        self, cves: list[dict[str, Any]], errors: list[str]
    ) -> None:
        """Fetch EPSS scores for all CVEs and merge them in-place.

        Batches CVE IDs into groups of 100 (API limit) and queries the
        FIRST.org EPSS API.
        """
        if not cves:
            return

        cve_ids = list({c.get("cve_id", "") for c in cves if c.get("cve_id")})
        if not cve_ids:
            return

        # Build lookup: cve_id -> {epss, percentile}
        epss_map: dict[str, dict[str, float]] = {}
        batch_size = 100

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=5.0, pool=5.0),
        ) as client:
            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i : i + batch_size]
                try:
                    response = await client.get(
                        self.EPSS_API_URL,
                        params={"cve": ",".join(batch)},
                    )
                    response.raise_for_status()
                    epss_data = response.json()
                    for entry in epss_data.get("data", []):
                        cve_id = entry.get("cve")
                        if cve_id:
                            try:
                                epss_map[cve_id] = {
                                    "epss": float(entry.get("epss", 0)),
                                    "percentile": float(entry.get("percentile", 0)),
                                }
                            except (ValueError, TypeError):
                                pass
                except Exception as exc:  # noqa: BLE001
                    error_msg = f"EPSS enrichment failed for batch: {exc}"
                    logger.warning(error_msg)
                    errors.append(error_msg)

        # Merge into CVE entries
        for cve in cves:
            cve_id = cve.get("cve_id", "")
            epss = epss_map.get(cve_id)
            if epss:
                cve["epss_score"] = epss["epss"]
                cve["epss_percentile"] = epss["percentile"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_severity(score: float | None) -> str:
        """Convert a numeric CVSS score to a human-readable severity label.

        Thresholds follow the NVD qualitative severity rating scale:

        * **critical**: score >= 9.0
        * **high**:     score >= 7.0
        * **medium**:   score >= 4.0
        * **low**:      score <  4.0
        * **unknown**:  score is ``None``

        Args:
            score: CVSS base score (0.0 -- 10.0) or ``None``.

        Returns:
            One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
            or ``"unknown"``.
        """
        if score is None:
            return "unknown"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"
