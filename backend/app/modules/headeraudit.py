"""
HTTP Security Header Analysis module for ReconScope.

Checks alive subdomains for the presence and correctness of critical
HTTP security headers (HSTS, CSP, X-Content-Type-Options, etc.).
Uses ``httpx`` (already installed) — **zero new dependencies**.

This is an **active** module that sends HTTP requests to the target.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)

_CONCURRENCY = 15

# Security headers to check: (header_name, recommendation)
SECURITY_HEADERS: list[tuple[str, str]] = [
    (
        "Strict-Transport-Security",
        "Add HSTS header with max-age >= 31536000 and includeSubDomains",
    ),
    (
        "Content-Security-Policy",
        "Add a Content-Security-Policy header to prevent XSS and data injection",
    ),
    (
        "X-Content-Type-Options",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing",
    ),
    (
        "X-Frame-Options",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking",
    ),
    (
        "Referrer-Policy",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter",
    ),
    (
        "Permissions-Policy",
        "Add a Permissions-Policy header to restrict browser feature access",
    ),
    (
        "X-XSS-Protection",
        "Add 'X-XSS-Protection: 0' (or rely on CSP). Header is deprecated but some scanners still check it",
    ),
]


@ModuleRegistry.register
class HeaderAuditModule(BaseReconModule):
    """HTTP security header analysis.

    Probes alive subdomains over HTTPS (falling back to HTTP) and checks
    for the presence of 7 critical security response headers.
    """

    name: str = "headeraudit"
    description: str = "HTTP Security Header Analysis"
    phase: ModulePhase = ModulePhase.ENRICHMENT
    depends_on: list[str] = ["dns"]

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Check alive subdomains for missing security headers.

        Args:
            target:  Root domain (e.g. ``"acme-corp.de"``).
            context: Must contain ``"resolved_ips"`` and ``"subdomains"``.

        Returns:
            A :class:`ModuleResult` with ``data["header_findings"]``.
        """
        start: float = time.monotonic()
        header_findings: list[dict[str, Any]] = []
        errors: list[str] = []

        resolved_ips: dict[str, str] = context.get("resolved_ips", {})

        alive_domains: list[str] = []
        for sub_dict in context.get("subdomains", []):
            name = sub_dict.get("name", "")
            if name in resolved_ips:
                alive_domains.append(name)

        if not alive_domains:
            alive_domains = [target]

        semaphore = asyncio.Semaphore(_CONCURRENCY)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0),
            follow_redirects=True,
            verify=False,  # noqa: S501
        ) as client:

            async def _audit_domain(domain: str) -> None:
                async with semaphore:
                    response = await self._fetch_response(client, domain)
                    if response is None:
                        return

                    for header_name, recommendation in SECURITY_HEADERS:
                        header_value = response.headers.get(header_name)
                        if header_value is None:
                            header_findings.append({
                                "domain": domain,
                                "header": header_name,
                                "status": "missing",
                                "recommendation": recommendation,
                            })
                        else:
                            issues = self._validate_header(
                                header_name, header_value
                            )
                            if issues:
                                header_findings.append({
                                    "domain": domain,
                                    "header": header_name,
                                    "status": "misconfigured",
                                    "recommendation": issues,
                                })

            await asyncio.gather(
                *(_audit_domain(d) for d in alive_domains),
                return_exceptions=True,
            )

        duration: float = time.monotonic() - start
        logger.info(
            "Header audit produced %d findings across %d domains in %.1fs",
            len(header_findings),
            len(alive_domains),
            duration,
        )

        return ModuleResult(
            module_name=self.name,
            success=True,
            data={"header_findings": header_findings},
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )

    @staticmethod
    async def _fetch_response(
        client: httpx.AsyncClient, domain: str
    ) -> httpx.Response | None:
        """Try HTTPS then HTTP to get a response from the domain."""
        for scheme in ("https", "http"):
            try:
                return await client.get(f"{scheme}://{domain}")
            except (httpx.ConnectError, httpx.TimeoutException):
                continue
            except Exception:
                continue
        return None

    @staticmethod
    def _validate_header(header_name: str, value: str) -> str | None:
        """Check a present header for common misconfigurations.

        Returns a recommendation string if misconfigured, else ``None``.
        """
        lower_value = value.lower()

        if header_name == "Strict-Transport-Security":
            if "max-age=" in lower_value:
                try:
                    max_age_part = lower_value.split("max-age=")[1].split(";")[0].strip()
                    max_age = int(max_age_part)
                    if max_age < 31536000:
                        return (
                            f"HSTS max-age is {max_age} seconds "
                            f"(< 1 year). Increase to at least 31536000"
                        )
                except (ValueError, IndexError):
                    pass

        if header_name == "X-Content-Type-Options":
            if "nosniff" not in lower_value:
                return "X-Content-Type-Options should be set to 'nosniff'"

        if header_name == "X-Frame-Options":
            if lower_value not in ("deny", "sameorigin") and not lower_value.startswith("allow-from"):
                return f"Invalid X-Frame-Options value: '{value}'"

        return None
