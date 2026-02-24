"""
SSL/TLS Audit module for ReconScope.

Connects to alive subdomains on port 443 and inspects the TLS certificate
and protocol configuration for common misconfigurations: expired certs,
self-signed certs, weak protocols (TLS 1.0/1.1), hostname mismatches, and
near-expiry warnings.  Uses only Python's built-in ``ssl`` module — **zero
new dependencies**.

This is an **active** module that establishes TLS connections to target hosts.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)

_CONCURRENCY = 20
_CONNECT_TIMEOUT = 8.0

# Weak TLS protocol versions to flag.
_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1"}


@ModuleRegistry.register
class SSLAuditModule(BaseReconModule):
    """SSL/TLS certificate and protocol audit.

    Checks certificate validity, expiry, issuer, hostname match, and
    protocol version on port 443 for all alive subdomains.
    """

    name: str = "sslaudit"
    description: str = "SSL/TLS Certificate & Protocol Audit"
    phase: ModulePhase = ModulePhase.ENRICHMENT
    depends_on: list[str] = ["dns"]

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Audit TLS configuration of alive subdomains.

        Args:
            target:  Root domain (e.g. ``"acme-corp.de"``).
            context: Must contain ``"resolved_ips"`` and ``"subdomains"``.

        Returns:
            A :class:`ModuleResult` with ``data["ssl_findings"]``.
        """
        start: float = time.monotonic()
        ssl_findings: list[dict[str, Any]] = []
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

        async def _audit_domain(domain: str) -> None:
            async with semaphore:
                try:
                    findings = await self._check_ssl(domain)
                    ssl_findings.extend(findings)
                except Exception as exc:
                    errors.append(f"SSL audit {domain}: {exc}")

        await asyncio.gather(
            *(_audit_domain(d) for d in alive_domains),
            return_exceptions=True,
        )

        duration: float = time.monotonic() - start
        logger.info(
            "SSL audit produced %d findings across %d domains in %.1fs",
            len(ssl_findings),
            len(alive_domains),
            duration,
        )

        return ModuleResult(
            module_name=self.name,
            success=True,
            data={"ssl_findings": ssl_findings},
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )

    @staticmethod
    async def _check_ssl(domain: str) -> list[dict[str, Any]]:
        """Perform SSL/TLS checks on a single domain.

        Args:
            domain: FQDN to connect to on port 443.

        Returns:
            A list of finding dicts.
        """
        findings: list[dict[str, Any]] = []

        # Create a permissive SSL context to inspect certs even if invalid.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, 443, ssl=ctx),
                timeout=_CONNECT_TIMEOUT,
            )
        except (asyncio.TimeoutError, OSError) as exc:
            logger.debug("SSL connect failed for %s: %s", domain, exc)
            return findings

        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                return findings

            # Protocol version
            protocol_version = ssl_object.version()
            if protocol_version in _WEAK_PROTOCOLS:
                findings.append({
                    "domain": domain,
                    "issue": "weak_protocol",
                    "severity": "high",
                    "details": f"{protocol_version} is deprecated and insecure",
                    "cert_expiry": None,
                    "cert_issuer": None,
                })

            # Certificate analysis
            cert_bin = ssl_object.getpeercert(binary_form=True)
            if cert_bin is None:
                findings.append({
                    "domain": domain,
                    "issue": "no_certificate",
                    "severity": "high",
                    "details": "Server did not present a certificate",
                    "cert_expiry": None,
                    "cert_issuer": None,
                })
                return findings

            # Re-connect with verification to check certificate validity
            verify_ctx = ssl.create_default_context()
            cert_info = await _get_verified_cert_info(domain, verify_ctx)

            if cert_info is None:
                # Verification failed — likely self-signed or hostname mismatch
                findings.append({
                    "domain": domain,
                    "issue": "certificate_validation_failed",
                    "severity": "high",
                    "details": "Certificate validation failed (self-signed or hostname mismatch)",
                    "cert_expiry": None,
                    "cert_issuer": None,
                })
            else:
                # Check expiry
                not_after_str = cert_info.get("notAfter", "")
                cert_issuer_parts = cert_info.get("issuer", ())
                cert_issuer = _format_issuer(cert_issuer_parts)

                if not_after_str:
                    not_after = ssl.cert_time_to_seconds(not_after_str)
                    expiry_dt = datetime.fromtimestamp(not_after, tz=timezone.utc)
                    expiry_str = expiry_dt.strftime("%Y-%m-%d")
                    now = datetime.now(timezone.utc)
                    days_left = (expiry_dt - now).days

                    if days_left < 0:
                        findings.append({
                            "domain": domain,
                            "issue": "certificate_expired",
                            "severity": "critical",
                            "details": f"Certificate expired {abs(days_left)} days ago",
                            "cert_expiry": expiry_str,
                            "cert_issuer": cert_issuer,
                        })
                    elif days_left < 30:
                        findings.append({
                            "domain": domain,
                            "issue": "certificate_expiring_soon",
                            "severity": "medium",
                            "details": f"Certificate expires in {days_left} days",
                            "cert_expiry": expiry_str,
                            "cert_issuer": cert_issuer,
                        })

                # Check hostname match
                san_names = _extract_san(cert_info)
                if not _hostname_matches(domain, san_names):
                    findings.append({
                        "domain": domain,
                        "issue": "hostname_mismatch",
                        "severity": "high",
                        "details": f"Certificate SANs {san_names} do not match {domain}",
                        "cert_expiry": expiry_str if not_after_str else None,
                        "cert_issuer": cert_issuer,
                    })

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        return findings


async def _get_verified_cert_info(
    domain: str, ctx: ssl.SSLContext
) -> dict[str, Any] | None:
    """Attempt a verified TLS connection and return the parsed cert dict."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx),
            timeout=_CONNECT_TIMEOUT,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        cert_info = ssl_object.getpeercert() if ssl_object else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return cert_info
    except Exception:
        return None


def _format_issuer(issuer_tuple: tuple) -> str:
    """Format the issuer tuple into a readable string."""
    parts = []
    for rdn in issuer_tuple:
        for attr_type, attr_value in rdn:
            if attr_type in ("organizationName", "commonName"):
                parts.append(attr_value)
    return ", ".join(parts) if parts else "Unknown"


def _extract_san(cert_info: dict[str, Any]) -> list[str]:
    """Extract Subject Alternative Names from a cert dict."""
    san_entries = cert_info.get("subjectAltName", ())
    return [value for kind, value in san_entries if kind == "DNS"]


def _hostname_matches(domain: str, san_names: list[str]) -> bool:
    """Check whether domain matches any SAN entry (including wildcards)."""
    for san in san_names:
        if san == domain:
            return True
        if san.startswith("*.") and domain.endswith(san[1:]):
            return True
    return False
