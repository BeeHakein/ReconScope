"""
DNS Enumeration module for ReconScope.

Resolves a comprehensive set of DNS record types (A, AAAA, MX, TXT,
CNAME, NS, SOA) for the target domain as well as every subdomain
discovered by earlier modules.  The resolved IP addresses are collected
separately so that downstream modules (e.g. technology detection) can
reference them directly.
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import dns.exception
import dns.resolver

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)

# Maximum number of concurrent DNS resolution tasks.
_DNS_CONCURRENCY = 30


@ModuleRegistry.register
class DnsEnumModule(BaseReconModule):
    """DNS record enumeration for the target and all known subdomains.

    Uses ``dnspython`` with conservative timeouts and handles common
    negative responses (NXDOMAIN, NoAnswer, etc.) gracefully so that a
    single failing domain never aborts the entire scan.

    Resolution is parallelised across domains using a bounded thread
    pool and asyncio semaphore so that large subdomain lists do not
    cause sequential timeouts.
    """

    name: str = "dns"
    description: str = "DNS Record Enumeration (A, AAAA, MX, TXT, CNAME, NS, SOA)"
    phase: ModulePhase = ModulePhase.ENUMERATION

    RECORD_TYPES: list[str] = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA"]

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Resolve DNS records for *target* and all subdomains from *context*.

        Args:
            target:  Root domain to resolve.
            context: Must contain a ``"subdomains"`` key (list of dicts
                     with a ``"name"`` field) when subdomains have already
                     been discovered.

        Returns:
            A :class:`ModuleResult` with::

                data = {
                    "records":      {domain: {rtype: [values]}},
                    "resolved_ips": {domain: ip_address},
                }
        """
        start: float = time.monotonic()
        records: dict[str, dict[str, list[str]]] = {}
        resolved_ips: dict[str, str] = {}
        errors: list[str] = []

        # Build the set of domains to resolve
        domains_to_resolve: set[str] = {target}
        for subdomain_entry in context.get("subdomains", []):
            name = subdomain_entry.get("name")
            if name:
                domains_to_resolve.add(name)

        # Configure a dedicated resolver instance with tight timeouts.
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 5.0

        loop = asyncio.get_running_loop()
        semaphore = asyncio.Semaphore(_DNS_CONCURRENCY)
        executor = ThreadPoolExecutor(max_workers=_DNS_CONCURRENCY)

        async def _resolve_domain(domain: str) -> None:
            """Resolve all record types for a single domain."""
            domain_records: dict[str, list[str]] = {}
            async with semaphore:
                for rtype in self.RECORD_TYPES:
                    try:
                        answers = await loop.run_in_executor(
                            executor, self._resolve_record, resolver, domain, rtype
                        )
                        if answers is None:
                            continue

                        values: list[str] = []
                        for rdata in answers:
                            value = str(rdata)
                            values.append(value)
                            if rtype in ("A", "AAAA"):
                                resolved_ips[domain] = value

                        if values:
                            domain_records[rtype] = values

                    except Exception as exc:  # noqa: BLE001
                        error_msg = f"DNS {rtype} for {domain}: {exc}"
                        logger.debug(error_msg)
                        errors.append(error_msg)

            records[domain] = domain_records

        # Resolve all domains concurrently (bounded by semaphore).
        await asyncio.gather(
            *(_resolve_domain(domain) for domain in sorted(domains_to_resolve)),
            return_exceptions=True,
        )

        executor.shutdown(wait=False)

        duration: float = time.monotonic() - start
        logger.info(
            "DNS resolved %d/%d domains with IPs in %.1fs",
            len(resolved_ips),
            len(domains_to_resolve),
            duration,
        )

        return ModuleResult(
            module_name=self.name,
            success=True,
            data={
                "records": records,
                "resolved_ips": resolved_ips,
            },
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_record(
        resolver: dns.resolver.Resolver,
        domain: str,
        rtype: str,
    ) -> dns.resolver.Answer | None:
        """Attempt to resolve a single DNS record type for *domain*.

        Returns ``None`` when the query yields a well-known negative
        response (NXDOMAIN, NoAnswer, NoNameservers, Timeout) so the
        caller can skip the record type silently.

        Args:
            resolver: Pre-configured :class:`dns.resolver.Resolver`.
            domain:   Fully-qualified domain name.
            rtype:    DNS record type string (e.g. ``"A"``, ``"MX"``).

        Returns:
            A :class:`dns.resolver.Answer` on success, or ``None`` when
            the domain/record combination does not exist.
        """
        try:
            return resolver.resolve(domain, rtype)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return None
