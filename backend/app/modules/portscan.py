"""
Port Scanner module for ReconScope.

Wraps ``nmap`` via the ``python-nmap`` library to perform service version
detection on the top 100 TCP ports of every resolved IP address.  This is
an **active** module that sends SYN/connect probes to the target hosts.
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import nmap

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)

_CONCURRENCY = 5


@ModuleRegistry.register
class PortScanModule(BaseReconModule):
    """TCP port scanning with service version detection via nmap.

    Scans the top 100 ports of each resolved IP and outputs detected
    services into ``context["technologies"]`` so the existing
    orchestrator persistence and CVE matching can process them.
    """

    name: str = "portscan"
    description: str = "Port Scanner (nmap) — Top 100 TCP ports with version detection"
    phase: ModulePhase = ModulePhase.ENUMERATION
    depends_on: list[str] = ["dns"]

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Scan resolved IPs for open ports and service versions.

        Args:
            target:  Root domain (e.g. ``"acme-corp.de"``).
            context: Must contain ``"resolved_ips"`` (``{domain: ip}``).

        Returns:
            A :class:`ModuleResult` with ``data["technologies"]`` containing
            detected services per port.
        """
        start: float = time.monotonic()
        technologies: list[dict[str, Any]] = []
        errors: list[str] = []

        resolved_ips: dict[str, str] = context.get("resolved_ips", {})
        if not resolved_ips:
            logger.info("No resolved IPs available; skipping port scan.")
            return ModuleResult(
                module_name=self.name,
                success=True,
                data={"technologies": []},
                duration_seconds=0.0,
            )

        # Deduplicate: multiple subdomains may share an IP.
        ip_to_domains: dict[str, list[str]] = {}
        for domain, ip in resolved_ips.items():
            ip_to_domains.setdefault(ip, []).append(domain)

        loop = asyncio.get_running_loop()
        semaphore = asyncio.Semaphore(_CONCURRENCY)
        executor = ThreadPoolExecutor(max_workers=_CONCURRENCY)

        async def _scan_ip(ip: str, domains: list[str]) -> None:
            async with semaphore:
                try:
                    result = await loop.run_in_executor(
                        executor, self._nmap_scan, ip
                    )
                    for port_info in result:
                        for domain in domains:
                            technologies.append({
                                "domain": domain,
                                "name": port_info["service"],
                                "version": port_info["version"],
                                "category": "service",
                                "confidence": 95,
                                "port": port_info["port"],
                                "source": "portscan",
                            })
                except Exception as exc:
                    error_msg = f"nmap scan {ip}: {exc}"
                    logger.warning(error_msg)
                    errors.append(error_msg)

        await asyncio.gather(
            *(
                _scan_ip(ip, domains)
                for ip, domains in ip_to_domains.items()
            ),
            return_exceptions=True,
        )

        executor.shutdown(wait=False)

        duration: float = time.monotonic() - start
        logger.info(
            "Port scan found %d services across %d IPs in %.1fs",
            len(technologies),
            len(ip_to_domains),
            duration,
        )

        return ModuleResult(
            module_name=self.name,
            success=True,
            data={"technologies": technologies},
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )

    @staticmethod
    def _nmap_scan(ip: str) -> list[dict[str, Any]]:
        """Run nmap service-version scan on the top 100 ports.

        Args:
            ip: The target IP address.

        Returns:
            A list of dicts with ``port``, ``service``, ``version``.
        """
        scanner = nmap.PortScanner()
        scanner.scan(
            hosts=ip,
            arguments="-sV -T4 --top-ports 100 --host-timeout 60s",
        )

        results: list[dict[str, Any]] = []
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in scanner[host][proto]:
                    port_data = scanner[host][proto][port]
                    if port_data.get("state") != "open":
                        continue
                    service_name = port_data.get("name", "unknown")
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    full_version = f"{product} {version}".strip() or "unknown"
                    results.append({
                        "port": port,
                        "service": service_name,
                        "version": full_version,
                    })

        return results
