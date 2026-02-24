"""
AlienVault OTX module for ReconScope.

Queries the AlienVault Open Threat Exchange (OTX) passive DNS API to
discover subdomains.  This is a free, keyless API that aggregates DNS
observations from the OTX sensor network.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)


@ModuleRegistry.register
class AlienVaultModule(BaseReconModule):
    """Subdomain discovery via AlienVault OTX passive DNS."""

    name: str = "alienvault"
    description: str = "Subdomain Discovery via AlienVault OTX Passive DNS"
    phase: ModulePhase = ModulePhase.DISCOVERY
    rate_limit: int = 10

    OTX_URL: str = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        start: float = time.monotonic()
        subdomains: set[str] = set()
        errors: list[str] = []

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
                follow_redirects=True,
            ) as client:
                response = await client.get(
                    self.OTX_URL.format(domain=target),
                )
                response.raise_for_status()

                data = response.json()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").strip().lower()
                    if not hostname:
                        continue
                    if hostname == target or hostname.endswith(f".{target}"):
                        subdomains.add(hostname)

        except httpx.TimeoutException as exc:
            error_msg = f"AlienVault OTX request timed out: {exc}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except httpx.HTTPStatusError as exc:
            error_msg = f"AlienVault OTX returned HTTP {exc.response.status_code}: {exc}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except Exception as exc:  # noqa: BLE001
            error_msg = f"AlienVault OTX query failed: {exc}"
            logger.exception(error_msg)
            errors.append(error_msg)

        duration: float = time.monotonic() - start

        return ModuleResult(
            module_name=self.name,
            success=len(errors) == 0,
            data={
                "subdomains": [
                    {"name": subdomain, "source": "alienvault"}
                    for subdomain in sorted(subdomains)
                ]
            },
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )
