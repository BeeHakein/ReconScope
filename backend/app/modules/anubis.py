"""
Anubis (jldc.me) module for ReconScope.

Queries the Anubis subdomain API at ``jldc.me`` to discover subdomains.
This is a free, keyless API that returns a JSON array of discovered
subdomain strings.
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
class AnubisModule(BaseReconModule):
    """Subdomain discovery via Anubis (jldc.me) API."""

    name: str = "anubis"
    description: str = "Subdomain Discovery via Anubis Database"
    phase: ModulePhase = ModulePhase.DISCOVERY
    rate_limit: int = 5

    API_URL: str = "https://jldc.me/anubis/subdomains/{domain}"

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
                    self.API_URL.format(domain=target),
                )
                response.raise_for_status()

                entries: list[str] = response.json()

                for raw_name in entries:
                    hostname = raw_name.strip().lower()
                    if not hostname:
                        continue
                    if hostname == target or hostname.endswith(f".{target}"):
                        subdomains.add(hostname)

        except httpx.TimeoutException as exc:
            error_msg = f"Anubis request timed out: {exc}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except httpx.HTTPStatusError as exc:
            error_msg = f"Anubis returned HTTP {exc.response.status_code}: {exc}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except Exception as exc:  # noqa: BLE001
            error_msg = f"Anubis query failed: {exc}"
            logger.exception(error_msg)
            errors.append(error_msg)

        duration: float = time.monotonic() - start

        return ModuleResult(
            module_name=self.name,
            success=len(errors) == 0,
            data={
                "subdomains": [
                    {"name": subdomain, "source": "anubis"}
                    for subdomain in sorted(subdomains)
                ]
            },
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )
