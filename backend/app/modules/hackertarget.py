"""
HackerTarget module for ReconScope.

Queries the HackerTarget free host search API to discover subdomains.
Returns plain-text results in ``host,ip`` format.  Free tier allows
~100 queries per day without an API key.
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
class HackerTargetModule(BaseReconModule):
    """Subdomain discovery via HackerTarget host search."""

    name: str = "hackertarget"
    description: str = "Subdomain Discovery via HackerTarget Host Search"
    phase: ModulePhase = ModulePhase.DISCOVERY
    rate_limit: int = 5

    API_URL: str = "https://api.hackertarget.com/hostsearch/"

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
                    self.API_URL,
                    params={"q": target},
                )
                response.raise_for_status()

                text = response.text.strip()

                # HackerTarget returns "error ..." on failure
                if text.startswith("error"):
                    errors.append(f"HackerTarget API error: {text}")
                else:
                    for line in text.splitlines():
                        parts = line.split(",", 1)
                        if not parts:
                            continue
                        hostname = parts[0].strip().lower()
                        if not hostname:
                            continue
                        if hostname == target or hostname.endswith(f".{target}"):
                            subdomains.add(hostname)

        except httpx.TimeoutException as exc:
            error_msg = f"HackerTarget request timed out: {exc}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except httpx.HTTPStatusError as exc:
            error_msg = f"HackerTarget returned HTTP {exc.response.status_code}: {exc}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except Exception as exc:  # noqa: BLE001
            error_msg = f"HackerTarget query failed: {exc}"
            logger.exception(error_msg)
            errors.append(error_msg)

        duration: float = time.monotonic() - start

        return ModuleResult(
            module_name=self.name,
            success=len(errors) == 0,
            data={
                "subdomains": [
                    {"name": subdomain, "source": "hackertarget"}
                    for subdomain in sorted(subdomains)
                ]
            },
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )
