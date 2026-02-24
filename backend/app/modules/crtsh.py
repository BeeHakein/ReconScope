"""
Certificate Transparency module for ReconScope.

Queries the crt.sh database to discover subdomains that appear in
publicly logged TLS certificates.  This is a purely passive technique
and one of the most effective ways to enumerate an organisation's
external attack surface.
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
class CrtshModule(BaseReconModule):
    """Subdomain discovery via Certificate Transparency logs (crt.sh).

    Sends a single JSON query to ``crt.sh`` for wildcard certificates
    matching the target domain and extracts unique subdomain names from
    the ``name_value`` field of each certificate entry.
    """

    name: str = "crtsh"
    description: str = "Subdomain Discovery via Certificate Transparency Logs"
    phase: ModulePhase = ModulePhase.DISCOVERY
    rate_limit: int = 5  # crt.sh applies its own rate limiting

    CRTSH_URL: str = "https://crt.sh/"

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Query crt.sh for certificates matching ``*.{target}``.

        Args:
            target:  Root domain to search for (e.g. ``"acme-corp.de"``).
            context: Results from previously executed modules (unused here).

        Returns:
            A :class:`ModuleResult` whose ``data`` dict contains a
            ``"subdomains"`` key with a sorted list of unique subdomain
            dicts ``{"name": ..., "source": "crtsh"}``.
        """
        start: float = time.monotonic()
        subdomains: set[str] = set()
        errors: list[str] = []

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
                follow_redirects=True,
            ) as client:
                response = await client.get(
                    self.CRTSH_URL,
                    params={"q": f"%.{target}", "output": "json"},
                )
                response.raise_for_status()

                entries: list[dict[str, Any]] = response.json()

                for entry in entries:
                    name_value: str = entry.get("name_value", "")
                    for raw_name in name_value.split("\n"):
                        name = raw_name.strip().lower()
                        # Strip leading wildcard notation (e.g. "*.sub.domain.tld")
                        name = name.lstrip("*.")
                        if not name:
                            continue
                        if name == target or name.endswith(f".{target}"):
                            subdomains.add(name)

        except httpx.TimeoutException as exc:
            error_msg = f"crt.sh request timed out: {exc}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except httpx.HTTPStatusError as exc:
            error_msg = (
                f"crt.sh returned HTTP {exc.response.status_code}: {exc}"
            )
            logger.warning(error_msg)
            errors.append(error_msg)
        except Exception as exc:  # noqa: BLE001
            error_msg = f"crt.sh query failed: {exc}"
            logger.exception(error_msg)
            errors.append(error_msg)

        duration: float = time.monotonic() - start

        return ModuleResult(
            module_name=self.name,
            success=len(errors) == 0,
            data={
                "subdomains": [
                    {"name": subdomain, "source": "crtsh"}
                    for subdomain in sorted(subdomains)
                ]
            },
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )
