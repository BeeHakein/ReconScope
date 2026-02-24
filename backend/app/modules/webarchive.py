"""
Wayback Machine (web.archive.org) module for ReconScope.

Queries the CDX Server API to extract subdomains from archived URLs.
This is a free, keyless API maintained by the Internet Archive.
The CDX API supports wildcard queries and can reveal subdomains that
appeared in historical web snapshots.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)


@ModuleRegistry.register
class WebArchiveModule(BaseReconModule):
    """Subdomain discovery via Wayback Machine CDX API."""

    name: str = "webarchive"
    description: str = "Subdomain Discovery via Wayback Machine Archive"
    phase: ModulePhase = ModulePhase.DISCOVERY
    rate_limit: int = 3

    CDX_URL: str = "https://web.archive.org/cdx/search/cdx"

    # Valid DNS hostname: labels separated by dots, each label is alphanumeric
    # or hyphen, starting with a letter or digit.
    _VALID_HOSTNAME_RE = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
    )

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        start: float = time.monotonic()
        subdomains: set[str] = set()
        errors: list[str] = []

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0),
                follow_redirects=True,
            ) as client:
                response = await client.get(
                    self.CDX_URL,
                    params={
                        "url": f"*.{target}",
                        "output": "json",
                        "fl": "original",
                        "collapse": "urlkey",
                        "limit": "10000",
                    },
                )
                response.raise_for_status()

                rows: list[list[str]] = response.json()

                # First row is the header ["original"]
                for row in rows[1:]:
                    if not row:
                        continue
                    url = row[0]
                    try:
                        hostname = urlparse(url).hostname
                    except Exception:
                        continue
                    if not hostname:
                        continue
                    hostname = hostname.strip().lower()
                    if hostname == target or hostname.endswith(f".{target}"):
                        # Filter junk: URL-encoded artifacts and invalid DNS names
                        if not self._VALID_HOSTNAME_RE.match(hostname):
                            continue
                        subdomains.add(hostname)

        except httpx.TimeoutException as exc:
            error_msg = f"Wayback Machine request timed out: {exc}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except httpx.HTTPStatusError as exc:
            error_msg = f"Wayback Machine returned HTTP {exc.response.status_code}: {exc}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except Exception as exc:  # noqa: BLE001
            error_msg = f"Wayback Machine query failed: {exc}"
            logger.exception(error_msg)
            errors.append(error_msg)

        duration: float = time.monotonic() - start

        return ModuleResult(
            module_name=self.name,
            success=len(errors) == 0,
            data={
                "subdomains": [
                    {"name": subdomain, "source": "webarchive"}
                    for subdomain in sorted(subdomains)
                ]
            },
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )
