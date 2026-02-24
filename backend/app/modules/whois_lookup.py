"""
WHOIS Lookup module for ReconScope.

Retrieves domain registration data (registrar, dates, name servers,
organisation, country, DNSSEC status) for the target domain through
the standard WHOIS protocol.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import date, datetime
from typing import Any

import whois  # python-whois

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)


@ModuleRegistry.register
class WhoisModule(BaseReconModule):
    """WHOIS registration data lookup for the target domain.

    Wraps the synchronous ``python-whois`` library inside
    :func:`asyncio.get_running_loop().run_in_executor` so it does not
    block the async event loop.  Date objects are serialised to ISO-8601
    strings for safe JSON transport.
    """

    name: str = "whois"
    description: str = "WHOIS Domain Registration Data"
    phase: ModulePhase = ModulePhase.DISCOVERY
    rate_limit: int = 3

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Perform a WHOIS lookup for *target*.

        Args:
            target:  Root domain to query (e.g. ``"acme-corp.de"``).
            context: Results from previously executed modules (unused here).

        Returns:
            A :class:`ModuleResult` whose ``data`` dict contains keys
            such as ``registrar``, ``creation_date``, ``expiration_date``,
            ``updated_date``, ``name_servers``, ``org``, ``country``, and
            ``dnssec``.
        """
        start: float = time.monotonic()

        loop = asyncio.get_running_loop()

        try:
            whois_response = await loop.run_in_executor(
                None, whois.whois, target
            )

            data: dict[str, Any] = {
                "registrar": whois_response.registrar,
                "creation_date": self._date_to_str(whois_response.creation_date),
                "expiration_date": self._date_to_str(whois_response.expiration_date),
                "updated_date": self._date_to_str(whois_response.updated_date),
                "name_servers": (
                    whois_response.name_servers
                    if whois_response.name_servers
                    else []
                ),
                "org": whois_response.org,
                "country": whois_response.country,
                "dnssec": (
                    whois_response.dnssec
                    if hasattr(whois_response, "dnssec")
                    else None
                ),
            }

            duration: float = time.monotonic() - start

            return ModuleResult(
                module_name=self.name,
                success=True,
                data=data,
                errors=None,
                duration_seconds=round(duration, 3),
                raw_response=str(whois_response),
            )

        except Exception as exc:  # noqa: BLE001
            error_msg = f"WHOIS lookup for {target} failed: {exc}"
            logger.exception(error_msg)

            duration = time.monotonic() - start

            return ModuleResult(
                module_name=self.name,
                success=False,
                data={},
                errors=[error_msg],
                duration_seconds=round(duration, 3),
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _date_to_str(
        value: datetime | date | list[datetime | date] | None,
    ) -> str | list[str] | None:
        """Convert WHOIS date field(s) to ISO-8601 string(s).

        The ``python-whois`` library may return a single ``datetime``, a
        ``date``, a list of either, or ``None``.  This helper normalises
        all variants into JSON-safe strings.

        Args:
            value: Raw date value from the WHOIS response.

        Returns:
            An ISO-formatted string, a list of such strings, or ``None``.
        """
        if value is None:
            return None
        if isinstance(value, list):
            return [
                item.isoformat() if isinstance(item, (datetime, date)) else str(item)
                for item in value
            ]
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        return str(value)
