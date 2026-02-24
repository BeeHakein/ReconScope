"""
Base module interface for all ReconScope reconnaissance modules.

Defines the abstract base class, standard result container, and execution
phase enumeration that every recon module must adhere to.  Inspired by
SpiderFoot's event-driven architecture but simplified for the ReconScope
use-case.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ModulePhase(Enum):
    """Determines the execution order of modules within a scan.

    Modules in the same phase may be executed in parallel.  Higher phases
    depend on the output of lower phases.

    Attributes:
        DISCOVERY:   Phase 1 -- subdomain and asset discovery.
        ENUMERATION: Phase 2 -- DNS resolution and IP enrichment.
        ENRICHMENT:  Phase 3 -- service and technology detection.
        ANALYSIS:    Phase 4 -- CVE matching, vulnerability assessment.
    """

    DISCOVERY = 1
    ENUMERATION = 2
    ENRICHMENT = 3
    ANALYSIS = 4


@dataclass
class ModuleResult:
    """Standardised result container returned by every recon module.

    Attributes:
        module_name:      Unique identifier of the module that produced this result.
        success:          ``True`` when the module completed without fatal errors.
        data:             Module-specific structured output (e.g. subdomains, records).
        errors:           Human-readable error messages collected during execution.
        duration_seconds: Wall-clock time the module spent executing.
        raw_response:     Optional raw upstream response kept for debugging purposes.
    """

    module_name: str
    success: bool
    data: dict[str, Any]
    errors: list[str] | None = None
    duration_seconds: float = 0.0
    raw_response: Any = None


class BaseReconModule(ABC):
    """Abstract base class that every reconnaissance module must implement.

    Subclasses **must** override :meth:`execute` and set the class-level
    attributes ``name``, ``description``, and ``phase`` to meaningful values.

    Attributes:
        name:             Short unique identifier used in the registry and API.
        description:      Human-readable one-liner describing the module.
        phase:            Execution phase (determines ordering).
        depends_on:       Names of modules whose output this module requires.
        rate_limit:       Maximum number of upstream requests per window.
        rate_limit_window: Duration of the rate-limit window in seconds.
        requires_api_key: Whether an external API key is needed at runtime.
        api_key_env_var:  Name of the environment variable holding the API key.
    """

    name: str = "base"
    description: str = ""
    phase: ModulePhase = ModulePhase.DISCOVERY
    depends_on: list[str] = []
    rate_limit: int = 10
    rate_limit_window: int = 60
    requires_api_key: bool = False
    api_key_env_var: str = ""

    @abstractmethod
    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Run the module against *target* and return structured results.

        Args:
            target:  The root domain to scan (e.g. ``"acme-corp.de"``).
            context: Aggregated results from previously completed modules.
                     Example keys: ``"subdomains"``, ``"technologies"``.

        Returns:
            A :class:`ModuleResult` containing the module's findings.
        """

    def validate_config(self) -> bool:
        """Check whether all prerequisites (API keys, etc.) are satisfied.

        Returns:
            ``True`` when the module is ready to run, ``False`` otherwise.
        """
        if self.requires_api_key:
            return bool(os.getenv(self.api_key_env_var))
        return True
