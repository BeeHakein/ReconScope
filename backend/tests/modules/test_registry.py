"""
Tests for the Module Registry.

Validates module registration, retrieval by name, phase-based grouping,
and execution order generation including filtered selection.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry


class _DummyDiscovery(BaseReconModule):
    """Test module for the DISCOVERY phase."""

    name = "_test_dummy_discovery"
    description = "Dummy discovery module for testing"
    phase = ModulePhase.DISCOVERY

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Return an empty successful result."""
        return ModuleResult(module_name=self.name, success=True, data={})


class _DummyEnrichment(BaseReconModule):
    """Test module for the ENRICHMENT phase."""

    name = "_test_dummy_enrichment"
    description = "Dummy enrichment module for testing"
    phase = ModulePhase.ENRICHMENT

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Return an empty successful result."""
        return ModuleResult(module_name=self.name, success=True, data={})


class _DummyAnalysis(BaseReconModule):
    """Test module for the ANALYSIS phase."""

    name = "_test_dummy_analysis"
    description = "Dummy analysis module for testing"
    phase = ModulePhase.ANALYSIS

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Return an empty successful result."""
        return ModuleResult(module_name=self.name, success=True, data={})


@pytest.fixture(autouse=True)
def _register_test_modules():
    """Register the test dummy modules and clean them up after each test."""
    ModuleRegistry.register(_DummyDiscovery)
    ModuleRegistry.register(_DummyEnrichment)
    ModuleRegistry.register(_DummyAnalysis)
    yield
    ModuleRegistry._modules.pop("_test_dummy_discovery", None)
    ModuleRegistry._modules.pop("_test_dummy_enrichment", None)
    ModuleRegistry._modules.pop("_test_dummy_analysis", None)


def test_register_module() -> None:
    """Registering a module makes it available in the registry."""
    assert "_test_dummy_discovery" in ModuleRegistry._modules
    assert ModuleRegistry._modules["_test_dummy_discovery"] is _DummyDiscovery


def test_get_module_by_name() -> None:
    """ModuleRegistry.get_module returns a fresh instance of the named module."""
    instance = ModuleRegistry.get_module("_test_dummy_discovery")
    assert isinstance(instance, _DummyDiscovery)
    assert instance.name == "_test_dummy_discovery"


def test_get_by_phase() -> None:
    """ModuleRegistry.get_by_phase returns only modules belonging to the requested phase."""
    discovery_modules = ModuleRegistry.get_by_phase(ModulePhase.DISCOVERY)
    names = {m.name for m in discovery_modules}
    assert "_test_dummy_discovery" in names
    assert "_test_dummy_enrichment" not in names
    assert "_test_dummy_analysis" not in names

    enrichment_modules = ModuleRegistry.get_by_phase(ModulePhase.ENRICHMENT)
    enrichment_names = {m.name for m in enrichment_modules}
    assert "_test_dummy_enrichment" in enrichment_names


def test_get_execution_order() -> None:
    """ModuleRegistry.get_execution_order groups modules by ascending phase value."""
    phases = ModuleRegistry.get_execution_order()

    assert len(phases) >= 3, "Expected at least 3 phases (DISCOVERY, ENRICHMENT, ANALYSIS)"

    # Verify ordering: DISCOVERY (1) < ENRICHMENT (2) < ANALYSIS (3).
    phase_values = []
    for phase_group in phases:
        phase_vals_in_group = {m.phase.value for m in phase_group}
        assert len(phase_vals_in_group) == 1, "All modules in a group must share the same phase"
        phase_values.append(phase_vals_in_group.pop())

    assert phase_values == sorted(phase_values), (
        f"Phase order must be ascending, got: {phase_values}"
    )


def test_get_execution_order_with_selection() -> None:
    """ModuleRegistry.get_execution_order with selected names filters to only those modules."""
    phases = ModuleRegistry.get_execution_order(
        selected=["_test_dummy_discovery", "_test_dummy_analysis"]
    )

    all_names = {m.name for phase_group in phases for m in phase_group}
    assert "_test_dummy_discovery" in all_names
    assert "_test_dummy_analysis" in all_names
    assert "_test_dummy_enrichment" not in all_names, (
        "Unselected module must not appear in the execution order"
    )

    # Verify that discovery comes before analysis.
    flat_names = [m.name for phase_group in phases for m in phase_group]
    disc_idx = flat_names.index("_test_dummy_discovery")
    anal_idx = flat_names.index("_test_dummy_analysis")
    assert disc_idx < anal_idx, "Discovery module must execute before Analysis module"
