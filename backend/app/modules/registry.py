"""
Module Registry for ReconScope reconnaissance modules.

Provides a central, class-level registry where modules register themselves
via the :meth:`ModuleRegistry.register` decorator.  The orchestrator uses
the registry to discover available modules, resolve dependencies, and
determine the correct execution order grouped by phase.
"""

from __future__ import annotations

from typing import Type

from app.modules.base import BaseReconModule, ModulePhase


class ModuleRegistry:
    """Manages all available reconnaissance modules.

    Modules are stored in a class-level dictionary keyed by their unique
    ``name`` attribute.  Registration happens at import time through the
    :meth:`register` class-method decorator.

    Example::

        @ModuleRegistry.register
        class MyModule(BaseReconModule):
            name = "mymodule"
            ...
    """

    _modules: dict[str, Type[BaseReconModule]] = {}

    @classmethod
    def register(cls, module_class: Type[BaseReconModule]) -> Type[BaseReconModule]:
        """Class-method decorator that registers a module in the registry.

        Args:
            module_class: The module class to register.  Its ``name``
                          attribute is used as the registry key.

        Returns:
            The unmodified *module_class* so the decorator is transparent.
        """
        cls._modules[module_class.name] = module_class
        return module_class

    @classmethod
    def get_module(cls, name: str) -> BaseReconModule:
        """Instantiate and return a single module by name.

        Args:
            name: The unique module identifier (e.g. ``"crtsh"``).

        Returns:
            A fresh instance of the requested module.

        Raises:
            KeyError: If no module with the given name is registered.
        """
        return cls._modules[name]()

    @classmethod
    def get_all(cls) -> list[BaseReconModule]:
        """Return fresh instances of every registered module.

        Returns:
            A list of module instances in arbitrary order.
        """
        return [module_cls() for module_cls in cls._modules.values()]

    @classmethod
    def get_by_phase(cls, phase: ModulePhase) -> list[BaseReconModule]:
        """Return instances of all modules belonging to a specific phase.

        Args:
            phase: The :class:`ModulePhase` to filter by.

        Returns:
            A list of module instances whose phase matches *phase*.
        """
        return [
            module_cls()
            for module_cls in cls._modules.values()
            if module_cls.phase == phase
        ]

    @classmethod
    def get_execution_order(
        cls, selected: list[str] | None = None
    ) -> list[list[BaseReconModule]]:
        """Return modules grouped by phase in ascending execution order.

        Modules within the same phase may be executed concurrently because
        they share no intra-phase dependencies.

        Args:
            selected: Optional list of module names to include.  When
                      ``None`` or empty, **all** registered modules are
                      returned.

        Returns:
            A list of lists, where each inner list contains modules that
            belong to the same phase.  The outer list is sorted by
            ascending phase value.
        """
        if selected:
            modules = [cls.get_module(name) for name in selected]
        else:
            modules = cls.get_all()

        phases: dict[int, list[BaseReconModule]] = {}
        for module in modules:
            phases.setdefault(module.phase.value, []).append(module)

        return [phases[phase_key] for phase_key in sorted(phases.keys())]
