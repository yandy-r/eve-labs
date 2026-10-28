"""Scenario registry (design 10, 13.3).

``SCENARIOS`` maps scenario id -> instance. Built-in scenario modules register
themselves with :func:`register_scenario` when :func:`load_builtin` imports them
(the planner and CLI call it; it is idempotent). ``PARAM_KINDS`` is the parameter
kind registry from :mod:`.base`.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TypeVar

from ..errors import LocalizeError
from .base import (
    PARAM_KINDS,
    Answers,
    Claim,
    ParamKind,
    PlanFragment,
    Question,
    Scenario,
    SubnetMap,
    ValueMaps,
    apply_answer,
    register_param_kind,
)

__all__ = [
    "BUILTIN_MODULES",
    "HELPER_MODULES",
    "PARAM_KINDS",
    "SCENARIOS",
    "Answers",
    "Claim",
    "ParamKind",
    "PlanFragment",
    "Question",
    "Scenario",
    "SubnetMap",
    "ValueMaps",
    "apply_answer",
    "load_builtin",
    "ordered",
    "register_param_kind",
    "register_scenario",
]

SCENARIOS: dict[str, Scenario] = {}

# Helper modules in this package that are not scenarios (never auto-imported).
HELPER_MODULES = frozenset({"base", "extra_common"})


def _discover_modules() -> tuple[str, ...]:
    """Scenario modules in this package directory (auto-discovered, sorted).

    Every ``scenarios/<name>.py`` that is not private (``_name``) and not in
    ``HELPER_MODULES`` is imported by :func:`load_builtin`, so a new in-tree
    scenario needs no registry edit (design 13.3).  Import order does not
    matter: :func:`ordered` sorts by ``order`` then id.
    """
    return tuple(
        sorted(
            m.name
            for m in pkgutil.iter_modules(__path__)
            if not m.ispkg
            and not m.name.startswith("_")
            and m.name not in HELPER_MODULES
        )
    )


BUILTIN_MODULES: tuple[str, ...] = _discover_modules()

T = TypeVar("T")


def _origin(obj: object) -> tuple[str, str]:
    cls = obj if isinstance(obj, type) else type(obj)
    return cls.__module__, cls.__qualname__


def register_scenario(obj: T, *, override: bool = False) -> T:
    """Register a scenario class (instantiated with no arguments) or instance.

    Re-registering the same class (module reload) replaces the entry; a
    *different* class under an existing id raises ``SCENARIO_DUPLICATE``
    unless ``override=True`` (a plugin deliberately replacing a built-in;
    use ``register_scenario(Cls, override=True)`` or
    ``functools.partial(register_scenario, override=True)`` as decorator).
    """
    inst = obj() if isinstance(obj, type) else obj
    sid = getattr(inst, "id", None)
    if not sid:
        raise ValueError(f"scenario {obj!r} has no id")
    existing = SCENARIOS.get(sid)
    if existing is not None and not override and _origin(existing) != _origin(inst):
        mod, qual = _origin(existing)
        raise LocalizeError(
            f"scenario {sid!r} is already registered by {mod}.{qual}",
            code="SCENARIO_DUPLICATE",
        )
    SCENARIOS[sid] = inst  # type: ignore[assignment]
    return obj


_loaded = False


def load_builtin() -> dict[str, Scenario]:
    """Import every built-in scenario module (missing optional modules are skipped)."""
    global _loaded
    if not _loaded:
        for name in BUILTIN_MODULES:
            full = f"{__name__}.{name}"
            try:
                importlib.import_module(full)
            except ModuleNotFoundError as exc:
                if exc.name != full:
                    raise
        _loaded = True
    return SCENARIOS


def ordered() -> list[Scenario]:
    """Registered scenarios sorted by ``order`` then id."""
    load_builtin()
    return sorted(SCENARIOS.values(), key=lambda s: (s.order, s.id))
