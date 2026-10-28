"""Dialect registry: ``register``, ``pick``, ``load_packs`` (design 3.2, 6.1, 13.3).

``REGISTRY`` maps a dialect name to a shared instance.  Built-in dialect modules
(every non-private ``dialects/<name>.py`` except the helpers in
``HELPER_MODULES``; auto-discovered, see ``BUILTIN_MODULES``) register
themselves with ``@register`` when imported; they are imported lazily on first
use together
with the declarative ``packs/*.toml`` shipped next to this file.  Out-of-tree
packs (``*.toml``) and plugins (``*.py``) are loaded with ``load_packs(dirs)``
(CLI ``--plugins DIR``).

Selection (``pick``) uses template, image and content only, never the node name.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import pkgutil
import sys
import tomllib
from pathlib import Path

from ..errors import LocalizeError
from ..model import Node
from .base import (
    Dialect,
    IfaceInfo,
    ParsedConfig,
    PatternRule,
    RenderCtx,
    RuleDialect,
    build_rule_dialect,
    make_fact_id,
)

__all__ = [
    "BUILTIN_MODULES",
    "PLUGIN_SOURCES",
    "REGISTRY",
    "Dialect",
    "IfaceInfo",
    "ParsedConfig",
    "PatternRule",
    "RenderCtx",
    "RuleDialect",
    "get",
    "load_builtin",
    "load_packs",
    "make_fact_id",
    "names",
    "pick",
    "register",
]

REGISTRY: dict[str, Dialect] = {}

# Helper modules in this package that are not dialects (never auto-imported).
HELPER_MODULES = frozenset({"base", "blocks"})


def _discover_modules() -> tuple[str, ...]:
    """Dialect modules in this package directory (auto-discovered, sorted).

    Every ``dialects/<name>.py`` that is not private (``_name``) and not a
    helper in ``HELPER_MODULES`` is imported by ``load_builtin``; a new
    in-tree dialect needs no registry edit (design 13.3).
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


BUILTIN_MODULES = _discover_modules()
PACKS_DIR = Path(__file__).resolve().parent / "packs"
FALLBACK = "generic"

_loaded = False

# Dialects registered from out-of-tree ``--plugins`` files: name -> source file.
# Built-in modules and the shipped ``packs/`` are not listed.  The CLI records
# the plugin dialects a localized lab used in ``state.json`` so ``revert`` /
# ``check`` refuse (UNKNOWN_DIALECT) when they are not loaded (review fix #27).
PLUGIN_SOURCES: dict[str, str] = {}
_current_source: str | None = None


def _origin(obj: object) -> tuple[str, str]:
    cls = obj if isinstance(obj, type) else type(obj)
    return cls.__module__, cls.__qualname__


def register(cls: type[Dialect]) -> type[Dialect]:
    """Class decorator: instantiate ``cls`` and add it to ``REGISTRY``.

    Re-registering the same class (module reload, pack loaded twice) replaces
    the entry; a *different* class with an existing name is an error.
    """
    name = getattr(cls, "name", "")
    if not isinstance(name, str) or not name:
        raise LocalizeError(f"{cls!r} has no dialect name", code="DIALECT_INVALID")
    existing = REGISTRY.get(name)
    if existing is not None and _origin(existing) != _origin(cls):
        mod, qual = _origin(existing)
        raise LocalizeError(
            f"dialect {name!r} is already registered by {mod}.{qual}",
            code="DIALECT_DUPLICATE",
        )
    REGISTRY[name] = cls()
    if _current_source is not None:
        PLUGIN_SOURCES[name] = _current_source
    else:
        PLUGIN_SOURCES.pop(name, None)
    return cls


def names() -> list[str]:
    """Registered dialect names (built-ins loaded), sorted."""
    load_builtin()
    return sorted(REGISTRY)


def get(name: str) -> Dialect:
    """The dialect called ``name``."""
    load_builtin()
    try:
        return REGISTRY[name]
    except KeyError:
        raise LocalizeError(
            f"unknown dialect {name!r}; known: {', '.join(sorted(REGISTRY)) or '-'}",
            code="UNKNOWN_DIALECT",
        ) from None


def load_builtin() -> None:
    """Import the built-in dialect modules and load the shipped packs, once."""
    global _loaded
    if _loaded:
        return
    _loaded = True
    for mod in BUILTIN_MODULES:
        full = f"{__name__}.{mod}"
        try:
            importlib.import_module(full)
        except ModuleNotFoundError as exc:
            if exc.name != full:  # a real missing import inside the module
                raise
    if PACKS_DIR.is_dir():
        load_packs([PACKS_DIR])


def pick(node: Node | None, text: str, override: str | None = None) -> Dialect:
    """Choose the dialect for a config.

    ``override`` (manifest ``dialect = "..."``) always wins.  Otherwise the
    highest ``score`` wins (ties: higher ``priority``, then name); with no
    positive score the ``generic`` fallback is returned.
    """
    load_builtin()
    if override:
        return get(override)
    # Memoised per (registry contents, node scalars, text): a lab is analysed
    # several times per run with the same texts (performance, review #38).
    key: tuple[object, ...] = (
        tuple((k, id(v)) for k, v in sorted(REGISTRY.items())),
        (
            None
            if node is None
            else (node.id, node.name, node.type, node.template, node.image)
        ),
        text,
    )
    hit = _PICK_CACHE.get(key)
    if hit is not None:
        return hit
    choice = _pick(node, text)
    _PICK_CACHE[key] = choice
    if len(_PICK_CACHE) > 4096:
        _PICK_CACHE.pop(next(iter(_PICK_CACHE)))
    return choice


_PICK_CACHE: dict[tuple[object, ...], Dialect] = {}


def _pick(node: Node | None, text: str) -> Dialect:
    best: Dialect | None = None
    best_key: tuple[int, int] | None = None
    for name in sorted(REGISTRY):
        if name == FALLBACK:
            continue
        dialect = REGISTRY[name]
        score = dialect.score(node, text)
        if score <= 0:
            continue
        key = (score, int(getattr(dialect, "priority", 0)))
        # highest score, then priority; sorted iteration: alphabetical first wins
        if best_key is None or key > best_key:
            best, best_key = dialect, key
    if best is not None:
        return best
    if FALLBACK not in REGISTRY:
        raise LocalizeError(
            "no dialect matched and no 'generic' fallback is registered",
            code="NO_DIALECT",
        )
    return REGISTRY[FALLBACK]


def _load_toml(path: Path) -> None:
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise LocalizeError(
            f"{path}: cannot read pack: {exc}", code="PACK_INVALID"
        ) from exc
    try:
        cls = build_rule_dialect(data, str(path))
    except ValueError as exc:
        raise LocalizeError(f"{path}: {exc}", code="PACK_INVALID") from exc
    register(cls)  # type: ignore[arg-type]


def _load_plugin(path: Path) -> None:
    digest = hashlib.sha1(str(path.resolve()).encode()).hexdigest()[:8]
    modname = f"evelab_localize_plugin_{path.stem}_{digest}"
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        raise LocalizeError(f"{path}: cannot load plugin", code="PLUGIN_ERROR")
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    try:
        spec.loader.exec_module(module)
    except LocalizeError:
        sys.modules.pop(modname, None)
        raise
    except Exception as exc:
        sys.modules.pop(modname, None)
        raise LocalizeError(
            f"{path}: plugin failed: {type(exc).__name__}: {exc}", code="PLUGIN_ERROR"
        ) from exc


def load_packs(dirs: list[Path]) -> None:
    """Load declarative ``*.toml`` packs and ``*.py`` plugins from ``dirs``.

    Files are processed in sorted order, TOML before Python; names starting
    with ``_`` or ``.`` are ignored.  A plugin registers dialects (and
    scenarios) by importing ``evelab.localize`` and using ``@register`` as usual.
    A missing directory or a broken file raises ``LocalizeError``.
    """
    global _current_source
    for d in dirs:
        d = Path(d)
        if not d.is_dir():
            raise LocalizeError(f"{d}: not a directory", code="PLUGIN_DIR")
        shipped = d.resolve() == PACKS_DIR
        files = sorted(
            p for p in d.iterdir() if p.is_file() and not p.name.startswith(("_", "."))
        )
        ordered = [p for p in files if p.suffix == ".toml"]
        ordered += [p for p in files if p.suffix == ".py"]
        for path in ordered:
            outer = _current_source
            _current_source = None if shipped else str(path.resolve())
            try:
                if path.suffix == ".toml":
                    _load_toml(path)
                else:
                    _load_plugin(path)
            finally:
                _current_source = outer
