"""Run ``scripts/check-labs.py`` in-process on a set of ``.unl`` files."""

from __future__ import annotations

import contextlib
import importlib.util
import io
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

from .errors import EveLabError
from .paths import SCRIPTS_DIR

__all__ = ["CHECK_LABS", "run_check_labs"]

CHECK_LABS = SCRIPTS_DIR / "check-labs.py"

_cache: dict[Path, ModuleType] = {}


def _load(script: Path) -> ModuleType:
    script = Path(script).resolve()
    mod = _cache.get(script)
    if mod is None:
        spec = importlib.util.spec_from_file_location("check_labs", script)
        if spec is None or spec.loader is None:
            raise EveLabError(f"cannot load {script}", code="CHECK_LABS")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _cache[script] = mod
    return mod


def run_check_labs(paths: Sequence[Path], script: Path = CHECK_LABS) -> tuple[int, str]:
    """Run ``check-labs.main`` on ``paths`` (each must end in ``.unl``).

    Returns ``(exit status, combined stdout/stderr)``.
    """
    mod = _load(script)
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = mod.main([str(p) for p in paths])
    return int(rc or 0), out.getvalue()
