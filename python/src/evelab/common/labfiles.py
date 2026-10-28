"""Find the lab files of a checkout: git top, tracked ``*.unl``, name lookup."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

from .errors import EveLabError
from .paths import REPO_ROOT

__all__ = ["all_labs", "find_root", "git_top", "rel_path", "resolve_lab_names"]


def git_top(start: Path) -> Path | None:
    """``git rev-parse --show-toplevel`` from ``start``; ``None`` outside git."""
    try:
        res = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = res.stdout.strip()
    return Path(out).resolve() if res.returncode == 0 and out else None


def find_root(arg: Path | None) -> Path:
    """``--root``, else the git top of the current directory, else this checkout."""
    if arg is not None:
        return arg.resolve()
    return git_top(Path.cwd()) or REPO_ROOT


def all_labs(root: Path) -> list[Path]:
    """``git ls-files '*.unl'`` under ``root``; fallback: rglob (no dot dirs)."""
    paths: list[Path] = []
    if git_top(root) == root:
        try:
            out = subprocess.run(
                ["git", "-C", str(root), "ls-files", "-z", "--", "*.unl"],
                capture_output=True,
                timeout=30,
                check=False,
            ).stdout
            paths = [root / p for p in out.decode().split("\0") if p]
        except (OSError, subprocess.SubprocessError):
            paths = []
    if not paths:
        for p in root.rglob("*.unl"):
            rel = p.relative_to(root).parts
            if any(part.startswith(".") for part in rel[:-1]):
                continue
            paths.append(p)
    return sorted(p for p in paths if p.is_file())


def rel_path(root: Path, path: Path) -> str:
    """``path`` relative to ``root`` (posix), or as given when outside it."""
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return str(path)


def resolve_lab_names(root: Path, names: Sequence[str]) -> list[Path]:
    """Paths for LAB arguments: existing files, else unique path substrings.

    A relative path is resolved against ``root`` first; a CWD-relative or
    absolute path is accepted only if it lies under ``root``, so the lab
    written and any state kept for it belong to the same tree. Errors:
    ``LAB_OUTSIDE_ROOT``, ``NO_LAB``, ``AMBIGUOUS_LAB``.
    """
    out: list[Path] = []
    labs: list[Path] | None = None
    root = root.resolve()
    for name in names:
        cand = [Path(name)] if Path(name).is_absolute() else [root / name, Path(name)]
        hit = next((c for c in cand if c.is_file()), None)
        if hit is not None:
            if not hit.resolve().is_relative_to(root):
                raise EveLabError(
                    f"{name!r} resolves to {hit.resolve()}, outside --root {root}",
                    code="LAB_OUTSIDE_ROOT",
                )
            out.append(hit.resolve())
            continue
        if labs is None:
            labs = all_labs(root)
        low = name.lower()
        matches = [p for p in labs if low in rel_path(root, p).lower()]
        if len(matches) > 1:
            exact = [p for p in matches if p.stem.lower() == low]
            matches = exact or matches
        if not matches:
            raise EveLabError(f"no lab matches {name!r}", code="NO_LAB")
        if len(matches) > 1:
            listing = ", ".join(rel_path(root, p) for p in matches)
            raise EveLabError(
                f"{name!r} matches several labs: {listing}", code="AMBIGUOUS_LAB"
            )
        out.append(matches[0].resolve())
    seen: list[Path] = []
    for p in out:
        if p not in seen:
            seen.append(p)
    return seen
