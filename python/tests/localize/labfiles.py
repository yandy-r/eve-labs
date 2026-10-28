"""Shared helpers for tests that read lab files (real labs and minilabs).

Real labs are read-only: tests must copy them to a temp dir before writing.
"""

from __future__ import annotations

import atexit
import shutil
import subprocess
import tempfile
from functools import cache
from pathlib import Path

from evelab.common.unl import RawLab

TESTS_DIR = Path(__file__).resolve().parent
REPO = TESTS_DIR.parents[2]
MINILABS = TESTS_DIR / "fixtures" / "minilabs"


@cache
def real_lab_paths() -> tuple[Path, ...]:
    """Tracked ``labs/**/*.unl`` files (falls back to a glob outside git)."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--", "labs/*.unl"],
            cwd=REPO,
            check=True,
            capture_output=True,
        ).stdout
        paths = [REPO / p for p in out.decode().split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        paths = []
    if not paths:
        paths = sorted((REPO / "labs").rglob("*.unl"))
    return tuple(sorted(paths))


@cache
def read_real(path: Path) -> RawLab:
    """Parse a lab once per test run (RawLab is never mutated)."""
    return RawLab.read(path)


def has_clouds(path: Path) -> bool:
    """True if the lab has at least one cloud (non-``bridge``) network."""
    return any(n.get("type", "bridge") != "bridge" for n in read_real(path).networks())


@cache
def cloud_lab_stems() -> tuple[str, ...]:
    """Stems of the tracked real labs WITH cloud networks (derived from the tree,
    so a new lab is covered without editing a list; review fix #28)."""
    return tuple(p.stem for p in real_lab_paths() if has_clouds(p))


@cache
def no_cloud_lab_stems() -> tuple[str, ...]:
    """Stems of the tracked real labs without cloud networks."""
    return tuple(p.stem for p in real_lab_paths() if not has_clouds(p))


def minilab_names() -> list[str]:
    """Stems of all ``fixtures/minilabs/*.unl.fixture`` files."""
    return sorted(
        p.name[: -len(".unl.fixture")] for p in MINILABS.glob("*.unl.fixture")
    )


def minilab_path(stem: str) -> Path:
    """Copy a minilab into a fresh temp dir and return the path of ``<stem>.unl``.

    Fixtures are stored as ``<stem>.unl.fixture`` so EVE and ``git ls-files '*.unl'``
    never see them.  The copy is named ``<stem>.unl`` and brings every
    ``<stem>*_cfgs`` sidecar directory along, so path logic (stem derivation, sidecar
    discovery) behaves exactly as for a real lab and tests can never write into the
    repo.  The temp dir is removed at interpreter exit.
    """
    src = MINILABS / f"{stem}.unl.fixture"
    if not src.is_file():
        raise FileNotFoundError(src)
    tmp = Path(tempfile.mkdtemp(prefix=f"evelab-localize-minilab-{stem}-"))
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)
    dest = tmp / f"{stem}.unl"
    shutil.copyfile(src, dest)
    for d in MINILABS.iterdir():
        if d.is_dir() and d.name.startswith(stem) and d.name.endswith("_cfgs"):
            shutil.copytree(d, tmp / d.name)
    return dest


def minilab(stem: str) -> RawLab:
    """Parse a temp copy of ``fixtures/minilabs/<stem>.unl.fixture``."""
    return RawLab.read(minilab_path(stem))
