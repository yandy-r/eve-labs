"""Locations of this checkout, for tools that live in ``<repo>/python/src``."""

from pathlib import Path

# common/ -> evelab/ -> src/ -> python/ -> <repo>
REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIR = REPO_ROOT / "scripts"
