"""Test suite for evelab (``cd python && python3 -m unittest discover -s tests -t .``).

Makes the ``src`` layout importable without installing the package, so the tests
run on a bare checkout (the EVE host has no pip).
"""

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
