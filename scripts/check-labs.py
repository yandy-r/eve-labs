#!/usr/bin/env python3
"""Validate EVE-NG lab files.

Checks every tracked (or given) `.unl` file:
  - is well-formed XML with a `<lab>` root element
  - has a non-empty `id` attribute on `<lab>` (EVE 7 rejects labs without one)
  - that `id` is unique across all labs

Usage: scripts/check-labs.py [FILE ...]   (default: all `*.unl` tracked by git)
Exits non-zero on any failure.
"""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def tracked_labs() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.unl"],
        check=True,
        capture_output=True,
    ).stdout
    return [Path(p) for p in out.decode().split("\0") if p]


def main(argv: list[str]) -> int:
    files = [Path(a) for a in argv if a.endswith(".unl")] if argv else tracked_labs()
    errors: list[str] = []
    seen: dict[str, Path] = {}

    for path in files:
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError) as exc:
            errors.append(f"{path}: invalid XML: {exc}")
            continue
        if root.tag != "lab":
            errors.append(f"{path}: root element is <{root.tag}>, expected <lab>")
            continue
        lab_id = (root.get("id") or "").strip()
        if not lab_id:
            errors.append(f"{path}: <lab> is missing an id attribute")
        elif lab_id in seen:
            errors.append(f"{path}: duplicate lab id {lab_id} (also in {seen[lab_id]})")
        else:
            seen[lab_id] = path

    for err in errors:
        print(f"ERROR {err}", file=sys.stderr)
    print(f"check-labs: {len(files)} lab(s) checked, {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
