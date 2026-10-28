"""Diagnostic record reported by analysis, planning and host checks."""

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Finding:
    # e.g. "STRUCTURAL_TAGGING", "LEAK", "UNCONFIGURED", "IPV6_UNHANDLED"
    code: str
    severity: Literal["info", "warn", "conflict", "blocker", "error"]
    msg: str
    refs: list[str] = field(default_factory=list)
