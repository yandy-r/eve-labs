"""Text-position primitives shared by the lab and config parsers."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Span:
    start: int
    end: int


@dataclass
class TextEdit:
    start: int
    end: int
    old: str
    new: str
