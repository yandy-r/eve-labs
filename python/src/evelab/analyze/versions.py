"""Image naming: which host images can stand in for a lab's image, newest first.

EVE lists a QEMU image for a template when its folder is named
``<template>-<anything>`` (``nxosv9k-9300v-10.3.3.F`` for ``nxosv9k``), so the
template is the family. After the template prefix the name splits into a
*variant* (``9300v``, ``FGT``, ``adventerprisek9``) and a *version*
(``10.3.3.F``, ``v7-build2702``): the variant is everything before the first
version-like token. Same-variant images are preferred over other variants.

IOL images have no template prefix; the family is L2 or L3 (``l2`` in the
name). Dynamips images use the platform before the first ``-`` (``c7200``),
docker images the repository before ``:``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

__all__ = [
    "VERSIONED",
    "Candidate",
    "candidates",
    "family",
    "newest",
    "split_image",
    "version_key",
]

# Types whose names carry a comparable version. IOL builds and docker tags do
# not (``latest`` vs ``v2``), so they never get "newer" upgrade offers.
VERSIONED = ("qemu", "dynamips")

_VERSIONISH = re.compile(r"(?:v|build|r)?\d+", re.IGNORECASE)
_PIECES = re.compile(r"\d+|[a-z]+", re.IGNORECASE)


def _version_like(token: str) -> bool:
    if not any(ch.isdigit() for ch in token):
        return False
    return "." in token or bool(_VERSIONISH.fullmatch(token))


def split_image(node_type: str, template: str, image: str) -> tuple[str, str]:
    """``(variant, version)`` of ``image``; ``variant`` may be empty."""
    if node_type == "docker":
        repo, _, tag = image.partition(":")
        return repo, tag or "latest"
    rest = image
    if node_type == "qemu" and template and image.startswith(template + "-"):
        rest = image[len(template) + 1 :]
    elif node_type in ("dynamips", "iol"):
        return family(node_type, template, image), image
    tokens = rest.split("-")
    for i, tok in enumerate(tokens):
        if _version_like(tok):
            return "-".join(tokens[:i]), "-".join(tokens[i:])
    return rest, ""


def family(node_type: str, template: str, image: str) -> str:
    """Images of one family can replace each other (see the module docstring)."""
    if node_type == "qemu":
        return template
    if node_type == "iol":
        return "l2" if re.search(r"l2", image, re.IGNORECASE) else "l3"
    if node_type == "dynamips":
        return image.split("-", 1)[0].lower()
    if node_type == "docker":
        return image.partition(":")[0]
    return node_type


def version_key(text: str) -> tuple[tuple[int, int, str], ...]:
    """Natural sort key: numbers compare as numbers, words case-insensitively."""
    return tuple(
        (1, int(p), "") if p.isdigit() else (0, 0, p.lower())
        for p in _PIECES.findall(text)
    )


@dataclass(frozen=True)
class Candidate:
    """A host image that can replace a lab image."""

    image: str
    same_variant: bool
    newer: bool  # same variant and a higher version than the lab's image

    @property
    def note(self) -> str:
        parts = ["newer" if self.newer else ""]
        if not self.same_variant:
            parts.append("other variant")
        return ", ".join(p for p in parts if p)


def _in_family(node_type: str, template: str, fam: str, name: str) -> bool:
    if node_type == "qemu":
        return name.startswith(template + "-")
    return family(node_type, template, name) == fam


def candidates(
    node_type: str, template: str, image: str, host_images: Iterable[str]
) -> list[Candidate]:
    """Host images of ``image``'s family (``image`` itself excluded).

    Order: same variant first, then newest version first within each group.
    ``newer`` is only set for :data:`VERSIONED` types.
    """
    fam = family(node_type, template, image)
    variant, version = split_image(node_type, template, image)
    vkey = version_key(version)
    ordered = node_type in VERSIONED
    out: list[tuple[bool, tuple[tuple[int, int, str], ...], Candidate]] = []
    for name in host_images:
        if name == image or not _in_family(node_type, template, fam, name):
            continue
        v2, ver2 = split_image(node_type, template, name)
        same = v2.lower() == variant.lower()
        key = version_key(ver2)
        newer = ordered and same and key > vkey
        out.append((same, key, Candidate(name, same, newer)))
    out.sort(key=lambda t: t[2].image)
    out.sort(key=lambda t: t[1], reverse=True)  # stable: newest first
    out.sort(key=lambda t: not t[0])  # same variant first
    return [c for _, _, c in out]


def newest(cands: Sequence[Candidate]) -> Candidate | None:
    """The first same-variant candidate, else the first candidate."""
    same = [c for c in cands if c.same_variant]
    return (same or list(cands) or [None])[0]
