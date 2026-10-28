"""Fallback dialect and shared helpers for the T11 dialects (design 6.1, 11.3).

``generic`` is what ``pick`` returns when no dialect scores: it reports every
IPv4 token (``ip_host``, with an adjacent mask), distinctive label-like tokens
(``label_ref``) and ``pnetN`` mentions (``cloud_ref``), all HEURISTIC.  It never
produces tag facts.  Discovery upgrades facts that fall inside proven subnets
to CORRELATED (design 7.3 step 4); nothing here is PROVEN.

Label / ``pnetN`` tokens and the "every token inside a context region" rules
come from ``_common`` (T10: ``ContextRule``, ``LABEL_TOKEN``, ``CLOUD_TOKEN``)
so every dialect agrees on what a label word is.

Shared helper used by ``junos``, ``linuxsh`` and ``vpcs``:
``attach_iface_blocks`` synthesises ``interface`` blocks for flat / set-style
configs so facts get an ``iface`` (``dev eth0`` -> ``eth0``).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from ..model import Confidence, Span
from . import register
from ._common import CLOUD_TOKEN, LABEL_TOKEN, ContextRule, ContextRulesMixin
from .base import PatternRule, RuleDialect
from .blocks import Block, Layout, Line

# A resolver returns (iface name, name span or None) for a line, or None.
IfaceResolver = Callable[[str, Line], "tuple[str, Span | None] | None"]


def attach_iface_blocks(layout: Layout, resolver: IfaceResolver) -> Layout:
    """Give lines an ``interface`` block chosen by ``resolver`` (in place).

    Used where the syntax has no interface blocks (shell scripts, Junos set
    style).  One block per interface name; it spans from its first to its last
    line.  Lines already inside an interface block are left alone.  The
    resolver may keep state (it is called once per line, in order).
    """
    by_name: dict[str, Block] = {}
    for i, line in enumerate(layout.lines):
        if line.skip or any(b.kind == "interface" for b in line.chain):
            continue
        got = resolver(layout.text[line.start : line.end], line)
        if got is None:
            continue
        name, span = got
        blk = by_name.get(name)
        if blk is None:
            blk = Block(
                kind="interface",
                name=name,
                path=f"interface/{name}",
                start=line.start,
                end=line.end,
                header_line=line.no,
                depth=len(line.chain),
                name_span=span,
            )
            by_name[name] = blk
            layout.blocks.append(blk)
        blk.end = max(blk.end, line.end)
        layout.lines[i] = dataclasses.replace(line, chain=(*line.chain, blk))
    return layout


@register
class Generic(ContextRulesMixin, RuleDialect):
    """Unknown vendor: HEURISTIC IPv4 + label tokens, never tags (design 6.1)."""

    name = "generic"
    templates = ()
    sniff = ()
    block_style = "flat"
    mask_form = "mixed"
    default_confidence = Confidence.HEURISTIC
    subif_re = None
    rules = (
        PatternRule(
            "generic.ipv4",
            r"(?P<many>.+)",
            "ip_host",
        ),
    )
    context_rules = (
        ContextRule(
            "generic.label",
            r"(?P<ctx>.+)",
            LABEL_TOKEN,
            "label_ref",
            flags=("cosmetic",),
        ),
        ContextRule(
            "generic.cloud_ref",
            r"(?P<ctx>.+)",
            CLOUD_TOKEN,
            "cloud_ref",
            flags=("cosmetic",),
        ),
    )

    def score(self, node: object, text: str) -> int:
        """The fallback never competes in ``pick``."""
        return 0
