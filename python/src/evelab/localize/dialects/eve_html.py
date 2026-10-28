"""EVE canvas textobjects (HTML) — text-node facts only (design 6.2, 11.2).

Only text between ``>`` and ``<`` is scanned (``blocks`` ``html`` style, which
skips tag interiors, inline ``style``, comments and whole ``<svg>`` subtrees),
so CSS pixel sizes and SVG geometry never become facts.  Facts:

* ``ip_host``      every IPv4 token, with an adjacent ``/len`` (CIDR labels such
                   as ``169.1.100.0/24`` are network addresses; the offset map
                   keeps them network addresses);
* ``vlan_mention`` ``VLAN 100``, ``cloud_ref`` ``pnetN`` and ``label_ref``
                   label words (``TENANT-1``, ``EVE-MGMT-203``), all flagged
                   cosmetic, via ``_common.label_context_rules`` (same token
                   definitions as every other dialect).

All are HEURISTIC; discovery correlates IPs inside proven subnets and the
label scenario only touches tokens equal to an old distinctive label.  HTML
entities (``&nbsp;``) are left as they are and act as separators.
"""

from __future__ import annotations

import re

from ..model import Confidence, Node
from . import register
from ._common import ContextRulesMixin, label_context_rules
from .base import PatternRule, RuleDialect

_HTML_RE = re.compile(r"<(?:div|p|span|font|br|svg|b|i|u|strong)\b", re.IGNORECASE)


@register
class EveHtml(ContextRulesMixin, RuleDialect):
    name = "eve_html"
    templates = ()
    sniff = (
        r"<div\b[^>]*\bcustom(?:Text|Shape)",
        r"</(?:p|div|span|font)>",
    )
    block_style = "html"
    mask_form = "prefix"
    default_confidence = Confidence.HEURISTIC
    subif_re = None
    priority = 10
    rules = (PatternRule("eve_html.ipv4", r"(?P<many>.+)", "ip_host"),)
    # label words, pnetN and "VLAN n" in every text-node line (cosmetic)
    context_rules = label_context_rules("eve_html", (("text", r"(?P<ctx>.+)"),))

    def score(self, node: Node | None, text: str) -> int:
        """HTML fragments (textobject ``<data>``) score 95; anything else 0."""
        head = text.lstrip()
        if head.startswith("<") and _HTML_RE.search(text):
            return 95
        return 0
