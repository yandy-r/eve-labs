"""NameExplainer: what the numbers in a cloud network name mean (design 7.4).

Every digit run of a label is classified against the segment it belongs to:

``tag``        equals a VLAN tag of the segment (``INET-1240``)
``octet3``     equals the third octet of the segment subnet (``mgmt-104``)
``host``       equals the last octet of a host attached to that network (``203-67``)
``netid``      equals the EVE network id (``mgmt58`` on network 58)
``ambiguous``  both ``tag`` and ``octet3`` (``EVE-INET-201``)
``unknown``    none of the above

The classes only drive *suggested* label templates (``EVE-MGMT-{octet3}``,
``{octet3}-{host}``, ``INET-{tag}``); they are never used as values.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from ..model import NameClass, NameToken, Span

__all__ = [
    "NameContext",
    "NameExplainer",
    "digit_runs",
    "explain",
    "octets3",
    "render_template",
    "suggest_template",
]

_DIGITS = re.compile(r"\d+")
_FIELD = re.compile(r"\{([a-z0-9]+)\}")
TEMPLATE_KINDS = ("tag", "octet3", "host", "netid")


def digit_runs(label: str) -> list[tuple[str, Span]]:
    """``[(digits, span)]`` for every digit run of ``label``."""
    return [(m.group(0), Span(m.start(), m.end())) for m in _DIGITS.finditer(label)]


def octets3(subnet: IPv4Network | None) -> set[int]:
    """Third octets covered by ``subnet`` (one for /24 or longer, else a range)."""
    if subnet is None:
        return set()
    first = int(subnet.network_address)
    if subnet.prefixlen >= 24:
        return {(first >> 8) & 0xFF}
    if subnet.prefixlen < 16:
        return set()
    count = 1 << (24 - subnet.prefixlen)
    base = (first >> 8) & 0xFF
    return {base + i for i in range(count)}


@dataclass
class NameContext:
    """What a label is compared against."""

    tags: set[int] = field(default_factory=set)
    octet3: set[int] = field(default_factory=set)
    hosts: set[int] = field(default_factory=set)
    netid: str | None = None


class NameExplainer:
    """Classifies digit runs of cloud network names."""

    def classify(self, digits: str, ctx: NameContext) -> NameClass:
        value = int(digits)
        is_tag = value in ctx.tags
        is_oct = value in ctx.octet3
        if is_tag and is_oct:
            return "ambiguous"
        if is_tag:
            return "tag"
        if is_oct:
            return "octet3"
        if value in ctx.hosts:
            return "host"
        if ctx.netid is not None and ctx.netid.isdigit() and int(ctx.netid) == value:
            return "netid"
        return "unknown"

    def explain(self, label: str, ctx: NameContext) -> list[NameToken]:
        return [
            NameToken(text, span, self.classify(text, ctx), int(text))
            for text, span in digit_runs(label)
        ]

    def template(self, label: str, tokens: Iterable[NameToken]) -> str | None:
        """Suggested template; ``None`` when a token is ambiguous (ask the user)."""
        toks = sorted(tokens, key=lambda t: t.span.start)
        if any(t.kind == "ambiguous" for t in toks):
            return None
        counts: dict[str, int] = {}
        for t in toks:
            counts[t.kind] = counts.get(t.kind, 0) + 1
        seen: dict[str, int] = {}
        out: list[str] = []
        pos = 0
        for t in toks:
            out.append(_escape(label[pos : t.span.start]))
            if t.kind in TEMPLATE_KINDS:
                seen[t.kind] = seen.get(t.kind, 0) + 1
                name = t.kind if counts[t.kind] == 1 else f"{t.kind}{seen[t.kind]}"
                out.append("{" + name + "}")
            else:
                out.append(t.text)
            pos = t.span.end
        out.append(_escape(label[pos:]))
        tpl = "".join(out)
        return tpl if "{" in tpl.replace("{{", "") else None


def _escape(text: str) -> str:
    return text.replace("{", "{{").replace("}", "}}")


_EXPLAINER = NameExplainer()


def explain(
    label: str,
    *,
    tags: Iterable[int] = (),
    octet3: Iterable[int] = (),
    hosts: Iterable[int] = (),
    netid: str | None = None,
) -> list[NameToken]:
    """Module-level shortcut for :meth:`NameExplainer.explain`."""
    ctx = NameContext(set(tags), set(octet3), set(hosts), netid)
    return _EXPLAINER.explain(label, ctx)


def suggest_template(label: str, tokens: Iterable[NameToken]) -> str | None:
    return _EXPLAINER.template(label, tokens)


def render_template(template: str, values: Mapping[str, object]) -> str:
    """Fill ``{tag}``/``{octet3}``/``{host}``/``{host1}``... (``{{`` escapes)."""

    def sub(m: re.Match[str]) -> str:
        key = m.group(1)
        if key not in values:
            raise KeyError(key)
        return str(values[key])

    parts = template.split("{{")
    out = []
    for part in parts:
        subparts = part.split("}}")
        out.append("}".join(_FIELD.sub(sub, s) for s in subparts))
    return "{".join(out)
