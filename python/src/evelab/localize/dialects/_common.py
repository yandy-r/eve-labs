"""Shared building blocks for the firewall / appliance dialects (T10).

Used by ``asa``, ``fortios`` and ``f5tmsh``; kept generic so other dialects can
reuse them.  Three mixins, each combined with :class:`RuleDialect` *before* it
in the MRO (``class X(ContextRulesMixin, ..., RuleDialect)``):

``ContextRulesMixin``
    :class:`ContextRule` = "a context region on one line" + "a token regex run
    inside it", one fact per token.  ``PatternRule`` yields one value per match,
    which cannot express "every label-like word inside a quoted alias" or "every
    domain inside ``search replace-all-with { a b }``".
``HostnameServiceMixin``
    ``dns_server`` / ``ntp_server`` facts may hold host names
    (``pool.ntp.org``); render accepts a host name there while IPv4-looking
    values are still validated strictly by ``RuleDialect.render``.
``StanzaDeleteMixin``
    the "stanza deletion support flag" (design 11.3 / 15 #34): dialects that can
    delete a whole route stanza set ``supports_stanza_delete = True`` and
    implement ``stanza_span``; callers use ``delete_stanza(fact, ctx)``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from ipaddress import AddressValueError, IPv4Address

from ..errors import LocalizeError
from ..model import Confidence, ConfigText, Fact, Span, TextEdit
from .base import ParsedConfig, RenderCtx, make_fact_id, rule_applies

# A label-like word in free text (design 10.4 distinctiveness, approximated):
# >= 5 chars of [A-Za-z0-9_-], starts/ends alphanumeric, contains a digit or a
# hyphen, is not all digits, and is not a cloud bridge reference (pnet0-trunk:
# the ``pnet0`` part is a ``cloud_ref`` instead).  Never part of an IP/FQDN.
LABEL_TOKEN = (
    r"(?<![\w.-])"
    r"(?P<v>"
    r"(?=[\w-]{5,}(?![\w-]))"
    r"(?=[\w-]*[A-Za-z_-])"
    r"(?=[\w-]*[\d-])"
    r"(?!(?:pnet|cloud|nat)\d+(?![A-Za-z0-9]))"
    r"[A-Za-z0-9](?:[\w-]*[A-Za-z0-9])?"
    r")"
    r"(?![\w-]|\.\w)"
)
# ``pnet0`` / ``cloud1`` / ``nat0`` bridge names mentioned in text.
CLOUD_TOKEN = r"(?<![\w.-])(?P<v>(?:pnet|cloud|nat)\d+)(?![\w.]|\.\w)"
# ``VLAN 3`` / ``(VLAN 201)``; never a range (``VLANs 1240-1243``).
VLAN_MENTION_TOKEN = r"\b(?i:vlan)[ ](?P<v>\d{1,4})(?![\w-]|\.\d)"
# A host name or IPv4 inside a list such as ``{ pool.ntp.org 10.1.1.1 }``.
HOST_TOKEN = r"(?<![\w.-])(?P<v>[A-Za-z0-9](?:[\w.-]*[A-Za-z0-9])?)(?![\w.-])"

HOSTNAME_RE = re.compile(
    r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)


@cache
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.MULTILINE)


@dataclass(frozen=True)
class ContextRule:
    """One fact per ``token`` match inside the ``ctx`` group of ``context``.

    ``context`` is applied line by line like a ``PatternRule`` (``^``/``$`` are
    line anchors) and must define a ``ctx`` group; ``token`` must define ``v``
    and is searched only inside ``ctx`` (it cannot see past the region end).
    """

    id: str
    context: str
    token: str
    kind: str
    block: str | None = None
    flags: tuple[str, ...] = ()
    negative: tuple[str, ...] = ()  # lines whose context must yield no token

    def __post_init__(self) -> None:
        if "ctx" not in _compile(self.context).groupindex:
            raise ValueError(f"context rule {self.id}: context needs (?P<ctx>...)")
        if "v" not in _compile(self.token).groupindex:
            raise ValueError(f"context rule {self.id}: token needs (?P<v>...)")

    def tokens(self, text: str, start: int, end: int) -> list[Span]:
        """Token spans found in ``text[start:end]`` (one physical line)."""
        out: list[Span] = []
        for m in _compile(self.context).finditer(text, start, end):
            a, b = m.span("ctx")
            if a < 0 or a == b:
                continue
            for t in _compile(self.token).finditer(text, a, b):
                if t.start("v") < t.end("v"):
                    out.append(Span(t.start("v"), t.end("v")))
        return out

    def matches_line(self, line: str) -> bool:
        return bool(self.tokens(line, 0, len(line)))


class ContextRulesMixin:
    """Adds ``context_rules`` facts on top of ``RuleDialect.parse``."""

    context_rules: tuple[ContextRule, ...] = ()

    def parse(self, ct: ConfigText) -> ParsedConfig:
        parsed: ParsedConfig = super().parse(ct)  # type: ignore[misc]
        if not self.context_rules:
            return parsed
        dialect = self  # RuleDialect helpers (_layout, _iface_block, ...)
        text = ct.text
        layout = dialect._layout(text)  # type: ignore[attr-defined]
        seen = {(f.kind, f.span.start, f.span.end) for f in parsed.facts}
        parents: dict[int, str | None] = {}
        extra: list[Fact] = []
        base_conf: Confidence = dialect.default_confidence  # type: ignore[attr-defined]
        for line in layout.lines:
            if line.skip:
                continue
            iblock = dialect._iface_block(line.chain)  # type: ignore[attr-defined]
            for rule in self.context_rules:
                if not rule_applies(rule.block, line.chain):
                    continue
                for span in rule.tokens(text, line.start, line.end):
                    key = (rule.kind, span.start, span.end)
                    if key in seen:
                        continue
                    seen.add(key)
                    orphan = iblock is not None and iblock.orphan
                    iface = parent = None
                    if iblock is not None and not orphan:
                        iface = dialect.iface_key(  # type: ignore[attr-defined]
                            iblock.name
                        )
                        parent = dialect._block_parent(  # type: ignore[attr-defined]
                            iblock, layout, parents
                        )
                    conf = (
                        min(base_conf, Confidence.CORRELATED) if orphan else base_conf
                    )
                    extra.append(
                        Fact(
                            id=make_fact_id(
                                ct.store, ct.node_id, span.start, rule.kind
                            ),
                            kind=rule.kind,
                            value=text[span.start : span.end],
                            store=ct.store,
                            node_id=ct.node_id,
                            span=span,
                            line=line.no,
                            rule=rule.id,
                            iface=iface,
                            parent=parent,
                            confidence=conf,
                            orphan=orphan,
                            flags=frozenset(rule.flags),
                        )
                    )
        if extra:
            parsed.facts.extend(extra)
            parsed.facts.sort(key=lambda f: (f.span.start, f.span.end, f.kind, f.rule))
        return parsed


def label_context_rules(
    prefix: str,
    contexts: tuple[tuple[str, str], ...],
    *,
    block: str | None = None,
) -> tuple[ContextRule, ...]:
    """``label_ref`` + ``cloud_ref`` + ``vlan_mention`` rules for free text.

    ``contexts`` is ``((suffix, context_regex), ...)``; every rule is flagged
    ``cosmetic`` (design 11.3: label tokens, ``pnet0`` mentions and ``(VLAN n)``
    text are cosmetic groups decided by the scenarios).
    """
    out: list[ContextRule] = []
    for suffix, rx in contexts:
        for kind, token, what in (
            ("label_ref", LABEL_TOKEN, "label"),
            ("cloud_ref", CLOUD_TOKEN, "cloud"),
            ("vlan_mention", VLAN_MENTION_TOKEN, "vlan"),
        ):
            out.append(
                ContextRule(
                    f"{prefix}.{suffix}_{what}",
                    rx,
                    token,
                    kind,
                    block=block,
                    flags=("cosmetic",),
                )
            )
    return tuple(out)


# --------------------------------------------------------------------------- #
# host names in service facts
# --------------------------------------------------------------------------- #

HOSTNAME_KINDS = frozenset({"dns_server", "ntp_server", "probe_target"})
_IPV4ISH = re.compile(r"[\d.]+")


class HostnameServiceMixin:
    """``dns_server``/``ntp_server``/``probe_target``: IPv4 or a host name."""

    def render(self, fact: Fact, new: str, ctx: RenderCtx) -> list[TextEdit]:
        sup = super()
        if fact.kind not in HOSTNAME_KINDS or fact.mask_span is not None:
            return sup.render(fact, new, ctx)  # type: ignore[misc,no-any-return]
        sup.render(fact, fact.value, ctx)  # type: ignore[misc]  # stale check only
        if new == fact.value:
            return []
        if _IPV4ISH.fullmatch(new):
            try:
                IPv4Address(new)
            except AddressValueError as exc:
                raise LocalizeError(
                    f"{fact.kind}: {new!r} is not an IPv4 address", code="BAD_VALUE"
                ) from exc
        elif not HOSTNAME_RE.fullmatch(new):
            raise LocalizeError(
                f"{fact.kind}: {new!r} is neither an IPv4 address nor a host name",
                code="BAD_VALUE",
            )
        return [TextEdit(fact.span.start, fact.span.end, fact.value, new)]


# --------------------------------------------------------------------------- #
# stanza deletion
# --------------------------------------------------------------------------- #


def line_span(text: str, pos: int) -> Span:
    """The physical line holding ``pos``, including its line terminator."""
    start = text.rfind("\n", 0, pos) + 1
    nl = text.find("\n", pos)
    return Span(start, len(text) if nl == -1 else nl + 1)


def through_eol(text: str, end: int) -> int:
    """``end`` extended past a directly following ``\\r\\n`` / ``\\n``."""
    if text.startswith("\r\n", end):
        return end + 2
    if text.startswith("\n", end):
        return end + 1
    return end


class StanzaDeleteMixin:
    """Whole-stanza deletion for route facts (design 11.3 ``site_routes``).

    ``supports_stanza_delete`` is the capability flag planners check with
    ``getattr(dialect, "supports_stanza_delete", False)``.  ``stanza_span``
    returns the span to delete (whole lines, terminator included) or ``None``
    when the fact is not inside a deletable stanza.
    """

    supports_stanza_delete: bool = True

    def stanza_span(self, fact: Fact, text: str) -> Span | None:
        raise NotImplementedError

    def delete_stanza(self, fact: Fact, ctx: RenderCtx) -> list[TextEdit]:
        """One edit removing the stanza holding ``fact`` (stale facts refused)."""
        self.render(fact, fact.value, ctx)  # type: ignore[attr-defined]
        span = self.stanza_span(fact, ctx.text)
        if span is None:
            raise LocalizeError(
                f"fact {fact.id} ({fact.rule}) is not inside a deletable stanza",
                code="NO_STANZA",
                refs=[fact.id],
            )
        return [TextEdit(span.start, span.end, ctx.text[span.start : span.end], "")]
