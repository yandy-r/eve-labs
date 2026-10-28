"""Dialect contract and the data-driven ``RuleDialect`` (design section 6.1).

Most vendors only declare data::

    @register
    class EOS(RuleDialect):
        name = "eos"
        templates = ("veos*", "ceos*")
        sniff = (r"^! device: .* EOS",)
        block_style = "indent"
        mask_form = "prefix"
        iface_aliases = {"Et": "Ethernet", "Ma": "Management"}
        rules = (
            PatternRule("eos.ip", r"^\\s+ip address (?P<v>IPV4)(?P<mask>/\\d+)$",
                        "ip_host", block="interface"),
        )

Rule patterns are applied **line by line** (``finditer`` limited to one physical
line, ``re.MULTILINE``), so ``^`` and ``$`` are line anchors and ``\\s`` never
crosses a newline.  Inside a pattern ``IPV4`` expands to the boundary-aware IPv4
token and ``MASK`` to "``/NN`` or dotted quad" (both non-capturing).

Named groups understood by :meth:`RuleDialect.parse`:

``v``       the value (required unless ``many`` is used).  Fact span = this group.
``mask``    adjacent mask token (``/24``, ``255.255.255.0``, value after ``netmask``;
            a contiguous ``0.0.0.255`` ACL wildcard gets mask_form ``wildcard``).
``wildcard`` adjacent ACL wildcard token, always read as a host mask (so
            ``0.0.0.0`` is /32); rewritten as a wildcard when the prefix changes.
``parent``  physical parent interface (raw name; stored as an iface key).
``list``    the VLAN list text (list rules; falls back to ``v``).
``many``    a region holding several IPv4 tokens: one fact per token
            (with its own mask when ``find_ipv4`` finds one); ``v`` is ignored.
``add``     (role ``trunk_allowed``) present when the line says ``add``.
``kw``      (role ``trunk_allowed``) ``all`` or ``none``: no list fact is made.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from ipaddress import AddressValueError, IPv4Address
from pathlib import Path
from typing import ClassVar, Literal, Protocol, cast, runtime_checkable

from evelab.common.textutil import (
    IPV4_SRC,
    MASK_SRC,
    LineIndex,
    VlanList,
    VlanListError,
    find_ipv4,
    find_ipv6,
    hostmask_to_prefix,
    mask_form_of,
    mask_prefix_as,
    mask_render,
)

from ..errors import ConflictError, LocalizeError
from ..model import (
    CORE_FACT_KINDS,
    Confidence,
    ConfigText,
    Fact,
    Node,
    Span,
    Store,
    TextEdit,
)
from . import blocks as _blocks
from .blocks import Block, Layout, Line

MaskForm = Literal["dotted", "prefix", "netmask", "wildcard", "none"]
BLOCK_STYLES = _blocks.STYLES
LIST_STYLES = ("nxos", "ios", "space", "brace")
MASK_FORMS = ("dotted", "prefix", "mixed")
# Roles let a rule feed IfaceInfo / vlan_db (see RuleDialect).
ROLES = (
    "access_vlan",
    "trunk_allowed",
    "native_vlan",
    "encap_tag",
    "mode_access",
    "mode_trunk",
)

IPV4_KINDS = frozenset(
    {
        "ip_host",
        "ip_gateway",
        "ip_route_dst",
        "dns_server",
        "ntp_server",
        "peer_ip",
        "router_id",
    }
)
INT_KINDS = frozenset({"vlan_tag", "asn"})
LIST_KINDS = frozenset({"vlan_list"})

_PLACEHOLDERS = re.compile(r"\b(IPV4|MASK)\b")
_PLACEHOLDER_SRC = {"IPV4": f"(?:{IPV4_SRC})", "MASK": MASK_SRC}


@cache
def compile_pattern(pattern: str) -> re.Pattern[str]:
    """Expand ``IPV4`` / ``MASK`` and compile with ``re.MULTILINE``."""
    expanded = _PLACEHOLDERS.sub(lambda m: _PLACEHOLDER_SRC[m.group(1)], pattern)
    return re.compile(expanded, re.MULTILINE)


@dataclass(frozen=True)
class PatternRule:
    id: str  # "iosxe.encap_dot1q"
    pattern: str  # Python regex; named groups v [, mask, parent, list, many, ...]
    kind: str  # a fact kind; "" = no fact, role only
    block: str | None = None  # "interface" | "vlan" | "vrf" | "system dns" | ... | None
    l2: bool = False  # contributes to l2_ports()
    list_style: Literal["nxos", "ios", "space", "brace"] | None = None
    anchored_keywords: tuple[str, ...] = ()  # documentation + negative-test hints
    negative: tuple[str, ...] = ()  # example lines that must NOT match
    # Extensions (design 6.1 lists the fields above; these default to "off"):
    role: str | None = None  # one of ROLES; inferred from kind + l2 when None
    flags: tuple[str, ...] = ()  # copied to Fact.flags, e.g. ("cosmetic",)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("PatternRule needs an id")
        if self.list_style is not None and self.list_style not in LIST_STYLES:
            raise ValueError(f"rule {self.id}: bad list_style {self.list_style!r}")
        if self.role is not None and self.role not in ROLES:
            raise ValueError(f"rule {self.id}: bad role {self.role!r}")
        if not self.kind and self.role is None:
            raise ValueError(f"rule {self.id}: empty kind needs a role")
        try:
            rx = compile_pattern(self.pattern)
        except re.error as exc:
            raise ValueError(f"rule {self.id}: bad pattern: {exc}") from exc
        groups = set(rx.groupindex)
        if self.kind and not groups & {"v", "many", "list"}:
            raise ValueError(f"rule {self.id}: pattern needs a (?P<v>...) group")

    def regex(self) -> re.Pattern[str]:
        """Compiled pattern (placeholders expanded, MULTILINE)."""
        return compile_pattern(self.pattern)

    def effective_role(self) -> str | None:
        if self.role:
            return self.role
        if self.l2 and self.kind == "vlan_tag":
            return "access_vlan"
        if self.l2 and self.kind == "vlan_list":
            return "trunk_allowed"
        return None

    def matches_line(self, line: str) -> bool:
        """True if the rule's regex matches somewhere in ``line``."""
        return self.regex().search(line) is not None


@dataclass(frozen=True)
class RenderCtx:
    """Context for :meth:`Dialect.render`.

    ``text`` is the store text the fact was parsed from (used to verify the span
    still holds the old value).  ``new_prefix`` asks for the fact's adjacent mask
    token to be rewritten, in its own form, when the prefix length changes.
    """

    text: str
    new_prefix: int | None = None


@dataclass
class IfaceInfo:
    key: str
    name: str
    parent: str | None
    name_span: Span | None
    mode: Literal["routed", "access", "trunk", "unknown"]
    access_vlan: int | None
    trunk_vlans: VlanList | None  # None = ALL (no allowed list)
    native_vlan: int | None
    tag: int | None
    dhcp: bool
    orphan: bool


@dataclass
class ParsedConfig:
    dialect: str
    facts: list[Fact]
    ifaces: dict[str, IfaceInfo]
    vlan_db: set[int]  # explicit `vlan N` defs | implicit (access/allowed/SVI)
    is_switch: bool
    notes: list[str]


@dataclass
class _Event:
    """A matched rule with a role: feeds IfaceInfo after the scan."""

    role: str
    facts: list[Fact]
    groups: Mapping[str, str | None]
    iblock: Block | None
    line: int


@runtime_checkable
class Dialect(Protocol):
    name: str
    templates: tuple[str, ...]  # fnmatch on node.template / node.image
    sniff: tuple[str, ...]  # content regexes
    block_style: Literal["indent", "fortios", "brace", "flat", "html"]
    mask_form: Literal["dotted", "prefix", "mixed"]

    def score(self, node: Node | None, text: str) -> int: ...
    def iface_key(self, name: str) -> str: ...
    def eve_to_config(self, eve_name: str) -> list[str]: ...
    def parse(self, ct: ConfigText) -> ParsedConfig: ...
    def render(self, fact: Fact, new: str, ctx: RenderCtx) -> list[TextEdit]: ...
    def secret_spans(self, text: str) -> list[Span]: ...


def make_fact_id(store: Store, node_id: str | None, start: int, kind: str) -> str:
    """Stable id: ``sha1(store, node, start, kind)[:12]``."""
    raw = "\x1f".join(
        (store.kind, store.name, store.scope, node_id or "", str(start), kind)
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def _validate_value(kind: str, new: str) -> None:
    if kind in IPV4_KINDS:
        try:
            IPv4Address(new)
        except AddressValueError as exc:
            raise LocalizeError(
                f"{kind}: {new!r} is not an IPv4 address", code="BAD_VALUE"
            ) from exc
    elif kind in INT_KINDS:
        if not new.isdigit():
            raise LocalizeError(f"{kind}: {new!r} is not a number", code="BAD_VALUE")
        if kind == "vlan_tag" and int(new) > 4095:
            raise LocalizeError(f"{kind}: {new!r} out of range", code="BAD_VALUE")
    elif kind in LIST_KINDS:
        try:
            VlanList.parse(new)
        except VlanListError as exc:
            raise LocalizeError(f"{kind}: {exc}", code="BAD_VALUE") from exc


def _block_matches(rule_block: str, kind: str) -> bool:
    if rule_block == kind:
        return True
    if any(c in rule_block for c in "*?["):
        return fnmatch.fnmatchcase(kind, rule_block)
    return kind.startswith(rule_block + ":")


def rule_applies(rule_block: str | None, chain: Sequence[Block]) -> bool:
    """Block filter: None = anywhere, ``"top"`` = outside any block."""
    if rule_block is None:
        return True
    if rule_block == "top":
        return not chain
    return any(_block_matches(rule_block, b.kind) for b in chain)


_ALPHA_PREFIX_RE = re.compile(r"^([A-Za-z][A-Za-z-]*?)\s*(\d.*|)$")


class RuleDialect:
    """Default dialect implementation driven by ``rules`` / ``secret_rules``.

    Class attributes to set in a subclass: ``name``, ``templates``, ``sniff``,
    ``block_style``, ``mask_form``, ``rules``, ``secret_rules``,
    ``iface_aliases`` (abbreviation -> full name, e.g. ``{"Gi":
    "GigabitEthernet"}``) and optionally:

    ``iface_block_kinds``  block kinds (fnmatch ok) that are interfaces
                           (default ``("interface",)``; fortios ``("edit:system
                           interface",)``).
    ``block_starts``       override of ``blocks.DEFAULT_INDENT_STARTS``.
    ``block_parent_re``    regex (group ``parent``) searched in an interface
                           block to find its physical parent (fortios ``set
                           interface "port8"``).
    ``subif_re``           regex (group ``parent``) on the interface name giving
                           the parent of a subinterface (default ``X.N``);
                           ``None`` disables it.
    ``default_confidence`` confidence of a parsed fact (orphans: CORRELATED max).
    ``detect_ipv6``        emit ``ipv6_literal`` facts (default True).
    ``priority``           tie-break in ``pick`` when scores are equal.
    """

    name: str = ""
    templates: tuple[str, ...] = ()
    sniff: tuple[str, ...] = ()
    block_style: Literal["indent", "fortios", "brace", "flat", "html"] = "indent"
    mask_form: Literal["dotted", "prefix", "mixed"] = "dotted"
    rules: tuple[PatternRule, ...] = ()
    secret_rules: tuple[str, ...] = ()
    iface_aliases: ClassVar[dict[str, str]] = {}

    iface_block_kinds: tuple[str, ...] = ("interface",)
    block_starts: tuple[tuple[str, str], ...] | None = None
    block_parent_re: str | None = None
    subif_re: str | None = r"^(?P<parent>\S+?)\.\d+$"
    default_confidence: Confidence = Confidence.PROVEN
    detect_ipv6: bool = True
    priority: int = 0

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if not cls.__dict__.get("name"):
            return  # abstract intermediate class
        cls.validate_spec()

    # ------------------------------------------------------------ validation

    @classmethod
    def validate_spec(cls) -> None:
        """Fail early on a malformed declaration (called at class creation)."""
        if cls.block_style not in BLOCK_STYLES:
            raise ValueError(f"{cls.name}: bad block_style {cls.block_style!r}")
        if cls.mask_form not in MASK_FORMS:
            raise ValueError(f"{cls.name}: bad mask_form {cls.mask_form!r}")
        seen: set[str] = set()
        for rule in cls.rules:
            if rule.id in seen:
                raise ValueError(f"{cls.name}: duplicate rule id {rule.id!r}")
            seen.add(rule.id)
            if rule.kind and rule.kind not in CORE_FACT_KINDS:
                raise ValueError(
                    f"{cls.name}: rule {rule.id} uses unregistered fact kind "
                    f"{rule.kind!r} (add it to model.CORE_FACT_KINDS first)"
                )
        for rx in (*cls.sniff, *cls.secret_rules):
            re.compile(rx, re.MULTILINE)
        for rx in (cls.block_parent_re, cls.subif_re):
            if rx:
                re.compile(rx)

    # --------------------------------------------------------------- scoring

    def score(self, node: Node | None, text: str) -> int:
        """0..100 from template/image (70) plus content sniff (up to +30).

        Never looks at the node *name*.  Sniff-only matches reach 50.
        """
        by_node = False
        if node is not None:
            subjects = [s.lower() for s in (node.template, node.image) if s]
            by_node = any(
                fnmatch.fnmatchcase(s, pat.lower())
                for s in subjects
                for pat in self.templates
            )
        hits = sum(
            1 for rx in self.sniff if re.search(rx, text, re.MULTILINE) is not None
        )
        if by_node:
            return 70 + (30 if hits else 0)
        return min(50, 20 + 10 * hits) if hits else 0

    # ---------------------------------------------------------------- ifaces

    def _split_iface(self, name: str) -> tuple[str, str]:
        m = _ALPHA_PREFIX_RE.match(name.strip())
        if m is None:
            return "", name.strip()
        return m.group(1), m.group(2)

    def _canon_prefix(self, prefix: str) -> str:
        """Lower-case canonical abbreviation for an interface name prefix."""
        low = prefix.lower()
        if not low or not self.iface_aliases:
            return low
        fulls: dict[str, str] = {}  # full.lower() -> first abbreviation
        for abbr, full in self.iface_aliases.items():
            fulls.setdefault(full.lower(), abbr.lower())
        for abbr, full in self.iface_aliases.items():
            if abbr.lower() == low:
                return fulls[full.lower()]
        matches = {full for full in fulls if full.startswith(low)}
        if len(matches) == 1:
            return fulls[matches.pop()]
        return low

    def iface_key(self, name: str) -> str:
        """``GigabitEthernet16.2`` / ``Gi16.2`` -> ``gi16.2`` (lower, no spaces)."""
        prefix, rest = self._split_iface(name)
        return self._canon_prefix(prefix) + re.sub(r"\s+", "", rest).lower()

    def eve_to_config(self, eve_name: str) -> list[str]:
        """EVE port name -> candidate config names (``Gi16`` -> GigabitEthernet16)."""
        prefix, rest = self._split_iface(eve_name)
        low = prefix.lower()
        out: list[str] = []
        for abbr, full in self.iface_aliases.items():
            if abbr.lower() == low or (low and full.lower().startswith(low)):
                cand = full + rest
                if cand not in out:
                    out.append(cand)
        return out or [eve_name]

    # ----------------------------------------------------------------- parse

    def _layout(self, text: str) -> Layout:
        return _blocks.split(text, self.block_style, self.block_starts)

    def _iface_block(self, chain: Sequence[Block]) -> Block | None:
        for blk in reversed(chain):
            if any(_block_matches(k, blk.kind) for k in self.iface_block_kinds):
                return blk
        return None

    def _block_parent(
        self, blk: Block, layout: Layout, cache_: dict[int, str | None]
    ) -> str | None:
        ident = id(blk)
        if ident in cache_:
            return cache_[ident]
        parent: str | None = None
        if self.block_parent_re:
            rx = re.compile(self.block_parent_re, re.MULTILINE)
            for ln in layout.block_lines(blk):
                m = rx.search(layout.text, ln.start, ln.end)
                if m and m.group("parent"):
                    parent = self.iface_key(m.group("parent"))
                    break
        if parent is None and self.subif_re and blk.name:
            m2 = re.match(self.subif_re, blk.name)
            if m2:
                parent = self.iface_key(m2.group("parent"))
        cache_[ident] = parent
        return parent

    def _rules_for_chain(
        self, chain: Sequence[Block]
    ) -> tuple[tuple[PatternRule, re.Pattern[str], str | None], ...]:
        """The rules whose block filter accepts ``chain`` (memoised).

        ``rule_applies`` only depends on the block kinds of the chain, so the
        applicable ``(rule, regex, role)`` list is cached per kind tuple (and
        per ``rules`` object, so a manifest-extended copy has its own cache).
        Rule order is preserved.  Performance fix (review #38).
        """
        kinds = tuple(b.kind for b in chain)
        memo = self.__dict__.get("_rule_memo")
        if memo is None or memo[0] is not self.rules:
            memo = (self.rules, {})
            self.__dict__["_rule_memo"] = memo
        hit = memo[1].get(kinds)
        if hit is None:
            hit = tuple(
                (r, r.regex(), r.effective_role())
                for r in self.rules
                if rule_applies(r.block, chain)
            )
            memo[1][kinds] = hit
        return hit

    def parse(self, ct: ConfigText) -> ParsedConfig:
        text = ct.text
        layout = self._layout(text)
        lines_idx = LineIndex(text)
        facts: list[Fact] = []
        events: list[_Event] = []
        seen: set[tuple[str, int, int]] = set()
        notes: list[str] = []
        parents: dict[int, str | None] = {}

        def add(
            kind: str,
            rule_id: str,
            span: Span,
            line: Line,
            iblock: Block | None,
            *,
            rule: PatternRule | None = None,
            mask: tuple[Span, str] | None = None,
            list_value: VlanList | None = None,
            parent: str | None = None,
            extra_flags: frozenset[str] = frozenset(),
            confidence: Confidence | None = None,
        ) -> Fact | None:
            key = (kind, span.start, span.end)
            if key in seen:
                return None
            seen.add(key)
            orphan = iblock is not None and iblock.orphan
            iface = None
            if iblock is not None and not orphan:
                iface = self.iface_key(iblock.name)
            if parent is None and iblock is not None and not orphan:
                parent = self._block_parent(iblock, layout, parents)
            conf = confidence if confidence is not None else self.default_confidence
            if orphan:
                conf = min(conf, Confidence.CORRELATED)
            flags = frozenset(rule.flags) if rule else frozenset()
            fact = Fact(
                id=make_fact_id(ct.store, ct.node_id, span.start, kind),
                kind=kind,
                value=text[span.start : span.end],
                store=ct.store,
                node_id=ct.node_id,
                span=span,
                line=line.no,
                rule=rule_id,
                iface=iface,
                parent=parent,
                mask_span=mask[0] if mask else None,
                mask_form=cast(MaskForm, mask[1]) if mask else "none",
                list_value=list_value,
                confidence=conf,
                orphan=orphan,
                flags=flags | extra_flags,
            )
            facts.append(fact)
            return fact

        for line in layout.lines:
            if line.skip:
                continue
            iblock = self._iface_block(line.chain)
            for rule, rx, role in self._rules_for_chain(line.chain):
                for m in rx.finditer(text, line.start, line.end):
                    gd = m.groupdict()
                    made: list[Fact] = []
                    if gd.get("many") is not None:
                        for tok in find_ipv4(text, m.start("many"), m.end("many")):
                            mk = (
                                (tok.mask.span, tok.mask.form)
                                if tok.mask and not tok.mask.wildcard
                                else None
                            )
                            f = add(
                                rule.kind,
                                rule.id,
                                tok.span,
                                line,
                                iblock,
                                rule=rule,
                                mask=mk,
                            )
                            if f:
                                made.append(f)
                    elif rule.kind:
                        group = "list" if gd.get("list") else "v"
                        if not gd.get(group):
                            continue
                        span = Span(m.start(group), m.end(group))
                        lv: VlanList | None = None
                        if rule.list_style or rule.kind in LIST_KINDS:
                            try:
                                lv = VlanList.parse(m.group(group))
                            except VlanListError as exc:
                                notes.append(f"line {line.no}: {rule.id}: {exc}")
                                continue
                        mk = None
                        if gd.get("mask"):
                            mtext = m.group("mask")
                            before = text[line.start : m.start("mask")].rstrip()
                            form = mask_form_of(
                                mtext, keyword_before=before.endswith("netmask")
                            )
                            if form != "none":
                                mk = (Span(m.start("mask"), m.end("mask")), form)
                        elif gd.get("wildcard"):
                            # declared ACL wildcard: 0.0.0.0 is /32, not /0
                            if hostmask_to_prefix(m.group("wildcard")) is not None:
                                ws = Span(m.start("wildcard"), m.end("wildcard"))
                                mk = (ws, "wildcard")
                        parent = (
                            self.iface_key(gd["parent"]) if gd.get("parent") else None
                        )
                        f = add(
                            rule.kind,
                            rule.id,
                            span,
                            line,
                            iblock,
                            rule=rule,
                            mask=mk,
                            list_value=lv,
                            parent=parent,
                        )
                        if f:
                            made.append(f)
                    if role:
                        events.append(_Event(role, made, gd, iblock, line.no))
            if self.detect_ipv6 and ":" in layout.text[line.start : line.end]:
                for tok6 in find_ipv6(text, line.start, line.end):
                    add(
                        "ipv6_literal",
                        f"{self.name}.ipv6",
                        tok6.span,
                        line,
                        iblock,
                        confidence=Confidence.HEURISTIC,
                    )

        for span in self._secret_spans(layout):
            line_no = lines_idx.line(span.start)
            key = ("secret", span.start, span.end)
            if key in seen:
                continue
            seen.add(key)
            iblock = None
            ln = layout.line_at(span.start)
            if ln is not None:
                iblock = self._iface_block(ln.chain)
            facts.append(
                Fact(
                    id=make_fact_id(ct.store, ct.node_id, span.start, "secret"),
                    kind="secret",
                    value=text[span.start : span.end],
                    store=ct.store,
                    node_id=ct.node_id,
                    span=span,
                    line=line_no,
                    rule=f"{self.name}.secret",
                    iface=(
                        self.iface_key(iblock.name)
                        if iblock is not None and not iblock.orphan
                        else None
                    ),
                    parent=None,
                    confidence=self.default_confidence,
                    flags=frozenset({"secret"}),
                )
            )

        self._group_facts(facts)
        facts.sort(key=lambda f: (f.span.start, f.span.end, f.kind, f.rule))
        ifaces = self._build_ifaces(layout, facts, events, parents)
        vlan_db = self._build_vlan_db(facts, ifaces)
        return ParsedConfig(
            dialect=self.name,
            facts=facts,
            ifaces=ifaces,
            vlan_db=vlan_db,
            is_switch=self._is_switch(ifaces),
            notes=notes,
        )

    # ------------------------------------------------------- parse internals

    def _group_facts(self, facts: list[Fact]) -> None:
        """Tie a subif/SVI name to the tag facts of the same interface."""
        named = {
            f.iface for f in facts if f.kind in ("subif_name", "svi_name") and f.iface
        }
        for f in facts:
            if f.iface in named and f.kind in ("subif_name", "svi_name", "vlan_tag"):
                f.group = f"subif:{f.iface}"

    def _build_ifaces(
        self,
        layout: Layout,
        facts: list[Fact],
        events: list[_Event],
        parents: dict[int, str | None],
    ) -> dict[str, IfaceInfo]:
        ifaces: dict[str, IfaceInfo] = {}
        keys: dict[int, str] = {}
        for blk in layout.blocks:
            if not any(_block_matches(k, blk.kind) for k in self.iface_block_kinds):
                continue
            if blk.orphan:
                key = f"orphan:{blk.header_line}"
                parent = None
            else:
                key = self.iface_key(blk.name)
                parent = self._block_parent(blk, layout, parents)
            keys[id(blk)] = key
            ifaces[key] = IfaceInfo(
                key=key,
                name=blk.name,
                parent=parent,
                name_span=blk.name_span,
                mode="unknown",
                access_vlan=None,
                trunk_vlans=None,
                native_vlan=None,
                tag=None,
                dhcp=False,
                orphan=blk.orphan,
            )
        flags: dict[str, set[str]] = {k: set() for k in ifaces}
        for ev in events:
            if ev.iblock is None or id(ev.iblock) not in keys:
                continue
            key = keys[id(ev.iblock)]
            info = ifaces[key]
            fact = ev.facts[0] if ev.facts else None
            if ev.role == "access_vlan" and fact and fact.value.isdigit():
                info.access_vlan = int(fact.value)
                flags[key].add("access")
            elif ev.role == "native_vlan" and fact and fact.value.isdigit():
                info.native_vlan = int(fact.value)
            elif ev.role == "encap_tag" and fact and fact.value.isdigit():
                info.tag = int(fact.value)
            elif ev.role == "mode_access":
                flags[key].add("access")
            elif ev.role == "mode_trunk":
                flags[key].add("trunk")
            elif ev.role == "trunk_allowed":
                flags[key].add("trunk_allowed")
                kw = (ev.groups.get("kw") or "").lower()
                if kw == "all":
                    info.trunk_vlans = None
                elif kw == "none":
                    info.trunk_vlans = VlanList(())
                elif fact and fact.list_value is not None:
                    if ev.groups.get("add"):
                        if info.trunk_vlans is not None:
                            info.trunk_vlans = VlanList.from_vlans(
                                [*info.trunk_vlans, *fact.list_value],
                                fact.list_value.sep,
                            )
                    else:
                        info.trunk_vlans = fact.list_value
        for f in facts:
            if f.kind == "dhcp" and f.iface in ifaces:
                ifaces[f.iface].dhcp = True
        routed = {f.iface for f in facts if f.kind in ("ip_host", "dhcp") and f.iface}
        for key, info in ifaces.items():
            fl = flags[key]
            if "trunk" in fl or "trunk_allowed" in fl:
                info.mode = "trunk"
            elif "access" in fl:
                info.mode = "access"
            elif key in routed:
                info.mode = "routed"
        return ifaces

    def _is_switch(self, ifaces: Mapping[str, IfaceInfo]) -> bool:
        return any(i.mode in ("access", "trunk") for i in ifaces.values())

    def l2_ports(self, parsed: ParsedConfig) -> list[IfaceInfo]:
        """Interfaces configured as access or trunk ports."""
        return [i for i in parsed.ifaces.values() if i.mode in ("access", "trunk")]

    def _build_vlan_db(
        self, facts: Sequence[Fact], ifaces: Mapping[str, IfaceInfo]
    ) -> set[int]:
        db: set[int] = set()
        for f in facts:
            if f.kind in ("vlan_def", "vlan_list") and not f.orphan:
                try:
                    db.update(VlanList.parse(f.value))
                except VlanListError:
                    continue
            elif f.kind == "svi_name" and not f.orphan:
                m = re.search(r"(\d+)$", f.value)
                if m:
                    db.add(int(m.group(1)))
        for info in ifaces.values():
            if info.access_vlan is not None and not info.orphan:
                db.add(info.access_vlan)
        return db

    # ---------------------------------------------------------------- secrets

    def _secret_spans(self, layout: Layout) -> list[Span]:
        spans: list[Span] = []
        if not self.secret_rules:
            return spans
        compiled = [re.compile(rx, re.MULTILINE) for rx in self.secret_rules]
        for line in layout.lines:
            if line.skip:
                continue
            for rx in compiled:
                for m in rx.finditer(layout.text, line.start, line.end):
                    group = "s" if "s" in rx.groupindex else 0
                    if m.start(group) < m.end(group):
                        spans.append(Span(m.start(group), m.end(group)))
        return sorted(set(spans), key=lambda s: (s.start, s.end))

    def secret_spans(self, text: str) -> list[Span]:
        """Spans of committed secrets (group ``s`` of each secret rule)."""
        return self._secret_spans(self._layout(text))

    # ----------------------------------------------------------------- render

    def render(self, fact: Fact, new: str, ctx: RenderCtx) -> list[TextEdit]:
        """Edits that give ``fact`` the value ``new``.

        Returns ``[]`` for a no-op.  When ``ctx.new_prefix`` differs from the
        prefix of the adjacent mask token a second edit rewrites that token in
        its own form (dotted / ``/n`` / after ``netmask``).
        """
        text = ctx.text
        cur = text[fact.span.start : fact.span.end]
        if cur != fact.value:
            raise ConflictError(
                f"fact {fact.id} ({fact.rule}) is stale: expected {fact.value!r}, "
                f"found {cur!r}",
                code="STALE_FACT",
                refs=[fact.id],
            )
        edits: list[TextEdit] = []
        if new != fact.value:
            _validate_value(fact.kind, new)
            edits.append(TextEdit(fact.span.start, fact.span.end, fact.value, new))
        if fact.mask_span is not None and ctx.new_prefix is not None:
            old_mask = text[fact.mask_span.start : fact.mask_span.end]
            old_prefix = mask_prefix_as(old_mask, fact.mask_form)
            if old_prefix is not None and old_prefix != ctx.new_prefix:
                rendered = mask_render(fact.mask_form, ctx.new_prefix)
                if fact.mask_form == "prefix" and not old_mask.startswith("/"):
                    rendered = rendered[1:]
                edits.append(
                    TextEdit(
                        fact.mask_span.start, fact.mask_span.end, old_mask, rendered
                    )
                )
        edits.sort(key=lambda e: e.start)
        return edits


# --------------------------------------------------------------------------- #
# Declarative specs (TOML packs build their classes through this)
# --------------------------------------------------------------------------- #

_SPEC_KEYS = {
    "dialect",
    "templates",
    "sniff",
    "block_style",
    "mask_form",
    "iface_aliases",
    "secret_rules",
    "fact_kinds",
    "iface_block_kinds",
    "block_parent_re",
    "subif_re",
    "priority",
    "rule",
}
_RULE_KEYS = {
    "id",
    "pattern",
    "kind",
    "block",
    "l2",
    "list_style",
    "anchored_keywords",
    "negative",
    "role",
    "flags",
}


def _str_tuple(value: object, what: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(v, str) for v in value
    ):
        raise ValueError(f"{what} must be a list of strings")
    return tuple(value)


def rule_from_dict(data: Mapping[str, object], where: str) -> PatternRule:
    """Build a ``PatternRule`` from a TOML ``[[rule]]`` table (strict keys)."""
    unknown = set(data) - _RULE_KEYS
    if unknown:
        raise ValueError(f"{where}: unknown rule keys {sorted(unknown)}")
    for req in ("id", "pattern", "kind"):
        if not isinstance(data.get(req), str):
            raise ValueError(f"{where}: rule needs string {req!r}")
    kwargs: dict[str, object] = {}
    for key in ("block", "list_style", "role"):
        if key in data:
            if not isinstance(data[key], str):
                raise ValueError(f"{where}: {key} must be a string")
            kwargs[key] = data[key]
    if "l2" in data:
        if not isinstance(data["l2"], bool):
            raise ValueError(f"{where}: l2 must be a boolean")
        kwargs["l2"] = data["l2"]
    for key in ("anchored_keywords", "negative", "flags"):
        if key in data:
            kwargs[key] = _str_tuple(data[key], f"{where}: {key}")
    return PatternRule(
        str(data["id"]),
        str(data["pattern"]),
        str(data["kind"]),
        **kwargs,  # type: ignore[arg-type]
    )


def build_rule_dialect(
    spec: Mapping[str, object], source: str = "<spec>"
) -> type[RuleDialect]:
    """Create a ``RuleDialect`` subclass from a declarative spec dict.

    Same keys as a TOML pack (``dialect``, ``templates``, ``sniff``,
    ``block_style``, ``mask_form``, ``iface_aliases``, ``secret_rules``,
    ``fact_kinds``, ``iface_block_kinds``, ``block_parent_re``, ``subif_re``,
    ``priority`` and ``[[rule]]`` tables).  Unknown keys are errors.  Extra
    ``fact_kinds`` are added to ``model.CORE_FACT_KINDS``.
    """
    unknown = set(spec) - _SPEC_KEYS
    if unknown:
        raise ValueError(f"{source}: unknown keys {sorted(unknown)}")
    name = spec.get("dialect")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name):
        raise ValueError(f"{source}: 'dialect' must be a lower-case identifier")
    attrs: dict[str, object] = {"name": name}
    for key in (
        "templates",
        "sniff",
        "secret_rules",
        "iface_block_kinds",
    ):
        if key in spec:
            attrs[key] = _str_tuple(spec[key], f"{source}: {key}")
    for key in ("block_style", "mask_form", "block_parent_re", "subif_re"):
        if key in spec:
            if not isinstance(spec[key], str):
                raise ValueError(f"{source}: {key} must be a string")
            attrs[key] = spec[key]
    if "priority" in spec:
        if not isinstance(spec["priority"], int):
            raise ValueError(f"{source}: priority must be an integer")
        attrs["priority"] = spec["priority"]
    aliases = spec.get("iface_aliases", {})
    if not isinstance(aliases, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in aliases.items()
    ):
        raise ValueError(f"{source}: iface_aliases must be a table of strings")
    attrs["iface_aliases"] = dict(aliases)
    raw_rules = spec.get("rule", [])
    if not isinstance(raw_rules, list):
        raise ValueError(f"{source}: [[rule]] must be an array of tables")
    attrs["rules"] = tuple(
        rule_from_dict(r, f"{source} rule #{i + 1}") for i, r in enumerate(raw_rules)
    )
    if "fact_kinds" in spec:
        CORE_FACT_KINDS.update(_str_tuple(spec["fact_kinds"], f"{source}: fact_kinds"))
    attrs["__module__"] = "evelab.localize.dialects.packs"
    # The source file is part of the class identity: re-loading the same pack
    # file replaces it quietly, but two *different* files declaring the same
    # dialect name raise DIALECT_DUPLICATE in ``register`` (review fix #31).
    try:
        origin = str(Path(source).resolve())
    except (OSError, ValueError):
        origin = source
    attrs["__qualname__"] = f"pack:{name}@{origin}"
    attrs["__doc__"] = f"Declarative pack dialect from {source}."
    return type(f"Pack_{name}", (RuleDialect,), attrs)
