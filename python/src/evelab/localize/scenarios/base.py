"""Scenario contract: ``Scenario`` protocol, ``Question``, ``Claim``, value maps.

A scenario turns an :class:`~evelab.localize.model.Analysis` into questions (section 10)
and, once the answers are known, into a :class:`PlanFragment` of *claims*
(proposed span replacements, section 11.1). The planner resolves the claims of
all scenarios together (dedupe, precedence, conflicts, protected facts) and
turns the survivors into :class:`~evelab.localize.model.Edit` objects.

``Answers`` is :data:`evelab.localize.profile.Answers` (an alias of ``Profile``); it is
re-exported here, never redefined.

``ValueMaps`` and ``SubnetMap`` live here (not in ``planner.py``) so scenario
modules can import them at runtime without an import cycle; ``planner`` re-exports
both names.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

from ..errors import LocalizeError
from ..model import (
    Analysis,
    Confidence,
    ConfigText,
    Fact,
    Finding,
    Scheme,
    Segment,
    Store,
    TextEdit,
)
from ..profile import Answers, Profile, SegmentAnswer

if TYPE_CHECKING:
    from ..manifest import Manifest

__all__ = [
    "PARAM_KINDS",
    "Answers",
    "Claim",
    "ParamKind",
    "PlanFragment",
    "Question",
    "QuestionGroup",
    "Scenario",
    "SubnetMap",
    "ValueMaps",
    "apply_answer",
    "fact_claim",
    "register_param_kind",
    "segment_setter",
]

QuestionGroup = Literal[
    "A Clouds",
    "B VLAN tags",
    "C Addressing",
    "D Labels",
    "E Services",
    "F Site routes",
    "G Scenarios",
    "H Secrets",
    "S Scope",
]

Validator = Callable[[str, Answers], "str | None"]
Setter = Callable[[Answers, Any], None]


# --------------------------------------------------------------------------- #
# Parameter kinds (section 13.3)
# --------------------------------------------------------------------------- #


@dataclass
class ParamKind:
    """A value type a question can ask for; the name is the serialisation key.

    ``parse`` turns the typed string into the stored value (raises ``ValueError``);
    ``validate`` returns an error message or ``None``; ``fact_kinds`` documents
    which facts it drives (documentation only).  ``render`` is RESERVED and never
    called: edits are always produced by ``Dialect.render`` through
    :func:`render_fact` inside a scenario's ``plan()`` - a new kind needs a
    scenario that asks the question and plans the edits (design 13.3; review
    fix #30).
    """

    name: str
    parse: Callable[[str], Any]
    validate: Validator
    render: Callable[[Fact, str, Any], list[TextEdit]] | None = None
    fact_kinds: frozenset[str] = frozenset()


PARAM_KINDS: dict[str, ParamKind] = {}


def register_param_kind(kind: ParamKind) -> ParamKind:
    PARAM_KINDS[kind.name] = kind
    return kind


def _try(parse: Callable[[str], Any]) -> Validator:
    def check(value: str, _ans: Answers) -> str | None:
        try:
            parse(value)
        except (ValueError, TypeError) as exc:
            return str(exc) or f"invalid value {value!r}"
        return None

    return check


_BRIDGE_RE = re.compile(r"(pnet\d+|nat\d+|cloud\d+)")
_LABEL_BAD = re.compile(r"[<>&\"\x00-\x1f]")
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?"
)


def _parse_bridge(s: str) -> str:
    s = s.strip()
    if not s or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", s):
        raise ValueError(f"invalid bridge name {s!r}")
    return s


def _validate_bridge(value: str, ans: Answers) -> str | None:
    value = value.strip()
    if _BRIDGE_RE.fullmatch(value) or value in ans.bridges:
        return None
    return f"{value!r} is not pnetN/natN/cloudN and not declared in [bridges]"


def _parse_vlan(s: str) -> int:
    v = int(s.strip())
    if not 1 <= v <= 4094:
        raise ValueError(f"VLAN {v} out of range 1-4094")
    return v


def _parse_cidr(s: str) -> IPv4Network:
    net = ip_network(s.strip(), strict=False)
    if not isinstance(net, IPv4Network):
        raise ValueError("IPv6 is not supported")
    if str(net) != s.strip() and "/" in s:
        # host bits set: accept, but the stored value is the network
        pass
    return net


def _parse_ip(s: str) -> IPv4Address:
    addr = ip_address(s.strip())
    if not isinstance(addr, IPv4Address):
        raise ValueError("IPv6 is not supported")
    return addr


def _parse_label(s: str) -> str:
    s = s.strip()
    if not s:
        raise ValueError("empty label")
    if _LABEL_BAD.search(s):
        raise ValueError('label contains < > & " or control characters')
    return s


def _parse_domain(s: str) -> str:
    s = s.strip()
    if s == "":
        return s  # "" = drop (list contexts only)
    if not _DOMAIN_RE.fullmatch(s):
        raise ValueError(f"{s!r} is not a valid domain name")
    if s.rstrip(".").rsplit(".", 1)[-1].isdigit():
        # RFC 1123 2.1: a host name never has the dotted-decimal form
        raise ValueError(f"{s!r} is an address, not a domain name")
    return s


def _parse_host(s: str) -> str:
    s = s.strip()
    try:
        return str(_parse_ip(s))
    except ValueError:
        return _parse_domain(s)


def _parse_asn(s: str) -> int:
    v = int(s.strip())
    if not 1 <= v <= 4294967295:
        raise ValueError(f"ASN {v} out of range")
    return v


def _parse_bool(s: str) -> bool:
    low = s.strip().lower()
    if low in ("y", "yes", "true", "1", "on"):
        return True
    if low in ("n", "no", "false", "0", "off", ""):
        return False
    raise ValueError(f"expected yes/no, got {s!r}")


def _parse_route_list(s: str) -> list[IPv4Network]:
    out = []
    for part in re.split(r"[,\s]+", s.strip()):
        if part:
            out.append(_parse_cidr(part))
    return out


for _k in (
    ParamKind("bridge", _parse_bridge, _validate_bridge, fact_kinds=frozenset()),
    ParamKind(
        "vlan",
        _parse_vlan,
        _try(_parse_vlan),
        fact_kinds=frozenset({"vlan_tag", "vlan_list", "vlan_def"}),
    ),
    ParamKind(
        "cidr", _parse_cidr, _try(_parse_cidr), fact_kinds=frozenset({"ip_host"})
    ),
    ParamKind("ip", _parse_ip, _try(_parse_ip), fact_kinds=frozenset({"ip_gateway"})),
    ParamKind("label", _parse_label, _try(_parse_label)),
    ParamKind(
        "domain",
        _parse_domain,
        _try(_parse_domain),
        fact_kinds=frozenset({"domain", "search_list"}),
    ),
    ParamKind(
        "host",
        _parse_host,
        _try(_parse_host),
        fact_kinds=frozenset({"dns_server", "ntp_server", "probe_target"}),
    ),
    ParamKind("asn", _parse_asn, _try(_parse_asn), fact_kinds=frozenset({"asn"})),
    ParamKind("bool", _parse_bool, _try(_parse_bool)),
    ParamKind("choice", str.strip, lambda v, a: None),
    ParamKind("text", str, lambda v, a: None),
    ParamKind("secret", str, lambda v, a: None, fact_kinds=frozenset({"secret"})),
    ParamKind("routes", _parse_route_list, _try(_parse_route_list)),
):
    register_param_kind(_k)


# --------------------------------------------------------------------------- #
# Questions
# --------------------------------------------------------------------------- #


@dataclass
class Question:
    """One prompt (section 10.1). ``id`` is stable and used in answers files.

    ``apply`` (additive) stores a parsed answer into ``Answers``; use
    :func:`apply_answer` rather than calling it directly.
    """

    id: str  # "<site_key>/<kind>[@scope]" or "<lab_stem>/<param>"
    group: QuestionGroup
    kind: str  # registered ParamKind name
    prompt: str
    current: str | None
    default: str | None
    default_source: str
    choices: list[str] | None
    validate: Validator
    depends_on: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)  # fact ids
    affects: int = 0
    # additive (T16)
    scenario: str = ""
    segment: str | None = None  # segment key the question belongs to
    apply: Setter | None = None
    notes: list[str] = field(default_factory=list)


def segment_setter(
    site_key: str, attr: str, lab_id: str | None = None, segment_key: str | None = None
) -> Setter:
    """Setter writing ``SegmentAnswer.<attr>`` (lab override when ``lab_id`` given)."""

    def setter(ans: Answers, value: Any) -> None:
        if lab_id is not None and segment_key is not None:
            from ..profile import LabOverride

            lab = ans.labs.setdefault(lab_id, LabOverride())
            sa = lab.segments.setdefault(segment_key, SegmentAnswer())
        else:
            sa = ans.segments.setdefault(site_key, SegmentAnswer())
        setattr(sa, attr, value)

    return setter


def apply_answer(ans: Answers, q: Question, raw: str) -> str | None:
    """Validate ``raw`` for ``q`` and store it in ``ans``. Returns an error or None.

    The empty string / ``"k"`` keep the current value: nothing is stored.
    """
    kind = PARAM_KINDS.get(q.kind)
    if kind is None:
        return f"unknown parameter kind {q.kind!r}"
    err = kind.validate(raw, ans) or q.validate(raw, ans)
    if err:
        return err
    try:
        value = kind.parse(raw)
    except (ValueError, TypeError) as exc:
        return str(exc)
    if q.apply is not None:
        q.apply(ans, value)
    return None


# --------------------------------------------------------------------------- #
# Value maps (section 11.1)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SubnetMap:
    """Offset-preserving map ``old`` -> ``new`` (a split map has several entries)."""

    old: IPv4Network
    new: IPv4Network

    def covers(self, ip: IPv4Address) -> bool:
        return ip in self.old

    def fits(self) -> bool:
        return self.new.num_addresses >= self.old.num_addresses

    def map_host(self, ip: IPv4Address) -> IPv4Address | None:
        """``new.network + (ip - old.network)``; None when outside / not fitting."""
        if ip not in self.old:
            return None
        off = int(ip) - int(self.old.network_address)
        if off >= self.new.num_addresses:
            return None
        return IPv4Address(int(self.new.network_address) + off)

    def map_net(self, net: IPv4Network) -> IPv4Network | None:
        """Map a network inside ``old`` (e.g. a route to the segment subnet)."""
        if not net.subnet_of(self.old):
            return None
        base = self.map_host(net.network_address)
        if base is None:
            return None
        plen = net.prefixlen + (self.new.prefixlen - self.old.prefixlen)
        if plen < 0 or plen > 32:
            return None
        try:
            return IPv4Network(f"{base}/{plen}")
        except ValueError:
            return None


@dataclass
class ValueMaps:
    """Answers resolved into old -> new maps; every scenario plans from these."""

    bridges: dict[str, str] = field(default_factory=dict)  # segment key -> bridge
    labels: dict[str, str] = field(default_factory=dict)  # network id -> new name
    text_labels: dict[str, str] = field(default_factory=dict)  # old -> new (distinct)
    tags: dict[tuple[str, int], int] = field(default_factory=dict)
    subnets: dict[str, list[SubnetMap]] = field(default_factory=dict)
    exact_ips: dict[IPv4Address, IPv4Address] = field(default_factory=dict)
    services: dict[tuple[str, str], str] = field(default_factory=dict)
    asns: dict[tuple[str, int], int] = field(default_factory=dict)
    routes: dict[str, list[IPv4Network] | None] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    # additive (T16/T18)
    gateways: dict[str, dict[IPv4Address, IPv4Address]] = field(default_factory=dict)
    seg_exact: dict[str, dict[IPv4Address, IPv4Address]] = field(default_factory=dict)
    # segment key -> canonical old subnet -> answered subnet (mask decisions)
    primary: dict[str, SubnetMap] = field(default_factory=dict)
    old_labels: dict[str, str] = field(default_factory=dict)  # network id -> old name
    cloud_text: dict[str, str] = field(default_factory=dict)  # old bridge -> new
    legacy_scopes: dict[str, set[str]] = field(default_factory=dict)  # seg -> scopes
    skipped: set[str] = field(default_factory=set)  # segment keys skipped
    lab_id: str = ""
    manifest: Any = None  # Manifest | None (for generic_labels, templates...)
    include_outliers: bool = False
    subif_policy: str = "rename"  # rename | keep-name
    cosmetic_text: bool = True

    def tag_for(self, segment: str, old: int) -> int | None:
        return self.tags.get((segment, old))

    def map_ip(self, segment: str | None, ip: IPv4Address) -> IPv4Address | None:
        """exact_ips > per-segment exact > gateway > subnet offset."""
        if ip in self.exact_ips:
            return self.exact_ips[ip]
        if segment is None:
            return None
        if ip in self.seg_exact.get(segment, {}):
            return self.seg_exact[segment][ip]
        if ip in self.gateways.get(segment, {}):
            return self.gateways[segment][ip]
        for sm in self.subnets.get(segment, ()):
            if sm.covers(ip):
                return sm.map_host(ip)
        return None

    def subnet_for(self, segment: str | None, ip: IPv4Address) -> SubnetMap | None:
        if segment is None:
            return None
        for sm in self.subnets.get(segment, ()):
            if sm.covers(ip):
                return sm
        return None

    def empty(self) -> bool:
        return not any(
            (
                self.bridges,
                self.labels,
                self.text_labels,
                self.tags,
                self.subnets,
                self.exact_ips,
                self.services,
                self.asns,
                self.routes,
                self.secrets,
                self.gateways,
                self.seg_exact,
            )
        )


# --------------------------------------------------------------------------- #
# Claims and fragments
# --------------------------------------------------------------------------- #

# precedence (higher wins on the same span; ties with different text = conflict)
PRIO_MEMBERSHIP = 10  # subnet offset map
PRIO_GATEWAY = 20
PRIO_EXACT = 30  # exact_ips / host overrides
PRIO_SCENARIO_EXACT = 40  # peer / ASN claims of a specific scenario


@dataclass
class Claim:
    """A proposed replacement of ``[start, end)`` in one store text.

    Offsets: for ``store.kind == "xml"`` they are the BYTE offsets of the attribute
    value in the ``.unl`` (``RawAttr.span``) and ``old``/``new`` are decoded values;
    for every other store they index the store's ``ConfigText.text``. The planner
    converts them to the apply offset contract.
    """

    store: Store
    node_id: str | None
    start: int
    end: int
    old: str
    new: str
    category: str
    group: str
    confidence: Confidence
    question: str = ""
    fact_ids: tuple[str, ...] = ()
    rule: str = ""
    evidence: str = ""
    priority: int = PRIO_MEMBERSHIP
    secret: bool = False
    scenario: str = ""
    # xml claims only: (network id, attribute name)
    xml: tuple[str, str] | None = None
    # ignore protected-fact checks (scenario-exact claims on known values)
    exact: bool = False

    @property
    def key(self) -> tuple[Any, ...]:
        return (self.store, self.node_id, self.start, self.end)


@dataclass
class PlanFragment:
    claims: list[Claim] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def extend(self, other: PlanFragment) -> None:
        self.claims.extend(other.claims)
        self.findings.extend(other.findings)
        self.notes.extend(other.notes)


def fact_claim(
    fact: Fact,
    edit: TextEdit,
    *,
    category: str,
    group: str,
    question: str = "",
    priority: int = PRIO_MEMBERSHIP,
    confidence: Confidence | None = None,
    scenario: str = "",
    extra_facts: tuple[str, ...] = (),
) -> Claim:
    """Claim for one ``TextEdit`` produced by ``dialect.render(fact, ...)``."""
    return Claim(
        store=fact.store,
        node_id=fact.node_id,
        start=edit.start,
        end=edit.end,
        old=edit.old,
        new=edit.new,
        category=category,
        group=group,
        confidence=confidence if confidence is not None else fact.confidence,
        question=question,
        fact_ids=(fact.id, *extra_facts),
        rule=fact.rule,
        evidence=fact.evidence,
        priority=priority,
        secret="secret" in fact.flags,
        scenario=scenario,
    )


# --------------------------------------------------------------------------- #
# Scenario protocol
# --------------------------------------------------------------------------- #


@runtime_checkable
class Scenario(Protocol):
    """Section 3.2. Optional extras the planner honours when present:

    ``gated: bool`` (True = "G Scenarios" yes/no gate, runs only when the answers
    enable it) and ``contribute(a, ans, maps, ctx)`` (adds entries to the value maps
    before any scenario plans, e.g. exact peer IPs or ASNs).
    """

    id: str
    order: int

    def applies(self, a: Analysis, m: Manifest | None) -> bool: ...

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]: ...

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment: ...


# --------------------------------------------------------------------------- #
# Shared helpers for scenarios
# --------------------------------------------------------------------------- #

GENERIC_LABELS = frozenset({"internet", "net", "mgmt", "trunk", "out"})


class TextIndex:
    """Config texts of an analysis by ``(store, node_id)`` (node "" = none)."""

    def __init__(self, a: Analysis) -> None:
        self.by_key: dict[tuple[Store, str], ConfigText] = {}
        for ct in a.texts:
            self.by_key.setdefault((ct.store, ct.node_id or ""), ct)

    def config(self, store: Store, node_id: str | None) -> ConfigText | None:
        return self.by_key.get((store, node_id or ""))

    def text(self, store: Store, node_id: str | None) -> str | None:
        ct = self.config(store, node_id)
        return None if ct is None or ct.opaque else ct.text

    def dialect(self, store: Store, node_id: str | None) -> Any:
        from .. import dialects

        ct = self.config(store, node_id)
        name = ct.dialect if ct is not None else "generic"
        try:
            return dialects.get(name)
        except LocalizeError:
            return dialects.get("generic")


def text_index(a: Analysis) -> TextIndex:
    """Cached :class:`TextIndex` (stored on the analysis object)."""
    idx = a.__dict__.get("_scenario_text_index")
    if idx is None:
        idx = TextIndex(a)
        a.__dict__["_scenario_text_index"] = idx
    return idx


def line_bounds(text: str, pos: int, end: int | None = None) -> tuple[int, int]:
    """``[start, end)`` of the line holding ``pos`` (no EOL)."""
    start = text.rfind("\n", 0, pos) + 1
    stop = text.find("\n", end if end is not None else pos)
    if stop < 0:
        stop = len(text)
    if stop > start and text[stop - 1] == "\r":
        stop -= 1
    return start, stop


def context_text(store: Store, text: str, pos: int, end: int) -> str:
    """The line around a span; for HTML (textobjects) the enclosing text node."""
    if store.kind == "textobject":
        s = text.rfind(">", 0, pos) + 1
        e = text.find("<", end)
        return text[s : e if e >= 0 else len(text)]
    s, e = line_bounds(text, pos, end)
    return text[s:e]


def render_fact(
    a: Analysis, fact: Fact, new: str, new_prefix: int | None = None
) -> tuple[list[TextEdit], Finding | None]:
    """``dialect.render`` for ``fact`` with errors turned into a finding."""
    from ..dialects.base import RenderCtx

    idx = text_index(a)
    text = idx.text(fact.store, fact.node_id)
    if text is None:
        return [], Finding(
            "NO_TEXT", "warn", f"fact {fact.id}: store text unavailable", [fact.id]
        )
    try:
        edits = idx.dialect(fact.store, fact.node_id).render(
            fact, new, RenderCtx(text, new_prefix)
        )
    except LocalizeError as exc:
        sev = "conflict" if exc.code in ("STALE_FACT", "CONFLICT") else "warn"
        return [], Finding(exc.code, sev, f"{fact.rule} {fact.id}: {exc}", [fact.id])
    return list(edits), None


def canonical_scheme(seg: Segment) -> Scheme | None:
    return seg.schemes[0] if seg.schemes else None


def primary_label(seg: Segment) -> str:
    """Most common cloud network name of the segment (ties: lowest net id)."""
    if not seg.labels:
        return seg.key
    counts = Counter(seg.labels.values())
    best = max(counts.values())
    for nid in sorted(seg.labels, key=_id_order):
        if counts[seg.labels[nid]] == best:
            return seg.labels[nid]
    return seg.key


def current_bridge(a: Analysis, seg: Segment) -> str:
    """Most common cloud ``type`` among the segment networks."""
    types = [a.networks[n].type for n in seg.network_ids if n in a.networks]
    if not types:
        return sorted(seg.cloud_types)[0] if seg.cloud_types else ""
    return Counter(types).most_common(1)[0][0]


def is_tagged(seg: Segment) -> bool:
    return seg.status == "CARRIER" or any(isinstance(s.tag, int) for s in seg.schemes)


def _id_order(nid: str) -> tuple[int, str]:
    return (int(nid), nid) if nid.isdigit() else (1 << 30, nid)


def seg_answer(ans: Answers, a: Analysis, seg: Segment) -> SegmentAnswer:
    return ans.segment_answer(seg.site_key, a.lab.lab_id, seg.key)


def active_fact(f: Fact, include_outliers: bool = False) -> bool:
    """Attributed, not an outlier (unless asked), not in a textobject-less store."""
    if f.segment is None:
        return False
    return not ("outlier" in f.flags and not include_outliers)


def group_name(seg_key: str, what: str) -> str:
    return f"{seg_key}/{what}"
