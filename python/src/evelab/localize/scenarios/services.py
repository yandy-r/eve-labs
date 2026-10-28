"""DNS / NTP / domain / search / SLA probe targets (design 6.4, 10.2, 11.3).

Questions: one per distinct ``(map kind, old value)`` found in service facts, keyed
by the old value (services are plain values, section 9): ``services/dns:1.1.1.1``,
``services/domain:netlab.local``, ``services/ntp:pool.ntp.org``,
``services/probe:8.8.8.8``. The answer is stored in ``[map.<kind>]`` and the
planner turns every ``[map.*]`` entry into ``ValueMaps.services``.

=============  ==========================  =========
map kind       fact kinds                  param kind
=============  ==========================  =========
``dns``        ``dns_server``              ``host``
``ntp``        ``ntp_server``              ``host``
``domain``     ``domain``, ``search_list``  ``domain``
``probe``      ``probe_target``            ``host`` (advanced, default keep)
=============  ==========================  =========

Plan: only the anchored fact spans are rewritten (``dialect.render``). An empty new
value (``""``) drops the domain from search lists (token plus its separating
blank); it is refused for ``domain-name`` statements, DNS/NTP servers and probe
targets, and for the last entry of a list (``SERVICE_DROP_REFUSED`` warning).

Internal values (review fixes): an IPv4 service value inside the protected
inventory (``Analysis.protected_prefixes``: unattributed interface/loopback
networks plus the manifest ``protect`` list) is a lab-internal server, not a site
setting. No question is asked for it, and a ``[map.<kind>]`` entry for it (answers
file or profile) is refused with a ``SERVICE_INTERNAL`` warning (left unchanged;
a warning, not a blocker, because profile maps are shared by every lab).

Prompt validation (review fixes): a host answer must be an IPv4 address when any
targeted fact's dialect cannot render host names (no ``HostnameServiceMixin``), so
the prompt refuses what the dialect would later reject with ``BAD_VALUE``.
"""

from __future__ import annotations

from collections import Counter
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from typing import TYPE_CHECKING

from .. import dialects
from ..dialects._common import HostnameServiceMixin
from ..model import Analysis, Fact, Finding
from ..profile import Profile
from . import register_scenario
from .base import (
    PARAM_KINDS,
    PRIO_EXACT,
    Answers,
    Claim,
    PlanFragment,
    Question,
    Setter,
    TextIndex,
    Validator,
    ValueMaps,
    fact_claim,
    render_fact,
    text_index,
)

if TYPE_CHECKING:
    from ..manifest import Manifest

__all__ = [
    "MAP_KIND",
    "SERVICE_KINDS",
    "ServicesScenario",
    "drop_edit",
    "map_kind",
    "question_id",
    "service_facts",
]

# fact kind -> [map.<kind>] key
MAP_KIND: dict[str, str] = {
    "dns_server": "dns",
    "ntp_server": "ntp",
    "domain": "domain",
    "search_list": "domain",
    "probe_target": "probe",
}
SERVICE_KINDS = frozenset(MAP_KIND)
PARAM_KIND = {"dns": "host", "ntp": "host", "domain": "domain", "probe": "host"}
TITLE = {"dns": "DNS", "ntp": "NTP", "domain": "domain", "probe": "SLA probe target"}
CATEGORY = {"dns": "dns", "ntp": "ntp", "domain": "domain", "probe": "ip"}
ORDER = ("dns", "domain", "ntp", "probe")


def map_kind(fact: Fact) -> str | None:
    return MAP_KIND.get(fact.kind)


def question_id(kind: str, old: str) -> str:
    return f"services/{kind}:{old}"


def service_facts(a: Analysis) -> list[Fact]:
    """Service facts of every non-opaque store, in a stable order."""
    idx = text_index(a)
    out = [
        f
        for f in a.facts.values()
        if f.kind in SERVICE_KINDS and idx.text(f.store, f.node_id) is not None
    ]
    out.sort(key=lambda f: (tuple(f.store), f.node_id or "", f.span.start))
    return out


def _dialect_name(idx: TextIndex, f: Fact) -> str:
    ct = idx.config(f.store, f.node_id)
    return ct.dialect if ct is not None else "?"


def internal_prefix(a: Analysis, value: str) -> IPv4Network | None:
    """The protected prefix holding IPv4 ``value`` (host names never match)."""
    try:
        ip = IPv4Address(value.strip())
    except AddressValueError:
        return None
    for p in a.protected_prefixes:
        if ip in p:
            return p
    return None


def _ipv4_only(idx: TextIndex, facts: list[Fact]) -> list[str]:
    """Dialects among ``facts`` that only render IPv4 service values."""
    out: set[str] = set()
    for f in facts:
        name = _dialect_name(idx, f)
        d = dialects.REGISTRY.get(name)
        if f.mask_span is not None or not isinstance(d, HostnameServiceMixin):
            out.add(name)
    return sorted(out)


def _map_setter(kind: str, old: str) -> Setter:
    def setter(ans: Answers, value: object) -> None:
        ans.maps.setdefault(kind, {})[old] = "" if value is None else str(value)

    return setter


def _validator(
    kind: str, droppable: bool, ipv4_only: list[str] | None = None
) -> Validator:
    def validate(value: str, _ans: Answers) -> str | None:
        if value.strip() == "" and value != "":
            return "empty value"
        if ipv4_only and PARAM_KIND[kind] == "host" and value.strip():
            try:
                IPv4Address(value.strip())
            except AddressValueError:
                return (
                    f"this lab's {', '.join(ipv4_only)} config(s) need an IPv4 "
                    f"address for a {TITLE[kind]}"
                )
        if value == "" and not droppable:
            if kind == "domain":
                return (
                    "this domain is a domain-name (not only a search entry): it "
                    "cannot be dropped"
                )
            return f"a {TITLE[kind]} cannot be dropped (keep it or give a new value)"
        return None

    return validate


def drop_edit(text: str, fact: Fact) -> tuple[int, int]:
    """Span removing a list entry and one adjacent run of blanks."""
    start, end = fact.span.start, fact.span.end
    s = start
    while s > 0 and text[s - 1] in " \t":
        s -= 1
    if s < start:
        return s, end
    e = end
    while e < len(text) and text[e] in " \t":
        e += 1
    return start, e


@register_scenario
class ServicesScenario:
    id = "services"
    order = 50

    def applies(self, a: Analysis, m: Manifest | None) -> bool:
        return bool(service_facts(a))

    # ------------------------------------------------------------- questions

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]:
        groups: dict[tuple[str, str], list[Fact]] = {}
        for f in service_facts(a):
            kind = MAP_KIND[f.kind]
            groups.setdefault((kind, f.value), []).append(f)
        idx = text_index(a)
        out: list[Question] = []
        for (kind, old), facts in sorted(
            groups.items(), key=lambda kv: (ORDER.index(kv[0][0]), kv[0][1])
        ):
            if internal_prefix(a, old) is not None:
                continue  # lab-internal server: not a site setting
            counts = Counter((_dialect_name(idx, f), f.store.kind) for f in facts)
            where = ", ".join(f"{d} {st} x{n}" for (d, st), n in sorted(counts.items()))
            droppable = kind == "domain" and all(f.kind == "search_list" for f in facts)
            mapped = prof.map_value(kind, old)
            if mapped is not None:
                default, source = mapped, f"map.{kind}"
            else:
                default, source = old, "keep"
            notes = []
            if kind == "probe":
                notes.append("advanced: SLA/health-check targets, default keep")
            if droppable:
                notes.append('search-list entry only: "" drops it from the lists')
            out.append(
                Question(
                    id=question_id(kind, old),
                    group="E Services",
                    kind=PARAM_KIND[kind],
                    prompt=f"{TITLE[kind]} {old} ({where})",
                    current=old,
                    default=default,
                    default_source=source,
                    choices=None,
                    validate=_validator(kind, droppable, _ipv4_only(idx, facts)),
                    evidence=[f.id for f in facts],
                    affects=len(facts) if default != old else 0,
                    scenario=self.id,
                    apply=_map_setter(kind, old),
                    notes=notes,
                )
            )
        return out

    # ------------------------------------------------------------------ plan

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment:
        frag = PlanFragment()
        if not maps.services:
            return frag
        facts = service_facts(a)
        drops: dict[tuple, list[Fact]] = {}
        internal: dict[tuple[str, str], list[str]] = {}
        for f in facts:
            kind = MAP_KIND[f.kind]
            new = maps.services.get((kind, f.value))
            if new is None or new == f.value:
                continue
            if internal_prefix(a, f.value) is not None:
                internal.setdefault((kind, f.value), []).append(f.id)
                continue
            err = new and PARAM_KINDS[PARAM_KIND[kind]].validate(new, ans)
            if err:  # e.g. a [map.domain] profile entry holding an address
                frag.findings.append(
                    Finding(
                        "BAD_VALUE",
                        "warn",
                        f"{TITLE[kind]} {f.value}: {err}; left unchanged",
                        [f.id],
                    )
                )
                continue
            qid = question_id(kind, f.value)
            group = f"services/{kind}"
            if new == "":
                if f.kind != "search_list":
                    frag.findings.append(
                        Finding(
                            "SERVICE_DROP_REFUSED",
                            "warn",
                            f"{TITLE[kind]} {f.value}: an empty replacement is only "
                            f"allowed in search lists ({f.rule}, node {f.node_id}, "
                            f"line {f.line}); left unchanged",
                            [f.id],
                        )
                    )
                    continue
                drops.setdefault((f.store, f.node_id, f.line), []).append(f)
                continue
            edits, finding = render_fact(a, f, new)
            if finding is not None:
                frag.findings.append(finding)
            for e in edits:
                frag.claims.append(
                    fact_claim(
                        f,
                        e,
                        category=CATEGORY[kind],
                        group=group,
                        question=qid,
                        priority=PRIO_EXACT,
                        scenario=self.id,
                    )
                )
        if drops:
            self._drops(a, facts, drops, frag)
        for (kind, old), ids in sorted(internal.items()):
            net = internal_prefix(a, old)
            frag.findings.append(
                Finding(
                    "SERVICE_INTERNAL",
                    "warn",
                    f"{TITLE[kind]} {old} is a lab-internal address (inside "
                    f"protected {net}); [map.{kind}] entry ignored, left unchanged "
                    f"({len(ids)} span(s))",
                    ids,
                )
            )
        return frag

    def _drops(
        self,
        a: Analysis,
        facts: list[Fact],
        drops: dict[tuple, list[Fact]],
        frag: PlanFragment,
    ) -> None:
        idx = text_index(a)
        siblings: Counter[tuple] = Counter(
            (f.store, f.node_id, f.line) for f in facts if f.kind == "search_list"
        )
        for key, dropped in drops.items():
            if len(dropped) >= siblings[key]:
                for f in dropped:
                    frag.findings.append(
                        Finding(
                            "SERVICE_DROP_REFUSED",
                            "warn",
                            f"search entry {f.value} is the last entry of its list "
                            f"({f.rule}, node {f.node_id}, line {f.line}); "
                            "left unchanged",
                            [f.id],
                        )
                    )
                continue
            for f in dropped:
                text = idx.text(f.store, f.node_id)
                if text is None or text[f.span.start : f.span.end] != f.value:
                    frag.findings.append(
                        Finding(
                            "STALE_FACT",
                            "conflict",
                            f"{f.rule} {f.id}: span no longer holds {f.value!r}",
                            [f.id],
                        )
                    )
                    continue
                s, e = drop_edit(text, f)
                frag.claims.append(
                    Claim(
                        store=f.store,
                        node_id=f.node_id,
                        start=s,
                        end=e,
                        old=text[s:e],
                        new="",
                        category="domain",
                        group="services/domain",
                        confidence=f.confidence,
                        question=question_id("domain", f.value),
                        fact_ids=(f.id,),
                        rule=f.rule,
                        evidence=f.evidence,
                        priority=PRIO_EXACT,
                        scenario=self.id,
                    )
                )
