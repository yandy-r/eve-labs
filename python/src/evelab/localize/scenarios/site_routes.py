"""Supernet / home routes via external gateways (design 10.2, 11.3 "Supernets").

A *site route* is an ``ip_route_dst`` fact (with a mask) whose next hop, on the
same line or inside the same deletable stanza (Forti ``edit N`` ... ``next``), is an
``ip_gateway`` of a segment (attributed to it, or equal to its scheme gateway).
Excluded: default routes, routes inside any segment subnet (``segment_l3``
territory) and host routes to a known ``peer_ip`` (``azure_s2s`` /
``bgp_upstream`` territory).

Question (group "F Site routes"): one ``<site_key>/site_routes`` per segment,
kind ``site_routes``: ``keep``, ``delete`` or a replacement list
(``192.168.0.0/16, 10.0.0.0/8``). Stored in ``[site_routes."<site_key>"]``
(``[]`` = delete); the planner copies it to ``ValueMaps.routes[segment key]``.

Plan, per segment, from the discovered list ``old`` and the answer ``new``:

* routes in both lists stay untouched;
* the remaining old routes are paired, in address order, with the routes of
  ``new`` not present yet: destination and mask are rewritten in place;
* unpaired old routes are deleted where the dialect supports stanza deletion
  (``supports_stanza_delete``), otherwise a ``ROUTE_DELETE_UNSUPPORTED`` blocker;
* unpaired new routes cannot be created (no stanza synthesis):
  ``ROUTES_NOT_ADDED`` warning listing them.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING

from ..dialects.base import RenderCtx
from ..discover.segments import host_network
from ..errors import LocalizeError
from ..model import Analysis, Fact, Finding, Segment, Span
from ..profile import Profile
from . import register_scenario
from .base import (
    PRIO_EXACT,
    Answers,
    Claim,
    ParamKind,
    PlanFragment,
    Question,
    ValueMaps,
    fact_claim,
    register_param_kind,
    render_fact,
    text_index,
)

if TYPE_CHECKING:
    from ..manifest import Manifest

__all__ = [
    "DELETE_WORDS",
    "KEEP_WORDS",
    "SiteRoute",
    "SiteRoutesScenario",
    "parse_site_routes",
    "route_actions",
    "site_routes",
]

KEEP_WORDS = frozenset({"", "k", "keep"})
DELETE_WORDS = frozenset({"d", "delete", "none", "[]", "-"})


def parse_site_routes(text: str) -> list[IPv4Network] | None:
    """``keep`` -> None, ``delete`` -> [], else a list of networks."""
    low = text.strip().lower()
    if low in KEEP_WORDS:
        return None
    if low in DELETE_WORDS:
        return []
    out: list[IPv4Network] = []
    for part in low.replace(",", " ").split():
        net = IPv4Network(part, strict=False)
        if net not in out:
            out.append(net)
    return out


def _validate(value: str, _ans: Answers) -> str | None:
    try:
        nets = parse_site_routes(value)
    except ValueError as exc:
        return str(exc)
    if nets and any(n.prefixlen == 0 for n in nets):
        return "a default route is not a site route"
    return None


register_param_kind(
    ParamKind(
        "site_routes",
        parse_site_routes,
        _validate,
        fact_kinds=frozenset({"ip_route_dst"}),
    )
)


@dataclass
class SiteRoute:
    fact: Fact  # ip_route_dst
    gateway: Fact  # ip_gateway (same line / stanza)
    net: IPv4Network


def _addr(value: str) -> IPv4Address | None:
    try:
        return IPv4Address(value)
    except ValueError:
        return None


def _stanza(a: Analysis, f: Fact, text: str) -> Span | None:
    d = text_index(a).dialect(f.store, f.node_id)
    if not getattr(d, "supports_stanza_delete", False):
        return None
    try:
        return d.stanza_span(f, text)  # type: ignore[no-any-return]
    except Exception:  # noqa: BLE001 - dialect hook failure = no stanza
        return None


def site_routes(a: Analysis) -> dict[str, list[SiteRoute]]:
    """Segment key -> its site routes (cached on the analysis)."""
    cached = a.__dict__.get("_site_routes")
    if cached is not None:
        return cached  # type: ignore[no-any-return]
    idx = text_index(a)
    segs = [s for s in a.segments if s.status != "CARRIER"]
    gw_owner: dict[IPv4Address, str] = {}
    subnets: list[IPv4Network] = []
    for s in segs:
        for sch in s.schemes:
            if sch.gateway is not None:
                gw_owner.setdefault(sch.gateway, s.key)
            if sch.subnet is not None:
                subnets.append(sch.subnet)
    peers = {f.value for f in a.facts.values() if f.kind == "peer_ip"}
    gws: dict[tuple, list[Fact]] = {}
    for f in a.facts.values():
        if f.kind == "ip_gateway":
            gws.setdefault((f.store, f.node_id), []).append(f)
    out: dict[str, list[SiteRoute]] = {}
    for f in sorted(
        a.facts.values(), key=lambda x: (tuple(x.store), x.node_id or "", x.span.start)
    ):
        if f.kind != "ip_route_dst" or f.store.kind == "textobject":
            continue
        text = idx.text(f.store, f.node_id)
        if text is None:
            continue
        net = host_network(f, text)
        if net is None or net.prefixlen == 0:
            continue
        if any(net.subnet_of(sn) for sn in subnets):
            continue
        if net.prefixlen == 32 and f.value in peers:
            continue
        span = _stanza(a, f, text)
        cands = [
            g
            for g in gws.get((f.store, f.node_id), ())
            if (
                span.start <= g.span.start < span.end
                if span is not None
                else g.line == f.line
            )
        ]
        for g in cands:
            key = g.segment
            if key is None:
                ip = _addr(g.value)
                key = gw_owner.get(ip) if ip is not None else None
            if key is not None and any(s.key == key for s in segs):
                out.setdefault(key, []).append(SiteRoute(f, g, net))
                break
    a.__dict__["_site_routes"] = out
    return out


def old_list(routes: list[SiteRoute]) -> list[IPv4Network]:
    nets = {r.net for r in routes}
    return sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen))


def route_actions(
    old: list[IPv4Network], new: list[IPv4Network]
) -> tuple[dict[IPv4Network, IPv4Network | None], list[IPv4Network]]:
    """(old -> new | None (delete), routes that cannot be added)."""
    keep = [o for o in old if o in new]
    rest_old = [o for o in old if o not in new]
    to_add = [n for n in new if n not in old]
    actions: dict[IPv4Network, IPv4Network | None] = {o: o for o in keep}
    for i, o in enumerate(rest_old):
        actions[o] = to_add[i] if i < len(to_add) else None
    return actions, to_add[len(rest_old) :]


def _fmt(nets: list[IPv4Network]) -> str:
    return ", ".join(str(n) for n in nets)


def _setter(site_key: str):  # type: ignore[no-untyped-def]
    def setter(ans: Answers, value: object) -> None:
        if value is None:
            ans.site_routes.pop(site_key, None)
        else:
            ans.site_routes[site_key] = list(value)  # type: ignore[call-overload]

    return setter


@register_scenario
class SiteRoutesScenario:
    id = "site_routes"
    order = 60

    def applies(self, a: Analysis, m: Manifest | None) -> bool:
        return bool(site_routes(a))

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]:
        out: list[Question] = []
        routes = site_routes(a)
        for seg in a.segments:
            mine = routes.get(seg.key)
            if not mine:
                continue
            old = old_list(mine)
            files = {(r.fact.store, r.fact.node_id) for r in mine}
            gws = sorted({r.gateway.value for r in mine})
            if seg.site_key in prof.site_routes:
                ans_nets = prof.site_routes[seg.site_key]
                default = _fmt(ans_nets) if ans_nets else "delete"
                source = f"site_routes.{seg.site_key}"
            else:
                default, source = "keep", "keep"
            dels = sorted(
                {
                    r.fact.store.kind
                    for r in mine
                    if not getattr(
                        text_index(a).dialect(r.fact.store, r.fact.node_id),
                        "supports_stanza_delete",
                        False,
                    )
                }
            )
            notes = []
            if dels:
                notes.append(
                    "deleting routes is not supported in some of these configs: "
                    "a shorter list is a blocker there"
                )
            out.append(
                Question(
                    id=f"{seg.site_key}/site_routes",
                    group="F Site routes",
                    kind="site_routes",
                    prompt=(
                        f"{seg.key} site routes via gw {', '.join(gws)}: {_fmt(old)} "
                        f"({len(files)} config(s)) [k]eep / list / [d]elete"
                    ),
                    current=_fmt(old),
                    default=default,
                    default_source=source,
                    choices=None,
                    validate=lambda v, a: None,
                    evidence=[r.fact.id for r in mine],
                    affects=len(mine) if default != "keep" else 0,
                    scenario=self.id,
                    segment=seg.key,
                    apply=_setter(seg.site_key),
                    notes=notes,
                )
            )
        return out

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment:
        frag = PlanFragment()
        routes = site_routes(a)
        for seg in a.segments:
            if seg.key in maps.skipped or seg.key not in routes:
                continue
            new = maps.routes.get(seg.key)
            if new is None and seg.site_key in ans.site_routes:
                new = list(ans.site_routes[seg.site_key])
            if new is None:
                continue
            self._plan_segment(a, seg, routes[seg.key], new, frag)
        return frag

    def _plan_segment(
        self,
        a: Analysis,
        seg: Segment,
        mine: list[SiteRoute],
        new: list[IPv4Network],
        frag: PlanFragment,
    ) -> None:
        old = old_list(mine)
        actions, missing = route_actions(old, new)
        qid = f"{seg.site_key}/site_routes"
        group = f"{seg.key}/routes"
        if missing:
            frag.findings.append(
                Finding(
                    "ROUTES_NOT_ADDED",
                    "warn",
                    f"{seg.key}: route(s) {_fmt(missing)} cannot be added (only "
                    f"{len(old)} existing route stanza(s) to rewrite); add them on "
                    "the devices",
                    [f"segment:{seg.key}"],
                )
            )
        idx = text_index(a)
        deleted: set[tuple] = set()
        for r in mine:
            target = actions.get(r.net, r.net)
            if target == r.net:
                continue
            f = r.fact
            if target is not None:
                edits, finding = render_fact(
                    a, f, str(target.network_address), target.prefixlen
                )
                if finding is not None:
                    frag.findings.append(finding)
                for e in edits:
                    c = fact_claim(
                        f,
                        e,
                        category="route",
                        group=group,
                        question=qid,
                        priority=PRIO_EXACT,
                        scenario=self.id,
                        extra_facts=(r.gateway.id,),
                    )
                    c.exact = True
                    frag.claims.append(c)
                continue
            text = idx.text(f.store, f.node_id) or ""
            d = idx.dialect(f.store, f.node_id)
            if not getattr(d, "supports_stanza_delete", False):
                frag.findings.append(
                    Finding(
                        "ROUTE_DELETE_UNSUPPORTED",
                        "blocker",
                        f"{seg.key}: route {r.net} ({f.rule}, node {f.node_id}, "
                        f"{f.store.kind}:{f.store.name} line {f.line}) cannot be "
                        f"deleted: dialect {getattr(d, 'name', '?')} has no stanza "
                        "deletion; keep it in the list",
                        [f.id],
                    )
                )
                continue
            try:
                edits = d.delete_stanza(f, RenderCtx(text))
            except LocalizeError as exc:
                frag.findings.append(
                    Finding(
                        "ROUTE_DELETE_UNSUPPORTED",
                        "blocker",
                        f"{seg.key}: route {r.net} ({f.rule}, node {f.node_id}): "
                        f"{exc}",
                        [f.id],
                    )
                )
                continue
            for e in edits:
                key = (f.store, f.node_id, e.start, e.end)
                if key in deleted:
                    continue
                deleted.add(key)
                frag.claims.append(
                    Claim(
                        store=f.store,
                        node_id=f.node_id,
                        start=e.start,
                        end=e.end,
                        old=e.old,
                        new="",
                        category="route",
                        group=group,
                        confidence=f.confidence,
                        question=qid,
                        fact_ids=(f.id, r.gateway.id),
                        rule=f.rule,
                        evidence=f"delete route {r.net} via {r.gateway.value}",
                        priority=PRIO_EXACT,
                        scenario=self.id,
                        exact=True,
                    )
                )
