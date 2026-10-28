"""Upstream eBGP toward the home router (design 10.2 "scenario groups", 15 #48/#49).

Signature: a node running ``router bgp L`` has an eBGP neighbor (``remote-as P``,
directly or through its peer group, ``P != L``) whose address lies inside a
segment subnet (an external network). A manifest
``[scenarios.bgp_upstream]`` (``nodes``, ``peer_group``) pins the nodes.

Gated (group "G Scenarios", default no). Questions, stored in
``[labs."<lab_id>".scenarios.bgp_upstream]``:

* ``peer_ip``: the home router address (default: follows the segment subnet map;
  an answer becomes a per-segment host override, so every reference agrees);
* ``peer_as`` (the home AS) and ``local_as`` (the lab AS: changed lab-wide, and
  ``set community`` values of the outbound route-map are recomputed,
  ``L:NN`` and the 32-bit ``L*65536+NN`` form);
* ``prefixes``: the entries of the prefix-list(s) matched by the outbound
  route-map (keep / list); an overlap with the protected inventory is a warning.

IOS-family syntax only (``neighbor X remote-as``, ``neighbor X peer-group G``,
``neighbor G route-map M out``, ``ip prefix-list``); other dialects keep their
values and get a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING

from ..model import Analysis, Confidence, Fact, Finding, Segment, Store
from ..profile import Profile
from . import register_scenario
from .base import (
    PRIO_SCENARIO_EXACT,
    Answers,
    Claim,
    PlanFragment,
    Question,
    Setter,
    ValueMaps,
    fact_claim,
    render_fact,
    text_index,
)
from .extra_common import (
    gate_question,
    lab_scenario,
    manifest_options,
    node_facts,
    opt_asn,
    opt_list,
    option_setter,
    parse_ip,
    scenario_options,
)
from .site_routes import route_actions

if TYPE_CHECKING:
    from ..manifest import Manifest

__all__ = ["BgpUpstreamScenario", "Upstream", "community_map", "find_upstreams"]

SID = "bgp_upstream"
IOS_DIALECTS = frozenset({"ios", "iosxe", "nxos"})
_ROUTER_BGP = re.compile(r"^router bgp (\d+)\s*$", re.M)
_PREFIX_RE = r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})"


@dataclass
class PrefixEntry:
    store: Store
    node_id: str
    span: tuple[int, int]  # the A.B.C.D/len token
    line: tuple[int, int]  # whole line incl. EOL (for deletion)
    net: IPv4Network


@dataclass
class Upstream:
    """One upstream eBGP session on one node/config."""

    node_id: str
    store: Store
    peer: str
    group: str | None
    local_as: int
    peer_as: int
    segment: str
    route_maps: list[str] = field(default_factory=list)
    prefixes: list[PrefixEntry] = field(default_factory=list)
    communities: list[tuple[int, int, str]] = field(default_factory=list)


def _seg_of(a: Analysis, ip: IPv4Address) -> Segment | None:
    for s in a.segments:
        if s.status == "CARRIER":
            continue
        for sch in s.schemes:
            if sch.subnet is not None and ip in sch.subnet:
                return s
    return None


def _remote_as(text: str, name: str) -> int | None:
    m = re.search(rf"^\s*neighbor {re.escape(name)} remote-as (\d+)\s*$", text, re.M)
    return int(m.group(1)) if m else None


def _block(text: str, header: re.Pattern[str]) -> list[tuple[int, int]]:
    """``(start, end)`` of each top-level block whose header matches."""
    out = []
    for m in header.finditer(text):
        start = m.start()
        nxt = re.compile(r"^\S", re.M).search(text, m.end() + 1)
        out.append((start, nxt.start() if nxt else len(text)))
    return out


def _scan_policy(text: str, up: Upstream) -> None:
    names = [n for n in (up.peer, up.group) if n]
    maps_: list[str] = []
    for n in names:
        for m in re.finditer(
            rf"^\s*neighbor {re.escape(n)} route-map (\S+) out\s*$", text, re.M
        ):
            if m.group(1) not in maps_:
                maps_.append(m.group(1))
    up.route_maps = maps_
    plists: list[str] = []
    for rm in maps_:
        hdr = re.compile(rf"^route-map {re.escape(rm)} permit \d+\s*$", re.M)
        for s, e in _block(text, hdr):
            body = text[s:e]
            for m in re.finditer(
                r"^\s+match ip address prefix-list (.+?)\s*$", body, re.M
            ):
                for pl in m.group(1).split():
                    if pl not in plists:
                        plists.append(pl)
            for m in re.finditer(r"^\s+set community (.+?)\s*$", body, re.M):
                base = s + m.start(1)
                for t in re.finditer(r"\S+", m.group(1)):
                    up.communities.append(
                        (base + t.start(), base + t.end(), t.group(0))
                    )
    for pl in plists:
        rx = re.compile(
            rf"^ip prefix-list {re.escape(pl)} (?:seq \d+ )?permit "
            rf"{_PREFIX_RE}[^\n]*\n?",
            re.M,
        )
        for m in rx.finditer(text):
            try:
                net = IPv4Network(m.group(1), strict=False)
            except ValueError:
                continue
            up.prefixes.append(
                PrefixEntry(
                    up.store,
                    up.node_id,
                    (m.start(1), m.end(1)),
                    (m.start(), m.end()),
                    net,
                )
            )


def find_upstreams(a: Analysis, m: Manifest | None = None) -> list[Upstream]:
    """Upstream eBGP sessions (cached per analysis for the no-manifest case)."""
    pin = manifest_options(m, SID)
    nodes = None
    group_pin = None
    if pin is not None:
        raw = pin.get("nodes")
        if isinstance(raw, list):
            nodes = {str(n) for n in raw}
        elif isinstance(raw, (str, int)):
            nodes = {str(raw)}
        g = pin.get("peer_group")
        group_pin = str(g) if isinstance(g, str) else None
    idx = text_index(a)
    out: list[Upstream] = []
    seen: set[tuple] = set()
    for f in sorted(
        a.facts.values(), key=lambda x: (tuple(x.store), x.node_id or "", x.span.start)
    ):
        if f.kind != "peer_ip" or "object_name" in f.flags or f.node_id is None:
            continue
        if nodes is not None and f.node_id not in nodes:
            continue
        ct = idx.config(f.store, f.node_id)
        if ct is None or ct.opaque or ct.dialect not in IOS_DIALECTS:
            continue
        ip = parse_ip(f.value)
        seg = _seg_of(a, ip) if ip is not None else None
        if seg is None:
            continue
        key = (f.store, f.node_id, f.value)
        if key in seen:
            continue
        seen.add(key)
        text = ct.text
        rb = _ROUTER_BGP.search(text)
        if rb is None:
            continue
        local = int(rb.group(1))
        gm = re.search(
            rf"^\s*neighbor {re.escape(f.value)} peer-group (\S+)\s*$", text, re.M
        )
        group = gm.group(1) if gm else None
        if group_pin is not None and group != group_pin:
            continue
        remote = _remote_as(text, f.value)
        if remote is None and group is not None:
            remote = _remote_as(text, group)
        if remote is None or remote == local:
            continue
        up = Upstream(f.node_id, f.store, f.value, group, local, remote, seg.key)
        _scan_policy(text, up)
        out.append(up)
    return out


def community_map(token: str, old_as: int, new_as: int) -> str | None:
    """New community text when it encodes ``old_as`` (None = unchanged/unmappable)."""
    if ":" in token:
        hi, _, lo = token.partition(":")
        if hi.isdigit() and int(hi) == old_as and new_as <= 0xFFFF:
            return f"{new_as}:{lo}"
        return None
    if token.isdigit():
        n = int(token)
        if n >> 16 == old_as and new_as <= 0xFFFF:
            return str((new_as << 16) | (n & 0xFFFF))
    return None


def _fmt(nets: list[IPv4Network]) -> str:
    return ", ".join(str(n) for n in nets)


def _prefix_list(ups: list[Upstream]) -> list[IPv4Network]:
    out: list[IPv4Network] = []
    for up in ups:
        for p in up.prefixes:
            if p.net not in out:
                out.append(p.net)
    return out


def _no_check(value: str, _ans: Answers) -> str | None:
    return None


def _peer_answers(opts: dict) -> dict[str, IPv4Address]:
    """``peers = { "<old>" = "<new>" }`` option (invalid entries ignored)."""
    raw = opts.get("peers")
    out: dict[str, IPv4Address] = {}
    if isinstance(raw, dict):
        for old, new in raw.items():
            ip = parse_ip(new)
            if ip is not None and parse_ip(old) is not None:
                out[str(old)] = ip
    return out


def _peer_setter(peer: str, lab_id: str) -> Setter:
    def setter(ans: Answers, value: object) -> None:
        entry = lab_scenario(ans, SID, lab_id)
        peers = entry.options.get("peers")
        table = dict(peers) if isinstance(peers, dict) else {}
        if value is None or str(value) == peer:
            table.pop(peer, None)
        else:
            table[peer] = str(value)
        if table:
            entry.options["peers"] = table
        else:
            entry.options.pop("peers", None)

    return setter


@register_scenario
class BgpUpstreamScenario:
    id = SID
    order = 70
    gated = True

    def applies(self, a: Analysis, m: Manifest | None) -> bool:
        return bool(find_upstreams(a, m))

    # ------------------------------------------------------------- questions

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]:
        ups = find_upstreams(a, m)
        if not ups:
            return []
        lab_id = a.lab.lab_id
        opts = scenario_options(prof, SID, lab_id)
        names = {n: a.nodes[n].name for n in {u.node_id for u in ups} if n in a.nodes}
        peers = sorted({u.peer for u in ups})
        peer_as = sorted({u.peer_as for u in ups})
        local_as = sorted({u.local_as for u in ups})
        segs = sorted({u.segment for u in ups})
        prefixes = _prefix_list(ups)
        gate_id = f"{SID}/enabled"
        out = [
            gate_question(
                SID,
                lab_id,
                f"Upstream eBGP on {', '.join(sorted(names.values()))} "
                f"(peer {', '.join(peers)} AS {', '.join(map(str, peer_as))}, "
                f"via {', '.join(segs)}): localize it?",
                notes=["replaces a default route toward the home network"],
                evidence=[f"node:{n}" for n in sorted(names)],
            )
        ]

        def q(key: str, kind: str, prompt: str, current: str, notes: list[str]) -> None:
            ans_v = opts.get(key)
            default = (
                current
                if ans_v is None
                else (
                    _fmt(opt_list(opts, key) or [])
                    if isinstance(ans_v, list)
                    else str(ans_v)
                )
            )
            out.append(
                Question(
                    id=f"{SID}/{key}",
                    group="G Scenarios",
                    kind=kind,
                    prompt=prompt,
                    current=current,
                    default=default,
                    default_source="keep" if ans_v is None else f"scenarios.{SID}",
                    choices=None,
                    validate=_no_check,
                    depends_on=[gate_id],
                    scenario=SID,
                    apply=option_setter(SID, key, lab_id),
                    notes=notes,
                )
            )

        answered = _peer_answers(opts)
        for up in sorted({(u.peer, u.segment) for u in ups}):
            peer, seg_key = up
            mapped = answered.get(peer)
            out.append(
                Question(
                    id=f"{SID}/peer:{peer}",
                    group="G Scenarios",
                    kind="ip",
                    prompt=f"home BGP peer {peer} (in {seg_key})",
                    current=peer,
                    default=str(mapped) if mapped is not None else peer,
                    default_source=(
                        f"scenarios.{SID}.peers" if mapped is not None else "keep"
                    ),
                    choices=None,
                    validate=_no_check,
                    depends_on=[gate_id],
                    scenario=SID,
                    apply=_peer_setter(peer, lab_id),
                    notes=["keeping the current value follows the segment subnet map"],
                )
            )
        if len(peer_as) == 1:
            q("peer_as", "asn", "home (peer) AS", str(peer_as[0]), [])
        if len(local_as) == 1:
            q(
                "local_as",
                "asn",
                "lab (local) AS",
                str(local_as[0]),
                ["changed lab-wide; route-map communities follow"],
            )
        if prefixes:
            internal = [
                str(p)
                for p in prefixes
                if any(p.overlaps(x) for x in a.protected_prefixes)
            ]
            notes = ["advanced: prefixes advertised to the home router"]
            if internal:
                notes.append(
                    f"internal prefix(es) exported upstream: {', '.join(internal)}"
                )
            out.append(
                Question(
                    id=f"{SID}/prefixes",
                    group="G Scenarios",
                    kind="site_routes",
                    prompt="advertised prefixes [k]eep / list",
                    current=_fmt(prefixes),
                    default=(
                        _fmt(opt_list(opts, "prefixes") or [])
                        if opts.get("prefixes") is not None
                        else "keep"
                    ),
                    default_source="keep",
                    choices=None,
                    validate=lambda v, a: (
                        "the prefix list cannot be emptied"
                        if v.strip().lower() in ("d", "delete", "none", "[]", "-")
                        else None
                    ),
                    depends_on=[gate_id],
                    scenario=SID,
                    apply=option_setter(SID, "prefixes", lab_id),
                    notes=notes,
                )
            )
        return out

    # ------------------------------------------------------------------ plan

    def _answers(self, a: Analysis, ans: Answers) -> dict:
        return scenario_options(ans, SID, a.lab.lab_id)

    def contribute(self, a: Analysis, ans: Answers, maps: ValueMaps) -> None:
        """The answered peer address becomes a host override of its segment."""
        opts = self._answers(a, ans)
        peers = _peer_answers(opts)
        for up in find_upstreams(a, maps.manifest):
            new = peers.get(up.peer)
            old = IPv4Address(up.peer)
            if new is not None and new != old:
                maps.seg_exact.setdefault(up.segment, {}).setdefault(old, new)

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment:
        frag = PlanFragment()
        ups = find_upstreams(a, maps.manifest)
        if not ups:
            return frag
        opts = self._answers(a, ans)
        nodes = sorted({u.node_id for u in ups})
        peers = _peer_answers(opts)
        new_peer_as = opt_asn(opts, "peer_as")
        new_local = opt_asn(opts, "local_as")
        new_prefixes = opt_list(opts, "prefixes")

        def claim_facts(facts: list[Fact], new: str, what: str, exact: bool) -> None:
            for f in facts:
                edits, finding = render_fact(a, f, new)
                if finding is not None:
                    frag.findings.append(finding)
                for e in edits:
                    c = fact_claim(
                        f,
                        e,
                        category="bgp",
                        group=f"{SID}/{what}",
                        question=f"{SID}/{what}",
                        priority=PRIO_SCENARIO_EXACT,
                        scenario=SID,
                    )
                    c.exact = exact
                    frag.claims.append(c)

        for up in ups:
            new_peer = peers.get(up.peer)
            if new_peer is not None and IPv4Address(up.peer) != new_peer:
                facts = [
                    f
                    for f in node_facts(a, [up.node_id], ["peer_ip"])
                    if f.value == up.peer
                ]
                claim_facts(facts, str(new_peer), "peer_ip", True)
        if new_peer_as is not None:
            for old in sorted({u.peer_as for u in ups}):
                if old == new_peer_as:
                    continue
                facts = [
                    f for f in node_facts(a, nodes, ["asn"]) if f.value == str(old)
                ]
                claim_facts(facts, str(new_peer_as), "peer_as", False)
        if new_local is not None:
            for old in sorted({u.local_as for u in ups}):
                if old == new_local:
                    continue
                facts = [
                    f
                    for f in a.facts.values()
                    if f.kind == "asn" and f.value == str(old)
                ]
                facts.sort(
                    key=lambda f: (tuple(f.store), f.node_id or "", f.span.start)
                )
                claim_facts(facts, str(new_local), "local_as", False)
                self._communities(a, ups, old, new_local, frag)
        if new_prefixes is not None:
            self._prefixes(a, ups, new_prefixes, frag)
        return frag

    def _communities(
        self,
        a: Analysis,
        ups: list[Upstream],
        old: int,
        new: int,
        frag: PlanFragment,
    ) -> None:
        done: set[tuple] = set()
        for up in ups:
            for start, end, tok in up.communities:
                key = (up.store, up.node_id, start)
                if key in done:
                    continue
                done.add(key)
                rep = community_map(tok, old, new)
                if rep is None:
                    if (tok.isdigit() and int(tok) >> 16 == old) or tok.startswith(
                        f"{old}:"
                    ):
                        frag.findings.append(
                            Finding(
                                "COMMUNITY_UNMAPPABLE",
                                "warn",
                                f"node {up.node_id}: community {tok} encodes AS {old} "
                                f"but AS {new} does not fit 16 bits; left unchanged",
                                [f"node:{up.node_id}"],
                            )
                        )
                    continue
                frag.claims.append(
                    Claim(
                        store=up.store,
                        node_id=up.node_id,
                        start=start,
                        end=end,
                        old=tok,
                        new=rep,
                        category="bgp",
                        group=f"{SID}/local_as",
                        confidence=Confidence.CORRELATED,
                        question=f"{SID}/local_as",
                        rule=f"{SID}.community",
                        evidence=f"route-map {', '.join(up.route_maps)} set community",
                        priority=PRIO_SCENARIO_EXACT,
                        scenario=SID,
                    )
                )

    def _prefixes(
        self,
        a: Analysis,
        ups: list[Upstream],
        new: list[IPv4Network],
        frag: PlanFragment,
    ) -> None:
        old = _prefix_list(ups)
        if not old:
            return
        actions, missing = route_actions(old, new)
        if missing:
            frag.findings.append(
                Finding(
                    "PREFIXES_NOT_ADDED",
                    "warn",
                    f"{SID}: prefix(es) {_fmt(missing)} cannot be added to the "
                    "prefix-list (only existing entries are rewritten)",
                    [f"scenario:{SID}"],
                )
            )
        for net in new:
            hit = [str(p) for p in a.protected_prefixes if net.overlaps(p)]
            if hit:
                frag.findings.append(
                    Finding(
                        "PREFIX_INTERNAL",
                        "warn",
                        f"{SID}: advertised prefix {net} overlaps internal prefix(es) "
                        f"{', '.join(hit)}",
                        [f"scenario:{SID}"],
                    )
                )
        idx = text_index(a)
        done: set[tuple] = set()
        for up in ups:
            text = idx.text(up.store, up.node_id) or ""
            for p in up.prefixes:
                key = (p.store, p.node_id, p.span)
                if key in done:
                    continue
                done.add(key)
                target = actions.get(p.net, p.net)
                if target == p.net:
                    continue
                if target is None:
                    s, e = p.line
                    new_text = ""
                else:
                    s, e = p.span
                    new_text = str(target)
                frag.claims.append(
                    Claim(
                        store=p.store,
                        node_id=p.node_id,
                        start=s,
                        end=e,
                        old=text[s:e],
                        new=new_text,
                        category="bgp",
                        group=f"{SID}/prefixes",
                        confidence=Confidence.CORRELATED,
                        question=f"{SID}/prefixes",
                        rule=f"{SID}.prefix_list",
                        evidence=f"prefix-list entry {p.net}",
                        priority=PRIO_SCENARIO_EXACT,
                        scenario=SID,
                    )
                )
