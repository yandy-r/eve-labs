"""Segments: grouping, merge rules, schemes, status, attribution (design 7.3).

Pipeline (``build``):

1. **Units.**  Cloud networks are grouped by manifest segment, else by
   ``(type, name)``.  A group whose every network is a switch trunk with no
   addressed endpoint of its own is a **carrier**; its traffic is split into
   **sub-units** per wire tag.  Sub-units are keyed by ``(cloud type, tag)`` (all
   ``pnet0`` clouds are one bridge, so VLAN ``v`` is one L2 domain), and two
   sub-units ending at the same EVE port in different scopes (``1102`` in startup,
   ``204`` in the backbone configset) are the same unit.  Sub-unit names are
   ``<carrier label>:<tag>`` (``trunk:204``, ``EVE-TRUNK:2``).
2. **Merge** (union-find): (a) manifest segments / ``[[merge]]``; (b) equal
   PROVEN ``(tag, subnet)`` consensus in a common scope and no conflicting subnet;
   (c) a switch ``vlan v`` whose ``name`` equals another unit's label.  Numbers in a
   label equal to a carrier tag are only a **hint** (``MERGE_HINT``).
3. **Schemes** per scope: tag / subnet (broadest consistent prefix) / gateway
   consensus; identical tuples merge across scopes; an endpoint that does not fit
   its scope's consensus joins another scheme it fits, else it is an **outlier**.
4. **Status, key, site_key, role, name hints.**
5. **Attribution**: endpoint facts PROVEN; switch VLAN-domain facts CORRELATED
   (``uncabled`` flag); correlation pass (IPv4 facts inside a scheme subnet,
   CORRELATED); SVI names; orphan tags; mirror sidecars copy their source.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    NetmaskValueError,
    ip_network,
)
from typing import TYPE_CHECKING

from evelab.common.textutil import mask_prefix

from ..model import (
    Attachment,
    Confidence,
    ConfigText,
    Fact,
    Finding,
    Scheme,
    Segment,
    Tag,
)
from .l2trace import Endpoint, TraceResult, VlanDomain, domain_facts, fact_vlans
from .names import NameContext, NameExplainer, octets3
from .topology import ConfigIndex, Topology

if TYPE_CHECKING:
    from ..manifest import Manifest, ManifestSegment

__all__ = [
    "CORRELATION_KINDS",
    "SegmentBuild",
    "Unit",
    "build",
    "host_network",
]

# Facts on an endpoint iface that belong to the segment (PROVEN).
ENDPOINT_KINDS = frozenset(
    {"ip_host", "dhcp", "mask", "vlan_tag", "subif_name", "svi_name", "vlan_list"}
)
# IPv4 kinds the correlation pass attributes when inside a scheme subnet.  Service
# kinds (dns/ntp/log/probe) are left to the services scenario; route destinations
# (supernets) to site_routes.
CORRELATION_KINDS = frozenset({"ip_host", "ip_gateway", "peer_ip", "router_id"})
ROLE_WORDS = (
    ("mgmt", ("MGMT", "OOB", "MANAGEMENT")),
    ("inet", ("INET", "INTERNET", "ISP", "WAN", "OUT")),
)
_KEY_BAD = re.compile(r"[^A-Za-z0-9_.-]+")


# ------------------------------------------------------------------ helpers


def host_network(fact: Fact, text: str) -> IPv4Network | None:
    """``ip_network(ip/len, strict=False)`` of an address fact with a mask."""
    if fact.mask_span is None or fact.mask_form == "wildcard":
        return None  # an ACL wildcard is a match, not an interface network
    mask = text[fact.mask_span.start : fact.mask_span.end]
    try:
        prefix = mask_prefix(mask)
    except (ValueError, KeyError):
        return None
    if prefix is None:
        return None
    try:
        return ip_network(f"{fact.value}/{prefix}", strict=False)  # type: ignore[return-value]
    except (ValueError, AddressValueError, NetmaskValueError):
        return None


def _addr(value: str) -> IPv4Address | None:
    try:
        return IPv4Address(value)
    except (AddressValueError, ValueError):
        return None


def _tag_key(tag: Tag) -> tuple[int, int]:
    if isinstance(tag, int):
        return (1, tag)
    return (0 if tag == "untagged" else 2, 0)


class _UF:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, i: int) -> int:
        while self.p[i] != i:
            self.p[i] = self.p[self.p[i]]
            i = self.p[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


@dataclass
class Unit:
    """A seed for a segment: a cloud group, or one VLAN of a carrier."""

    name: str
    aliases: set[str]
    label: str | None  # network name (None for sub-units)
    network_ids: list[str]
    cloud_type: str
    tags: set[Tag]  # sub-unit wire tags (empty for groups)
    endpoints: list[Endpoint] = field(default_factory=list)
    domains: list[VlanDomain] = field(default_factory=list)
    pinned: ManifestSegment | None = None
    carrier: bool = False  # True for the carrier group itself (not a sub-unit)
    sub: bool = False


@dataclass
class _Host:
    fact: Fact
    net: IPv4Network | None
    addr: IPv4Address


@dataclass
class _EpInfo:
    ep: Endpoint
    hosts: list[_Host]


@dataclass
class SegmentBuild:
    segments: list[Segment]
    findings: list[Finding]
    units: list[Unit]
    endpoints: dict[str, list[Endpoint]]  # segment key -> endpoints
    domains: dict[str, list[VlanDomain]]  # segment key -> VLAN domains


# ------------------------------------------------------------------- units


def _groups(
    topo: Topology, manifest: Manifest | None
) -> list[tuple[str, str, list[str], ManifestSegment | None]]:
    """``[(label, type, net ids, pinned manifest segment)]`` in document order."""
    out: list[tuple[str, str, list[str], ManifestSegment | None]] = []
    taken: set[str] = set()
    if manifest is not None:
        for ms in manifest.segments:
            nets = [n for n in ms.networks if n in topo.clouds and n not in taken]
            if not nets:
                continue
            taken.update(nets)
            labels = Counter(topo.clouds[n].name for n in nets)
            label = labels.most_common(1)[0][0]
            out.append((label, topo.clouds[nets[0]].type, nets, ms))
    by_name: dict[tuple[str, str], list[str]] = {}
    for nid, net in topo.clouds.items():
        if nid in taken:
            continue
        by_name.setdefault((net.type, net.name), []).append(nid)
    for (ctype, name), nets in by_name.items():
        out.append((name, ctype, nets, None))
    order = {nid: i for i, nid in enumerate(topo.clouds)}
    out.sort(key=lambda g: min(order[n] for n in g[2]))
    return out


def _is_carrier(
    nets: Sequence[str],
    pinned: ManifestSegment | None,
    traces: Mapping[str, TraceResult],
) -> bool:
    """Every port of the group is a switch trunk carrying two or more VLANs."""
    if pinned is not None:
        if pinned.status == "CARRIER" or pinned.carries:
            return True
        if pinned.status is not None:
            return False
    for tr in traces.values():
        if not all(tr.trunk_only.get(nid) for nid in nets):
            continue
        tags = {t for nid in nets for t in tr.wire_tags(nid) if isinstance(t, int)}
        if len(tags) >= 2:
            return True
    return False


def _units(
    topo: Topology, traces: Mapping[str, TraceResult], manifest: Manifest | None
) -> list[Unit]:
    units: list[Unit] = []
    subs: dict[tuple[str, Tag], Unit] = {}
    for label, ctype, nets, pinned in _groups(topo, manifest):
        netset = set(nets)
        eps = [
            e for tr in traces.values() for e in tr.endpoints if e.cloud_id in netset
        ]
        doms = [d for tr in traces.values() for d in tr.domains if d.cloud_id in netset]
        if _is_carrier(nets, pinned, traces):
            units.append(
                Unit(label, {label}, label, list(nets), ctype, set(), [], [], pinned)
            )
            units[-1].carrier = True
            for e in eps:
                sub = _sub(subs, ctype, e.tag, label)
                sub.endpoints.append(e)
            for d in doms:
                sub = _sub(subs, ctype, d.tag, label)
                sub.domains.append(d)
            continue
        units.append(Unit(label, {label}, label, list(nets), ctype, set(), eps, doms))
        units[-1].pinned = pinned
    # sub-units ending at the same node interface (in different scopes) are one unit
    sub_list = list(subs.values())
    uf = _UF(len(sub_list))
    owner: dict[tuple[str, str], int] = {}
    for i, sub in enumerate(sub_list):
        for e in sub.endpoints:
            key = (e.node_id, e.iface or e.eve_iface)
            if key in owner:
                uf.union(owner[key], i)
            else:
                owner[key] = i
    merged: dict[int, Unit] = {}
    for i, sub in enumerate(sub_list):
        root = uf.find(i)
        if root not in merged:
            merged[root] = sub
            continue
        tgt = merged[root]
        tgt.aliases |= sub.aliases
        tgt.tags |= sub.tags
        tgt.endpoints.extend(sub.endpoints)
        tgt.domains.extend(sub.domains)
    for sub in merged.values():
        sub.name = sorted(sub.aliases)[0]
        units.append(sub)
    return units


def _sub(subs: dict[tuple[str, Tag], Unit], ctype: str, tag: Tag, label: str) -> Unit:
    key = (ctype, tag)
    if key not in subs:
        subs[key] = Unit(f"{label}:{tag}", set(), None, [], ctype, {tag})
        subs[key].sub = True
    subs[key].aliases.add(f"{label}:{tag}")
    return subs[key]


# --------------------------------------------------------------- consensus


def _ep_infos(eps: Iterable[Endpoint]) -> list[_EpInfo]:
    out: list[_EpInfo] = []
    seen: set[tuple[str, str, str | None, Tag, str]] = set()
    for e in eps:
        sig = (e.scope, e.node_id, e.iface, e.tag, e.cloud_id)
        if sig in seen or not e.configured:
            continue
        seen.add(sig)
        hosts: list[_Host] = []
        text = e.config.text.text if e.config is not None else ""
        for f in e.facts:
            if f.kind != "ip_host":
                continue
            addr = _addr(f.value)
            if addr is None:
                continue
            hosts.append(_Host(f, host_network(f, text), addr))
        out.append(_EpInfo(e, hosts))
    return out


def _consensus_tag(infos: Sequence[_EpInfo]) -> Tag:
    tags = Counter(i.ep.tag for i in infos if i.ep.tag != "unknown")
    if not tags:
        return "unknown"
    best = max(tags.values())
    for i in infos:  # first (document order) among the most common
        if tags.get(i.ep.tag) == best:
            return i.ep.tag
    return "unknown"


def _consensus_subnet(hosts: Sequence[_Host]) -> IPv4Network | None:
    nets = [h.net for h in hosts if h.net is not None]
    if not nets:
        return None
    exact = Counter(nets)
    floor = max(1, (max(exact.values()) + 3) // 4)
    best: tuple[int, int, int] | None = None
    winner: IPv4Network | None = None
    for cand, count in exact.items():
        if count < floor:
            continue
        support = sum(1 for h in hosts if h.addr in cand)
        key = (support, count, -cand.prefixlen)
        if best is None or key > best:
            best, winner = key, cand
    return winner


def _gateway(
    infos: Sequence[_EpInfo], subnet: IPv4Network | None
) -> tuple[IPv4Address | None, list[Fact]]:
    if subnet is None:
        return None, []
    plain: Counter[IPv4Address] = Counter()
    hops: Counter[IPv4Address] = Counter()
    facts: dict[IPv4Address, list[Fact]] = {}
    seen: set[str] = set()
    for info in infos:
        cfg = info.ep.config
        if cfg is None or not info.hosts:
            continue
        for f in cfg.parsed.facts:
            if f.kind != "ip_gateway" or f.orphan or f.id in seen:
                continue
            addr = _addr(f.value)
            if addr is None or addr not in subnet:
                continue
            seen.add(f.id)
            facts.setdefault(addr, []).append(f)
            (hops if "nexthop" in f.flags else plain)[addr] += 1
    pool = plain or hops
    if not pool:
        return None, []
    gw = pool.most_common(1)[0][0]
    return gw, facts.get(gw, [])


def _unit_consensus(unit: Unit) -> dict[str, tuple[Tag, IPv4Network | None]]:
    out: dict[str, tuple[Tag, IPv4Network | None]] = {}
    infos = _ep_infos(unit.endpoints)
    for scope in sorted({i.ep.scope for i in infos}):
        si = [i for i in infos if i.ep.scope == scope]
        tag = _consensus_tag(si)
        hosts = [h for i in si if i.ep.tag == tag for h in i.hosts]
        out[scope] = (tag, _consensus_subnet(hosts))
    return out


# ------------------------------------------------------------------ merging


def _merge(
    units: list[Unit],
    manifest: Manifest | None,
    findings: list[Finding],
) -> list[tuple[list[Unit], list[str]]]:
    """Union-find over non-carrier units: ``[(units, merge reasons)]``."""
    seeds = [u for u in units if not u.carrier]
    uf = _UF(len(seeds))
    reasons: list[tuple[int, str]] = []

    def pinned_conflict(a: Unit, b: Unit) -> bool:
        return (
            a.pinned is not None and b.pinned is not None and a.pinned is not b.pinned
        )

    def join(i: int, j: int, why: str) -> None:
        if uf.find(i) == uf.find(j):
            return
        uf.union(i, j)
        reasons.append((i, why))

    # (a) one manifest segment
    for i, a in enumerate(seeds):
        for j in range(i + 1, len(seeds)):
            if a.pinned is not None and seeds[j].pinned is a.pinned:
                join(i, j, f"manifest segment {a.pinned.key}")
    # (a) [[merge]]
    by_alias: dict[str, int] = {}
    for i, u in enumerate(seeds):
        for alias in u.aliases | {u.name}:
            by_alias.setdefault(alias.lower(), i)
    # Units named by their manifest baseline label still resolve after a relabel
    # (localized lab): current names win (T21 fix).
    carrier_base = {
        u.label: u.pinned.baseline.label
        for u in units
        if u.carrier and u.label and u.pinned is not None and u.pinned.baseline.label
    }
    for i, u in enumerate(seeds):
        extra: set[str] = set()
        if u.pinned is not None and u.pinned.baseline.label:
            extra.add(u.pinned.baseline.label)
        for alias in u.aliases:
            label, sep, tag = alias.rpartition(":")
            if sep and label in carrier_base:
                extra.add(f"{carrier_base[label]}:{tag}")
        for alias in extra:
            by_alias.setdefault(alias.lower(), i)
    if manifest is not None:
        for m in manifest.merges:
            idx = []
            for name in m.units:
                if name.lower() in by_alias:
                    idx.append(by_alias[name.lower()])
                else:
                    findings.append(
                        Finding(
                            "MERGE_UNKNOWN_UNIT",
                            "warn",
                            f"manifest [[merge]] names unknown unit {name!r}",
                            [name],
                        )
                    )
            for j in idx[1:]:
                join(idx[0], j, "manifest [[merge]] " + " + ".join(m.units))
    # (b) same PROVEN (tag, subnet) in a common scope, no conflicting subnet
    cons = [_unit_consensus(u) for u in seeds]
    for i in range(len(seeds)):
        for j in range(i + 1, len(seeds)):
            if pinned_conflict(seeds[i], seeds[j]):
                continue
            common = [
                s
                for s in cons[i]
                if s in cons[j]
                and cons[i][s][1] is not None
                and cons[j][s][1] is not None
                and cons[i][s][0] != "unknown"
            ]
            if not common:
                continue
            if any(cons[i][s][1] != cons[j][s][1] for s in common):
                continue
            hit = [s for s in common if cons[i][s] == cons[j][s]]
            if hit:
                tag, net = cons[i][hit[0]]
                join(
                    i,
                    j,
                    f"{seeds[i].name} = {seeds[j].name}: tag {tag} {net} ({hit[0]})",
                )
    # (c) switch `vlan v` / `name X` where X is another unit's label
    by_label: dict[str, int] = {}
    for i, u in enumerate(seeds):
        if u.label:
            by_label.setdefault(u.label.lower(), i)
    for i, u in enumerate(seeds):
        for d in u.domains:
            for f, _unc in domain_facts(d.config, d.vlan):
                if f.kind != "vlan_name":
                    continue
                j = by_label.get(f.value.lower())
                if j is None or j == i or pinned_conflict(u, seeds[j]):
                    continue
                join(i, j, f"vlan {d.vlan} name {f.value} on node {d.node_id}")
    groups: dict[int, tuple[list[Unit], list[str]]] = {}
    for i, u in enumerate(seeds):
        groups.setdefault(uf.find(i), ([], []))[0].append(u)
    for i, why in reasons:
        groups[uf.find(i)][1].append(why)
    return list(groups.values())


# ------------------------------------------------------------------ schemes


@dataclass
class _SchemeBuild:
    scheme: Scheme
    members: list[Fact] = field(default_factory=list)
    outliers: list[Fact] = field(default_factory=list)
    gateways: list[Fact] = field(default_factory=list)
    evidence: dict[str, str] = field(default_factory=dict)  # fact id -> path


def _fits(info: _EpInfo, tag: Tag, subnet: IPv4Network | None) -> bool:
    if info.ep.tag != tag and info.ep.tag != "unknown":
        return False
    if subnet is None:
        return True
    return all(h.addr in subnet for h in info.hosts)


def _schemes(
    eps: Sequence[Endpoint],
    scope_order: Sequence[str],
    canonical: str | None,
    outlier_pins: set[tuple[str, str]],
    include_outliers: bool,
) -> list[_SchemeBuild]:
    infos = _ep_infos(eps)
    if not infos:
        return []
    by_scope: dict[str, list[_EpInfo]] = {}
    for info in infos:
        by_scope.setdefault(info.ep.scope, []).append(info)
    tuples: dict[str, tuple[Tag, IPv4Network | None, IPv4Address | None]] = {}
    gw_facts: dict[str, list[Fact]] = {}
    for scope, si in by_scope.items():
        tag = _consensus_tag(si)
        hosts = [h for i in si if i.ep.tag == tag for h in i.hosts]
        subnet = _consensus_subnet(hosts)
        fitting = [i for i in si if _fits(i, tag, subnet)]
        gw, gfacts = _gateway(fitting, subnet)
        tuples[scope] = (tag, subnet, gw)
        gw_facts[scope] = gfacts
    builds: dict[tuple[Tag, IPv4Network | None, IPv4Address | None], _SchemeBuild] = {}
    order = {s: i for i, s in enumerate(scope_order)}
    for scope in sorted(tuples, key=lambda s: order.get(s, 99)):
        t = tuples[scope]
        if t not in builds:
            builds[t] = _SchemeBuild(Scheme(t[0], t[1], t[2], set(), [], []))
        builds[t].scheme.scopes.add(scope)
    assigned: list[tuple[_EpInfo, _SchemeBuild, _SchemeBuild | None]] = []
    for scope in sorted(by_scope, key=lambda s: order.get(s, 99)):
        own = builds[tuples[scope]]
        for g in gw_facts[scope]:
            if g not in own.gateways:
                own.gateways.append(g)
        for info in by_scope[scope]:
            target: _SchemeBuild | None = None
            pinned_out = (scope, info.ep.node_id) in outlier_pins
            if not pinned_out:
                if _fits(info, own.scheme.tag, own.scheme.subnet):
                    target = own
                else:
                    for b in builds.values():
                        if b is not own and _fits(info, b.scheme.tag, b.scheme.subnet):
                            target = b
                            b.scheme.scopes.add(scope)
                            break
                if target is None and include_outliers:
                    target = own
            assigned.append((info, own, target))
    if not include_outliers:
        # one address on two nodes of a scheme: the later node's endpoint is an outlier
        owners: dict[tuple[int, IPv4Address], set[str]] = {}
        for info, _own, target in assigned:
            if target is not None:
                for h in info.hosts:
                    owners.setdefault((id(target), h.addr), set()).add(info.ep.node_id)
        for i, (info, _own, target) in enumerate(assigned):
            if target is None:
                continue
            for h in info.hosts:
                nodes = owners.get((id(target), h.addr), set())
                if len(nodes) > 1 and info.ep.node_id != min(nodes, key=_node_order):
                    assigned[i] = (info, target, None)
                    break
    for info, own, target in assigned:
        facts = [f for f in info.ep.facts if f.kind in ENDPOINT_KINDS]
        path = " -> ".join(info.ep.path)
        bucket = own.outliers if target is None else target.members
        dest = own if target is None else target
        for f in facts:
            if f not in bucket:
                bucket.append(f)
                dest.evidence[f.id] = path
    for b in builds.values():  # a fact both member and outlier stays a member
        b.outliers = [f for f in b.outliers if f not in b.members]
    out = list(builds.values())

    def rank(b: _SchemeBuild) -> tuple[int, int]:
        return (0 if canonical in b.scheme.scopes else 1, -len(b.members))

    out.sort(key=rank)
    for b in out:
        b.scheme.members = [f.id for f in b.members] + [f.id for f in b.gateways]
        b.scheme.outliers = [f.id for f in b.outliers]
    return out


def _node_order(node_id: str) -> tuple[int, str]:
    return (int(node_id), node_id) if node_id.isdigit() else (1 << 30, node_id)


# ------------------------------------------------------------- key / role


def normalise_key(label: str) -> str | None:
    """``EVE-MGMT-203`` -> ``MGMT-203``; None when no letter remains."""
    key = label.strip()
    if key.upper().startswith("EVE-"):
        key = key[4:]
    key = _KEY_BAD.sub("-", key).strip("-_.").upper()
    if not key or not any(c.isalpha() for c in key):
        return None
    if not key[0].isalpha():
        key = "N" + key
    return key


def guess_role(labels: Iterable[str], ctype: str, carrier: bool) -> str | None:
    if carrier:
        return "trunk"
    if ctype.startswith("nat"):
        return "nat"
    words = " ".join(labels).upper()
    for role, keys in ROLE_WORDS:
        if any(re.search(rf"(?<![A-Z]){k}(?![A-Z])", words) for k in keys):
            return role
    return None


# ------------------------------------------------------------------- build


def _status(eps: Sequence[Endpoint], schemes: Sequence[_SchemeBuild]) -> str:
    configured = [e for e in eps if e.configured]
    if any(e.kind in ("routed", "svi") for e in configured):
        return "CONFIGURABLE"
    if any(
        isinstance(b.scheme.tag, int) or b.scheme.subnet is not None for b in schemes
    ):
        return "CONFIGURABLE"
    if configured and all(e.kind == "dhcp" for e in configured):
        return "DHCP"
    if eps:
        return "LABEL_ONLY"
    return "UNKNOWN"


def build(
    topo: Topology,
    index: ConfigIndex,
    traces: Mapping[str, TraceResult],
    facts: Mapping[str, Fact],
    texts: Sequence[ConfigText],
    *,
    lab_stem: str,
    manifest: Manifest | None = None,
    canonical_scope: str | None = None,
    include_outliers: bool = False,
) -> SegmentBuild:
    """Group clouds into segments, compute schemes and attribute facts."""
    findings: list[Finding] = []
    if not topo.clouds:
        return SegmentBuild([], findings, [], {}, {})
    units = _units(topo, traces, manifest)
    groups = _merge(units, manifest, findings)
    outlier_pins = {(o.scope, o.node) for o in (manifest.outliers if manifest else [])}
    canonical = canonical_scope or (manifest.canonical_scope if manifest else None)
    if canonical is None:
        counts = Counter(topo.active_scope.values())
        canonical = counts.most_common(1)[0][0] if counts else "startup"
    explainer = NameExplainer()
    order = {nid: i for i, nid in enumerate(topo.clouds)}

    plans: list[dict] = []
    for g, why in groups:
        nets = sorted({n for u in g for n in u.network_ids}, key=lambda n: order[n])
        eps = [e for u in g for e in u.endpoints]
        doms = [d for u in g for d in u.domains]
        pinned = next((u.pinned for u in g if u.pinned is not None), None)
        builds = _schemes(eps, topo.scopes, canonical, outlier_pins, include_outliers)
        plans.append(
            {
                "units": g,
                "nets": nets,
                "eps": eps,
                "doms": doms,
                "why": list(dict.fromkeys(why)),
                "pinned": pinned,
                "builds": builds,
            }
        )
    # carriers: group those that carry a common segment
    carriers = [u for u in units if u.carrier]
    unit_plan: dict[int, int] = {
        id(u): pi for pi, p in enumerate(plans) for u in p["units"]
    }
    carried_by: dict[int, set[int]] = {}
    for ci, c in enumerate(carriers):
        label = c.label or ""
        for pi, p in enumerate(plans):
            if any(
                u.sub and any(a.startswith(label + ":") for a in u.aliases)
                for u in p["units"]
            ):
                carried_by.setdefault(ci, set()).add(pi)
    cuf = _UF(len(carriers))
    for i in range(len(carriers)):
        for j in range(i + 1, len(carriers)):
            pi, pj = carriers[i].pinned, carriers[j].pinned
            if pi is not None and pj is not None and pi is not pj:
                continue
            if carried_by.get(i, set()) & carried_by.get(j, set()):
                cuf.union(i, j)
    carrier_groups: dict[int, list[int]] = {}
    for i in range(len(carriers)):
        carrier_groups.setdefault(cuf.find(i), []).append(i)

    # keys
    used: set[str] = set()

    def unique(key: str, nets: Sequence[str]) -> str:
        if key not in used:
            used.add(key)
            return key
        alt = f"{key}-{nets[0]}" if nets else f"{key}-2"
        n = 2
        while alt in used:
            alt = f"{key}-{n}"
            n += 1
        used.add(alt)
        return alt

    def derive_key(nets: Sequence[str]) -> str | None:
        labels = Counter(topo.clouds[n].name for n in nets)
        if not labels:
            return None
        best = max(labels.values())
        for n in nets:  # document order among the most common
            if labels[topo.clouds[n].name] == best:
                return normalise_key(topo.clouds[n].name) or f"cloud-{min_id(nets)}"
        return None

    def min_id(nets: Sequence[str]) -> str:
        return min(nets, key=_node_order)

    carrier_keys: dict[int, str] = {}
    carrier_segments: list[tuple[Segment, list[int]]] = []
    for root, members in carrier_groups.items():
        nets = sorted(
            {n for i in members for n in carriers[i].network_ids},
            key=lambda n: order[n],
        )
        pinned = next((carriers[i].pinned for i in members if carriers[i].pinned), None)
        key = pinned.key if pinned else (derive_key(nets) or f"cloud-{min_id(nets)}")
        key = unique(key, nets)
        carrier_keys[root] = key
        seg = Segment(
            key=key,
            site_key=(
                pinned.site_key if pinned and pinned.site_key else f"{lab_stem}.{key}"
            ),
            role=(pinned.role if pinned and pinned.role else "trunk"),
            network_ids=nets,
            cloud_types={topo.clouds[n].type for n in nets},
            labels={n: topo.clouds[n].name for n in nets},
            attachments=[],
            schemes=[],
            status="CARRIER",
        )
        attrs = sorted(
            {
                f"{a}={topo.clouds[n].attrs[a]}"
                for n in nets
                for a in ("native_vlan", "vlan8021ad")
                if a in topo.clouds[n].attrs
            }
        )
        if attrs:
            seg.notes.append("EVE trunk attributes: " + ", ".join(attrs))
            findings.append(
                Finding(
                    "TRUNK_ATTRS",
                    "info",
                    f"carrier {key}: {', '.join(attrs)} (shown only, never edited)",
                    [f"segment:{key}"],
                )
            )
        carrier_segments.append((seg, members))

    segments: list[Segment] = []
    seg_eps: dict[str, list[Endpoint]] = {}
    seg_doms: dict[str, list[VlanDomain]] = {}
    plan_keys: dict[int, str] = {}
    for pi, p in enumerate(plans):
        nets: list[str] = p["nets"]
        pinned = p["pinned"]
        units_g: list[Unit] = p["units"]
        if pinned is not None:
            key = pinned.key
        elif nets:
            key = derive_key(nets) or f"cloud-{min_id(nets)}"
        else:
            ckey = None
            for root, members in carrier_groups.items():
                if any(pi in carried_by.get(i, set()) for i in members):
                    ckey = carrier_keys[root]
                    break
            tags = sorted({t for u in units_g for t in u.tags}, key=_tag_key)
            key = f"{ckey or 'CARRIED'}-" + "-".join(str(t) for t in tags)
        key = unique(key, nets)
        plan_keys[pi] = key
        builds: list[_SchemeBuild] = p["builds"]
        eps: list[Endpoint] = p["eps"]
        labels = {n: topo.clouds[n].name for n in nets}
        status = _status(eps, builds)
        if pinned is not None and pinned.status:
            status = pinned.status
        attachments = []
        seen_att: set[tuple] = set()
        for e in sorted(eps, key=lambda e: (not e.direct, e.scope)):
            att = e.to_attachment()
            sig = (att.node_id, att.iface, att.network_id, att.scope)
            if sig in seen_att:
                continue
            seen_att.add(sig)
            attachments.append(att)
        ctype = {topo.clouds[n].type for n in nets} or {u.cloud_type for u in units_g}
        seg = Segment(
            key=key,
            site_key=(
                pinned.site_key if pinned and pinned.site_key else f"{lab_stem}.{key}"
            ),
            role=(
                pinned.role
                if pinned and pinned.role
                else guess_role(
                    (
                        [*labels.values(), *[a for u in units_g for a in u.aliases]]
                        if labels
                        else [a for u in units_g for a in u.aliases]
                    ),
                    next(iter(ctype)),
                    False,
                )
            ),
            network_ids=nets,
            cloud_types=ctype,
            labels=labels,
            attachments=attachments,
            schemes=[b.scheme for b in builds],
            status=status,  # type: ignore[arg-type]
        )
        for w in p["why"]:
            seg.notes.append(f"merged: {w}")
        if not nets:
            seg.notes.append("no cloud network of its own: reached only via a carrier")
        # name hints
        tags = {b.scheme.tag for b in builds if isinstance(b.scheme.tag, int)}
        octs: set[int] = set()
        for b in builds:
            octs |= octets3(b.scheme.subnet)
        for n in nets:
            hosts: set[int] = set()
            for b in builds:
                for f in b.members:
                    if f.kind != "ip_host":
                        continue
                    if not any(
                        e.network_id == n and f in e.facts for e in eps if e.direct
                    ):
                        continue
                    addr = _addr(f.value)
                    if addr is not None:
                        hosts.add(int(addr) & 0xFF)
            ctx = NameContext(set(tags), octs, hosts, n)
            seg.name_hints[n] = explainer.explain(labels[n], ctx)
        segments.append(seg)
        seg_eps[key] = eps
        seg_doms[key] = p["doms"]
    for seg, members in carrier_segments:
        carried: list[str] = []
        for i in members:
            for pi in sorted(carried_by.get(i, set())):
                if plan_keys[pi] not in carried:
                    carried.append(plan_keys[pi])
        pinned = next((carriers[i].pinned for i in members if carriers[i].pinned), None)
        seg.carries = list(pinned.carries) if pinned and pinned.carries else carried
        atts = []
        for i in members:
            for nid in carriers[i].network_ids:
                for port in topo.ports_by_net.get(nid, []):
                    atts.append(
                        Attachment(
                            port.node_id,
                            port.eve_name,
                            nid,
                            topo.active_scope.get(port.node_id, "startup"),
                            [topo.clouds[nid].name],
                            True,
                            "tagged",
                        )
                    )
        seg.attachments = atts
        for key in seg.carries:
            for s in segments:
                if s.key == key:
                    s.notes.append(f"carried by {seg.key}")
    # order: by first network, carried-only segments after their carrier
    all_segments = segments + [s for s, _ in carrier_segments]
    all_segments.sort(
        key=lambda s: (
            min((order[n] for n in s.network_ids), default=len(order)),
            s.key,
        )
    )
    if manifest is not None:
        for leg in manifest.legacy:
            for s in all_segments:
                if s.key == leg.segment:
                    s.notes.append(
                        f"legacy scopes {', '.join(leg.scopes)}: policy {leg.policy}"
                    )
    # hints: label numbers equal to a carrier tag
    for u in units:
        if u.sub or u.carrier:
            continue
        p_i = unit_plan[id(u)]
        for tok in re.findall(r"\d+", u.label or ""):
            val = int(tok)
            for pi2, p2 in enumerate(plans):
                if pi2 == p_i or p2["nets"]:
                    continue
                if any(val in uu.tags for uu in p2["units"]):
                    other = plan_keys[pi2]
                    msg = (
                        f"{u.name} may be the same segment as {other} "
                        f"(label number {val} = carrier tag); confirm with [[merge]]"
                    )
                    findings.append(Finding("MERGE_HINT", "info", msg, [u.name, other]))
                    seg_key = plan_keys[p_i]
                    for s in all_segments:
                        if s.key == seg_key:
                            s.notes.append("hint: " + msg)
    sb = SegmentBuild(all_segments, findings, units, seg_eps, seg_doms)
    _attribute(sb, plans, plan_keys, topo, index, facts, texts, include_outliers)
    _segment_findings(sb, topo, traces, facts)
    return sb


# ------------------------------------------------------------- attribution


def _set(
    fact: Fact,
    key: str,
    conf: Confidence,
    evidence: str,
    extra: frozenset[str] = frozenset(),
) -> bool:
    """Attribute ``fact`` to segment ``key`` (first attribution wins)."""
    if fact.segment is not None:
        return fact.segment == key
    fact.segment = key
    fact.confidence = conf
    fact.evidence = evidence
    if extra:
        fact.flags = fact.flags | extra
    return True


def _attribute(
    sb: SegmentBuild,
    plans: list[dict],
    plan_keys: dict[int, str],
    topo: Topology,
    index: ConfigIndex,
    facts: Mapping[str, Fact],
    texts: Sequence[ConfigText],
    include_outliers: bool,
) -> None:
    findings = sb.findings
    # 1. endpoint facts (PROVEN) and gateways; then outliers
    for pi, p in enumerate(plans):
        key = plan_keys[pi]
        for b in p["builds"]:
            for f in b.members:
                _set(f, key, Confidence.PROVEN, b.evidence.get(f.id, ""))
            for f in b.gateways:
                _set(f, key, Confidence.PROVEN, "default gateway inside the subnet")
    for pi, p in enumerate(plans):
        key = plan_keys[pi]
        for b in p["builds"]:
            for f in b.outliers:
                _set(
                    f,
                    key,
                    min(f.confidence, Confidence.CORRELATED),
                    b.evidence.get(f.id, "") + " (outlier)",
                    frozenset({"outlier"}),
                )
    for pi, p in enumerate(plans):
        key = plan_keys[pi]
        for b in p["builds"]:
            nodes = sorted({f.node_id or "" for f in b.outliers})
            for nid in nodes:
                node = topo.nodes.get(nid)
                vals = sorted(
                    {
                        f.value
                        for f in b.outliers
                        if f.node_id == nid and f.kind == "ip_host"
                    }
                )
                findings.append(
                    Finding(
                        "OUTLIER",
                        "warn",
                        f"segment {key}: node {nid} ({node.name if node else '?'}) "
                        f"{', '.join(vals) or 'tag'} does not match scheme "
                        f"{_scheme_text(b.scheme)}; excluded by default",
                        [f"segment:{key}", f"node:{nid}"],
                    )
                )
    # 2. switch VLAN-domain rule (CORRELATED, uncabled flag)
    for pi, p in enumerate(plans):
        key = plan_keys[pi]
        for d in p["doms"]:
            for f, uncabled in domain_facts(d.config, d.vlan):
                if f.segment is not None and f.segment != key:
                    continue
                extra = frozenset({"uncabled"}) if uncabled else frozenset()
                ev = " -> ".join(d.path) + f" (switch VLAN {d.vlan} = tag {d.tag})"
                _set(f, key, Confidence.CORRELATED, ev, extra)
    # 3. correlation pass: IPv4 facts inside a scheme subnet
    nets: list[tuple[IPv4Network, set[str], str]] = []
    for s in sb.segments:
        if s.status == "CARRIER":
            continue
        for sch in s.schemes:
            if sch.subnet is not None and sch.subnet.prefixlen < 32:
                nets.append((sch.subnet, sch.scopes, s.key))
    for f in facts.values():
        if f.segment is not None or f.kind not in CORRELATION_KINDS:
            continue
        addr = _addr(f.value)
        if addr is None:
            continue
        cands = [n for n in nets if addr in n[0]]
        if not cands:
            continue
        scoped = [n for n in cands if f.store.scope in n[1]] or cands
        scoped.sort(key=lambda n: -n[0].prefixlen)
        net, _scopes, key = scoped[0]
        _set(f, key, Confidence.CORRELATED, f"inside {net}")
        for s in sb.segments:
            if s.key == key:
                for sch in s.schemes:
                    if sch.subnet == net and f.id not in sch.members:
                        sch.members.append(f.id)
                        break
    # 4. an SVI address inside a segment proves that switch VLAN (CORRELATED):
    #    SVI name, VLAN definition/name, uncabled/truncated port tags, orphan tags
    for nc in index.all_configs():
        svis = {
            f.iface: f
            for f in nc.parsed.facts
            if f.kind == "svi_name" and f.iface and not f.orphan
        }
        for f in nc.parsed.facts:
            if f.kind != "ip_host" or f.iface not in svis or not f.segment:
                continue
            if "outlier" in f.flags:
                continue
            svi = svis[f.iface]
            ev = f"SVI {svi.value} has {f.value} in segment {f.segment}"
            _set(svi, f.segment, Confidence.CORRELATED, ev)
            if not nc.is_switch:
                continue
            for vlan in fact_vlans(svi):
                for g, uncabled in domain_facts(nc, vlan):
                    extra = frozenset({"uncabled"}) if uncabled else frozenset()
                    _set(g, f.segment, Confidence.CORRELATED, ev, extra)
        by_vlan: dict[int, str] = {}
        for f in nc.parsed.facts:
            if f.segment and not f.orphan and "outlier" not in f.flags:
                for v in fact_vlans(f):
                    by_vlan.setdefault(v, f.segment)
        for f in nc.parsed.facts:
            if not f.orphan or f.kind not in ("vlan_tag", "vlan_list"):
                continue
            if f.segment is not None:
                continue
            vl = fact_vlans(f)
            hit = [by_vlan[v] for v in sorted(vl) if v in by_vlan]
            if hit:
                _set(
                    f,
                    hit[0],
                    Confidence.CORRELATED,
                    "orphan block: same VLAN as an attributed fact on this node",
                )
            elif vl & _external_tags(sb):
                findings.append(
                    Finding(
                        "UNATTRIBUTED_TAG",
                        "warn",
                        f"node {nc.node_id} {nc.store.kind}:{nc.store.name} line "
                        f"{f.line}: orphan {f.kind} {f.value} not attributed",
                        [f"node:{nc.node_id}", f"fact:{f.id}"],
                    )
                )
    # 5. mirror sidecars copy their source
    by_text: dict[tuple, ConfigText] = {}
    for ct in texts:
        if ct.store.kind in ("startup", "configset"):
            by_text[(ct.store.scope, ct.node_id)] = ct
    for ct in texts:
        if ct.mirror_of is None:
            continue
        src = by_text.get(ct.mirror_of)
        if src is None:
            continue
        nsrc, nmir = index.of(src), index.of(ct)
        if nsrc is None or nmir is None:
            continue
        spans = {(f.kind, f.span.start, f.span.end): f for f in nsrc.parsed.facts}
        for f in nmir.parsed.facts:
            o = spans.get((f.kind, f.span.start, f.span.end))
            if o is None or o.segment is None:
                continue
            f.segment = o.segment
            f.confidence = o.confidence
            f.evidence = f"mirror of {o.store.scope}: {o.evidence}"
            f.flags = f.flags | (o.flags & {"uncabled", "outlier"})


def _external_tags(sb: SegmentBuild) -> set[int]:
    return {
        sch.tag for s in sb.segments for sch in s.schemes if isinstance(sch.tag, int)
    }


def _scheme_text(s: Scheme) -> str:
    return f"tag {s.tag} {s.subnet or '-'} gw {s.gateway or '-'}"


def _segment_findings(
    sb: SegmentBuild,
    topo: Topology,
    traces: Mapping[str, TraceResult],
    facts: Mapping[str, Fact],
) -> None:
    configured: set[tuple[str, str]] = set()
    for tr in traces.values():
        for port, kind in tr.direct_ports.items():
            if kind in ("access", "trunk"):
                configured.add(port)
        for e in tr.endpoints:
            if e.direct and e.configured:
                configured.add((e.node_id, e.eve_iface))
    node_segments: dict[str, set[str]] = {}
    for f in facts.values():
        if f.segment and f.node_id and "outlier" not in f.flags:
            node_segments.setdefault(f.node_id, set()).add(f.segment)
    for s in sb.segments:
        if s.status == "CARRIER":
            continue
        eps = sb.endpoints.get(s.key, [])
        unconf = sorted(
            {
                (e.node_id, e.eve_iface)
                for e in eps
                if e.direct and (e.node_id, e.eve_iface) not in configured
            }
        )
        if unconf:
            names = ", ".join(
                f"{topo.nodes[n].name if n in topo.nodes else n} {i}" for n, i in unconf
            )
            sb.findings.append(
                Finding(
                    "UNCONFIGURED",
                    "info",
                    f"segment {s.key}: no config on {names} (bridge/label only)",
                    [f"segment:{s.key}"] + [f"node:{n}" for n, _ in unconf],
                )
            )
        if s.status == "LABEL_ONLY":
            others = sorted(
                {
                    k
                    for n, _ in unconf
                    for k in node_segments.get(n, set())
                    if k != s.key
                }
            )
            for other in others:
                msg = (
                    f"{s.key}: attached nodes have addresses in segment {other}; "
                    "it may be the same segment (confirm with [[merge]])"
                )
                s.notes.append("hint: " + msg)
                sb.findings.append(Finding("MERGE_HINT", "info", msg, [s.key, other]))
        if s.status == "DHCP":
            nodes = sorted({e.node_id for e in eps if e.kind == "dhcp"})
            sb.findings.append(
                Finding(
                    "DHCP_UPLINK",
                    "info",
                    f"segment {s.key}: DHCP uplink on "
                    + ", ".join(topo.nodes[n].name for n in nodes if n in topo.nodes)
                    + "; the target bridge must provide DHCP",
                    [f"segment:{s.key}"] + [f"node:{n}" for n in nodes],
                )
            )
