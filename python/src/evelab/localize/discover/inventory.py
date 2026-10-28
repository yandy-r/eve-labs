"""Protected inventory: everything internal that edits must never touch (design 7.5).

* ``protected_vlans[scope]``: VLAN numbers named by tag-bearing facts that are not
  attributed to an external segment (and VLANs of a partly external list that are
  not external on that switch), plus platform-reserved VLANs when such a platform
  carries a segment (IOS/IOL 1002-1005, NX-OS 3968-4094).
* ``protected_prefixes``: networks of unattributed ``ip/len`` host facts (not inside
  an external scheme subnet) plus the manifest ``protect`` list.

The planner uses :func:`protected_fact_ids` to hard-block edits on protected facts
and :func:`lookalikes` for the "1240 appears 8x on internal links" list.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, collapse_addresses

from ..model import Fact, Segment
from .l2trace import fact_vlans
from .segments import host_network
from .topology import ConfigIndex

__all__ = [
    "RESERVED_VLANS",
    "Inventory",
    "build",
    "lookalikes",
    "protected_fact_ids",
]

RESERVED_VLANS: dict[str, range] = {
    "ios": range(1002, 1006),
    "nxos": range(3968, 4095),
}
TAG_FACT_KINDS = frozenset(
    {"vlan_tag", "vlan_list", "vlan_def", "svi_name", "subif_name"}
)
PREFIX_FACT_KINDS = frozenset({"ip_host"})
PROTECTABLE_KINDS = TAG_FACT_KINDS | frozenset(
    {"ip_host", "ip_gateway", "ip_route_dst", "peer_ip", "router_id", "mask"}
)


@dataclass
class Inventory:
    vlans: dict[str, set[int]]
    prefixes: list[IPv4Network]


def build(
    facts: Mapping[str, Fact],
    segments: Sequence[Segment],
    index: ConfigIndex,
    scopes: Iterable[str],
    protect: Iterable[IPv4Network] = (),
) -> Inventory:
    scopes = list(scopes)
    vlans: dict[str, set[int]] = {s: set() for s in scopes}
    external_nets = [
        sch.subnet
        for s in segments
        if s.status != "CARRIER"
        for sch in s.schemes
        if sch.subnet is not None
    ]
    # external VLANs per (store, node): from attributed tag facts
    ext: dict[tuple, set[int]] = {}
    for f in facts.values():
        if f.segment and f.kind in TAG_FACT_KINDS and "outlier" not in f.flags:
            ext.setdefault((f.store, f.node_id), set()).update(fact_vlans(f))
    for f in facts.values():
        if f.kind not in TAG_FACT_KINDS or f.store.kind == "textobject":
            continue
        if "outlier" in f.flags:
            continue
        scope = f.store.scope
        bucket = vlans.setdefault(scope, set())
        vl = fact_vlans(f)
        if f.segment is None:
            bucket.update(vl)
        else:
            bucket.update(vl - ext.get((f.store, f.node_id), set()))
    # platform-reserved VLANs where such a platform carries an external segment
    carrying = {f.node_id for f in facts.values() if f.segment}
    for nc in index.all_configs():
        if nc.node_id not in carrying:
            continue
        reserved = RESERVED_VLANS.get(nc.dialect.name)
        if reserved is not None:
            for s in vlans:
                vlans[s].update(reserved)
    prefixes: set[IPv4Network] = set(protect)
    texts = {(nc.store, nc.node_id): nc.text.text for nc in index.all_configs()}
    for f in facts.values():
        if f.segment is not None or f.kind not in PREFIX_FACT_KINDS:
            continue
        if f.store.kind == "textobject" or f.mask_span is None:
            continue
        text = texts.get((f.store, f.node_id))
        if text is None:
            continue
        net = host_network(f, text)
        if net is None or net.prefixlen == 0:
            continue
        if net.prefixlen < 31 and str(net.network_address) == f.value:
            # a network address is a route/ACL reference, never an interface
            continue
        if any(net.subnet_of(x) for x in external_nets):
            continue
        prefixes.add(net)
    ordered = sorted(prefixes, key=lambda n: (int(n.network_address), n.prefixlen))
    return Inventory(vlans, ordered)


def protected_fact_ids(facts: Mapping[str, Fact]) -> set[str]:
    """Ids of facts an edit must never touch (unattributed, value-bearing)."""
    return {
        f.id
        for f in facts.values()
        if f.segment is None and f.kind in PROTECTABLE_KINDS
    }


def lookalikes(facts: Mapping[str, Fact], segment: Segment) -> list[Fact]:
    """Protected facts with one of ``segment``'s tags or an address in its subnets."""
    tags = {s.tag for s in segment.schemes if isinstance(s.tag, int)}
    out: list[Fact] = []
    for f in facts.values():
        if f.segment is not None:
            continue
        if f.kind in TAG_FACT_KINDS and fact_vlans(f) & tags:
            out.append(f)
    return out


def summarize(prefixes: Iterable[IPv4Network]) -> list[IPv4Network]:
    """Collapse adjacent prefixes (display helper)."""
    return list(collapse_addresses(prefixes))  # type: ignore[arg-type]
