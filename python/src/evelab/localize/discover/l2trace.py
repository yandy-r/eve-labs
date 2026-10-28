"""L2 trace: where each cloud's frames end up, per config scope (design 7.2).

For every cloud network the BFS starts at each cabled port with the state
``incoming="any"`` (a cloud delivers untagged frames *and* any tag) and follows:

* **routed endpoint** (not a switch port): the addressed physical iface (and
  Junos/F5 children with no tag) is an *untagged* endpoint; each sub-interface or
  Forti VLAN iface **whose parent is the attached iface** is a *tagged* endpoint.
  Nothing configured -> ``unconfigured`` endpoint (tag ``unknown``).
* **switch port**: access ``v`` maps untagged frames to switch VLAN ``v``; a trunk
  carries its allowed list, or **all of ``vlan_db``** when it has none (``vlan_db``
  includes implicit VLANs).  The switch VLAN then leaves through every other port
  carrying it (access -> peer receives untagged, trunk -> tagged) and ends at an
  addressed SVI ``Vlan v`` on the switch itself.
* bridge networks are crossed to every peer; reaching another cloud records a
  ``cloud_link`` and stops.  Depth (bridge hops) is capped at ``max_depth``.

``Endpoint.tag`` is the VLAN **on the cloud wire** (``"untagged"``, an int, or
``"unknown"``).  Each switch VLAN proven equal to a wire tag is recorded as a
:class:`VlanDomain`; :func:`domain_facts` lists the tag facts the switch
VLAN-domain rule attributes (definition, name, uncabled ports).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Literal

from evelab.common.textutil import VlanList, VlanListError

from ..model import Attachment, Fact, Finding, Tag
from .topology import ConfigIndex, NodeConfig, Topology

__all__ = [
    "Endpoint",
    "TraceResult",
    "VlanDomain",
    "domain_facts",
    "fact_vlans",
    "trace_all",
    "trace_scope",
]

Incoming = Literal["any", "untagged"] | int
EndpointKind = Literal["routed", "dhcp", "svi", "tag_only", "unconfigured"]
TAG_KINDS = frozenset({"vlan_tag", "vlan_list", "vlan_def", "svi_name", "subif_name"})
MAX_DEPTH = 6


@dataclass
class Endpoint:
    """A place where a cloud's traffic terminates (or would, if configured)."""

    cloud_id: str  # cloud network the trace started from
    scope: str
    node_id: str
    eve_iface: str  # EVE port where the frames enter this node
    iface: str | None  # config iface holding the addresses (None: no config)
    network_id: str  # network that port is cabled to
    tag: Tag  # VLAN on the cloud wire
    arrives: Literal["untagged", "tagged"]
    direct: bool
    kind: EndpointKind
    path: list[str]
    config: NodeConfig | None = None
    facts: list[Fact] = field(default_factory=list)

    @property
    def configured(self) -> bool:
        return self.kind != "unconfigured"

    def to_attachment(self) -> Attachment:
        return Attachment(
            node_id=self.node_id,
            iface=self.iface or self.eve_iface,
            network_id=self.network_id,
            scope=self.scope,
            path=list(self.path),
            direct=self.direct,
            arrives=self.arrives,
        )


@dataclass
class VlanDomain:
    """Switch VLAN ``vlan`` on ``node_id`` proven to carry wire tag ``tag``."""

    scope: str
    cloud_id: str
    tag: Tag
    node_id: str
    vlan: int
    config: NodeConfig
    path: list[str]


@dataclass
class TraceResult:
    scope: str
    endpoints: list[Endpoint] = field(default_factory=list)
    domains: list[VlanDomain] = field(default_factory=list)
    # cloud id -> True when every configured direct port is a switch trunk
    trunk_only: dict[str, bool] = field(default_factory=dict)
    cloud_links: list[tuple[str, str, Tag]] = field(default_factory=list)
    # (node id, EVE port) of every direct cloud port -> routed|access|trunk|none
    direct_ports: dict[tuple[str, str], str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def for_cloud(self, cloud_id: str) -> list[Endpoint]:
        return [e for e in self.endpoints if e.cloud_id == cloud_id]

    def wire_tags(self, cloud_id: str) -> set[Tag]:
        tags: set[Tag] = {e.tag for e in self.for_cloud(cloud_id)}
        tags.update(d.tag for d in self.domains if d.cloud_id == cloud_id)
        return tags


@dataclass(frozen=True)
class _Item:
    node_id: str
    eve: str
    net_id: str
    incoming: Incoming
    wire: Tag
    cloud: str
    path: tuple[str, ...]
    depth: int


def _allowed(cfg: NodeConfig, trunk_vlans: VlanList | None) -> set[int]:
    if trunk_vlans is None:
        return set(cfg.parsed.vlan_db)
    return set(trunk_vlans)


class _Tracer:
    def __init__(
        self, topo: Topology, index: ConfigIndex, scope: str, max_depth: int
    ) -> None:
        self.topo = topo
        self.index = index
        self.scope = scope
        self.max_depth = max_depth
        self.res = TraceResult(scope)
        self.queue: deque[_Item] = deque()
        self.seen_ports: set[tuple[str, str, str, Incoming]] = set()
        self.seen_vlans: set[tuple[str, str, int, Tag]] = set()
        self.seen_eps: set[tuple[str, str, str | None, Tag, str]] = set()

    def name(self, node_id: str) -> str:
        node = self.topo.nodes.get(node_id)
        return node.name if node else node_id

    # ------------------------------------------------------------- driver

    def run(self) -> TraceResult:
        for cloud_id in self.topo.clouds:
            kinds: list[str] = []
            for port in self.topo.ports_by_net.get(cloud_id, []):
                kind = self._port_kind(port.node_id, port.eve_name)
                kinds.append(kind)
                self.res.direct_ports[(port.node_id, port.eve_name)] = kind
                self.queue.append(
                    _Item(
                        port.node_id,
                        port.eve_name,
                        cloud_id,
                        "any",
                        "unknown",
                        cloud_id,
                        (f"{self.topo.clouds[cloud_id].name}",),
                        0,
                    )
                )
            configured = [k for k in kinds if k != "none"]
            self.res.trunk_only[cloud_id] = bool(configured) and all(
                k == "trunk" for k in configured
            )
            while self.queue:
                self._visit(self.queue.popleft())
        return self.res

    def _port_kind(self, node_id: str, eve: str) -> str:
        cfg = self.index.config_for(node_id, self.scope)
        if cfg is None:
            return "none"
        info = cfg.info(cfg.iface_for(eve))
        if info is None or info.orphan:
            return "none"
        if info.mode in ("access", "trunk"):
            return info.mode
        return "routed"

    # ------------------------------------------------------------- visits

    def _visit(self, it: _Item) -> None:
        key = (it.cloud, it.node_id, it.eve, it.incoming)
        if key in self.seen_ports:
            return
        self.seen_ports.add(key)
        cfg = self.index.config_for(it.node_id, self.scope)
        if cfg is None:
            self._emit(it, None, None, "unconfigured", "untagged", self._unk(it))
            return
        k = cfg.iface_for(it.eve)
        info = cfg.info(k)
        if info is not None and not info.orphan and info.mode in ("access", "trunk"):
            self._switch_in(it, cfg, k or "", info)
            return
        self._routed(it, cfg, k)

    @staticmethod
    def _unk(it: _Item) -> Tag:
        return "unknown" if it.incoming == "any" else it.wire

    def _emit(
        self,
        it: _Item,
        cfg: NodeConfig | None,
        iface: str | None,
        kind: EndpointKind,
        arrives: Literal["untagged", "tagged"],
        tag: Tag,
        node_id: str | None = None,
        path: tuple[str, ...] | None = None,
    ) -> None:
        nid = node_id or it.node_id
        sig = (it.cloud, nid, iface, tag, it.eve)
        if sig in self.seen_eps:
            return
        self.seen_eps.add(sig)
        facts = cfg.iface_facts(iface) if cfg is not None and iface else []
        hop = f"{self.name(nid)} {iface or it.eve}"
        self.res.endpoints.append(
            Endpoint(
                cloud_id=it.cloud,
                scope=self.scope,
                node_id=nid,
                eve_iface=it.eve,
                iface=iface,
                network_id=it.net_id,
                tag=tag,
                arrives=arrives,
                direct=it.depth == 0,
                kind=kind,
                path=[*(path or it.path), hop],
                config=cfg,
                facts=facts,
            )
        )

    def _addr_kind(self, cfg: NodeConfig, key: str) -> EndpointKind:
        facts = cfg.iface_facts(key)
        if any(f.kind == "ip_host" for f in facts):
            return "routed"
        return "dhcp"

    def _routed(self, it: _Item, cfg: NodeConfig, k: str | None) -> None:
        if k is None:
            self._emit(it, cfg, None, "unconfigured", "untagged", self._unk(it))
            return
        kids = cfg.children(k)
        tagged = [c for c in kids if c.tag is not None]
        phys = [k, *[c.key for c in kids if c.tag is None]]
        emitted = False
        if it.incoming in ("any", "untagged"):
            wire: Tag = "untagged" if it.incoming == "any" else it.wire
            for key in phys:
                if cfg.addressed(key):
                    self._emit(
                        it, cfg, key, self._addr_kind(cfg, key), "untagged", wire
                    )
                    emitted = True
        for c in tagged:
            if it.incoming == "any":
                wire = c.tag if c.tag is not None else "unknown"
            elif it.incoming == c.tag:
                wire = it.wire
            else:
                continue
            kind = self._addr_kind(cfg, c.key) if cfg.addressed(c.key) else "tag_only"
            self._emit(it, cfg, c.key, kind, "tagged", wire)
            emitted = True
        if not emitted:
            self._emit(it, cfg, k, "unconfigured", "untagged", self._unk(it))

    def _switch_in(self, it: _Item, cfg: NodeConfig, k: str, info) -> None:
        pairs: list[tuple[int, Tag]] = []
        if info.mode == "access":
            v = info.access_vlan or 1
            if it.incoming == "any":
                pairs.append((v, "untagged"))
            elif it.incoming == "untagged":
                pairs.append((v, it.wire))
        else:
            allowed = _allowed(cfg, info.trunk_vlans)
            native = info.native_vlan or 1
            if it.incoming == "any":
                for v in sorted(allowed):
                    pairs.append((v, "untagged" if v == native else v))
            elif it.incoming == "untagged":
                if native in allowed or info.trunk_vlans is None:
                    pairs.append((native, it.wire))
            elif it.incoming in allowed:
                pairs.append((int(it.incoming), it.wire))
        for v, wire in pairs:
            self._switch_vlan(it, cfg, k, v, wire)

    def _switch_vlan(
        self, it: _Item, cfg: NodeConfig, entry: str, v: int, wire: Tag
    ) -> None:
        vk = (it.cloud, it.node_id, v, wire)
        if vk in self.seen_vlans:
            return
        self.seen_vlans.add(vk)
        here = (*it.path, f"{self.name(it.node_id)} {it.eve} vlan {v}")
        self.res.domains.append(
            VlanDomain(self.scope, it.cloud, wire, it.node_id, v, cfg, list(here))
        )
        for info in cfg.parsed.ifaces.values():
            if info.orphan or info.key == entry:
                continue
            if info.mode == "access" and (info.access_vlan or 1) == v:
                out: Incoming = "untagged"
            elif info.mode == "trunk" and v in _allowed(cfg, info.trunk_vlans):
                out = "untagged" if v == (info.native_vlan or 1) else v
            else:
                continue
            eve = cfg.eve_for(info.key)
            if eve is None:
                continue  # uncabled
            port = self.topo.port(it.node_id, eve)
            if port is None:
                continue
            if self.topo.is_cloud(port.network_id):
                if port.network_id != it.cloud:
                    self.res.cloud_links.append((it.cloud, port.network_id, wire))
                continue
            if it.depth + 1 > self.max_depth:
                self.res.findings.append(
                    Finding(
                        "TRACE_DEPTH",
                        "info",
                        f"L2 trace from cloud {it.cloud} stopped at depth "
                        f"{self.max_depth} ({self.name(it.node_id)} {eve})",
                        [f"node:{it.node_id}"],
                    )
                )
                continue
            hop = (*here, f"-> {eve}")
            for peer in self.topo.peers(port):
                self.queue.append(
                    _Item(
                        peer.node_id,
                        peer.eve_name,
                        port.network_id,
                        out,
                        wire,
                        it.cloud,
                        hop,
                        it.depth + 1,
                    )
                )
        svi = cfg.svi_for(v)
        if svi and cfg.addressed(svi):
            self._emit(
                it, cfg, svi, self._addr_kind(cfg, svi), "tagged", wire, path=here
            )


def trace_scope(
    topo: Topology, index: ConfigIndex, scope: str, max_depth: int = MAX_DEPTH
) -> TraceResult:
    """Trace every cloud of ``topo`` with the configs of ``scope``."""
    return _Tracer(topo, index, scope, max_depth).run()


def trace_all(
    topo: Topology, index: ConfigIndex, max_depth: int = MAX_DEPTH
) -> dict[str, TraceResult]:
    """One :class:`TraceResult` per scope (``startup`` + every configset)."""
    return {s: trace_scope(topo, index, s, max_depth) for s in topo.scopes}


# ----------------------------------------------------------- VLAN-domain rule


def fact_vlans(fact: Fact) -> set[int]:
    """VLAN numbers a tag-bearing fact names (empty for other kinds)."""
    if fact.kind in ("vlan_tag",):
        return {int(fact.value)} if fact.value.isdigit() else set()
    if fact.kind in ("vlan_list", "vlan_def"):
        if fact.list_value is not None:
            return set(fact.list_value)
        try:
            return set(VlanList.parse(fact.value))
        except VlanListError:
            return set()
    if fact.kind in ("svi_name", "subif_name"):
        end = len(fact.value)
        start = end
        while start > 0 and fact.value[start - 1].isdigit():
            start -= 1
        if start < end and (fact.kind == "svi_name" or "." in fact.value):
            return {int(fact.value[start:end])}
    return set()


def _vlan_names(cfg: NodeConfig) -> dict[str, int]:
    """``vlan_name`` fact id -> VLAN of the ``vlan N`` definition just above it."""
    out: dict[str, int] = {}
    last: Fact | None = None
    for f in cfg.parsed.facts:  # sorted by span
        if f.orphan:
            continue
        if f.kind == "vlan_def":
            last = f
        elif f.kind == "vlan_name" and last is not None:
            vl = fact_vlans(last)
            if len(vl) == 1 and 0 <= f.line - last.line <= 5:
                out[f.id] = next(iter(vl))
    return out


def domain_facts(cfg: NodeConfig, vlan: int) -> list[tuple[Fact, bool]]:
    """Tag facts for ``vlan`` on a switch config: ``[(fact, uncabled)]``.

    Covers L2 port tags (access / allowed lists / native), ``vlan N`` definitions
    and their ``name``, and the SVI name.  Routed sub-interface tags and orphan
    facts are excluded.
    """
    out: list[tuple[Fact, bool]] = []
    names = _vlan_names(cfg)
    for f in cfg.parsed.facts:
        if f.orphan:
            continue
        if f.kind == "vlan_name":
            if names.get(f.id) == vlan:
                out.append((f, False))
            continue
        if f.kind not in TAG_KINDS or f.kind == "subif_name":
            continue
        if vlan not in fact_vlans(f):
            continue
        info = cfg.info(f.iface)
        uncabled = False
        if f.kind in ("vlan_tag", "vlan_list"):
            if info is None and f.iface is not None:
                continue
            if info is not None:
                if info.mode not in ("access", "trunk"):
                    continue
                uncabled = cfg.eve_for(info.key) is None
        out.append((f, uncabled))
    return out
