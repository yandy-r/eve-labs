"""Topology: clouds, cabled ports, active scopes, parsed configs (design 7.1).

``build(lab)`` gives a :class:`Topology` (pure XML view: networks, ports, scopes).
``ConfigIndex`` parses every usable :class:`~evelab.localize.model.ConfigText` exactly
once and answers "which config does node N use in scope S" plus the EVE port
name <-> config interface key mapping (``Gi16`` -> ``gi16``, ``e0/1`` ->
``et0/1``, ``E1/6`` -> ``eth1/6``, ``fxp0``, ``port8``, F5 ``E1.1`` -> ``1.1``).

Scope selection for a node (EVE behaviour): the blob of that configset if the
node has one, else its startup blob.  Sidecars that mirror an embedded blob are
never used for tracing (their facts are copies); independent sidecars (Forti /
F5 with no blob) stand in for the node's embedded config.
"""

from __future__ import annotations

import contextlib
import copy
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .. import dialects
from ..model import ConfigText, Fact, Finding, Network, Node

if TYPE_CHECKING:
    from evelab.common.unl import RawLab

    from ..dialects.base import Dialect, IfaceInfo, ParsedConfig, PatternRule

__all__ = [
    "ADDRESS_KINDS",
    "ConfigIndex",
    "NodeConfig",
    "Port",
    "Topology",
    "build",
    "with_rules",
]

STARTUP = "startup"
# Fact kinds that make an interface "configured" (routed endpoint).
ADDRESS_KINDS = frozenset({"ip_host", "dhcp"})


@dataclass(frozen=True)
class Port:
    """One cabled EVE interface: ``node_id`` port ``eve_name`` on ``network_id``."""

    node_id: str
    iface_id: str
    eve_name: str
    network_id: str


@dataclass
class Topology:
    nodes: dict[str, Node]
    networks: dict[str, Network]
    configsets: dict[str, str]  # configset id -> name
    scopes: list[str]  # "startup" first, then configset names (document order)
    clouds: dict[str, Network]
    ports_by_net: dict[str, list[Port]]
    ports_by_node: dict[str, list[Port]]
    active_scope: dict[str, str]  # node id -> scope it boots from
    blob_scopes: dict[str, set[str]]  # node id -> scopes holding an embedded blob
    findings: list[Finding] = field(default_factory=list)

    @property
    def status(self) -> str:
        """``"NONE"`` when the lab has no cloud network (nothing to localize)."""
        return "NONE" if not self.clouds else "CLOUDS"

    def cloud_ports(self) -> list[Port]:
        """Direct cloud attachments (every port cabled to a cloud network)."""
        return [p for nid in self.clouds for p in self.ports_by_net.get(nid, [])]

    def peers(self, port: Port) -> list[Port]:
        """Other ports on the same network."""
        return [p for p in self.ports_by_net.get(port.network_id, []) if p != port]

    def port(self, node_id: str, eve_name: str) -> Port | None:
        for p in self.ports_by_node.get(node_id, []):
            if p.eve_name == eve_name:
                return p
        return None

    def is_cloud(self, net_id: str) -> bool:
        return net_id in self.clouds


def build(
    lab: RawLab,
    nodes: Mapping[str, Node] | None = None,
    networks: Mapping[str, Network] | None = None,
) -> Topology:
    """Read the XML topology of ``lab`` (design 7.1 steps 1-3)."""
    nodes = dict(nodes if nodes is not None else lab.node_models())
    networks = dict(networks if networks is not None else lab.network_models())
    configsets = lab.configsets()
    scopes = [STARTUP, *[n for n in configsets.values() if n != STARTUP]]
    clouds = {nid: n for nid, n in networks.items() if n.is_cloud}
    by_net: dict[str, list[Port]] = {nid: [] for nid in networks}
    by_node: dict[str, list[Port]] = {nid: [] for nid in nodes}
    findings: list[Finding] = []
    for node in nodes.values():
        for itf in node.ifaces:
            if not itf.network_id or itf.network_id == "0":
                continue
            if itf.network_id not in networks:
                findings.append(
                    Finding(
                        "DANGLING_IFACE",
                        "warn",
                        f"node {node.id} ({node.name}) {itf.name} references missing "
                        f"network {itf.network_id}",
                        [f"node:{node.id}"],
                    )
                )
                continue
            port = Port(node.id, itf.id, itf.name, itf.network_id)
            by_net[itf.network_id].append(port)
            by_node[node.id].append(port)
    blob_scopes: dict[str, set[str]] = {}
    for blob in lab.config_blobs():
        if blob.self_closing or not blob.b64.strip():
            continue
        nid = blob.node_id or blob.id
        scope = blob.scope[3:] if blob.scope.startswith("cs:") else blob.scope
        blob_scopes.setdefault(nid, set()).add(scope)
    active: dict[str, str] = {}
    for node in nodes.values():
        scope = configsets.get(node.config_attr)
        if scope is not None and scope in blob_scopes.get(node.id, set()):
            active[node.id] = scope
        else:
            active[node.id] = STARTUP
        if node.config_attr == "0" and blob_scopes.get(node.id):
            findings.append(
                Finding(
                    "CONFIG_NOT_PUSHED",
                    "info",
                    f'node {node.id} ({node.name}) has config="0": the embedded '
                    "config is not pushed at boot",
                    [f"node:{node.id}"],
                )
            )
    return Topology(
        nodes=nodes,
        networks=networks,
        configsets=configsets,
        scopes=scopes,
        clouds=clouds,
        ports_by_net=by_net,
        ports_by_node=by_node,
        active_scope=active,
        blob_scopes=blob_scopes,
        findings=findings,
    )


# ------------------------------------------------------------------ configs


@dataclass
class NodeConfig:
    """One parsed config text of a node plus the EVE <-> config iface mapping."""

    node_id: str
    text: ConfigText
    parsed: ParsedConfig
    dialect: Dialect
    eve_map: dict[str, str | None]  # EVE port name -> config iface key (cabled ports)

    @property
    def store(self):
        return self.text.store

    @property
    def is_switch(self) -> bool:
        return self.parsed.is_switch

    def iface_for(self, eve_name: str) -> str | None:
        """Config iface key for an EVE port name (None when not configured)."""
        if eve_name in self.eve_map:
            return self.eve_map[eve_name]
        return map_iface(self.dialect, self.parsed, eve_name)

    def eve_for(self, key: str) -> str | None:
        """EVE port name of a config iface key (None = uncabled / unknown)."""
        for eve, k in self.eve_map.items():
            if k == key:
                return eve
        return None

    def info(self, key: str | None) -> IfaceInfo | None:
        return self.parsed.ifaces.get(key) if key else None

    def children(self, key: str) -> list[IfaceInfo]:
        """Sub-interfaces / VLAN interfaces whose parent is ``key``."""
        return [
            i
            for i in self.parsed.ifaces.values()
            if i.parent == key and i.key != key and not i.orphan
        ]

    def iface_facts(self, key: str) -> list[Fact]:
        return [f for f in self.parsed.facts if f.iface == key and not f.orphan]

    def addressed(self, key: str) -> bool:
        info = self.parsed.ifaces.get(key)
        if info is not None and info.dhcp:
            return True
        return any(f.kind in ADDRESS_KINDS for f in self.iface_facts(key))

    def svi_for(self, vlan: int) -> str | None:
        """Iface key of the SVI for ``vlan`` (from ``svi_name`` facts)."""
        for f in self.parsed.facts:
            if f.kind != "svi_name" or f.orphan or not f.iface:
                continue
            if _trailing_int(f.value) == vlan:
                return f.iface
        return None


def with_rules(dialect: Dialect, rules: Sequence[PatternRule]) -> Dialect:
    """A copy of a rule dialect whose ``rules`` end with ``rules`` (manifest
    ``[[rule]]`` tables).  Parsing only: rendering never depends on the rule."""
    cls = type(dialect)
    known = {r.id for r in getattr(cls, "rules", ())}
    extra = tuple(r for r in rules if r.id not in known)
    sub = type(
        f"{cls.__name__}WithManifestRules",
        (cls,),
        {"rules": (*cls.rules, *extra), "__module__": cls.__module__},
    )
    return sub()


def _trailing_int(value: str) -> int | None:
    end = len(value)
    start = end
    while start > 0 and value[start - 1].isdigit():
        start -= 1
    return int(value[start:end]) if start < end else None


def map_iface(dialect: Dialect, parsed: ParsedConfig, eve_name: str) -> str | None:
    """EVE port name -> config iface key present in ``parsed`` (else None)."""
    cands: list[str] = []
    with contextlib.suppress(Exception):  # plugin hook failure = no candidate
        cands.extend(dialect.eve_to_config(eve_name))
    cands.append(eve_name)
    for cand in cands:
        try:
            key = dialect.iface_key(cand)
        except Exception:  # noqa: BLE001 - plugin hook failure = no match
            continue
        if key in parsed.ifaces:
            return key
    low = eve_name.lower()
    if low in parsed.ifaces:
        return low
    return None


# Parse results keyed by (dialect identity, rules, store, node, text): a lab is
# analysed several times per run (load, apply rescan, validation, revert, the
# example profile) and most texts do not change between those analyses.
# Callers mutate facts (attribution sets ``segment``/``confidence``), so a hit
# returns fresh copies; the cached original is never handed out.  Performance
# fix (review #38).
_PARSE_CACHE: OrderedDict[tuple[object, ...], ParsedConfig] = OrderedDict()
PARSE_CACHE_SIZE = 4096


def _base_class(dialect: Dialect) -> type:
    for cls in type(dialect).__mro__:
        if not cls.__name__.endswith("WithManifestRules"):
            return cls
    return type(dialect)


def _copy_parsed(p: ParsedConfig) -> ParsedConfig:
    return dialects.ParsedConfig(
        dialect=p.dialect,
        facts=[copy.copy(f) for f in p.facts],
        ifaces={k: copy.copy(v) for k, v in p.ifaces.items()},
        vlan_db=set(p.vlan_db),
        is_switch=p.is_switch,
        notes=list(p.notes),
    )


def cached_parse(dialect: Dialect, ct: ConfigText) -> ParsedConfig:
    """``dialect.parse(ct)`` memoised per (dialect, rules, store, node, text)."""
    try:
        key: tuple[object, ...] = (
            _base_class(dialect),
            dialect.name,
            tuple(getattr(dialect, "rules", ())),
            ct.store,
            ct.node_id,
            ct.dialect,
            ct.text,
        )
        hash(key)
    except TypeError:  # an unhashable plugin rule: no caching
        return dialect.parse(ct)
    hit = _PARSE_CACHE.get(key)
    if hit is not None:
        _PARSE_CACHE.move_to_end(key)
        return _copy_parsed(hit)
    parsed = dialect.parse(ct)
    if isinstance(parsed, dialects.ParsedConfig):
        _PARSE_CACHE[key] = _copy_parsed(parsed)
        while len(_PARSE_CACHE) > PARSE_CACHE_SIZE:
            _PARSE_CACHE.popitem(last=False)
    return parsed


class ConfigIndex:
    """Parses each usable config text once; per-scope config lookup."""

    def __init__(
        self,
        topo: Topology,
        texts: Iterable[ConfigText],
        extra_rules: Mapping[str, Sequence[PatternRule]] | None = None,
    ) -> None:
        self.topo = topo
        self.texts = list(texts)
        self.parsed: dict[int, NodeConfig] = {}  # id(ConfigText) -> NodeConfig
        self.notes: list[Finding] = []
        # manifest [[rule]]s: dialect name ("*" = every dialect) -> extra rules
        self.extra_rules = dict(extra_rules or {})
        self._extended: dict[str, Dialect] = {}
        self._by_node: dict[str, list[NodeConfig]] = {}
        for ct in self.texts:
            if ct.opaque or ct.store.kind == "textobject" or not ct.node_id:
                continue
            nc = self._parse(ct)
            if nc is not None:
                self._by_node.setdefault(ct.node_id, []).append(nc)

    def dialect_for(self, name: str) -> Dialect:
        """The registered dialect, extended with the manifest rules for it
        (also used for canvas textobjects).  An unknown name falls back to
        ``generic`` with an ``UNKNOWN_DIALECT`` warning, never silently."""
        try:
            dialect = dialects.get(name)
        except Exception as exc:  # noqa: BLE001 - reported as UNKNOWN_DIALECT
            msg = f"dialect {name!r}: {exc}; parsed with 'generic'"
            if not any(n.msg == msg for n in self.notes):
                self.notes.append(Finding("UNKNOWN_DIALECT", "warn", msg))
            dialect = dialects.get("generic")
        rules = [*self.extra_rules.get("*", ()), *self.extra_rules.get(name, ())]
        if not rules or not hasattr(dialect, "rules"):
            return dialect
        if name not in self._extended:
            self._extended[name] = with_rules(dialect, rules)
        return self._extended[name]

    _dialect = dialect_for  # backwards-compatible private name

    def _parse(self, ct: ConfigText) -> NodeConfig | None:
        dialect = self.dialect_for(ct.dialect)
        try:
            parsed = cached_parse(dialect, ct)
        except Exception as exc:  # noqa: BLE001 - reported as a PARSE_FAILED finding
            self.notes.append(
                Finding(
                    "PARSE_FAILED",
                    "error",
                    f"{ct.store.kind}:{ct.store.name} node {ct.node_id}: "
                    f"{ct.dialect} parse failed: {exc}",
                    [f"node:{ct.node_id}"],
                )
            )
            return None
        eve_map: dict[str, str | None] = {}
        for port in self.topo.ports_by_node.get(ct.node_id, []):
            eve_map[port.eve_name] = map_iface(dialect, parsed, port.eve_name)
        nc = NodeConfig(ct.node_id, ct, parsed, dialect, eve_map)
        self.parsed[id(ct)] = nc
        return nc

    def all_configs(self) -> list[NodeConfig]:
        return [nc for ncs in self._by_node.values() for nc in ncs]

    def of(self, ct: ConfigText) -> NodeConfig | None:
        return self.parsed.get(id(ct))

    def config_for(self, node_id: str, scope: str) -> NodeConfig | None:
        """The config node ``node_id`` uses when the lab boots scope ``scope``."""
        cands = self._by_node.get(node_id, [])
        if not cands:
            return None
        embedded = [c for c in cands if c.store.kind in ("startup", "configset")]
        own = [c for c in cands if c.text.mirror_of is None]

        def first(items: list[NodeConfig]) -> NodeConfig | None:
            return items[0] if items else None

        return (
            first([c for c in embedded if c.store.scope == scope])
            or first(
                [c for c in own if c.store.kind == "sidecar" and c.store.scope == scope]
            )
            or first([c for c in embedded if c.store.scope == STARTUP])
            or first([c for c in own if c.store.kind == "sidecar"])
        )
