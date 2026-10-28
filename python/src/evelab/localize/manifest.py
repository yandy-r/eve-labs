"""Lab manifests: ``<stem>.localize.toml`` (design section 8).

T4: the typed schema, the strict loader/validator, ``find_for`` and a serialiser
(``to_dict`` / ``dumps``). T15: ``generate()`` (``discover --write`` / ``--update``)
and ``check()`` (``localize-check``: counts, baseline, coverage, leaks, unpinned).

Strictness: unknown keys, unknown references (a ``carries`` / ``legacy.segment`` /
``label_value.segment`` naming a segment that does not exist), duplicate segment keys
and a network id claimed by two segments are errors. Scenario options, parameter
kinds and fact kinds are not checked against registries (those live in later
modules); they only have to be well-formed identifiers.
"""

from __future__ import annotations

import re
import tomllib
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from evelab.common import tomlw
from evelab.common.tomlschema import TableReader, parse_address, parse_network
from evelab.common.tomlw import TomlValue

from .errors import LocalizeError

if TYPE_CHECKING:
    from .model import Analysis, Fact, Finding, Scheme, Segment

SCHEMA = 1
MANIFEST_SUFFIX = ".localize.toml"
DRAFT_SUFFIX = ".localize.toml.draft"

ROLES: tuple[str, ...] = ("mgmt", "inet", "oob", "trunk", "nat", "wan")
SEGMENT_STATUSES: tuple[str, ...] = (
    "CONFIGURABLE",
    "DHCP",
    "LABEL_ONLY",
    "CARRIER",
    "UNKNOWN",
)
SUBIF_POLICIES: tuple[str, ...] = ("rename", "keep-name")
LEGACY_POLICIES: tuple[str, ...] = ("leave", "ask", "same")
PARAM_GROUPS: tuple[str, ...] = ("basic", "advanced")
# Parameters a segment baseline / expect table may carry. T15 extends this if
# discovery learns to count more per-segment values.
SEGMENT_PARAMS: tuple[str, ...] = ("label", "vlan", "subnet", "gateway")

_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*")
_NET_ID = re.compile(r"[0-9]+")
_BRIDGE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*")  # pnetN/natN/cloudN or declared


class ManifestError(LocalizeError):
    """A manifest is malformed, inconsistent or does not belong to its lab."""

    code = "MANIFEST"


# -- schema ---------------------------------------------------------------------


@dataclass
class Baseline:
    """Canonical scheme values at repo baseline (all optional)."""

    label: str | None = None
    vlan: int | None = None
    subnet: IPv4Network | None = None
    gateway: IPv4Address | None = None
    bridge: str | None = None  # cloud ``type`` of the segment networks


@dataclass
class ManifestSegment:
    key: str
    networks: list[str]
    site_key: str | None = None  # None: derived as "<labstem>.<key>" by discovery
    role: str | None = None
    status: str | None = None  # pinned status override (e.g. LABEL_ONLY, DHCP)
    label_template: str | None = None
    carries: list[str] = field(default_factory=list)
    baseline: Baseline = field(default_factory=Baseline)
    expect: dict[str, int] = field(default_factory=dict)


@dataclass
class NodeOverride:
    dialect: str | None = None


@dataclass
class Merge:
    """Confirmed hint-level merge: unit names like ``"204-31"`` or ``"trunk:204"``."""

    units: list[str]


@dataclass
class Legacy:
    """Other schemes on the same clouds (backbone)."""

    segment: str
    scopes: list[str]
    policy: str = "leave"
    baseline: Baseline = field(default_factory=Baseline)


@dataclass
class Outlier:
    scope: str
    node: str
    note: str = ""


@dataclass
class LabelValue:
    """Textobject values that no configuration proves."""

    textobject: str
    fields: dict[str, str]
    segment: str | None = None


@dataclass
class ScenarioPin:
    enabled: bool = True
    options: dict[str, TomlValue] = field(default_factory=dict)


@dataclass
class Param:
    """Lab-wide site parameter (DNS, NTP, domain, routes ...)."""

    key: str
    kind: str
    site_key: str | None = None
    baseline: list[str] = field(default_factory=list)
    expect: int | None = None
    group: str | None = None  # "basic" | "advanced"


@dataclass
class LocalRule:
    """Manifest-local declarative rule (rare one-offs); mirrors ``PatternRule``."""

    id: str
    kind: str
    pattern: str
    dialects: list[str] = field(default_factory=list)
    block: str | None = None
    negative: list[str] = field(default_factory=list)
    l2: bool = False


@dataclass
class Manifest:
    lab: str
    lab_id: str
    schema: int = SCHEMA
    generated: str = ""
    sidecar_dirs: list[str] = field(default_factory=list)
    canonical_scope: str | None = None
    protect: list[IPv4Network] = field(default_factory=list)
    generic_labels: list[str] = field(default_factory=list)
    subif_policy: str = "rename"
    nodes: dict[str, NodeOverride] = field(default_factory=dict)
    sidecar_map: dict[str, str] = field(default_factory=dict)
    segments: list[ManifestSegment] = field(default_factory=list)
    merges: list[Merge] = field(default_factory=list)
    legacy: list[Legacy] = field(default_factory=list)
    outliers: list[Outlier] = field(default_factory=list)
    label_values: list[LabelValue] = field(default_factory=list)
    scenarios: dict[str, ScenarioPin] = field(default_factory=dict)
    params: list[Param] = field(default_factory=list)
    rules: list[LocalRule] = field(default_factory=list)
    path: Path | None = None  # where it was loaded from (not serialised)

    def segment(self, key: str) -> ManifestSegment | None:
        return next((s for s in self.segments if s.key == key), None)

    def segment_for_network(self, net_id: str) -> ManifestSegment | None:
        return next((s for s in self.segments if net_id in s.networks), None)

    def param(self, key: str) -> Param | None:
        return next((p for p in self.params if p.key == key), None)

    def scenario_enabled(self, scenario_id: str) -> bool:
        pin = self.scenarios.get(scenario_id)
        return pin is not None and pin.enabled

    def matches_lab_id(self, lab_id: str) -> bool:
        return self.lab_id.lower() == lab_id.lower()


# -- loading ---------------------------------------------------------------------


def manifest_path_for(lab_path: Path) -> Path:
    """``dir/x.unl`` -> ``dir/x.localize.toml``."""
    return lab_path.with_name(lab_path.stem + MANIFEST_SUFFIX)


def draft_path_for(lab_path: Path) -> Path:
    """``dir/x.unl`` -> ``dir/x.localize.toml.draft`` (never loaded)."""
    return lab_path.with_name(lab_path.stem + DRAFT_SUFFIX)


def load(path: Path) -> Manifest:
    """Read and strictly validate a manifest. Raises ``ManifestError``."""
    path = Path(path)
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise ManifestError(f"{path}: cannot read manifest: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{path}: invalid TOML: {exc}") from exc
    manifest = parse(data, source=str(path))
    manifest.path = path
    return manifest


def find_for(lab_path: Path) -> Manifest | None:
    """Manifest next to ``lab_path``, or ``None`` when there is none.

    A manifest whose ``lab_id`` differs from the lab's own id is ignored (returns
    ``None``); ``check`` reports that case by loading the file itself. A manifest
    that names a different lab file, or is invalid, raises ``ManifestError``.
    """
    lab_path = Path(lab_path)
    path = manifest_path_for(lab_path)
    if not path.is_file():
        return None
    manifest = load(path)
    expected = (path.parent / PurePosixPath(manifest.lab)).resolve()
    if expected != lab_path.resolve():
        raise ManifestError(
            f"{path}: lab = {manifest.lab!r} does not name {lab_path.name}"
        )
    actual = read_lab_id(lab_path)
    if actual is not None and not manifest.matches_lab_id(actual):
        return None
    return manifest


def read_lab_id(lab_path: Path) -> str | None:
    """The ``id`` attribute of the root ``<lab>`` element, or ``None`` if unreadable."""
    try:
        with Path(lab_path).open("rb") as handle:
            for _event, elem in ET.iterparse(handle, events=("start",)):
                return elem.get("id") if elem.tag == "lab" else None
    except (OSError, ET.ParseError):
        return None
    return None


def parse(data: object, *, source: str = "") -> Manifest:
    """Validate an already-parsed TOML document (see ``load``)."""
    root = TableReader(data, "", ManifestError, source)
    schema = root.opt_int("schema")
    if schema != SCHEMA:
        raise root.fail("schema", f"must be {SCHEMA}, got {schema!r}")
    lab = root.req_str("lab")
    _check_relpath(root, "lab", lab)
    lab_id = root.req_str("lab_id")
    try:
        uuid.UUID(lab_id)
    except ValueError as exc:
        raise root.fail("lab_id", f"not a UUID: {lab_id!r}") from exc
    sidecar_dirs = root.str_list("sidecar_dirs")
    for entry in sidecar_dirs:
        _check_relpath(root, "sidecar_dirs", entry)
    manifest = Manifest(
        lab=lab,
        lab_id=lab_id,
        generated=root.opt_str("generated", "") or "",
        sidecar_dirs=sidecar_dirs,
        canonical_scope=root.opt_str("canonical_scope"),
        protect=[
            parse_network(root, "protect", text) for text in root.str_list("protect")
        ],
        generic_labels=root.str_list("generic_labels"),
        subif_policy=root.opt_str("subif_policy", "rename", choices=SUBIF_POLICIES)
        or "rename",
    )
    manifest.nodes = _nodes(root)
    manifest.sidecar_map = _sidecar_map(root)
    manifest.segments = [_segment(t) for t in root.table_array("segment")]
    manifest.merges = [_merge(t) for t in root.table_array("merge")]
    manifest.legacy = [_legacy(t) for t in root.table_array("legacy")]
    manifest.outliers = [_outlier(t) for t in root.table_array("outlier")]
    manifest.label_values = [_label_value(t) for t in root.table_array("label_value")]
    manifest.scenarios = _scenarios(root)
    manifest.params = [_param(t) for t in root.table_array("param")]
    manifest.rules = [_rule(t) for t in root.table_array("rule")]
    root.done()
    _cross_check(manifest, source)
    return manifest


def _check_relpath(reader: TableReader, key: str, value: str) -> None:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or ".." in pure.parts:
        raise reader.fail(key, f"{value!r} must be a relative path inside the repo")


def _ident(reader: TableReader, key: str, value: str) -> str:
    if not _IDENT.fullmatch(value):
        raise reader.fail(key, f"{value!r} is not a valid identifier")
    return value


def _baseline(reader: TableReader | None) -> Baseline:
    if reader is None:
        return Baseline()
    subnet = reader.opt_str("subnet")
    gateway = reader.opt_str("gateway")
    bridge = reader.opt_str("bridge")
    if bridge is not None and not _BRIDGE.fullmatch(bridge):
        raise reader.fail("bridge", f"{bridge!r} is not a bridge name")
    base = Baseline(
        bridge=bridge,
        label=reader.opt_str("label"),
        vlan=reader.opt_int("vlan", minimum=1, maximum=4094),
        subnet=None if subnet is None else parse_network(reader, "subnet", subnet),
        gateway=None if gateway is None else parse_address(reader, "gateway", gateway),
    )
    reader.done()
    if (
        base.subnet is not None
        and base.gateway is not None
        and base.gateway not in base.subnet
    ):
        raise reader.fail("gateway", f"{base.gateway} is outside {base.subnet}")
    return base


def _nodes(root: TableReader) -> dict[str, NodeOverride]:
    out: dict[str, NodeOverride] = {}
    for node_id, table in root.subtables("nodes").items():
        if not _NET_ID.fullmatch(node_id):
            raise root.fail(f"nodes.{node_id}", "node id must be numeric")
        dialect = table.opt_str("dialect")
        if dialect is not None:
            _ident(table, "dialect", dialect)
        table.done()
        out[node_id] = NodeOverride(dialect=dialect)
    return out


def _sidecar_map(root: TableReader) -> dict[str, str]:
    out = root.str_map("sidecar_map")
    for name, node_id in out.items():
        _check_relpath(root, "sidecar_map", name)
        if not _NET_ID.fullmatch(node_id):
            raise root.fail(f"sidecar_map.{name}", f"{node_id!r} must be numeric")
    return out


def _segment(t: TableReader) -> ManifestSegment:
    key = _ident(t, "key", t.req_str("key"))
    site_key = t.opt_str("site_key")
    if site_key is not None:
        _ident(t, "site_key", site_key)
    networks = t.str_list("networks", min_items=1)
    for net_id in networks:
        if not _NET_ID.fullmatch(net_id):
            raise t.fail("networks", f"network id {net_id!r} must be numeric")
    if len(set(networks)) != len(networks):
        raise t.fail("networks", "duplicate network id")
    seg = ManifestSegment(
        key=key,
        networks=networks,
        site_key=site_key,
        role=t.opt_str("role", choices=ROLES),
        status=t.opt_str("status", choices=SEGMENT_STATUSES),
        label_template=t.opt_str("label_template"),
        carries=t.str_list("carries"),
        baseline=_baseline(t.table("baseline")),
    )
    expect = t.table("expect")
    if expect is not None:
        for name in expect.keys():  # noqa: SIM118 - TableReader.keys(), not dict.keys()
            if name not in SEGMENT_PARAMS:
                raise expect.fail(name, f"unknown key (valid: {list(SEGMENT_PARAMS)})")
            count = expect.opt_int(name, minimum=0)
            assert count is not None
            seg.expect[name] = count
        expect.done()
    t.done()
    return seg


def _merge(t: TableReader) -> Merge:
    units = t.str_list("units", min_items=2)
    t.done()
    return Merge(units=units)


def _legacy(t: TableReader) -> Legacy:
    legacy = Legacy(
        segment=t.req_str("segment"),
        scopes=t.str_list("scopes", min_items=1),
        policy=t.opt_str("policy", "leave", choices=LEGACY_POLICIES) or "leave",
        baseline=_baseline(t.table("baseline")),
    )
    t.done()
    return legacy


def _outlier(t: TableReader) -> Outlier:
    out = Outlier(
        scope=t.req_str("scope"),
        node=t.req_str("node"),
        note=t.opt_str("note", "") or "",
    )
    if not _NET_ID.fullmatch(out.node):
        raise t.fail("node", f"node id {out.node!r} must be numeric")
    t.done()
    return out


def _label_value(t: TableReader) -> LabelValue:
    textobject = t.req_str("textobject")
    if not _NET_ID.fullmatch(textobject):
        raise t.fail("textobject", f"id {textobject!r} must be numeric")
    fields = t.str_map("fields")
    if not fields:
        raise t.fail("fields", "needs at least one field")
    value = LabelValue(
        textobject=textobject, fields=fields, segment=t.opt_str("segment")
    )
    t.done()
    return value


def _scenarios(root: TableReader) -> dict[str, ScenarioPin]:
    out: dict[str, ScenarioPin] = {}
    for name, table in root.subtables("scenarios").items():
        if not _IDENT.fullmatch(name):
            raise root.fail(f"scenarios.{name}", "not a valid scenario id")
        enabled = table.opt_bool("enabled", True)
        out[name] = ScenarioPin(enabled=enabled, options=table.rest())
        table.done()
    return out


def _param(t: TableReader) -> Param:
    key = _ident(t, "key", t.req_str("key"))
    kind = _ident(t, "kind", t.req_str("kind"))
    site_key = t.opt_str("site_key")
    if site_key is not None:
        _ident(t, "site_key", site_key)
    raw = t.raw("baseline")
    if raw is None:
        baseline: list[str] = []
    elif isinstance(raw, str):
        baseline = [raw]
    elif isinstance(raw, list) and all(isinstance(i, str) for i in raw):
        baseline = [i for i in raw if isinstance(i, str)]
    else:
        raise t.fail("baseline", "expected a string or an array of strings")
    param = Param(
        key=key,
        kind=kind,
        site_key=site_key,
        baseline=baseline,
        expect=t.opt_int("expect", minimum=0),
        group=t.opt_str("group", choices=PARAM_GROUPS),
    )
    t.done()
    return param


def _rule(t: TableReader) -> LocalRule:
    rule = LocalRule(
        id=_ident(t, "id", t.req_str("id")),
        kind=_ident(t, "kind", t.req_str("kind")),
        pattern=t.req_str("pattern"),
        dialects=t.str_list("dialects"),
        block=t.opt_str("block"),
        negative=t.str_list("negative"),
        l2=t.opt_bool("l2", False),
    )
    try:
        re.compile(rule.pattern, re.MULTILINE)
    except re.error as exc:
        raise t.fail("pattern", f"invalid regular expression: {exc}") from exc
    t.done()
    return rule


def _cross_check(m: Manifest, source: str) -> None:
    def bad(message: str) -> ManifestError:
        return ManifestError(f"{source + ': ' if source else ''}{message}")

    keys: set[str] = set()
    owner: dict[str, str] = {}
    for seg in m.segments:
        if seg.key in keys:
            raise bad(f"duplicate segment key {seg.key!r}")
        keys.add(seg.key)
        for net_id in seg.networks:
            if net_id in owner:
                raise bad(
                    f"network {net_id} is in both segment {owner[net_id]!r} "
                    f"and {seg.key!r}"
                )
            owner[net_id] = seg.key
    for seg in m.segments:
        for carried in seg.carries:
            if carried not in keys:
                raise bad(f"segment {seg.key!r} carries unknown segment {carried!r}")
            if carried == seg.key:
                raise bad(f"segment {seg.key!r} carries itself")
    for legacy in m.legacy:
        if legacy.segment not in keys:
            raise bad(f"legacy refers to unknown segment {legacy.segment!r}")
    for value in m.label_values:
        if value.segment is not None and value.segment not in keys:
            raise bad(
                f"label_value {value.textobject} refers to unknown "
                f"segment {value.segment!r}"
            )
    if len({p.key for p in m.params}) != len(m.params):
        raise bad("duplicate [[param]] key")
    if len({r.id for r in m.rules}) != len(m.rules):
        raise bad("duplicate [[rule]] id")


# -- serialising -----------------------------------------------------------------


def _baseline_dict(base: Baseline) -> dict[str, TomlValue]:
    out: dict[str, TomlValue] = {}
    if base.bridge is not None:
        out["bridge"] = base.bridge
    if base.label is not None:
        out["label"] = base.label
    if base.vlan is not None:
        out["vlan"] = base.vlan
    if base.subnet is not None:
        out["subnet"] = str(base.subnet)
    if base.gateway is not None:
        out["gateway"] = str(base.gateway)
    return out


def to_dict(m: Manifest) -> dict[str, TomlValue]:
    """Manifest as plain TOML data (defaults and empty collections omitted)."""
    out: dict[str, TomlValue] = {"schema": m.schema, "lab": m.lab, "lab_id": m.lab_id}
    if m.generated:
        out["generated"] = m.generated
    if m.sidecar_dirs:
        out["sidecar_dirs"] = list(m.sidecar_dirs)
    if m.canonical_scope is not None:
        out["canonical_scope"] = m.canonical_scope
    if m.protect:
        out["protect"] = [str(n) for n in m.protect]
    if m.generic_labels:
        out["generic_labels"] = list(m.generic_labels)
    if m.subif_policy != "rename":
        out["subif_policy"] = m.subif_policy
    if any(n.dialect for n in m.nodes.values()):
        out["nodes"] = {
            node_id: {"dialect": n.dialect}
            for node_id, n in m.nodes.items()
            if n.dialect
        }
    if m.sidecar_map:
        out["sidecar_map"] = dict(m.sidecar_map)
    out_segments: list[TomlValue] = []
    for seg in m.segments:
        item: dict[str, TomlValue] = {"key": seg.key}
        if seg.site_key is not None:
            item["site_key"] = seg.site_key
        if seg.role is not None:
            item["role"] = seg.role
        if seg.status is not None:
            item["status"] = seg.status
        item["networks"] = list(seg.networks)
        if seg.label_template is not None:
            item["label_template"] = seg.label_template
        if seg.carries:
            item["carries"] = list(seg.carries)
        if base := _baseline_dict(seg.baseline):
            item["baseline"] = base
        if seg.expect:
            item["expect"] = dict(seg.expect.items())
        out_segments.append(item)
    if out_segments:
        out["segment"] = out_segments
    if m.merges:
        out["merge"] = [{"units": list(x.units)} for x in m.merges]
    legacy_items: list[TomlValue] = []
    for leg in m.legacy:
        entry: dict[str, TomlValue] = {
            "segment": leg.segment,
            "scopes": list(leg.scopes),
            "policy": leg.policy,
        }
        if base := _baseline_dict(leg.baseline):
            entry["baseline"] = base
        legacy_items.append(entry)
    if legacy_items:
        out["legacy"] = legacy_items
    if m.outliers:
        out["outlier"] = [
            {"scope": o.scope, "node": o.node, **({"note": o.note} if o.note else {})}
            for o in m.outliers
        ]
    label_items: list[TomlValue] = []
    for lv in m.label_values:
        lv_item: dict[str, TomlValue] = {"textobject": lv.textobject}
        if lv.segment is not None:
            lv_item["segment"] = lv.segment
        lv_item["fields"] = dict(lv.fields)
        label_items.append(lv_item)
    if label_items:
        out["label_value"] = label_items
    if m.scenarios:
        out["scenarios"] = {
            name: {"enabled": pin.enabled, **pin.options}
            for name, pin in m.scenarios.items()
        }
    param_items: list[TomlValue] = []
    for p in m.params:
        p_item: dict[str, TomlValue] = {"key": p.key, "kind": p.kind}
        if p.site_key is not None:
            p_item["site_key"] = p.site_key
        if p.group is not None:
            p_item["group"] = p.group
        if p.baseline:
            p_item["baseline"] = list(p.baseline)
        if p.expect is not None:
            p_item["expect"] = p.expect
        param_items.append(p_item)
    if param_items:
        out["param"] = param_items
    rule_items: list[TomlValue] = []
    for r in m.rules:
        r_item: dict[str, TomlValue] = {"id": r.id, "kind": r.kind}
        if r.dialects:
            r_item["dialects"] = list(r.dialects)
        if r.block is not None:
            r_item["block"] = r.block
        if r.negative:
            r_item["negative"] = list(r.negative)
        if r.l2:
            r_item["l2"] = True
        r_item["pattern"] = r.pattern
        rule_items.append(r_item)
    if rule_items:
        out["rule"] = rule_items
    return out


def dumps(m: Manifest, *, header: str | None = None) -> str:
    """Deterministic TOML text for ``m`` (re-parse verified by ``tomlw``)."""
    return tomlw.dumps(to_dict(m), header=header)


# -- generate / check (T15) -------------------------------------------------------
#
# Counting rules shared by ``generate`` (writes ``expect``) and ``check`` (compares):
#
# * segment ``vlan``: tag-bearing facts (``TAG_KINDS``) attributed to the segment that
#   name the VLAN;
# * ``subnet``: IPv4-valued facts attributed to the segment inside the subnet, except
#   those equal to the gateway (counted separately);
# * ``gateway``: IPv4-valued facts attributed to the segment equal to the gateway;
# * ``label``: the segment's cloud networks named exactly ``label`` plus every
#   ``label_ref`` fact with that value;
# * ``[[param]]``: facts of the param's fact kinds (``param_fact_kinds``) whose value
#   is one of the baseline values.
#
# Facts flagged ``outlier`` are never counted (they are left alone by default).

TAG_KINDS = frozenset({"vlan_tag", "vlan_list", "vlan_def", "subif_name", "svi_name"})
SERVICE_KINDS = frozenset(
    {"dns_server", "ntp_server", "log_server", "probe_target", "domain", "search_list"}
)
DOMAIN_KINDS = frozenset({"domain", "search_list"})
# fact kind -> (draft param key, param kind, group)
_DRAFT_PARAMS: dict[str, tuple[str, str, str]] = {
    "dns_server": ("dns", "ipv4_list", "basic"),
    "ntp_server": ("ntp", "host_list", "basic"),
    "log_server": ("syslog", "host_list", "advanced"),
    "probe_target": ("sla_targets", "host_list", "advanced"),
    "domain": ("domain", "domain", "basic"),
    "search_list": ("domain", "domain", "basic"),
}
# words of a param key -> fact kinds it counts (first match wins)
_PARAM_WORDS: tuple[tuple[frozenset[str], frozenset[str]], ...] = (
    (frozenset({"dns", "nameserver", "resolver"}), frozenset({"dns_server"})),
    (frozenset({"ntp", "time"}), frozenset({"ntp_server"})),
    (frozenset({"sla", "probe", "probes"}), frozenset({"probe_target"})),
    (frozenset({"log", "logs", "syslog", "logging"}), frozenset({"log_server"})),
    (frozenset({"domain", "domains", "search"}), DOMAIN_KINDS),
    (
        frozenset({"route", "routes", "supernet", "prefixes"}),
        frozenset({"ip_route_dst"}),
    ),
    (frozenset({"peer", "peers"}), frozenset({"peer_ip"})),
    (frozenset({"asn", "as"}), frozenset({"asn"})),
)
_PARAM_KIND_FACTS: dict[str, frozenset[str]] = {
    "ipv4_list": frozenset({"dns_server", "ntp_server", "probe_target", "log_server"}),
    "host_list": frozenset({"dns_server", "ntp_server", "probe_target", "log_server"}),
    "domain": DOMAIN_KINDS,
    "domain_list": DOMAIN_KINDS,
    "prefix_list": frozenset({"ip_route_dst"}),
}
LEAK_EXAMPLES = 5


def param_fact_kinds(p: Param) -> frozenset[str]:
    """Fact kinds a ``[[param]]`` counts: its kind if that is a fact kind, else the
    words of its key (``dns_public`` -> ``dns_server``), else its param kind."""
    from .model import CORE_FACT_KINDS

    if p.kind in CORE_FACT_KINDS:
        kinds = {p.kind}
        if p.kind in DOMAIN_KINDS:
            kinds |= DOMAIN_KINDS
        return frozenset(kinds)
    words = set(re.split(r"[_.-]+", p.key.lower()))
    for keys, kinds_ in _PARAM_WORDS:
        if words & keys:
            return kinds_
    return _PARAM_KIND_FACTS.get(p.kind, SERVICE_KINDS)


class _Index:
    """Per-analysis lookups shared by the counting and leak helpers."""

    def __init__(self, a: Analysis) -> None:
        self.a = a
        self.text_of: dict[tuple[object, str], str] = {}
        for ct in a.texts:
            if not ct.opaque and ct.text:
                self.text_of.setdefault((ct.store, ct.node_id or ""), ct.text)
        self.facts = [f for f in a.facts.values() if "outlier" not in f.flags]
        self.by_segment: dict[str, list[Fact]] = {}
        for f in self.facts:
            if f.segment is not None:
                self.by_segment.setdefault(f.segment, []).append(f)
        self.segments = {s.key: s for s in a.segments}

    def norm(self, f: Fact) -> str:
        """Comparable value of a fact (CIDR for routes with a mask, lower-case
        domains)."""
        if f.kind in DOMAIN_KINDS:
            return f.value.lower().rstrip(".")
        if f.kind == "ip_route_dst" and f.mask_span is not None:
            from .discover.segments import host_network

            net = host_network(f, self.text_of.get((f.store, f.node_id or ""), ""))
            if net is not None:
                return str(net)
        return f.value


def _norm_baseline(value: str) -> str:
    text = value.strip()
    if "/" in text:
        try:
            return str(IPv4Network(text, strict=False))
        except ValueError:
            return text
    try:
        return str(IPv4Address(text))
    except ValueError:
        return text.lower().rstrip(".")


def _ipv4(value: str) -> IPv4Address | None:
    try:
        return IPv4Address(value)
    except ValueError:
        return None


def discovered_baseline(seg: Segment, a: Analysis | None = None) -> Baseline:
    """Current values of a discovered segment: canonical scheme + most common label
    (+ the cloud ``type`` of its networks when ``a`` is given and uniform)."""
    base = Baseline()
    if seg.network_ids:
        counts: dict[str, int] = {}
        for net_id in seg.network_ids:
            label = seg.labels.get(net_id)
            if label:
                counts[label] = counts.get(label, 0) + 1
        if counts:
            best = max(counts.values())
            base.label = next(k for k, v in counts.items() if v == best)
    if seg.status != "CARRIER" and seg.schemes:
        base = _scheme_baseline(seg.schemes[0], base.label)
    if a is not None:
        # Only a uniform bridge is a baseline: a mixed segment has no single one.
        types = {a.networks[n].type for n in seg.network_ids if n in a.networks}
        if len(types) == 1:
            base.bridge = types.pop()
    return base


def _scheme_baseline(scheme: Scheme, label: str | None = None) -> Baseline:
    gateway = scheme.gateway
    if (
        gateway is not None
        and scheme.subnet is not None
        and gateway not in scheme.subnet
    ):
        gateway = None
    return Baseline(
        label=label,
        vlan=scheme.tag if isinstance(scheme.tag, int) else None,
        subnet=scheme.subnet,
        gateway=gateway,
    )


def _segment_counts(ix: _Index, key: str, values: Baseline) -> dict[str, int]:
    from .discover.l2trace import fact_vlans

    facts = ix.by_segment.get(key, [])
    out: dict[str, int] = {}
    if values.label is not None:
        seg = ix.segments.get(key)
        nets = sum(
            1
            for n in (seg.network_ids if seg else [])
            if ix.a.networks.get(n) is not None
            and ix.a.networks[n].name == values.label
        )
        refs = sum(
            1 for f in ix.facts if f.kind == "label_ref" and f.value == values.label
        )
        out["label"] = nets + refs
    if values.vlan is not None:
        out["vlan"] = sum(
            1 for f in facts if f.kind in TAG_KINDS and values.vlan in fact_vlans(f)
        )
    if values.subnet is not None:
        subnet, gateway = values.subnet, values.gateway
        out["subnet"] = sum(
            1
            for f in facts
            if (ip := _ipv4(f.value)) is not None and ip in subnet and ip != gateway
        )
    if values.gateway is not None:
        out["gateway"] = sum(1 for f in facts if _ipv4(f.value) == values.gateway)
    return out


def segment_counts(a: Analysis, key: str, values: Baseline) -> dict[str, int]:
    """``expect`` counts of segment ``key`` for ``values`` (only the set fields)."""
    return _segment_counts(_Index(a), key, values)


def _param_facts(
    ix: _Index, p: Param, values: Sequence[str] | None = None
) -> list[Fact]:
    kinds = param_fact_kinds(p)
    wanted = {_norm_baseline(v) for v in (p.baseline if values is None else values)}
    return [f for f in ix.facts if f.kind in kinds and ix.norm(f) in wanted]


def param_count(a: Analysis, p: Param, values: Sequence[str] | None = None) -> int:
    """``expect`` count of a ``[[param]]`` (at ``values``, default its baseline)."""
    return len(_param_facts(_Index(a), p, values))


# -- generate ---------------------------------------------------------------------


def _generated_by(update: bool) -> str:
    from . import __version__

    return f"eve-localize {__version__} discover --{'update' if update else 'write'}"


def _sidecar_dirs(a: Analysis) -> list[str]:
    out: list[str] = []
    for ct in a.texts:
        if ct.store.kind != "sidecar":
            continue
        parts = PurePosixPath(ct.store.name).parts
        if len(parts) > 1 and parts[0] not in out:
            out.append(parts[0])
    return out


def _canonical_scope(a: Analysis) -> str | None:
    if not a.lab.configsets():
        return None
    counts: dict[str, int] = {}
    for scope in a.active_scope.values():
        counts[scope] = counts.get(scope, 0) + 1
    if not counts:
        return None
    best = max(counts.values())
    return next(k for k, v in counts.items() if v == best)


def _template(seg: Segment, label: str | None) -> str | None:
    from .discover import names

    ordered = [n for n in seg.network_ids if seg.labels.get(n) == label]
    ordered += [n for n in seg.network_ids if n not in ordered]
    for net_id in ordered:
        tokens = seg.name_hints.get(net_id)
        if tokens:
            tpl = names.suggest_template(seg.labels[net_id], tokens)
            if tpl:
                return tpl
    return None


def _ident_or(value: str | None, fallback: str | None) -> str | None:
    if value is not None and _IDENT.fullmatch(value):
        return value
    return fallback


def _legacy_scheme(seg: Segment, leg: Legacy) -> Scheme | None:
    """The non-canonical scheme a ``[[legacy]]`` entry describes."""
    others = seg.schemes[1:]
    base = leg.baseline

    def same(s: Scheme) -> bool:
        return (
            (base.vlan is None or s.tag == base.vlan)
            and (base.subnet is None or s.subnet == base.subnet)
            and (base.gateway is None or s.gateway == base.gateway)
            and (base.vlan is not None or not isinstance(s.tag, int))
        )

    exact = [s for s in others if same(s) and set(leg.scopes) <= s.scopes]
    if exact:
        return exact[0]
    exact = [s for s in others if same(s) and set(leg.scopes) & s.scopes]
    if exact:
        return exact[0]
    return next((s for s in others if set(leg.scopes) & s.scopes), None)


def _draft_params(ix: _Index, existing: list[Param], protect: Sequence) -> list[Param]:
    """``[[param]]`` rows for service values no existing param covers."""
    covered = {id(f) for p in existing for f in _param_facts(ix, p)}
    keys = {p.key for p in existing}
    lists: dict[str, list[str]] = {}
    meta: dict[str, tuple[str, str]] = {}
    domains: list[str] = []
    for f in ix.facts:
        if f.kind not in _DRAFT_PARAMS or id(f) in covered or f.segment is not None:
            continue
        key, kind, group = _DRAFT_PARAMS[f.kind]
        value = ix.norm(f)
        ip = _ipv4(value)
        if ip is not None and any(ip in net for net in protect):
            continue
        if f.kind in DOMAIN_KINDS:
            if value and value not in domains:
                domains.append(value)
            continue
        meta[key] = (kind, group)
        values = lists.setdefault(key, [])
        if value not in values:
            values.append(value)

    def unique(key: str) -> str:
        if key not in keys:
            keys.add(key)
            return key
        n = 2
        while f"{key}_{n}" in keys:
            n += 1
        keys.add(f"{key}_{n}")
        return f"{key}_{n}"

    out: list[Param] = []
    rows = [(k, meta[k][0], meta[k][1], v) for k, v in lists.items()]
    rows += [("domain", "domain", "basic", [d]) for d in domains]
    for key, kind, group, values in rows:
        name = unique(key)
        param = Param(
            key=name, kind=kind, site_key=f"site.{name}", baseline=values, group=group
        )
        param.expect = len(_param_facts(ix, param))
        out.append(param)
    return out


def build_manifest(a: Analysis, previous: Manifest | None = None) -> Manifest:
    """The manifest ``generate`` writes, as an object.

    Without ``previous`` this is a draft: every discovered segment with cloud
    networks, a ``[[legacy]]`` row (policy ``leave``) per non-canonical scheme and a
    ``[[param]]`` per service value group. With ``previous`` (``--update``) every
    author decision is kept (site_key, role, status, label_template, carries,
    merges, legacy scopes/policy, outliers, protect, generic labels, scenarios,
    params' keys/kinds/values, rules ...) and only the counts and discovered values
    (networks, baselines, sidecar dirs) are refreshed; service values no param
    covers are appended as new params.
    """
    prev = previous
    lab_name = a.lab.path.name if a.lab.path is not None else (prev.lab if prev else "")
    m = Manifest(
        lab=lab_name or "lab.unl",
        lab_id=a.lab.lab_id,
        generated=_generated_by(prev is not None),
        sidecar_dirs=_sidecar_dirs(a),
    )
    if prev is not None:
        m.canonical_scope = prev.canonical_scope
        m.protect = list(prev.protect)
        m.generic_labels = list(prev.generic_labels)
        m.subif_policy = prev.subif_policy
        m.nodes = dict(prev.nodes)
        m.sidecar_map = dict(prev.sidecar_map)
        m.merges = list(prev.merges)
        m.outliers = list(prev.outliers)
        m.scenarios = dict(prev.scenarios)
        m.rules = list(prev.rules)
        if not m.sidecar_dirs:
            m.sidecar_dirs = list(prev.sidecar_dirs)
    else:
        m.canonical_scope = _canonical_scope(a)
    ix = _Index(a)
    written = [s for s in a.segments if s.network_ids and _IDENT.fullmatch(s.key)]
    keys = {s.key for s in written}
    for seg in written:
        old = prev.segment(seg.key) if prev is not None else None
        values = discovered_baseline(seg, a)
        if old is not None:
            carries = [k for k in (old.carries or seg.carries) if k in keys]
            ms = ManifestSegment(
                key=seg.key,
                networks=list(seg.network_ids),
                site_key=old.site_key,
                role=old.role,
                status=old.status,
                label_template=old.label_template,
                carries=carries,
            )
        else:
            role = seg.role if seg.role in ROLES else None
            ms = ManifestSegment(
                key=seg.key,
                networks=list(seg.network_ids),
                site_key=_ident_or(seg.site_key, None),
                role=role,
                label_template=_template(seg, values.label),
                carries=[k for k in seg.carries if k in keys],
            )
        ms.baseline = values
        ms.expect = _segment_counts(ix, seg.key, values)
        m.segments.append(ms)
    if prev is not None:
        for leg in prev.legacy:
            seg = ix.segments.get(leg.segment)
            if leg.segment not in keys or seg is None:
                continue
            scheme = _legacy_scheme(seg, leg)
            base = _scheme_baseline(scheme) if scheme is not None else leg.baseline
            m.legacy.append(Legacy(leg.segment, list(leg.scopes), leg.policy, base))
        m.label_values = [
            lv for lv in prev.label_values if lv.segment is None or lv.segment in keys
        ]
        for p in prev.params:
            m.params.append(
                Param(
                    key=p.key,
                    kind=p.kind,
                    site_key=p.site_key,
                    baseline=list(p.baseline),
                    expect=len(_param_facts(ix, p)),
                    group=p.group,
                )
            )
    else:
        for seg in written:
            if seg.status == "CARRIER":
                continue
            for scheme in seg.schemes[1:]:
                m.legacy.append(
                    Legacy(
                        seg.key,
                        sorted(scheme.scopes),
                        "leave",
                        _scheme_baseline(scheme),
                    )
                )
    protect = list(a.protected_prefixes) + list(m.protect)
    m.params.extend(_draft_params(ix, m.params, protect))
    return m


def _header(a: Analysis, m: Manifest, previous: Manifest | None) -> str:
    lines = [f"Generated by {m.generated} (eve-localize manifest, schema {SCHEMA})."]
    if previous is None:
        lines += [
            "DRAFT: review every value, add author decisions (site_key bindings,",
            "[[merge]], [[outlier]], protect, generic_labels, scenarios), then rename",
            f"to {Path(m.lab).stem}{MANIFEST_SUFFIX}.",
        ]
    else:
        lines.append("Author decisions kept; counts and discovered values refreshed.")
        kept = {s.key for s in m.segments}
        dropped = [s.key for s in previous.segments if s.key not in kept]
        if dropped:
            lines.append("Dropped (no longer discovered): " + ", ".join(dropped))
    notes: list[str] = []
    for seg in a.segments:
        if not seg.network_ids:
            notes.append(
                f"segment {seg.key} ({seg.status}) has no cloud network of its own "
                "(reached via a carrier); pin it with [[merge]] if it is external"
            )
    for f in a.findings:
        if f.code in ("MERGE_HINT", "OUTLIER", "MANIFEST_STALE", "MERGE_UNKNOWN_UNIT"):
            notes.append(f"{f.code}: {f.msg}")
    if notes:
        lines.append("")
        lines.append("Discovery notes:")
        lines += [f"- {n}" for n in dict.fromkeys(notes)]
    return "\n".join(lines)


def generate(a: Analysis, previous: Manifest | None = None) -> str:
    """Draft (``previous=None``) or refreshed (``--update``) manifest TOML text.

    The text is verified to load back with ``parse`` before it is returned.
    """
    m = build_manifest(a, previous)
    text = dumps(m, header=_header(a, m, previous))
    parse(tomllib.loads(text), source="generated manifest")
    return text


# -- check ------------------------------------------------------------------------


def unpinned(a: Analysis) -> list[Finding]:
    """``UNPINNED`` warning for a lab with cloud networks and no manifest."""
    from .model import Finding

    clouds = [n for n in a.networks.values() if n.is_cloud]
    if not clouds:
        return []
    return [
        Finding(
            "UNPINNED",
            "warn",
            f"{len(clouds)} cloud network(s) but no manifest: run "
            "'eve-localize discover LAB --write' and review the draft",
        )
    ]


def _merged(base: Baseline, over: Baseline | None) -> Baseline:
    if over is None:
        return base
    return Baseline(
        label=over.label if over.label is not None else base.label,
        vlan=over.vlan if over.vlan is not None else base.vlan,
        subnet=over.subnet if over.subnet is not None else base.subnet,
        gateway=over.gateway if over.gateway is not None else base.gateway,
        bridge=over.bridge if over.bridge is not None else base.bridge,
    )


def _baseline_diffs(
    want: Baseline,
    scheme: Scheme | None,
    labels: Sequence[str],
    types: Sequence[str] = (),
) -> list[str]:
    out: list[str] = []
    if want.bridge is not None and any(t != want.bridge for t in types):
        have = sorted(set(types))
        out.append(f"bridge {want.bridge!r} != network types {have}")
    if want.label is not None and want.label not in labels:
        out.append(f"label {want.label!r} not found (have {sorted(set(labels))})")
    have = _scheme_baseline(scheme) if scheme is not None else Baseline()
    if want.vlan is not None and have.vlan != want.vlan:
        tag = scheme.tag if scheme is not None else None
        out.append(f"vlan {want.vlan} != discovered {tag}")
    if want.subnet is not None and have.subnet != want.subnet:
        out.append(f"subnet {want.subnet} != discovered {have.subnet}")
    if want.gateway is not None and have.gateway != want.gateway:
        out.append(f"gateway {want.gateway} != discovered {have.gateway}")
    return out


def check(
    a: Analysis,
    m: Manifest | None,
    *,
    localized: Mapping[str, Baseline] | None = None,
    localized_params: Mapping[str, Sequence[str]] | None = None,
    leaks: bool = True,
) -> list[Finding]:
    """CI check of a manifest against discovery (section 8.1, ``localize-check``).

    ``a`` must come from ``analyse(lab, m)``. ``m=None`` -> ``UNPINNED`` (warning)
    when the lab has clouds. Error findings: ``MANIFEST_LAB_ID`` /
    ``MANIFEST_LAB``, ``MANIFEST_COVERAGE`` (cloud outside every segment, unknown
    network, segment not discovered), ``COUNT_MISMATCH`` (stale ``expect``),
    ``NOT_AT_BASELINE``. Warnings: ``MANIFEST_EXPECT`` (count without a baseline
    value), ``PARAM_MISSING`` and ``LEAK`` (old values no fact covers).

    ``localized`` / ``localized_params`` give the current localized values of
    segments / params (from ``state.json``); those are then expected instead of the
    baseline (tri-state rule).
    """
    from .model import Finding

    if m is None:
        return unpinned(a)
    out: list[Finding] = []
    localized = localized or {}
    localized_params = localized_params or {}
    if not m.matches_lab_id(a.lab.lab_id):
        out.append(
            Finding(
                "MANIFEST_LAB_ID",
                "error",
                f"manifest lab_id {m.lab_id} != lab id {a.lab.lab_id}: "
                "manifest ignored",
            )
        )
    if a.lab.path is not None:
        named = PurePosixPath(m.lab).name
        if m.path is not None:
            same = (
                m.path.parent / PurePosixPath(m.lab)
            ).resolve() == a.lab.path.resolve()
        else:
            same = named == a.lab.path.name
        if not same:
            out.append(
                Finding(
                    "MANIFEST_LAB",
                    "error",
                    f"manifest lab = {m.lab!r} does not name {a.lab.path.name}",
                )
            )
    ix = _Index(a)
    out += _coverage(a, m, ix)
    for ms in m.segments:
        seg = ix.segments.get(ms.key)
        if seg is None:
            continue
        ref = [f"segment:{ms.key}"]
        want = _merged(ms.baseline, localized.get(ms.key))
        state = "localized values" if ms.key in localized else "baseline"
        labels = [seg.labels[n] for n in seg.network_ids if n in seg.labels]
        scheme = seg.schemes[0] if seg.schemes and seg.status != "CARRIER" else None
        types = [a.networks[n].type for n in seg.network_ids if n in a.networks]
        diffs = _baseline_diffs(want, scheme, labels, types)
        if diffs:
            out.append(
                Finding(
                    "NOT_AT_BASELINE",
                    "error",
                    f"segment {ms.key} is not at its {state}: " + "; ".join(diffs),
                    ref,
                )
            )
        counts = _segment_counts(ix, ms.key, want)
        for name, expected in ms.expect.items():
            if name not in counts:
                out.append(
                    Finding(
                        "MANIFEST_EXPECT",
                        "warn",
                        f"segment {ms.key}: expect.{name} has no baseline value "
                        "to count",
                        ref,
                    )
                )
            elif counts[name] != expected:
                out.append(
                    Finding(
                        "COUNT_MISMATCH",
                        "error",
                        f"segment {ms.key}: expect.{name} = {expected}, discovered "
                        f"{counts[name]} (lab changed: review and run "
                        "discover --update)",
                        ref,
                    )
                )
    for leg in m.legacy:
        seg = ix.segments.get(leg.segment)
        if seg is None:
            continue
        scheme = _legacy_scheme(seg, leg)
        diffs = _baseline_diffs(leg.baseline, scheme, [])
        if scheme is None:
            diffs = [f"no scheme in scopes {', '.join(leg.scopes)}"]
        if diffs:
            out.append(
                Finding(
                    "NOT_AT_BASELINE",
                    "error",
                    f"legacy scheme of {leg.segment} ({', '.join(leg.scopes)}): "
                    + "; ".join(diffs),
                    [f"segment:{leg.segment}"],
                )
            )
    for p in m.params:
        values = list(localized_params.get(p.key, p.baseline))
        facts = _param_facts(ix, p, values)
        ref = [f"param:{p.key}"]
        if p.expect is not None and len(facts) != p.expect:
            out.append(
                Finding(
                    "COUNT_MISMATCH",
                    "error",
                    f"param {p.key}: expect = {p.expect}, discovered {len(facts)}",
                    ref,
                )
            )
        found = {ix.norm(f) for f in facts}
        missing = [v for v in values if _norm_baseline(v) not in found]
        if missing:
            out.append(
                Finding(
                    "PARAM_MISSING",
                    "warn",
                    f"param {p.key}: value(s) {', '.join(missing)} not found in any "
                    f"{'/'.join(sorted(param_fact_kinds(p)))} fact",
                    ref,
                )
            )
    if leaks:
        out += leak_scan(a, m, localized=localized, localized_params=localized_params)
    return out


def _coverage(a: Analysis, m: Manifest, ix: _Index) -> list[Finding]:
    from .model import Finding

    out: list[Finding] = []
    pinned = {n for ms in m.segments for n in ms.networks}
    loose = [n.id for n in a.networks.values() if n.is_cloud and n.id not in pinned]
    if loose:
        out.append(
            Finding(
                "MANIFEST_COVERAGE",
                "error",
                f"cloud network(s) {', '.join(loose)} are in no manifest segment",
                [f"network:{n}" for n in loose],
            )
        )
    for ms in m.segments:
        bad = [
            n for n in ms.networks if n not in a.networks or not a.networks[n].is_cloud
        ]
        if bad:
            out.append(
                Finding(
                    "MANIFEST_COVERAGE",
                    "error",
                    f"segment {ms.key}: network(s) {', '.join(bad)} are not cloud "
                    "networks of this lab",
                    [f"segment:{ms.key}"],
                )
            )
        if ms.key not in ix.segments:
            out.append(
                Finding(
                    "MANIFEST_COVERAGE",
                    "error",
                    f"segment {ms.key} was not discovered (analyse the lab with its "
                    "manifest)",
                    [f"segment:{ms.key}"],
                )
            )
    return out


def _spans(facts: Iterable[Fact]) -> dict[tuple[object, str], list[tuple[int, int]]]:
    out: dict[tuple[object, str], list[tuple[int, int]]] = {}
    for f in facts:
        out.setdefault((f.store, f.node_id or ""), []).append(
            (f.span.start, f.span.end)
        )
    return out


def _covered(spans: Sequence[tuple[int, int]], start: int, end: int) -> bool:
    return any(s < end and start < e for s, e in spans)


def leak_scan(
    a: Analysis,
    m: Manifest | None = None,
    *,
    localized: Mapping[str, Baseline] | None = None,
    localized_params: Mapping[str, Sequence[str]] | None = None,
) -> list[Finding]:
    """``LEAK`` warnings: old external values that no planned edit would change.

    Every readable config text, sidecar and textobject is searched for IPv4 tokens
    inside a segment's subnet (manifest baseline, else the canonical scheme) that
    no fact of that segment (or of a ``[[param]]``) covers, and for occurrences of
    param baseline values (IPv4 tokens, domains) that no param fact covers. Such a
    value would survive localization unchanged.
    """
    from evelab.common.textutil import domain_re, find_ipv4

    from .model import Finding

    localized = localized or {}
    localized_params = localized_params or {}
    ix = _Index(a)
    params = list(m.params) if m is not None else []
    param_values = {
        p.key: list(localized_params.get(p.key, p.baseline)) for p in params
    }
    param_facts = [f for p in params for f in _param_facts(ix, p, param_values[p.key])]
    owners: list[tuple[str, str, IPv4Network | None, set[str], set[str], dict]] = []
    for seg in a.segments:
        ms = m.segment(seg.key) if m is not None else None
        if ms is not None:
            want = _merged(ms.baseline, localized.get(seg.key))
        else:
            want = discovered_baseline(seg)
        if want.subnet is None:
            continue
        cover = _spans([*ix.by_segment.get(seg.key, []), *param_facts])
        owners.append(
            (
                f"segment {seg.key}",
                f"segment:{seg.key}",
                want.subnet,
                set(),
                set(),
                cover,
            )
        )
    if params:
        cover = _spans([*param_facts, *(f for f in ix.facts if f.segment is not None)])
        ips: set[str] = set()
        domains: set[str] = set()
        for p in params:
            for value in param_values[p.key]:
                norm = _norm_baseline(value)
                if _ipv4(norm) is not None:
                    ips.add(norm)
                elif "/" not in norm and "." in norm:
                    domains.add(norm)
        if ips or domains:
            owners.append(("params", "params", None, ips, domains, cover))
    out: list[Finding] = []
    for ct in a.texts:
        if ct.opaque or not ct.text:
            continue
        text = ct.text
        tokens = find_ipv4(text)
        where = f"{ct.store.kind} {ct.store.name}" + (
            f" node {ct.node_id}" if ct.node_id else ""
        )
        key = (ct.store, ct.node_id or "")
        for label, ref, subnet, ips, domains, cover in owners:
            spans = cover.get(key, [])
            hits: list[tuple[int, str]] = []
            for tok in tokens:
                if subnet is not None and tok.address not in subnet:
                    continue
                if subnet is None and tok.value not in ips:
                    continue
                if not _covered(spans, tok.span.start, tok.span.end):
                    hits.append((tok.span.start, tok.value))
            for dom in sorted(domains):
                for mt in domain_re(dom).finditer(text):
                    if not _covered(spans, mt.start(), mt.end()):
                        hits.append((mt.start(), mt.group(0)))
            if not hits:
                continue
            hits.sort()
            shown = ", ".join(
                f"{v} (line {text.count(chr(10), 0, pos) + 1})"
                for pos, v in hits[:LEAK_EXAMPLES]
            )
            more = (
                f" (+{len(hits) - LEAK_EXAMPLES} more)"
                if len(hits) > LEAK_EXAMPLES
                else ""
            )
            refs = [ref, f"{ct.store.kind}:{ct.store.name}"]
            if ct.node_id:
                refs.append(f"node:{ct.node_id}")
            out.append(
                Finding(
                    "LEAK",
                    "warn",
                    f"{label}: {len(hits)} old value(s) in {where} that no planned "
                    f"edit covers: {shown}{more}",
                    refs,
                )
            )
    return out


__all__ = [
    "Baseline",
    "Manifest",
    "ManifestError",
    "build_manifest",
    "check",
    "discovered_baseline",
    "dumps",
    "find_for",
    "generate",
    "leak_scan",
    "load",
    "param_count",
    "param_fact_kinds",
    "parse",
    "segment_counts",
    "to_dict",
    "unpinned",
]
