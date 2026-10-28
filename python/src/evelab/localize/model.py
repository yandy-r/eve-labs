"""Shared dataclasses and enums: THE frozen contract (design section 4).

Changing anything here requires updating docs/internal/lab-localize-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import TYPE_CHECKING, Literal, NamedTuple

# Re-exported: the shared records moved to evelab.common but remain part of this
# contract module (``from evelab.localize.model import Span`` keeps working).
from evelab.common.findings import Finding as Finding
from evelab.common.labmodel import Interface as Interface
from evelab.common.labmodel import Network as Network
from evelab.common.labmodel import Node as Node
from evelab.common.spans import Span as Span
from evelab.common.spans import TextEdit as TextEdit

if TYPE_CHECKING:
    from evelab.common.codec import DecodedBlob
    from evelab.common.textutil import VlanList
    from evelab.common.unl import RawLab


class Confidence(IntEnum):
    HEURISTIC = 1
    CORRELATED = 2
    PROVEN = 3


class Store(NamedTuple):
    kind: Literal["xml", "startup", "configset", "sidecar", "textobject"]
    name: str  # "startup" | configset name | sidecar relpath | textobject id | "xml"
    scope: str  # "startup" | "<configset name>" | "-"


@dataclass
class ConfigText:
    store: Store
    node_id: str
    text: str
    dialect: str
    blob: DecodedBlob | None  # embedded
    path: Path | None  # sidecar
    # (scope, node_id) when byte-identical to an embedded blob
    mirror_of: tuple[str, str] | None = None
    opaque: bool = False


FactKind = str  # extendable; registered kinds below (see section 13.3)
CORE_FACT_KINDS: set[str] = {
    "ip_host",
    "ip_gateway",
    "ip_route_dst",
    "mask",
    "dhcp",
    "vlan_tag",
    "vlan_list",
    "vlan_def",
    "vlan_name",
    "subif_name",
    "svi_name",
    "label_ref",
    "cloud_ref",
    "vlan_mention",
    "dns_server",
    "domain",
    "search_list",
    "ntp_server",
    "log_server",  # syslog targets (added in T9)
    "probe_target",
    "peer_ip",
    "asn",
    "router_id",
    "secret",
    "ipv6_literal",
}


@dataclass
class Fact:
    id: str  # sha1(store, node, start, kind)[:12], stable
    kind: FactKind
    value: str
    store: Store
    node_id: str | None
    span: Span
    line: int
    rule: str  # "iosxe.encap_dot1q"
    # canonical iface key of the enclosing block ("gi16.2"); None = no/orphan block
    iface: str | None
    # physical parent iface key for subifs / Forti vlan ifaces
    parent: str | None
    mask_span: Span | None = None
    mask_form: Literal["dotted", "prefix", "netmask", "wildcard", "none"] = "none"
    list_value: VlanList | None = None
    group: str | None = None  # tokens that must change together (subif name + encap)
    segment: str | None = None  # set by attribution
    confidence: Confidence = Confidence.HEURISTIC
    # path / reason ("mgmt-80 e0/0 trunk(ALL) -> e0/2 access 2 -> mgmt0")
    evidence: str = ""
    orphan: bool = False  # inside a corrupt/truncated block
    # {"uncabled", "cosmetic", "outlier", "secret"}
    flags: frozenset[str] = frozenset()


Tag = int | Literal["untagged", "unknown"]

NameClass = Literal["tag", "octet3", "host", "netid", "ambiguous", "unknown"]


@dataclass(frozen=True)
class NameToken:
    """One digit run of a cloud network name, classified by the NameExplainer."""

    text: str  # the digits as written ("0203")
    span: Span  # offsets inside the network name
    kind: NameClass
    value: int | None = None  # int(text), None when not numeric-meaningful


@dataclass
class Scheme:
    tag: Tag
    subnet: IPv4Network | None
    gateway: IPv4Address | None
    scopes: set[str]
    members: list[str]
    outliers: list[str]


@dataclass
class Attachment:
    node_id: str
    iface: str
    network_id: str
    scope: str
    path: list[str]
    direct: bool
    arrives: Literal["untagged", "tagged"]


@dataclass
class Segment:
    key: str  # manifest key or derived ("MGMT-203", "cloud-22")
    site_key: str  # profile identity ("site.mgmt_a" or "<labstem>.<key>")
    role: str | None  # mgmt|inet|oob|trunk|nat|wan|None
    network_ids: list[str]
    cloud_types: set[str]
    labels: dict[str, str]  # net id -> name
    attachments: list[Attachment]
    schemes: list[Scheme]
    status: Literal["CONFIGURABLE", "DHCP", "LABEL_ONLY", "CARRIER", "UNKNOWN"]
    carries: list[str] = field(default_factory=list)  # CARRIER: segment keys it carries
    name_hints: dict[str, list[NameToken]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class Analysis:
    lab: RawLab
    nodes: dict[str, Node]
    networks: dict[str, Network]
    texts: list[ConfigText]
    facts: dict[str, Fact]
    segments: list[Segment]
    protected_vlans: dict[str, set[int]]  # scope -> vlans
    protected_prefixes: list[IPv4Network]
    active_scope: dict[str, str]  # node_id -> scope
    findings: list[Finding]
    pinned: bool  # manifest present and consistent


@dataclass
class Edit:
    id: str
    file: Path
    target: Literal["xml_attr", "blob", "sidecar", "textobject"]
    store: Store
    node_id: str | None
    text_edit: TextEdit
    # cloud|label|vlan|ip|mask|gateway|dns|domain|ntp|route|cosmetic|secret|derived
    category: str
    # review toggle group, e.g. "MGMT-203/vlan", "cosmetic/pnet-text"
    group: str
    confidence: Confidence
    secret: bool
    # [question id, fact id(s), rule id, evidence]
    provenance: list[str]


@dataclass
class Plan:
    schema: int
    lab: Path
    lab_id: str
    base_sha256: dict[str, str]  # every file touched (relpath -> sha)
    answers_digest: str
    edits: list[Edit]
    enabled_groups: set[str]
    findings: list[Finding]

    @property
    def blocked(self) -> bool:
        return any(
            f.severity in ("conflict", "blocker", "error") for f in self.findings
        )
