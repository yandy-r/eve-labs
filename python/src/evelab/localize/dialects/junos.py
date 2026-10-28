"""Junos (vJunos switch/router, vMX, vSRX, vQFX) — brace and set style.

Design 6.2 (``brace`` blocks), 6.3 (``vlan-id N;``, ``unit N { vlan-id N; }``),
6.4 (``name-server``, ``domain-name``/``domain-search``, ``ntp server``) and
11.3 (``address A/len;``, ``next-hop X;``, ``name-server { X routing-instance
...; }``).

Interfaces
----------
The brace layout is post-processed so ``interfaces { <ifd> { unit N { ... } } }``
blocks become ``interface`` blocks: the physical one is named ``<ifd>``
(``fxp0``, ``ge-0/0/1``) and each logical unit ``<ifd>.<N>`` (``fxp0.0``), whose
parent is ``<ifd>``.  Facts inside ``family inet`` therefore carry
``iface="fxp0.0"``, ``parent="fxp0"``.  A unit's ``IfaceInfo.tag`` is its
``vlan-id`` (``None`` = untagged); when an untagged unit is routed (has an
address or DHCP) the physical interface is marked ``routed`` too, so the L2
trace sees ``fxp0`` as a routed, untagged endpoint.

``unit N {`` produces a ``subif_name`` fact (value: the unit number ``N``) only
when the unit has a ``vlan-id``; it is grouped with that tag
(``group="subif:<ifd>.<N>"``) like an IOS ``interface X.N``.

Set style (``set interfaces ge-0/0/1 unit 0 family inet address ...``) is
recognised line by line with ``^set ...`` rules; interface blocks are
synthesised from ``set interfaces <ifd> [unit N]``.  Set-style units produce no
``subif_name`` (the unit number repeats on every line of the unit).

Not handled (reported by discovery as unattributed if relevant): Ethernet
switching ``interface-mode`` / ``vlan members`` (``members 1 2`` is never a tag),
``vlan-tags outer/inner``, apply-groups expansion.
"""

from __future__ import annotations

import re
from typing import Any

from ..model import ConfigText, Fact, Span
from . import register
from ._common import ContextRule, ContextRulesMixin, label_context_rules
from .base import IfaceInfo, ParsedConfig, PatternRule, RuleDialect
from .blocks import Block, Layout, Line
from .generic import attach_iface_blocks

_INACTIVE_RE = re.compile(r"^(?:(?:inactive|protect):[ \t]*)+")
_IFD_NAME_RE = re.compile(r"^[A-Za-z][\w./:-]*$")
_IFD_SKIP = frozenset({"traceoptions", "interface-range", "interface-set"})
_UNIT_RE = re.compile(r"^unit[ \t]+(\d+)$")
_SET_IFACE_RE = re.compile(
    r"^set[ \t]+(?:groups[ \t]+\S+[ \t]+)?interfaces[ \t]+(?P<ifd>[A-Za-z][\w./:-]*)"
    r"(?:[ \t]+unit[ \t]+(?P<unit>\d+))?(?=[ \t]|$)"
)

# block filters
_IFACE = "interface"
_STATIC = "*routing-options*static"
_RO = "*routing-options"
_BGP = "*protocols/bgp*"
_NS = "system/name-server"
_NTP = "system/ntp"

# set-style prefixes
_SET_RI = r"^set[ \t]+(?:routing-instances[ \t]+\S+[ \t]+)?"
_SET_STATIC = _SET_RI + r"routing-options[ \t]+static[ \t]+route[ \t]+"
_SET_UNIT = (
    r"^set[ \t]+(?:groups[ \t]+\S+[ \t]+)?interfaces[ \t]+\S+[ \t]+unit[ \t]+\d+[ \t]+"
)
_DOMAIN = r"[A-Za-z0-9][\w-]*(?:\.[\w-]+)*"
_DESCRIPTION = r"(?:^[ \t]*|^set[ \t].*?[ \t])description[ \t]+\"?(?P<ctx>[^\";]*)"


def _strip_inactive(name: str) -> tuple[str, int]:
    """``inactive: unit 0`` -> (``unit 0``, offset of the stripped text)."""
    m = _INACTIVE_RE.match(name)
    return (name[m.end() :], m.end()) if m else (name, 0)


def _mark_brace_ifaces(layout: Layout) -> None:
    """Turn ``interfaces/<ifd>`` and ``.../unit N`` blocks into ``interface``."""
    parent: dict[int, Block | None] = {}
    for line in layout.lines:
        for i, blk in enumerate(line.chain):
            parent.setdefault(id(blk), line.chain[i - 1] if i else None)
    ifds: set[int] = set()
    for blk in layout.blocks:  # opening order: parents first
        par = parent.get(id(blk))
        if par is None or blk.name_span is None:
            continue
        name, off = _strip_inactive(blk.name)
        par_name = _strip_inactive(par.name)[0]
        if (
            par_name == "interfaces"
            and par.kind != _IFACE
            and _IFD_NAME_RE.match(name)
            and name not in _IFD_SKIP
        ):
            blk.kind = _IFACE
            blk.name = name
            start = blk.name_span.start + off
            blk.name_span = Span(start, start + len(name))
            ifds.add(id(blk))
            continue
        if id(par) in ifds:
            m = _UNIT_RE.match(name)
            if m:
                blk.kind = _IFACE
                blk.name = f"{par.name}.{m.group(1)}"
                start = blk.name_span.start + off + m.start(1)
                blk.name_span = Span(start, start + len(m.group(1)))


def _set_resolver(text: str, line: Line) -> tuple[str, Span | None] | None:
    m = _SET_IFACE_RE.match(text)
    if m is None or m.group("ifd") in _IFD_SKIP:
        return None
    if m.group("unit") is not None:
        a = line.start + m.start("unit")
        return f"{m.group('ifd')}.{m.group('unit')}", Span(a, a + len(m.group("unit")))
    a = line.start + m.start("ifd")
    return m.group("ifd"), Span(a, a + len(m.group("ifd")))


def _r(
    rid: str, pattern: str, kind: str, block: str | None = None, **kw: Any
) -> PatternRule:
    return PatternRule(f"junos.{rid}", pattern, kind, block=block, **kw)


_NEG_TAG = ("    members 1 2;", "    rd 2:2;", "    vlan-id-list 100-200;")

BRACE_RULES = (
    _r(
        "address",
        r"^[ \t]*address[ \t]+(?P<v>IPV4)(?P<mask>/\d{1,2})(?=[ \t]*[;{]|[ \t]*$)",
        "ip_host",
        _IFACE,
        negative=("    address 2001:db8::1/64;", "    virtual-address 10.0.0.1;"),
    ),
    _r("dhcp", r"^[ \t]*(?P<v>dhcp(?:-client)?)[ \t]*[;{]", "dhcp", _IFACE),
    _r(
        "vlan_id",
        r"^[ \t]*vlan-id[ \t]+(?P<v>\d{1,4})[ \t]*;",
        "vlan_tag",
        _IFACE,
        role="encap_tag",
        negative=_NEG_TAG,
    ),
    _r(
        "unit",
        r"^[ \t]*(?:inactive:[ \t]*)?unit[ \t]+(?P<v>\d+)[ \t]*\{",
        "subif_name",
        _IFACE,
    ),
    _r(
        "vlan_def",
        r"^[ \t]*vlan-id[ \t]+(?P<v>\d{1,4})[ \t]*;",
        "vlan_def",
        "vlans/*",
        negative=_NEG_TAG,
    ),
    _r(
        "route_dst",
        r"^[ \t]*route[ \t]+(?P<v>IPV4)(?P<mask>/\d{1,2})(?=[ \t;{]|$)",
        "ip_route_dst",
        _STATIC,
    ),
    _r(
        "next_hop_inline",
        r"^[ \t]*route[ \t]+\S+[ \t]+next-hop[ \t]+(?P<v>IPV4)[ \t]*;",
        "ip_gateway",
        _STATIC,
    ),
    _r(
        "next_hop_list",
        r"^[ \t]*route[ \t]+\S+[ \t]+next-hop[ \t]+\[(?P<many>[^\]]*)\]",
        "ip_gateway",
        _STATIC,
    ),
    _r(
        "next_hop",
        r"^[ \t]*(?:qualified-)?next-hop[ \t]+(?P<v>IPV4)(?=[ \t]*[;{])",
        "ip_gateway",
        _STATIC,
    ),
    _r(
        "name_server",
        r"^[ \t]*(?P<v>IPV4)(?:[ \t]+routing-instance[ \t]+\S+?)?[ \t]*;",
        "dns_server",
        _NS,
    ),
    _r(
        "name_server_inline",
        r"^[ \t]*name-server[ \t]+(?P<v>IPV4)[ \t]*;",
        "dns_server",
        "system",
    ),
    _r(
        "name_server_list",
        r"^[ \t]*name-server[ \t]+\[(?P<many>[^\]]*)\]",
        "dns_server",
        "system",
    ),
    _r(
        "ntp_server",
        r"^[ \t]*(?:boot-)?server[ \t]+(?P<v>IPV4)(?=[ \t;{]|$)",
        "ntp_server",
        _NTP,
    ),
    _r(
        "domain_name",
        rf"^[ \t]*domain-name[ \t]+(?P<v>{_DOMAIN})[ \t]*;",
        "domain",
        "system",
    ),
    _r(
        "domain_search",
        rf"^[ \t]*domain-search[ \t]+(?P<v>{_DOMAIN})[ \t]*;",
        "search_list",
        "system",
    ),
    _r(
        "router_id",
        r"^[ \t]*router-id[ \t]+(?P<v>IPV4)[ \t]*;",
        "router_id",
        _RO,
    ),
    _r(
        "autonomous_system",
        r"^[ \t]*autonomous-system[ \t]+(?P<v>\d+)(?=[ \t;])",
        "asn",
        _RO,
    ),
    _r("peer_as", r"^[ \t]*peer-as[ \t]+(?P<v>\d+)[ \t]*;", "asn", _BGP),
    _r("local_as", r"^[ \t]*local-as[ \t]+(?P<v>\d+)(?=[ \t;])", "asn", _BGP),
    _r(
        "neighbor",
        r"^[ \t]*neighbor[ \t]+(?P<v>IPV4)(?=[ \t]*[;{])",
        "peer_ip",
        _BGP,
    ),
)

SET_RULES = (
    _r(
        "set_address",
        _SET_UNIT + r"family[ \t]+inet[ \t]+address[ \t]+(?P<v>IPV4)"
        r"(?P<mask>/\d{1,2})(?=[ \t]|$)",
        "ip_host",
        negative=(
            "set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
        ),
    ),
    _r(
        "set_dhcp",
        _SET_UNIT + r"family[ \t]+inet[ \t]+(?P<v>dhcp(?:-client)?)(?=[ \t]|$)",
        "dhcp",
    ),
    _r(
        "set_vlan_id",
        _SET_UNIT + r"vlan-id[ \t]+(?P<v>\d{1,4})[ \t]*$",
        "vlan_tag",
        role="encap_tag",
        negative=("set vlans V100 vlan-id 100",),
    ),
    _r(
        "set_vlan_def",
        r"^set[ \t]+vlans[ \t]+\S+[ \t]+vlan-id[ \t]+(?P<v>\d{1,4})[ \t]*$",
        "vlan_def",
        negative=("set vlans V100 vlan-id-list 100-200",),
    ),
    _r(
        "set_route_dst",
        _SET_STATIC + r"(?P<v>IPV4)(?P<mask>/\d{1,2})(?=[ \t]|$)",
        "ip_route_dst",
    ),
    _r(
        "set_next_hop",
        _SET_STATIC + r"\S+[ \t]+(?:qualified-)?next-hop[ \t]+(?P<v>IPV4)(?=[ \t]|$)",
        "ip_gateway",
    ),
    _r(
        "set_name_server",
        r"^set[ \t]+system[ \t]+name-server[ \t]+(?P<v>IPV4)(?=[ \t]|$)",
        "dns_server",
    ),
    _r(
        "set_ntp_server",
        r"^set[ \t]+system[ \t]+ntp[ \t]+(?:boot-)?server[ \t]+(?P<v>IPV4)(?=[ \t]|$)",
        "ntp_server",
    ),
    _r(
        "set_domain_name",
        rf"^set[ \t]+system[ \t]+domain-name[ \t]+(?P<v>{_DOMAIN})[ \t]*$",
        "domain",
    ),
    _r(
        "set_domain_search",
        rf"^set[ \t]+system[ \t]+domain-search[ \t]+(?P<v>{_DOMAIN})[ \t]*$",
        "search_list",
    ),
    _r(
        "set_router_id",
        _SET_RI + r"routing-options[ \t]+router-id[ \t]+(?P<v>IPV4)[ \t]*$",
        "router_id",
    ),
    _r(
        "set_autonomous_system",
        _SET_RI + r"routing-options[ \t]+autonomous-system[ \t]+(?P<v>\d+)(?=[ \t]|$)",
        "asn",
    ),
    _r(
        "set_peer_as",
        _SET_RI + r"protocols[ \t]+bgp[ \t]+group[ \t]+\S+[ \t]+"
        r"(?:neighbor[ \t]+\S+[ \t]+)?peer-as[ \t]+(?P<v>\d+)[ \t]*$",
        "asn",
    ),
    _r(
        "set_neighbor",
        _SET_RI + r"protocols[ \t]+bgp[ \t]+group[ \t]+\S+[ \t]+neighbor[ \t]+"
        r"(?P<v>IPV4)(?=[ \t]|$)",
        "peer_ip",
    ),
)


@register
class Junos(ContextRulesMixin, RuleDialect):
    name = "junos"
    templates = (
        "vjunos*",
        "vmx*",
        "vsrx*",
        "vqfx*",
        "junos*",
        "olive*",
        "vjunosevolved*",
    )
    sniff = (
        r"^version[ \t]+\d+\.\d+[A-Z]\d",
        r"^(?:system|interfaces|routing-options|protocols)[ \t]*\{[ \t]*$",
        r"^set[ \t]+(?:system[ \t]+host-name|interfaces[ \t]+\S+[ \t]+unit)[ \t]",
    )
    block_style = "brace"
    mask_form = "prefix"
    rules = BRACE_RULES + SET_RULES
    secret_rules = (
        r"\bencrypted-password[ \t]+\"(?P<s>[^\"]+)\"",
        r"\b(?:secret|authentication-key|simple-password|ascii-text|hexadecimal)"
        r"[ \t]+\"(?P<s>[^\"]+)\"",
    )
    context_rules = (
        ContextRule(
            "junos.domain_search_list",
            r"^[ \t]*domain-search[ \t]+\[(?P<ctx>[^\]]*)\]",
            rf"(?P<v>{_DOMAIN})",
            "search_list",
            block="system",
        ),
        *label_context_rules("junos", (("description", _DESCRIPTION),)),
    )

    def _layout(self, text: str) -> Layout:
        layout = super()._layout(text)
        _mark_brace_ifaces(layout)
        return attach_iface_blocks(layout, _set_resolver)

    def _group_facts(self, facts: list[Fact]) -> None:
        """Keep ``unit N`` names only for units that carry a ``vlan-id``."""
        tagged = {f.iface for f in facts if f.kind == "vlan_tag" and f.iface}
        facts[:] = [
            f for f in facts if not (f.rule == "junos.unit" and f.iface not in tagged)
        ]
        super()._group_facts(facts)

    def parse(self, ct: ConfigText) -> ParsedConfig:
        parsed: ParsedConfig = super().parse(ct)
        for info in list(parsed.ifaces.values()):
            if info.parent is None or info.orphan:
                continue
            phys = parsed.ifaces.get(info.parent)
            if phys is None:  # set style: only "set interfaces X unit N ..." lines
                phys = parsed.ifaces[info.parent] = IfaceInfo(
                    key=info.parent,
                    name=info.parent,
                    parent=None,
                    name_span=None,
                    mode="unknown",
                    access_vlan=None,
                    trunk_vlans=None,
                    native_vlan=None,
                    tag=None,
                    dhcp=False,
                    orphan=False,
                )
            if info.tag is not None:
                continue
            if info.mode == "routed" and phys.mode == "unknown":
                phys.mode = "routed"
            if info.dhcp:
                phys.dhcp = True
        return parsed
