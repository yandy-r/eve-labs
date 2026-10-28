"""Cisco NX-OS dialect: Nexus 9000v (design 6.1-6.5, 11.3).

Differences from IOS that matter here:

* masks are ``/len`` (``ip address 10.100.203.13/24 [tag N|secondary]``);
* 2-space indent; ``vrf context management`` holds ``ip route 0.0.0.0/0 GW`` and
  ``ip name-server ...`` (also accepted at top level with ``use-vrf``);
* ``vlan 1,100-101,202`` range lists (``list_style="nxos"``) and ``name X`` in the
  ``vlan N`` block (a ``vlan_name`` - ``name servers`` is never DNS);
* subinterfaces use lowercase ``encapsulation dot1q N``;
* BGP neighbors are blocks (``neighbor A`` / ``remote-as N`` on its own line);
* ``mgmt0`` is the management port (``vrf member management``).

Rule ids are ``nxos.<name>``; fact kinds as in ``ios`` (see its docstring).
"""

from __future__ import annotations

from typing import ClassVar

from . import register
from .base import PatternRule
from .ios import LOG_SERVER, NEG_TAG, CiscoDialect

_I = r"^\s+"
# optional NX-OS suffixes after "ip address A/len"
_TAIL = r"(?:[ \t]+(?:tag[ \t]+\d+|secondary))*\s*$"

NXOS_RULES: tuple[PatternRule, ...] = (
    # ---- interface names
    PatternRule(
        "nxos.subif_name",
        r"^interface (?P<v>(?P<parent>[A-Za-z][\w/-]*?\d)\.\d+)\s*$",
        "subif_name",
        block="interface",
        negative=("interface Ethernet1/5", "interface loopback0"),
    ),
    PatternRule(
        "nxos.svi_name",
        r"^interface (?P<v>Vlan\d+)\s*$",
        "svi_name",
        block="interface",
        negative=("interface nve1",),
    ),
    # ---- VLAN tags
    PatternRule(
        "nxos.encap_dot1q",
        _I + r"encapsulation dot1[Qq] (?P<v>\d+)\s*$",
        "vlan_tag",
        block="interface",
        role="encap_tag",
        anchored_keywords=("encapsulation dot1q",),
        negative=(*NEG_TAG, "  member vni 100100", "  vn-segment 100100"),
    ),
    PatternRule(
        "nxos.access_vlan",
        _I + r"switchport access vlan (?P<v>\d+)\s*$",
        "vlan_tag",
        block="interface",
        l2=True,
    ),
    PatternRule(
        "nxos.native_vlan",
        _I + r"switchport trunk native vlan (?P<v>\d+)\s*$",
        "vlan_tag",
        block="interface",
        role="native_vlan",
    ),
    PatternRule(
        "nxos.trunk_allowed",
        _I + r"switchport trunk allowed vlan (?:(?P<add>add) )?(?P<v>\d[\d,\-]*)\s*$",
        "vlan_list",
        block="interface",
        l2=True,
        list_style="nxos",
        negative=(
            "  switchport trunk allowed vlan all",
            "  switchport trunk allowed vlan none",
            "  switchport trunk allowed vlan remove 5",
            "  switchport trunk allowed vlan except 5",
        ),
    ),
    PatternRule(
        "nxos.trunk_allowed_kw",
        _I + r"switchport trunk allowed vlan (?P<kw>all|none)\s*$",
        "",
        block="interface",
        role="trunk_allowed",
    ),
    PatternRule(
        "nxos.mode_trunk",
        _I + r"switchport mode trunk\s*$",
        "",
        block="interface",
        role="mode_trunk",
    ),
    PatternRule(
        "nxos.mode_access",
        _I + r"switchport mode access\s*$",
        "",
        block="interface",
        role="mode_access",
    ),
    PatternRule(
        "nxos.vlan_def",
        r"^vlan (?P<v>\d[\d,\-]*)\s*$",
        "vlan_def",
        list_style="nxos",
        negative=(
            "spanning-tree vlan 1-4094 priority 61440",
            "  limit-resource vlan minimum 16 maximum 4094",
            "vlan configuration 100",
        ),
    ),
    PatternRule(
        "nxos.vlan_name",
        _I + r"name (?P<v>\S+)\s*$",
        "vlan_name",
        block="vlan",
    ),
    # ---- IPv4 on interfaces
    PatternRule(
        "nxos.ip",
        _I + r"ip address (?P<v>IPV4)(?P<mask>/\d{1,2})" + _TAIL,
        "ip_host",
        block="interface",
        negative=(
            "  ip address dhcp",
            "  ip unnumbered loopback0",
            "  ip router ospf UNDERLAY area 0.0.0.0",
        ),
    ),
    PatternRule(
        "nxos.dhcp",
        _I + r"ip address (?P<v>dhcp)\b",
        "dhcp",
        block="interface",
    ),
    PatternRule(
        "nxos.fhrp_vip",
        _I + r"ip (?P<v>IPV4)(?:[ \t]+secondary)?\s*$",
        "ip_host",
        block="interface",
        negative=("  ip forward", "  ip pim sparse-mode"),
    ),
    # ---- static routes / gateways (top level or inside vrf context)
    PatternRule(
        "nxos.route_default",
        r"^\s*ip route 0\.0\.0\.0/0 (?:[A-Za-z]\S*[ \t]+)?(?P<v>IPV4)",
        "ip_gateway",
        negative=("ip pim rp-address 169.254.255.100 group-list 224.0.0.0/4",),
    ),
    PatternRule(
        "nxos.route_dst",
        r"^\s*ip route (?!0\.0\.0\.0/0\b)(?P<v>IPV4)(?P<mask>/\d{1,2})\b",
        "ip_route_dst",
        negative=("  ip route 0.0.0.0/0 10.100.203.1",),
    ),
    PatternRule(
        "nxos.route_nexthop",
        r"^\s*ip route (?!0\.0\.0\.0/0\b)IPV4/\d{1,2} "
        r"(?:[A-Za-z]\S*[ \t]+)?(?P<v>IPV4)",
        "ip_gateway",
        flags=("nexthop",),
        negative=("  ip route 0.0.0.0/0 10.100.203.1",),
    ),
    # ---- services
    PatternRule(
        "nxos.name_server",
        r"^\s*ip name-server (?P<many>IPV4(?:[ \t]+IPV4)*)"
        r"(?:[ \t]+use-vrf[ \t]+\S+)?\s*$",
        "dns_server",
        anchored_keywords=("ip name-server",),
        negative=("  name servers", "name servers", "vlan 100"),
    ),
    PatternRule(
        "nxos.domain",
        r"^\s*ip domain-name (?P<v>[\w.-]+)(?:[ \t]+use-vrf[ \t]+\S+)?\s*$",
        "domain",
        negative=("no ip domain-lookup", "ip domain-lookup"),
    ),
    PatternRule(
        "nxos.domain_list",
        r"^\s*ip domain-list (?P<v>[\w.-]+)(?:[ \t]+use-vrf[ \t]+\S+)?\s*$",
        "search_list",
    ),
    PatternRule(
        "nxos.ntp_server",
        r"^ntp server (?P<v>IPV4)",
        "ntp_server",
        negative=("ntp source-interface mgmt0",),
    ),
    PatternRule(
        "nxos.log_server",
        r"^logging server (?P<v>IPV4)",
        LOG_SERVER,
        negative=("logging logfile messages 6", "  logging synchronous"),
    ),
    # ---- routing protocol identities
    PatternRule(
        "nxos.bgp_asn",
        r"^router bgp (?P<v>\d+)\s*$",
        "asn",
        negative=("evpn multisite border-gateway 65001",),
    ),
    PatternRule(
        "nxos.bgp_neighbor",
        _I + r"neighbor (?P<v>IPV4)\b",
        "peer_ip",
        block="router bgp",
    ),
    PatternRule(
        "nxos.bgp_remote_as",
        _I + r"(?:neighbor \S+ )?remote-as (?P<v>\d+)\s*$",
        "asn",
        block="router bgp",
        negative=("      rewrite-evpn-rt-asn",),
    ),
    PatternRule(
        "nxos.bgp_network",
        _I + r"network (?P<v>IPV4)(?P<mask>/\d{1,2})\b",
        "ip_route_dst",
        block="router bgp",
    ),
    PatternRule(
        "nxos.router_id",
        _I + r"router-id (?P<v>IPV4)\s*$",
        "router_id",
    ),
    # ---- free text in descriptions (cosmetic)
    PatternRule(
        "nxos.desc_cloud",
        _I + r"description\b.*?(?<![\w-])(?P<v>pnet\d+)(?![\w-])",
        "cloud_ref",
        flags=("cosmetic",),
        negative=("rmon event 1 log trap public description pnet0",),
    ),
    PatternRule(
        "nxos.desc_label",
        _I + r"description to pnet\d+: (?P<v>\S+)",
        "label_ref",
        flags=("cosmetic",),
    ),
    PatternRule(
        "nxos.desc_vlan",
        _I + r"description\b.*?\b(?i:vlan)[ \t]+(?P<v>\d+)\b",
        "vlan_mention",
        flags=("cosmetic",),
    ),
)

NXOS_SECRET_RULES: tuple[str, ...] = (
    r"^username \S+ password (?:\d+ )?(?P<s>\S+)",
    r"^snmp-server community (?P<s>\S+)",
    r"^snmp-server user \S+ (?:\S+ )?auth (?:md5|sha\S*) (?P<s>\S+)",
    r"^snmp-server user \S+ .*? priv (?:aes-128 |3des )?(?P<s>\S+)",
    r"^(?:tacacs|radius)-server (?:host \S+ .*?)?key (?:\d+ )?(?P<s>\S+)",
    r"^\s+password (?:\d+ )?(?P<s>\S+)\s*$",
)


@register
class NXOS(CiscoDialect):
    """NX-OS 9.x/10.x (Nexus 9000v)."""

    name = "nxos"
    templates = ("nxosv9k*", "nxosv*", "n9kv*", "titanium*")
    sniff = (
        r"^feature \S+",
        r"^vrf context \S+",
        r"^!Command: show running-config",
        r"^interface mgmt0\s*$",
        r"^copp profile ",
    )
    block_style = "indent"
    mask_form = "prefix"
    iface_aliases: ClassVar[dict[str, str]] = {
        "Eth": "Ethernet",
        "Lo": "loopback",
        "Vl": "Vlan",
        "Po": "port-channel",
        "mgmt": "mgmt",
        "nve": "nve",
        "Tunnel": "Tunnel",
    }
    rules = NXOS_RULES
    secret_rules = NXOS_SECRET_RULES
