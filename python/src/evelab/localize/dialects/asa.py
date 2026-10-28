"""Cisco ASA / ASAv dialect (design 6, 11.3).

Running-config text as saved by the ASA: a leading empty line, ``: ...``
header comments, ``ip address A M `` with a trailing space, single-line
``route <nameif> NET MASK GW 1`` statements and ``Cryptochecksum:`` (which goes
stale after any edit: reported as a note, never rewritten).

Tag-bearing syntax is only ``interface X.N`` + `` vlan N`` (6.3).  IPsec peers
used as object names (``tunnel-group 172.173.204.134``, ``group-policy ...``)
are ``peer_ip`` facts flagged ``object_name``: only the ``azure_s2s`` scenario
claims them (exact match).  Static routes support stanza (line) deletion.
"""

from __future__ import annotations

from typing import ClassVar

from ..model import ConfigText, Fact, Span
from . import register
from ._common import (
    ContextRule,
    ContextRulesMixin,
    StanzaDeleteMixin,
    label_context_rules,
    line_span,
)
from .base import ParsedConfig, PatternRule, RuleDialect
from .blocks import DEFAULT_INDENT_STARTS

_OBJ = ("object_name",)
ROUTE_RULES = frozenset({"asa.route_dst", "asa.route_gw"})


@register
class ASA(ContextRulesMixin, StanzaDeleteMixin, RuleDialect):
    name = "asa"
    templates = ("asav*", "asa*")
    sniff = (r"^ASA Version \S+", r"^Cryptochecksum:[0-9a-f]+", r"^: Saved\b")
    block_style = "indent"
    mask_form = "dotted"
    iface_aliases: ClassVar[dict[str, str]] = {
        "Gi": "GigabitEthernet",
        "Te": "TenGigabitEthernet",
        "Mgmt": "Management",
        "Ma": "Management",
        "Po": "Port-channel",
        "Re": "Redundant",
        "Tu": "Tunnel",
    }
    block_starts = (
        *DEFAULT_INDENT_STARTS,
        ("dns server-group", r"dns[ \t]+server-group[ \t]+(?P<name>\S+)"),
        ("tunnel-group", r"tunnel-group[ \t]+(?P<name>\S+)\b.*"),
        ("group-policy", r"group-policy[ \t]+(?P<name>\S+)\b.*"),
    )
    priority = 10  # beats the IOS family on an "interface ... / hostname" tie

    rules = (
        PatternRule(
            "asa.subif_name",
            r"^interface (?P<v>(?P<parent>\S+?)\.\d+)\s*$",
            "subif_name",
            block="interface",
            negative=("interface GigabitEthernet0/1", "interface Tunnel1"),
        ),
        PatternRule(
            "asa.vlan",
            r"^ vlan (?P<v>\d+)\s*$",
            "vlan_tag",
            block="interface",
            role="encap_tag",
            anchored_keywords=("vlan",),
            negative=(
                "vlan 100",
                " vlan-id 2",
                "  rd 2:2",
                " security-level 100",
                "tunnel-group 169.254.0.2 type ipsec-l2l",
            ),
        ),
        PatternRule(
            "asa.ip",
            r"^ ip address (?P<v>IPV4) (?P<mask>MASK)(?: standby IPV4)?\s*$",
            "ip_host",
            block="interface",
            negative=(
                " no ip address",
                " ip address dhcp setroute",
                "failover interface ip FO 192.168.1.1 255.255.255.252 "
                "standby 192.168.1.2",
            ),
        ),
        PatternRule(
            "asa.ip_standby",
            r"^ ip address IPV4 MASK standby (?P<v>IPV4)\s*$",
            "ip_host",
            block="interface",
        ),
        PatternRule(
            "asa.dhcp",
            r"^ ip address (?P<v>dhcp)\b",
            "dhcp",
            block="interface",
        ),
        PatternRule(
            "asa.tunnel_dst",
            r"^ tunnel destination (?P<v>IPV4)\s*$",
            "peer_ip",
            block="interface",
        ),
        PatternRule(
            "asa.route_dst",
            r"^route \S+ (?!0\.0\.0\.0 0\.0\.0\.0 )(?P<v>IPV4) (?P<mask>MASK) IPV4\b",
            "ip_route_dst",
            block="top",
            negative=("route outside 0.0.0.0 0.0.0.0 10.100.105.1 1",),
        ),
        PatternRule(
            "asa.route_gw",
            r"^route \S+ IPV4 MASK (?P<v>IPV4)\b",
            "ip_gateway",
            block="top",
            negative=("router bgp 65101", "route-map RM permit 10"),
        ),
        PatternRule("asa.bgp_asn", r"^router bgp (?P<v>\d+)\s*$", "asn"),
        PatternRule(
            "asa.bgp_router_id",
            r"^\s+bgp router-id (?P<v>IPV4)\s*$",
            "router_id",
            block="router bgp",
        ),
        PatternRule(
            "asa.bgp_peer",
            r"^\s+neighbor (?P<v>IPV4) ",
            "peer_ip",
            block="router bgp",
        ),
        PatternRule(
            "asa.bgp_remote_as",
            r"^\s+neighbor IPV4 remote-as (?P<v>\d+)\s*$",
            "asn",
            block="router bgp",
        ),
        PatternRule(
            "asa.tunnel_group",
            r"^tunnel-group (?P<v>IPV4) ",
            "peer_ip",
            flags=_OBJ,
        ),
        PatternRule(
            "asa.tunnel_group_map",
            r"^tunnel-group-map default-group (?P<v>IPV4)\s*$",
            "peer_ip",
            flags=_OBJ,
        ),
        PatternRule(
            "asa.group_policy",
            r"^group-policy (?P<v>IPV4) ",
            "peer_ip",
            flags=_OBJ,
        ),
        PatternRule(
            "asa.default_group_policy",
            r"^\s+default-group-policy (?P<v>IPV4)\s*$",
            "peer_ip",
            flags=_OBJ,
        ),
        PatternRule(
            "asa.dns",
            r"^\s+name-server (?P<many>IPV4(?: IPV4)*)(?: [A-Za-z]\S*)?\s*$",
            "dns_server",
            block="dns server-group",
            negative=(" name servers",),
        ),
        PatternRule(
            "asa.domain",
            r"^\s*domain-name (?P<v>[A-Za-z0-9][\w.-]*)\s*$",
            "domain",
            negative=(
                "user-identity default-domain LOCAL",
                "xlate per-session deny udp any4 any4 eq domain",
            ),
        ),
        PatternRule(
            "asa.ntp",
            r"^ntp server (?P<v>IPV4)\b",
            "ntp_server",
            block="top",
        ),
    )
    context_rules: tuple[ContextRule, ...] = label_context_rules(
        "asa", (("desc", r"^\s+description (?P<ctx>.+?)\s*$"),), block="interface"
    )
    secret_rules = (
        r"^enable password (?P<s>\S+)",
        r"^username \S+ password (?P<s>\S+)",
        r"\bpre-shared-key (?P<s>\S+)\s*$",
    )

    def parse(self, ct: ConfigText) -> ParsedConfig:
        parsed = super().parse(ct)
        if any(ln.startswith("Cryptochecksum:") for ln in ct.text.splitlines()):
            parsed.notes.append(
                "Cryptochecksum present: it goes stale after edits "
                "(the ASA recomputes it on 'write memory')"
            )
        return parsed

    def stanza_span(self, fact: Fact, text: str) -> Span | None:
        """A static route is one line: delete it with its terminator."""
        if fact.rule not in ROUTE_RULES:
            return None
        return line_span(text, fact.span.start)
