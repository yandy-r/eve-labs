"""Cisco IOS dialect: IOL L3, IOL L2, vIOS, IOSv-L2 (design 6.1-6.5, 11.3).

Data-only ``RuleDialect`` plus two small overrides:

* ``_layout`` masks ``banner <kind> ^C ... ^C`` regions (their text is free prose
  at column 0 and must never produce facts or open blocks);
* ``render`` validates ``log_server`` values as IPv4 (``base.IPV4_KINDS`` is
  frozen and predates the kind).

``ios_rules(prefix)`` builds the rule table so ``iosxe`` reuses it with its own
rule-id prefix.  Facts produced (rule ids ``<prefix>.<name>``):

=================  ======================================================
kind               syntax
=================  ======================================================
subif_name         ``interface Gi16.2`` (header token, parent = ``Gi16``)
svi_name           ``interface Vlan203``
vlan_tag           ``encapsulation dot1Q N``, ``switchport access vlan N``,
                   ``switchport trunk native vlan N``
vlan_list          ``switchport trunk allowed vlan [add] LIST``
vlan_def           top-level ``vlan N`` / ``vlan LIST``
vlan_name          ``name X`` inside a ``vlan`` block
ip_host            interface ``ip address A M [secondary]``, HSRP/VRRP VIPs
dhcp               ``ip address dhcp``
ip_gateway         default route next hop (``ip route [vrf X] 0.0.0.0 0.0.0.0``),
                   ``ip default-gateway``; flag ``nexthop`` = next hop of a
                   non-default static route
ip_route_dst       static route destination (+ mask), BGP ``network A mask M``
dns_server         ``ip name-server [vrf X] A [B ...]``
domain             ``ip domain-name X`` / ``ip domain name X``
search_list        ``ip domain-list X`` / ``ip domain list X``
ntp_server         ``ntp server [vrf X] A``
log_server         ``logging host A`` / ``logging A``
peer_ip            BGP ``neighbor A ...``, ``tunnel destination A``
asn                ``router bgp N``, ``neighbor X remote-as N``
router_id          ``bgp router-id A`` / ``router-id A`` / ``eigrp router-id A``
cloud_ref          ``pnetN`` in a description (cosmetic)
label_ref          label-like words anywhere in a description (cosmetic;
                   ``ios_context_rules``: ``to pnet0: EVE-MGMT-204``,
                   ``EVE-INET-201 (ISP1)``)
vlan_mention       ``VLAN N`` in a description (cosmetic)
secret             enable/username/snmp community/key-string/PSK/NHRP/... values
=================  ======================================================

Never facts (negative examples on the rules): ``rd 2:2``, ``route-target``,
``spanning-tree vlan 1-4094 ...``, ISIS ``net 49.0000...``, ``switchport trunk
encapsulation dot1q``, ``tunnel key 1001``, ``name servers`` outside DNS rules.
Unclassified IPv4 literals (``ip helper-address``, ``ip host``, prefix-lists,
ACLs, OSPF ``network``, NHRP maps) are left to discovery's literal scan.
"""

from __future__ import annotations

import re
from dataclasses import replace
from ipaddress import AddressValueError, IPv4Address

from ..errors import LocalizeError
from ..model import Fact, TextEdit
from . import register
from ._common import LABEL_TOKEN, ContextRule, ContextRulesMixin
from .base import PatternRule, RenderCtx, RuleDialect
from .blocks import Layout

# Syslog / logging-host targets (model.CORE_FACT_KINDS, added in T9).
LOG_SERVER = "log_server"

# Interface sub-command prefix (IOS uses one space; tolerate more).
_I = r"^\s+"


# --------------------------------------------------------------------------- #
# banners
# --------------------------------------------------------------------------- #

_BANNER_RE = re.compile(r"^banner[ \t]+\S+[ \t]+(?P<d>\^C|\S)", re.MULTILINE)


def mask_banners(layout: Layout) -> Layout:
    """Mark ``banner X <d> ... <d>`` lines as skipped (``skip="banner"``).

    The delimiter is ``^C`` (two characters, as IOS prints it) or the first
    character after the banner kind.  An unterminated banner is left alone
    (masking the rest of the config would hide real facts).
    """
    text = layout.text
    lines = list(layout.lines)
    masked: set[int] = set()
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = None if ln.skip else _BANNER_RE.match(text, ln.start, ln.end)
        if m is None:
            i += 1
            continue
        delim = m.group("d")
        j = i
        if text.find(delim, m.end(), ln.end) == -1:
            j = i + 1
            while j < len(lines) and text.find(delim, lines[j].start, lines[j].end) == (
                -1
            ):
                j += 1
            if j >= len(lines):
                i += 1
                continue
        for k in range(i, j + 1):
            lines[k] = replace(lines[k], chain=(), skip="banner")
            masked.add(lines[k].start)
        i = j + 1
    if not masked:
        return layout
    blocks = [b for b in layout.blocks if b.start not in masked]
    return Layout(text, layout.style, lines, blocks)


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #

NEG_TAG = (
    " rd 2:2",
    " rd 203:203",
    "  route-target export 1001:1001",
    " switchport trunk encapsulation dot1q",
    " tunnel key 1001",
    " encapsulation dot1Q 100 second-dot1q 200",
    "spanning-tree vlan 1-4094 priority 61440",
)


def ios_rules(p: str) -> tuple[PatternRule, ...]:
    """The IOS / IOS-XE rule table with rule ids ``<p>.<name>``."""
    return (
        # ---- interface names (tag-bearing headers)
        PatternRule(
            f"{p}.subif_name",
            r"^interface (?P<v>(?P<parent>[A-Za-z][\w/-]*?\d)\.\d+)"
            r"(?:[ \t]+(?:point-to-point|multipoint))?\s*$",
            "subif_name",
            block="interface",
            negative=("interface GigabitEthernet16", "interface Loopback0"),
        ),
        PatternRule(
            f"{p}.svi_name",
            r"^interface (?P<v>Vlan\d+)\s*$",
            "svi_name",
            block="interface",
            negative=("interface Vlan", "interface GigabitEthernet0/0"),
        ),
        # ---- VLAN tags
        PatternRule(
            f"{p}.encap_dot1q",
            _I + r"encapsulation dot1[Qq] (?P<v>\d+)(?:[ \t]+native)?\s*$",
            "vlan_tag",
            block="interface",
            role="encap_tag",
            anchored_keywords=("encapsulation dot1Q",),
            negative=NEG_TAG,
        ),
        PatternRule(
            f"{p}.access_vlan",
            _I + r"switchport access vlan (?P<v>\d+)\s*$",
            "vlan_tag",
            block="interface",
            l2=True,
            negative=(" switchport voice vlan 20", " switchport mode access"),
        ),
        PatternRule(
            f"{p}.native_vlan",
            _I + r"switchport trunk native vlan (?P<v>\d+)\s*$",
            "vlan_tag",
            block="interface",
            role="native_vlan",
            negative=(" switchport trunk native vlan tag",),
        ),
        PatternRule(
            f"{p}.trunk_allowed",
            _I + r"switchport trunk allowed vlan (?:(?P<add>add) )?"
            r"(?P<v>\d[\d,\-]*)\s*$",
            "vlan_list",
            block="interface",
            l2=True,
            list_style="ios",
            negative=(
                " switchport trunk allowed vlan all",
                " switchport trunk allowed vlan none",
                " switchport trunk allowed vlan remove 5",
                " switchport trunk allowed vlan except 5",
            ),
        ),
        PatternRule(
            f"{p}.trunk_allowed_kw",
            _I + r"switchport trunk allowed vlan (?P<kw>all|none)\s*$",
            "",
            block="interface",
            role="trunk_allowed",
        ),
        PatternRule(
            f"{p}.mode_trunk",
            _I + r"switchport mode trunk\s*$",
            "",
            block="interface",
            role="mode_trunk",
        ),
        PatternRule(
            f"{p}.mode_access",
            _I + r"switchport mode access\s*$",
            "",
            block="interface",
            role="mode_access",
        ),
        PatternRule(
            f"{p}.vlan_def",
            r"^vlan (?P<v>\d[\d,\-]*)\s*$",
            "vlan_def",
            list_style="ios",
            negative=(
                "spanning-tree vlan 1-4094 priority 61440",
                "vlan internal allocation policy ascending",
                " switchport access vlan 2",
                "vlan configuration 100",
            ),
        ),
        PatternRule(
            f"{p}.vlan_name",
            _I + r"name (?P<v>\S+)\s*$",
            "vlan_name",
            block="vlan",
        ),
        # ---- IPv4 on interfaces
        PatternRule(
            f"{p}.ip",
            _I + r"ip address (?P<v>IPV4) (?P<mask>MASK)(?:[ \t]+secondary)?\s*$",
            "ip_host",
            block="interface",
            negative=(" ip address dhcp", " no ip address", " ip addresses 1.1.1.1"),
        ),
        PatternRule(
            f"{p}.dhcp",
            _I + r"ip address (?P<v>dhcp)\b",
            "dhcp",
            block="interface",
            negative=(" ip dhcp pool VLAN50", " ip address 10.1.1.1 255.0.0.0"),
        ),
        PatternRule(
            f"{p}.fhrp_vip",
            _I
            + r"(?:standby(?: \d+)?|vrrp \d+) ip (?P<v>IPV4)(?:[ \t]+secondary)?\s*$",
            "ip_host",
            block="interface",
            negative=(" standby 10 priority 110", " standby version 2"),
        ),
        PatternRule(
            f"{p}.tunnel_dst",
            _I + r"tunnel destination (?P<v>IPV4)\s*$",
            "peer_ip",
            block="interface",
            negative=(" tunnel source GigabitEthernet3", " tunnel key 1001"),
        ),
        # ---- static routes / gateways
        PatternRule(
            f"{p}.route_default",
            r"^ip route (?:vrf \S+ )?0\.0\.0\.0 0\.0\.0\.0 "
            r"(?:[A-Za-z]\S*[ \t]+)?(?P<v>IPV4)",
            "ip_gateway",
            negative=("ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 Null0",),
        ),
        PatternRule(
            f"{p}.route_dst",
            r"^ip route (?:vrf \S+ )?(?!0\.0\.0\.0 0\.0\.0\.0\b)"
            r"(?P<v>IPV4) (?P<mask>MASK)\b",
            "ip_route_dst",
            negative=("ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 10.100.203.1",),
        ),
        PatternRule(
            f"{p}.route_nexthop",
            r"^ip route (?:vrf \S+ )?(?!0\.0\.0\.0 0\.0\.0\.0\b)IPV4 MASK "
            r"(?:[A-Za-z]\S*[ \t]+)?(?P<v>IPV4)",
            "ip_gateway",
            flags=("nexthop",),
            negative=("ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 10.100.203.1",),
        ),
        PatternRule(
            f"{p}.default_gateway",
            r"^ip default-gateway (?P<v>IPV4)\s*$",
            "ip_gateway",
        ),
        # ---- services (anchored keywords only)
        PatternRule(
            f"{p}.name_server",
            r"^ip name-server (?:vrf \S+ )?(?P<many>IPV4(?:[ \t]+IPV4)*)\s*$",
            "dns_server",
            anchored_keywords=("ip name-server",),
            negative=("name servers", " name servers", "ip domain-lookup"),
        ),
        PatternRule(
            f"{p}.domain",
            r"^ip domain[- ]name (?:vrf \S+ )?(?P<v>[\w.-]+)\s*$",
            "domain",
            negative=("no ip domain-lookup", "no ip domain lookup"),
        ),
        PatternRule(
            f"{p}.domain_list",
            r"^ip domain[- ]list (?:vrf \S+ )?(?P<v>[\w.-]+)\s*$",
            "search_list",
        ),
        PatternRule(
            f"{p}.ntp_server",
            r"^ntp server (?:vrf \S+ )?(?:ip )?(?P<v>IPV4)",
            "ntp_server",
            negative=("ntp source Loopback0", "ntp master 1"),
        ),
        PatternRule(
            f"{p}.log_server",
            r"^logging (?:host )?(?:vrf \S+ )?(?P<v>IPV4)",
            LOG_SERVER,
            negative=("logging synchronous", " logging synchronous", "logging enable"),
        ),
        # ---- routing protocol identities
        PatternRule(
            f"{p}.bgp_asn",
            r"^router bgp (?P<v>\d+)\s*$",
            "asn",
        ),
        PatternRule(
            f"{p}.bgp_neighbor",
            _I + r"neighbor (?P<v>IPV4)\b",
            "peer_ip",
            block="router bgp",
            negative=(" neighbor iBGP remote-as 65000",),
        ),
        PatternRule(
            f"{p}.bgp_remote_as",
            _I + r"neighbor \S+ remote-as (?P<v>\d+)\s*$",
            "asn",
            block="router bgp",
        ),
        PatternRule(
            f"{p}.bgp_template_as",
            r"^\s{2,}remote-as (?P<v>\d+)\s*$",
            "asn",
            block="router bgp",
        ),
        PatternRule(
            f"{p}.bgp_network",
            _I + r"network (?P<v>IPV4)(?: mask (?P<mask>MASK))?\s*$",
            "ip_route_dst",
            block="router bgp",
            negative=(" network 10.40.199.0 0.0.0.255 area 0",),
        ),
        PatternRule(
            f"{p}.router_id",
            r"^\s*(?:bgp |eigrp )?router-id (?P<v>IPV4)\s*$",
            "router_id",
            negative=(" router-id Loopback0", "mpls ldp router-id Loopback0"),
        ),
        # ---- free text in descriptions (cosmetic)
        PatternRule(
            f"{p}.desc_cloud",
            _I + r"description\b.*?(?<![\w-])(?P<v>pnet\d+)(?![\w-])",
            "cloud_ref",
            flags=("cosmetic",),
            negative=("rmon event 1 log trap public description pnet0",),
        ),
        PatternRule(
            f"{p}.desc_vlan",
            _I + r"description\b.*?\b(?i:vlan)[ \t]+(?P<v>\d+)\b",
            "vlan_mention",
            flags=("cosmetic",),
            negative=(" description users",),
        ),
    )


def ios_context_rules(p: str) -> tuple[ContextRule, ...]:
    """Free-text rules: every label-like word of a ``description`` is a
    ``label_ref`` (``to pnet0: EVE-MGMT-204``, ``EVE-INET-201 (ISP1)``); the
    planner only rewrites the ones equal to a segment's old label."""
    return (
        ContextRule(
            f"{p}.desc_label",
            _I + r"description (?P<ctx>.*)$",
            LABEL_TOKEN,
            "label_ref",
            flags=("cosmetic",),
        ),
    )


IOS_SECRET_RULES: tuple[str, ...] = (
    r"^enable (?:secret|password)(?: level \d+)? (?:\d+ )?(?P<s>\S+)",
    r"^username \S+ (?:.*? )?(?:secret|password) (?:\d+ )?(?P<s>\S+)",
    r"^snmp-server community (?P<s>\S+)",
    r"^\s+key-string (?:\d+ )?(?P<s>\S+)",
    r"^\s+pre-shared-key (?:address \S+(?: \S+)? )?key (?:\d+ )?(?P<s>\S+)",
    r"^crypto isakmp key (?:\d+ )?(?P<s>\S+)",
    r"^\s+ip nhrp authentication (?P<s>\S+)",
    r"^\s+neighbor \S+ password (?:\d+ )?(?P<s>\S+)",
    r"^\s+ip ospf (?:authentication-key|message-digest-key \d+ md5) "
    r"(?:\d+ )?(?P<s>\S+)",
    r"^(?:tacacs|radius)-server (?:host \S+ .*?)?key (?:\d+ )?(?P<s>\S+)",
    r"^\s+password (?:\d+ )?(?P<s>\S+)\s*$",
)

IOS_ALIASES: dict[str, str] = {
    "Gi": "GigabitEthernet",
    "Fa": "FastEthernet",
    "Te": "TenGigabitEthernet",
    "Tw": "TwentyFiveGigE",
    "Hu": "HundredGigE",
    "Et": "Ethernet",
    "Lo": "Loopback",
    "Vl": "Vlan",
    "Po": "Port-channel",
    "Tu": "Tunnel",
    "Se": "Serial",
    "BDI": "BDI",
    "Nv": "nve",
}


class CiscoDialect(RuleDialect):
    """Shared behaviour for the Cisco dialects (banners, ``log_server``)."""

    def _layout(self, text: str) -> Layout:
        return mask_banners(super()._layout(text))

    def render(self, fact: Fact, new: str, ctx: RenderCtx) -> list[TextEdit]:
        if fact.kind == LOG_SERVER and new != fact.value:
            try:
                IPv4Address(new)
            except AddressValueError as exc:
                raise LocalizeError(
                    f"{LOG_SERVER}: {new!r} is not an IPv4 address", code="BAD_VALUE"
                ) from exc
        return super().render(fact, new, ctx)

    #: ``vlan N`` / ``name X``: IOS and NX-OS accept at most 32 characters and
    #: no blanks (the name is one unquoted token).
    vlan_name_max = 32

    def label_problem(self, fact: Fact, new: str, text: str) -> str | None:
        """Label-propagation hook (``scenarios.labels``): why ``new`` cannot
        replace the label held by ``fact``, or None."""
        if fact.kind == "vlan_name":
            if len(new) > self.vlan_name_max:
                return (
                    f"{self.name} vlan name {new!r} is longer than "
                    f"{self.vlan_name_max} characters"
                )
            if any(c.isspace() for c in new):
                return f"{self.name} vlan name {new!r} contains blanks"
        return None


@register
class IOS(ContextRulesMixin, CiscoDialect):
    """IOS 12/15: IOL L3/L2, vIOS, IOSv-L2 (dotted masks, 1-space indent)."""

    name = "ios"
    templates = (
        "iol",
        "vios",
        "viosl2",
        "i86bi*",
        "vios-*",
        "viosl2-*",
        "iosv*",
        "c7200*",
        "c3725*",
    )
    sniff = (
        r"^version 1[0-5]\.\d+\s*$",
        r"^boot-start-marker\s*$",
        r"^service timestamps ",
    )
    block_style = "indent"
    mask_form = "dotted"
    iface_aliases = IOS_ALIASES
    rules = ios_rules("ios")
    context_rules = ios_context_rules("ios")
    secret_rules = IOS_SECRET_RULES
