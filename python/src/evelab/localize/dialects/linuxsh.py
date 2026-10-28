"""Docker / Linux startup scripts (design 6.2 ``flat``, 6.3, 6.4, 11.3).

Seen in the real labs (docker node configs and ``*_cfgs`` sidecars)::

    cat << EOF > /etc/resolv.conf        # heredoc block "heredoc:/etc/resolv.conf"
    nameserver 1.1.1.1
    search netlab.local yandy.dev
    EOF
    ip addr add 169.11.101.20/24 dev eth0 [|| true]
    ip route add default via 169.11.101.1 [|| true]
    ifconfig eth0 192.168.100.99 netmask 255.255.255.0
    route add default gw 192.168.100.1
    cat << EOF >> /etc/hosts             # "169.1.100.16 dc2-srv16" -> ip_host
    cat > /etc/resolv.conf << EOF

Also supported (common in Linux images): ``ip link add link P name P.N type
vlan id N`` / ``vconfig add P N`` (the only tag-bearing syntax, 6.3), ``nmcli``
``ipv4.addresses/gateway/dns`` and ``ip4/gw4``, netplan heredocs
(``addresses``, ``gateway4``, ``via``, ``to``, nameserver lists, ``search``)
and ``/etc/network/interfaces`` heredocs (``address``, ``netmask``,
``gateway``, ``dns-nameservers``, ``dns-search``).

Interface attribution: ``dev X``, ``ifconfig X``, the new link of ``ip link
add ... name X``, ``vconfig add P N`` (``P.N``), nmcli ``ifname X`` and the
current ``iface X`` stanza of an interfaces file open an ``interface`` block,
so ``eth0`` gets an ``IfaceInfo`` and its facts carry ``iface="eth0"``.
"""

from __future__ import annotations

import re

from ..model import Span
from . import register
from ._common import ContextRule, ContextRulesMixin, label_context_rules
from .base import PatternRule, RuleDialect
from .blocks import Layout, Line
from .generic import attach_iface_blocks

_L = r"^[ \t]*(?:sudo[ \t]+)?"
_IP = _L + r"ip[ \t]+(?:-4[ \t]+)?"
_QUAD = r"\d{1,3}(?:\.\d{1,3}){3}"
_NMCLI = _L + r"nmcli\b.*?[ \t]"
_NETPLAN = "heredoc:*netplan*"
_IFACES = "heredoc:*network/interfaces*"
_RESOLV = "heredoc:*resolv.conf*"
_DOMAIN_TOKEN = r"[A-Za-z0-9][\w-]*(?:\.[\w-]+)*"
_DOMAIN_V = rf"(?P<v>{_DOMAIN_TOKEN})"

_LINK_NAME_RE = re.compile(
    _IP + r"l(?:ink)?[ \t]+add\b.*?[ \t]name[ \t]+(?P<n>[\w.-]+)", re.MULTILINE
)
_DEV_RE = re.compile(r"[ \t]dev[ \t]+(?P<n>[\w.-]+)")
_IFCONFIG_RE = re.compile(_L + r"ifconfig[ \t]+(?P<n>[\w.:-]+)")
_VCONFIG_RE = re.compile(_L + r"vconfig[ \t]+add[ \t]+(?P<p>[\w.-]+)[ \t]+(?P<id>\d+)")
_IFNAME_RE = re.compile(r"[ \t]ifname[ \t]+(?P<n>[\w.-]+)")
_STANZA_RE = re.compile(r"^[ \t]*iface[ \t]+(?P<n>[\w.:-]+)[ \t]")
_STANZA_END_RE = re.compile(r"^[ \t]*(?:auto|allow-\S+|mapping|source)\b")


def _make_resolver():
    stanza: dict[str, str | None] = {"name": None}

    def resolve(text: str, line: Line) -> tuple[str, Span | None] | None:
        in_ifaces = any(
            b.kind.startswith("heredoc:") and "interfaces" in b.kind for b in line.chain
        )
        if in_ifaces:
            m = _STANZA_RE.match(text)
            if m:
                stanza["name"] = m.group("n")
                return m.group("n"), Span(
                    line.start + m.start("n"), line.start + m.end("n")
                )
            if _STANZA_END_RE.match(text):
                stanza["name"] = None
            return (stanza["name"], None) if stanza["name"] else None
        stanza["name"] = None
        for rx in (_LINK_NAME_RE, _IFCONFIG_RE, _IFNAME_RE, _DEV_RE):
            m = rx.search(text)
            if m:
                return m.group("n"), Span(
                    line.start + m.start("n"), line.start + m.end("n")
                )
        m = _VCONFIG_RE.match(text)
        if m:
            return f"{m.group('p')}.{m.group('id')}", None
        return None

    return resolve


@register
class LinuxSh(ContextRulesMixin, RuleDialect):
    name = "linuxsh"
    templates = ("docker*", "linux*", "eve-gui-server*", "eve-server*")
    sniff = (
        r"^[ \t]*(?:sudo[ \t]+)?ip[ \t]+(?:-4[ \t]+)?(?:a|addr|address|r|route|link)"
        r"[ \t]+(?:add|replace)\b",
        r"^[ \t]*nameserver[ \t]+\d",
        r"^[ \t]*(?:sudo[ \t]+)?ifconfig[ \t]+\S+[ \t]+\d",
        r"/etc/resolv\.conf",
    )
    block_style = "flat"
    mask_form = "mixed"
    # parent of a VLAN link: "ip link add link eth0 ..." / "vconfig add eth0 100"
    block_parent_re = (
        r"(?:[ \t]link[ \t]+(?!add\b)|\bvconfig[ \t]+add[ \t]+)(?P<parent>[\w.-]+)"
    )
    rules = (
        # ---- addresses
        PatternRule(
            "linuxsh.ip_addr",
            _IP + r"a(?:ddr(?:ess)?)?[ \t]+(?:add|replace|change)[ \t]+"
            r"(?:local[ \t]+)?(?P<v>IPV4)(?P<mask>/\d{1,2})?(?![\w./])",
            "ip_host",
            negative=("ip addr show dev eth0", "ip address flush dev eth0"),
        ),
        PatternRule(
            "linuxsh.ifconfig_prefix",
            _L + r"ifconfig[ \t]+\S+[ \t]+(?:inet[ \t]+)?(?P<v>IPV4)"
            r"(?P<mask>/\d{1,2})(?![\d.])",
            "ip_host",
        ),
        PatternRule(
            "linuxsh.ifconfig_netmask",
            _L + r"ifconfig[ \t]+\S+[ \t]+(?:inet[ \t]+)?(?P<v>IPV4)"
            rf"(?:[ \t]+netmask[ \t]+(?P<mask>{_QUAD}))?(?![\w./])",
            "ip_host",
            negative=("ifconfig eth0 up",),
        ),
        # ---- routes
        PatternRule(
            "linuxsh.route_gw",
            _L + r"route[ \t]+add[ \t]+(?:default|-net[ \t]+\S+(?:[ \t]+netmask"
            r"[ \t]+\S+)?|-host[ \t]+\S+)[ \t]+gw[ \t]+(?P<v>IPV4)",
            "ip_gateway",
        ),
        PatternRule(
            "linuxsh.route_net_prefix",
            _L + r"route[ \t]+add[ \t]+-net[ \t]+(?P<v>IPV4)(?P<mask>/\d{1,2})",
            "ip_route_dst",
        ),
        PatternRule(
            "linuxsh.route_net_netmask",
            _L + r"route[ \t]+add[ \t]+-net[ \t]+(?P<v>IPV4)"
            rf"(?:[ \t]+netmask[ \t]+(?P<mask>{_QUAD}))?(?![\w./])",
            "ip_route_dst",
        ),
        PatternRule(
            "linuxsh.ip_route_gw",
            _IP + r"r(?:o(?:ute)?)?[ \t]+(?:add|replace|change|append)[ \t]+\S+"
            r"(?:[ \t]+\S+)*?[ \t]+via[ \t]+(?P<v>IPV4)",
            "ip_gateway",
            negative=("ip route show via 10.0.0.1",),
        ),
        PatternRule(
            "linuxsh.ip_route_dst",
            _IP + r"r(?:o(?:ute)?)?[ \t]+(?:add|replace|change|append)[ \t]+"
            r"(?P<v>IPV4)(?P<mask>/\d{1,2})?(?![\w./])",
            "ip_route_dst",
        ),
        # ---- DNS (resolv.conf, echo into resolv.conf)
        PatternRule(
            "linuxsh.nameserver",
            r"(?:^[ \t]*|\becho[ \t]+(?:-e[ \t]+)?[\"']?)nameserver[ \t]+(?P<v>IPV4)",
            "dns_server",
            negative=("# nameserver list follows",),
        ),
        PatternRule(
            "linuxsh.resolv_domain",
            rf"^[ \t]*domain[ \t]+(?P<v>{_DOMAIN_TOKEN})[ \t]*$",
            "domain",
            block=_RESOLV,
        ),
        # ---- /etc/hosts
        PatternRule(
            "linuxsh.hosts",
            r"^[ \t]*(?P<v>IPV4)[ \t]+[A-Za-z]",
            "ip_host",
            block="heredoc:*hosts",
        ),
        PatternRule(
            "linuxsh.hosts_echo",
            r"\becho[ \t]+[\"']?(?P<v>IPV4)[ \t]+\S.*>[ \t]*/etc/hosts\b",
            "ip_host",
        ),
        # ---- VLAN links (the only tag-bearing syntax, 6.3)
        PatternRule(
            "linuxsh.vlan_link_name",
            _IP + r"l(?:ink)?[ \t]+add\b(?=.*[ \t]type[ \t]+vlan\b).*?[ \t]name"
            r"[ \t]+(?P<v>[\w.-]+)",
            "subif_name",
            negative=("ip link add br0 type bridge", "ip link set eth0.100 up"),
        ),
        PatternRule(
            "linuxsh.vlan_link_id",
            _IP + r"l(?:ink)?[ \t]+add\b.*?[ \t]type[ \t]+vlan\b.*?[ \t]id[ \t]+"
            r"(?P<v>\d{1,4})\b",
            "vlan_tag",
            role="encap_tag",
            negative=("ip link set eth0 up", "ip link add vx0 type vxlan id 100"),
        ),
        PatternRule(
            "linuxsh.vconfig",
            _L + r"vconfig[ \t]+add[ \t]+\S+[ \t]+(?P<v>\d{1,4})\b",
            "vlan_tag",
            role="encap_tag",
        ),
        PatternRule(
            "linuxsh.nmcli_vlan",
            _L + r"nmcli\b(?=.*[ \t]type[ \t]+vlan\b).*?[ \t](?:id|vlan\.id)[ \t]+"
            r"(?P<v>\d{1,4})\b",
            "vlan_tag",
            role="encap_tag",
        ),
        # ---- nmcli
        PatternRule(
            "linuxsh.nmcli_addr",
            _NMCLI + r"(?:ipv4\.addresses|ip4)[ \t]+[\"']?(?P<v>IPV4)"
            r"(?P<mask>/\d{1,2})?",
            "ip_host",
        ),
        PatternRule(
            "linuxsh.nmcli_gw",
            _NMCLI + r"(?:ipv4\.gateway|gw4)[ \t]+[\"']?(?P<v>IPV4)",
            "ip_gateway",
        ),
        PatternRule(
            "linuxsh.nmcli_dns",
            _NMCLI + r"ipv4\.dns[ \t]+[\"']?(?P<many>IPV4(?:[ \t,]+IPV4)*)",
            "dns_server",
        ),
        # ---- netplan heredoc
        PatternRule(
            "linuxsh.netplan_addr_list",
            r"^[ \t]*addresses:[ \t]*\[(?P<many>[^\]]*/[^\]]*)\]",
            "ip_host",
            block=_NETPLAN,
        ),
        PatternRule(
            "linuxsh.netplan_addr_item",
            r"^[ \t]*-[ \t]*[\"']?(?P<v>IPV4)(?P<mask>/\d{1,2})[\"']?[ \t]*$",
            "ip_host",
            block=_NETPLAN,
        ),
        PatternRule(
            "linuxsh.netplan_dns_list",
            r"^[ \t]*addresses:[ \t]*\[(?P<many>[^\]/]*)\]",
            "dns_server",
            block=_NETPLAN,
        ),
        PatternRule(
            "linuxsh.netplan_dns_item",
            r"^[ \t]*-[ \t]*[\"']?(?P<v>IPV4)[\"']?[ \t]*$",
            "dns_server",
            block=_NETPLAN,
        ),
        PatternRule(
            "linuxsh.netplan_gw",
            r"^[ \t]*(?:-[ \t]*)?(?:gateway4|via):[ \t]*[\"']?(?P<v>IPV4)",
            "ip_gateway",
            block=_NETPLAN,
        ),
        PatternRule(
            "linuxsh.netplan_to",
            r"^[ \t]*(?:-[ \t]*)?to:[ \t]*[\"']?(?P<v>IPV4)(?P<mask>/\d{1,2})",
            "ip_route_dst",
            block=_NETPLAN,
        ),
        # ---- /etc/network/interfaces heredoc
        PatternRule(
            "linuxsh.ifaces_address",
            r"^[ \t]*address[ \t]+(?P<v>IPV4)(?P<mask>/\d{1,2})?(?![\w./])",
            "ip_host",
            block=_IFACES,
        ),
        PatternRule(
            "linuxsh.ifaces_netmask",
            rf"^[ \t]*netmask[ \t]+(?P<v>{_QUAD})[ \t]*$",
            "mask",
            block=_IFACES,
        ),
        PatternRule(
            "linuxsh.ifaces_gateway",
            r"^[ \t]*gateway[ \t]+(?P<v>IPV4)",
            "ip_gateway",
            block=_IFACES,
        ),
        PatternRule(
            "linuxsh.ifaces_dns",
            r"^[ \t]*dns-nameservers[ \t]+(?P<many>.+)",
            "dns_server",
            block=_IFACES,
        ),
    )
    context_rules = (
        ContextRule(
            "linuxsh.search",
            r"^[ \t]*search[ \t]+(?P<ctx>.+?)[ \t]*$",
            _DOMAIN_V,
            "search_list",
        ),
        ContextRule(
            "linuxsh.netplan_search",
            r"^[ \t]*search:[ \t]*\[(?P<ctx>[^\]]*)\]",
            _DOMAIN_V,
            "search_list",
            block=_NETPLAN,
        ),
        ContextRule(
            "linuxsh.ifaces_search",
            r"^[ \t]*dns-search[ \t]+(?P<ctx>.+?)[ \t]*$",
            _DOMAIN_V,
            "search_list",
            block=_IFACES,
        ),
        *label_context_rules("linuxsh", (("comment", r"^[ \t]*#(?P<ctx>.*)$"),)),
    )

    def _layout(self, text: str) -> Layout:
        return attach_iface_blocks(super()._layout(text), _make_resolver())
