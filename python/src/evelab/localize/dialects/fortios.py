"""FortiOS (FortiGate) dialect (design 6, 11.3).

``config X`` / ``edit "y"`` / ``next`` / ``end`` blocks (``blocks.fortios``).
Interfaces are the ``edit`` entries of ``config system interface``; a VLAN
interface carries ``set vlanid N`` and names its physical parent with
``set interface "port8"`` (``IfaceInfo.parent`` / ``Fact.parent``, ``tag``).

Facts: ``set ip A M`` (dotted or ``/len``), ``set mode dhcp``, static route
``set dst`` / ``set gateway`` (and SD-WAN member gateways), ``set remote-gw``,
``set router-id``, BGP neighbor ``edit "IP"`` / ``set remote-as`` / ``set as``,
``config system dns`` primary/secondary/domain, ``config system ntp`` servers,
SD-WAN ``health-check`` ``set server "a" "b"`` (``probe_target``, never DNS),
label-like words / ``pnetN`` / ``(VLAN n)`` inside quoted ``alias``,
``description`` and ``comment(s)`` and in ``#`` comment lines (cosmetic), and
PSKs / admin passwords as secrets.  ``config router static`` ``edit N ... next``
stanzas can be deleted (``supports_stanza_delete``).
"""

from __future__ import annotations

import re
from typing import ClassVar

from ..model import Fact, Span
from . import register
from ._common import (
    ContextRule,
    ContextRulesMixin,
    HostnameServiceMixin,
    StanzaDeleteMixin,
    label_context_rules,
    through_eol,
)
from .base import PatternRule, RuleDialect

STATIC_EDIT = "edit:router static"
_SET = r"^\s*set "
_NEG_TAG = (
    "        set ike-version 2",
    "    edit 2",
    "        set community 204:204",
    "        set network-id 11",
    "        set members 1 2",
)


@register
class FortiOS(ContextRulesMixin, HostnameServiceMixin, StanzaDeleteMixin, RuleDialect):
    name = "fortios"
    templates = ("fortinet*", "fortigate*", "forti*")
    sniff = (
        r"^\s*config system (?:global|interface)\s*$",
        r"^\s*set vdom \"",
        r"^#.*FortiOS",
    )
    block_style = "fortios"
    mask_form = "dotted"
    iface_aliases: ClassVar[dict[str, str]] = {}
    iface_block_kinds = ("edit:system interface",)
    block_parent_re = r'^\s*set interface "(?P<parent>[^"]+)"'
    subif_re = None

    rules = (
        PatternRule(
            "fortios.vlanid",
            _SET + r"vlanid (?P<v>\d+)\s*$",
            "vlan_tag",
            block="edit:system interface",
            role="encap_tag",
            anchored_keywords=("set vlanid",),
            negative=_NEG_TAG,
        ),
        PatternRule(
            "fortios.ip",
            _SET + r"ip (?P<v>IPV4) ?(?P<mask>MASK)\s*$",
            "ip_host",
            block="edit:system interface",
            negative=(
                "        set ip-range 10.1.1.10 10.1.1.20",
                "        set subnet 169.1.0.0 255.255.0.0",
            ),
        ),
        PatternRule(
            "fortios.dhcp",
            _SET + r"mode (?P<v>dhcp)\s*$",
            "dhcp",
            block="edit:system interface",
            negative=("        set mode static",),
        ),
        PatternRule(
            "fortios.gateway",
            _SET + r"gateway (?P<v>IPV4)\s*$",
            "ip_gateway",
            negative=("        set default-gateway 10.1.1.1",),
        ),
        PatternRule(
            "fortios.route_dst",
            _SET + r"dst (?P<v>IPV4) ?(?P<mask>MASK)\s*$",
            "ip_route_dst",
            block=STATIC_EDIT,
            negative=('            set dst "DC-NETS"', '        set dstintf "port2"'),
        ),
        PatternRule(
            "fortios.remote_gw",
            _SET + r"remote-gw (?P<v>IPV4)\s*$",
            "peer_ip",
            block="edit:vpn ipsec phase1*",
        ),
        PatternRule(
            "fortios.router_id",
            _SET + r"router-id (?P<v>IPV4)\s*$",
            "router_id",
            block="router *",
        ),
        PatternRule(
            "fortios.bgp_as",
            _SET + r"as (?P<v>\d+)\s*$",
            "asn",
            block="router bgp",
            negative=("        set as-path-prepend 1",),
        ),
        PatternRule(
            "fortios.bgp_peer",
            r'^\s*edit "?(?P<v>IPV4)"?\s*$',
            "peer_ip",
            block="edit:neighbor",
        ),
        PatternRule(
            "fortios.bgp_remote_as",
            _SET + r"remote-as (?P<v>\d+)\s*$",
            "asn",
            block="edit:neighbor",
        ),
        PatternRule(
            "fortios.dns",
            _SET + r"(?:primary|secondary) (?P<v>IPV4)\s*$",
            "dns_server",
            block="system dns",
            negative=("        set primary-ip 10.1.1.1",),
        ),
        PatternRule(
            "fortios.domain",
            _SET + r'domain "(?P<v>[A-Za-z0-9][\w.-]*)"\s*$',
            "domain",
            block="system dns",
        ),
        PatternRule(
            "fortios.ntp",
            _SET + r'server "?(?P<v>[A-Za-z0-9][\w.-]*[A-Za-z0-9])"?\s*$',
            "ntp_server",
            block="edit:ntpserver",
        ),
    )
    context_rules: tuple[ContextRule, ...] = (
        ContextRule(
            "fortios.hc_server",
            _SET + r'server (?P<ctx>"[^"\n]*"(?: "[^"\n]*")*)\s*$',
            r'"(?P<v>[^"\s]+)"',
            "probe_target",
            block="edit:health-check",
        ),
        *label_context_rules(
            "fortios",
            (
                ("text", _SET + r'(?:alias|description|comments?) "(?P<ctx>[^"\n]*)"'),
                ("comment", r"^\s*#(?P<ctx>.*)$"),
            ),
        ),
    )
    secret_rules = (
        _SET + r"psksecret (?:ENC )?(?P<s>\S+)",
        _SET + r"(?:password|passwd) (?:ENC )?(?P<s>\S+)",
    )

    #: Maximum length of the quoted FortiOS fields label text is propagated into.
    label_field_max: ClassVar[dict[str, int]] = {
        "alias": 25,
        "description": 255,
        "comment": 1023,
    }
    _label_field_re = re.compile(
        r'\s*set (alias|description|comments?) "([^"\n]*)"', re.ASCII
    )

    def label_problem(self, fact: Fact, new: str, text: str) -> str | None:
        """Label-propagation hook (``scenarios.labels``): ``new`` must fit the
        quoted field the ``label_ref`` fact sits in (``alias``: 25 chars)."""
        if fact.kind != "label_ref":
            return None
        if '"' in new or "\\" in new:
            return f"FortiOS quoted strings cannot hold {new!r}"
        start = text.rfind("\n", 0, fact.span.start) + 1
        m = self._label_field_re.match(text, start)
        if m is None or not m.start(2) <= fact.span.start < m.end(2):
            return None
        key = "comment" if m.group(1) == "comments" else m.group(1)
        limit = self.label_field_max.get(key)
        size = len(m.group(2)) - len(fact.value) + len(new)
        if limit is not None and size > limit:
            return (
                f"FortiOS {m.group(1)} would be {size} characters "
                f"(max {limit}) with label {new!r}"
            )
        return None

    def stanza_span(self, fact: Fact, text: str) -> Span | None:
        """The ``edit N`` ... ``next`` entry of ``config router static``."""
        layout = self._layout(text)
        line = layout.line_at(fact.span.start)
        if line is None:
            return None
        for blk in reversed(line.chain):
            if blk.kind == STATIC_EDIT:
                return Span(blk.start, through_eol(text, blk.end))
        return None
