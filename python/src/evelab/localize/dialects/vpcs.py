"""VPCS startup configs (design 6.2 ``flat``, 11.3).

Syntax (VPCS ``ip`` command)::

    ip 10.3.80.100/24 10.3.80.1 [DNS]
    ip 10.3.80.100 255.255.255.0 10.3.80.1 [DNS]
    ip dhcp
    ip dns 8.8.8.8
    ip domain example.com
    set pcname VPC1

A VPCS has one port, ``eth0``; address lines are attributed to it so the L2
trace sees a routed endpoint.
"""

from __future__ import annotations

import re

from ..model import Span
from . import register
from .base import PatternRule, RuleDialect
from .blocks import Layout, Line
from .generic import attach_iface_blocks

_NETMASK = r"(?:255|254|252|248|240|224|192|128|0)(?:\.\d{1,3}){3}"
# "ip A/len" or "ip A MASK" (the address part, non-capturing)
_ADDR = rf"^[ \t]*ip[ \t]+IPV4(?:/\d{{1,2}}|[ \t]+{_NETMASK})"
_ADDR_LINE_RE = re.compile(r"^[ \t]*ip[ \t]+(?:\d|dhcp\b)")


def _resolve(text: str, line: Line) -> tuple[str, Span | None] | None:
    return ("eth0", None) if _ADDR_LINE_RE.match(text) else None


@register
class Vpcs(RuleDialect):
    name = "vpcs"
    templates = ("vpcs*",)
    sniff = (
        r"^[ \t]*ip[ \t]+\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?[ \t]+\d",
        r"^[ \t]*set[ \t]+pcname[ \t]",
    )
    block_style = "flat"
    mask_form = "mixed"
    subif_re = None
    rules = (
        PatternRule(
            "vpcs.ip_prefix",
            r"^[ \t]*ip[ \t]+(?P<v>IPV4)(?P<mask>/\d{1,2})(?![\d.])",
            "ip_host",
            negative=("ip dns 8.8.8.8", "ip dhcp"),
        ),
        PatternRule(
            "vpcs.ip_dotted",
            rf"^[ \t]*ip[ \t]+(?P<v>IPV4)[ \t]+(?P<mask>{_NETMASK})(?![\w.])",
            "ip_host",
            negative=("ip 10.1.1.1/24 10.1.1.254",),
        ),
        PatternRule(
            "vpcs.gateway",
            _ADDR + r"[ \t]+(?P<v>IPV4)",
            "ip_gateway",
            negative=("ip 10.1.1.1/24",),
        ),
        PatternRule(
            "vpcs.dns_inline",
            _ADDR + r"[ \t]+IPV4[ \t]+(?P<v>IPV4)",
            "dns_server",
        ),
        PatternRule("vpcs.dns", r"^[ \t]*ip[ \t]+dns[ \t]+(?P<v>IPV4)", "dns_server"),
        PatternRule(
            "vpcs.domain",
            r"^[ \t]*ip[ \t]+domain[ \t]+(?P<v>[\w-]+(?:\.[\w-]+)+)[ \t]*$",
            "domain",
        ),
        PatternRule("vpcs.dhcp", r"^[ \t]*ip[ \t]+(?P<v>dhcp)\b", "dhcp"),
    )

    def _layout(self, text: str) -> Layout:
        return attach_iface_blocks(super()._layout(text), _resolve)
