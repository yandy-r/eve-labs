"""Cisco IOS-XE dialect: CSR1000v / C8000v (design 6.1-6.5).

Same syntax as IOS for everything the tool touches (``ip domain name`` with a
space, ``vrf definition``, ``ip route vrf X``, ``GigabitEthernetN.M`` subifs); it
inherits the IOS behaviour and only changes the selection data and the rule-id
prefix (``iosxe.*``).
"""

from __future__ import annotations

from . import register
from .ios import IOS, ios_context_rules, ios_rules


@register
class IOSXE(IOS):
    """IOS-XE 16/17 (CSR1000v, C8000v, Cat8000v)."""

    name = "iosxe"
    templates = (
        "csr1000v*",
        "c8000v*",
        "cat8000v*",
        "cat9kv*",
        "c9kv*",
    )
    sniff = (
        r"^version 1[67]\.\d+\s*$",
        r"^license boot level ",
        r"^platform (?:qfp|punt-keepalive|console)\b",
        r"^netconf-yang\s*$",
    )
    rules = ios_rules("iosxe")
    context_rules = ios_context_rules("iosxe")
    priority = 1  # content-only tie with ios: IOS-XE markers are more specific
