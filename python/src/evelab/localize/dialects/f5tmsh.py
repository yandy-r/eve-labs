"""F5 BIG-IP ``tmsh`` command dialect (design 6, 11.3).

Sidecars hold one ``tmsh`` command per line (the ``tmsh `` prefix is optional,
as inside the tmsh shell).  Flat layout: no blocks.

Facts: ``sys management-ip A/len``, ``sys management-route ... gateway G``
(``network N/len`` too), ``sys dns name-servers replace-all-with { ... }``,
``search replace-all-with { ... }`` (one ``search_list`` fact per domain), the
FQDN suffix of ``global-settings hostname`` (``domain``), ``sys ntp servers
replace-all-with { ... }`` (IPs or host names), ``net vlan NAME ... tag N``
(the only tag-bearing syntax, 6.3), ``net self ... address A/len vlan NAME``,
``net route ... gw G network N/len``, label words / ``(VLAN n)`` in ``#``
comments and descriptions (cosmetic) and ``auth user`` passwords (secrets).

Interfaces: one ``IfaceInfo`` per ``net vlan`` (key = VLAN name, parent = its
first member interface such as ``1.1``, ``tag`` when that member is tagged) and
``mgmt`` for the management IP.  Self-IP / VLAN facts carry that iface key and
parent.  EVE port names map as ``E1.1`` -> ``1.1`` and ``Mgmt`` -> ``mgmt``.
Single-line ``net route`` / ``sys management-route`` commands can be deleted.
"""

from __future__ import annotations

import re
from typing import ClassVar

from ..model import ConfigText, Fact, Span
from . import register
from ._common import (
    HOST_TOKEN,
    ContextRule,
    ContextRulesMixin,
    HostnameServiceMixin,
    StanzaDeleteMixin,
    label_context_rules,
    line_span,
)
from .base import IfaceInfo, ParsedConfig, PatternRule, RuleDialect

_CMD = r"^(?:tmsh )?(?:create|modify) "
_LEN = r"(?P<mask>/\d{1,2})(?!\d)"
_LIST_ACTION = r"(?:replace-all-with|add)"
ROUTE_RULES = frozenset(
    {"f5.route_gw", "f5.route_dst", "f5.mgmt_route_gw", "f5.mgmt_route_dst"}
)

_VLAN_RE = re.compile(
    r"^(?:tmsh )?(?:create|modify) net vlan (?P<name>[\w.-]+)\b(?P<rest>.*)$",
    re.MULTILINE,
)
_MEMBER_RE = re.compile(
    r"\binterfaces (?:replace-all-with|add) \{ *(?P<if>[\w./-]+) "
    r"\{ *(?P<mode>tagged|untagged) *\}"
)
_TAG_RE = re.compile(r"\btag (?P<tag>\d+)\b")
_EVE_PORT_RE = re.compile(r"^[Ee](?P<port>\d+\.\d+)$")


def _routed_iface(
    name: str, name_span: Span | None = None, mode: str = "routed"
) -> IfaceInfo:
    return IfaceInfo(
        key=name.lower(),
        name=name,
        parent=None,
        name_span=name_span,
        mode=mode,  # type: ignore[arg-type]
        access_vlan=None,
        trunk_vlans=None,
        native_vlan=None,
        tag=None,
        dhcp=False,
        orphan=False,
    )


@register
class F5Tmsh(ContextRulesMixin, HostnameServiceMixin, StanzaDeleteMixin, RuleDialect):
    name = "f5tmsh"
    templates = ("bigip*", "f5*")
    sniff = (
        r"^(?:tmsh )?(?:create|modify) (?:sys|net|ltm|auth) ",
        r"^tmsh save sys config\b",
    )
    block_style = "flat"
    mask_form = "prefix"
    iface_aliases: ClassVar[dict[str, str]] = {}
    subif_re = None

    rules = (
        PatternRule(
            "f5.mgmt_ip",
            _CMD + r"sys management-ip (?P<v>IPV4)" + _LEN,
            "ip_host",
        ),
        PatternRule(
            "f5.mgmt_route_gw",
            _CMD + r"sys management-route \S+ (?:.*? )?gateway (?P<v>IPV4)\b",
            "ip_gateway",
        ),
        PatternRule(
            "f5.mgmt_route_dst",
            _CMD + r"sys management-route \S+ (?:.*? )?network (?P<v>IPV4)" + _LEN,
            "ip_route_dst",
        ),
        PatternRule(
            "f5.dns",
            _CMD
            + r"sys dns (?:.*? )?name-servers "
            + _LIST_ACTION
            + r" \{(?P<many>[^}\n]*)\}",
            "dns_server",
            anchored_keywords=("name-servers replace-all-with",),
            negative=("tmsh modify sys ntp servers replace-all-with { 10.1.1.1 }",),
        ),
        PatternRule(
            "f5.hostname_domain",
            _CMD + r"sys global-settings (?:.*? )?hostname [\w-]+\."
            r"(?P<v>[\w-]+(?:\.[\w-]+)+)\b",
            "domain",
        ),
        PatternRule(
            "f5.vlan_tag",
            _CMD + r"net vlan [\w.-]+ (?:.*? )?tag (?P<v>\d+)\b",
            "vlan_tag",
            anchored_keywords=("net vlan", "tag"),
            negative=(
                "tmsh create net self S address 10.1.1.1/24 vlan V allow-service none",
                "tmsh create net route R gw 10.1.1.1 network 10.2.0.0/16",
            ),
        ),
        PatternRule(
            "f5.vlan_name",
            _CMD + r"net vlan (?P<v>[\w.-]+)",
            "vlan_name",
        ),
        PatternRule(
            "f5.self_vlan",
            _CMD + r"net self \S+ (?:.*? )?vlan (?P<v>[\w.-]+)",
            "vlan_name",
        ),
        PatternRule(
            "f5.self_ip",
            _CMD + r"net self \S+ (?:.*? )?address (?P<v>IPV4)(?:%\d+)?" + _LEN,
            "ip_host",
        ),
        PatternRule(
            "f5.route_gw",
            _CMD + r"net route \S+ (?:.*? )?gw (?P<v>IPV4)\b",
            "ip_gateway",
        ),
        PatternRule(
            "f5.route_dst",
            _CMD + r"net route \S+ (?:.*? )?network (?P<v>IPV4)(?:%\d+)?" + _LEN,
            "ip_route_dst",
            negative=("tmsh create net route default gw 169.15.38.1 network default",),
        ),
    )
    context_rules: tuple[ContextRule, ...] = (
        ContextRule(
            "f5.search",
            _CMD
            + r"sys dns (?:.*? )?search "
            + _LIST_ACTION
            + r" \{(?P<ctx>[^}\n]*)\}",
            HOST_TOKEN,
            "search_list",
        ),
        ContextRule(
            "f5.ntp",
            _CMD
            + r"sys ntp (?:.*? )?servers "
            + _LIST_ACTION
            + r" \{(?P<ctx>[^}\n]*)\}",
            HOST_TOKEN,
            "ntp_server",
            negative=("tmsh modify sys dns name-servers replace-all-with { 1.1.1.1 }",),
        ),
        *label_context_rules(
            "f5",
            (
                ("comment", r"^\s*#(?P<ctx>.*)$"),
                ("desc", r"\bdescription '?\"(?P<ctx>[^\"\n]*)\"'?"),
            ),
        ),
    )
    secret_rules = (
        r"\bauth user \S+ (?:.*? )?(?:encrypted-)?password (?P<s>\S+)",
        r"\bauth password \S+ (?P<s>\S+)\s*$",
    )

    # ---------------------------------------------------------------- ifaces

    def eve_to_config(self, eve_name: str) -> list[str]:
        """``E1.1`` -> ``1.1``; ``Mgmt`` -> ``mgmt``."""
        m = _EVE_PORT_RE.match(eve_name.strip())
        if m:
            return [m.group("port")]
        if eve_name.strip().lower() == "mgmt":
            return ["mgmt"]
        return [eve_name]

    def parse(self, ct: ConfigText) -> ParsedConfig:
        parsed = super().parse(ct)
        text = ct.text
        ifaces: dict[str, IfaceInfo] = {}
        vlan_lines: dict[int, str] = {}  # line number -> vlan key
        for m in _VLAN_RE.finditer(text):
            name = m.group("name")
            key = self.iface_key(name)
            line_no = text.count("\n", 0, m.start()) + 1
            vlan_lines[line_no] = key
            info = ifaces.get(key)
            if info is None:
                info = ifaces[key] = _routed_iface(
                    name, Span(m.start("name"), m.end("name")), mode="unknown"
                )
            rest = m.group("rest")
            mem = _MEMBER_RE.search(rest)
            if mem:
                info.parent = self.iface_key(mem.group("if"))
                tag = _TAG_RE.search(rest)
                if mem.group("mode") == "tagged" and tag:
                    info.tag = int(tag.group("tag"))
        by_line: dict[int, list[Fact]] = {}
        for f in parsed.facts:
            by_line.setdefault(f.line, []).append(f)
        for f in parsed.facts:
            key: str | None = None
            if f.line in vlan_lines and f.kind in ("vlan_tag", "vlan_name"):
                key = vlan_lines[f.line]
            elif f.rule in ("f5.self_ip", "f5.self_vlan"):
                ref = next(
                    (g for g in by_line[f.line] if g.rule == "f5.self_vlan"), None
                )
                key = self.iface_key(ref.value) if ref else None
            elif f.rule == "f5.mgmt_ip":
                key = "mgmt"
            if key is None:
                continue
            f.iface = key
            if f.kind == "vlan_name":
                f.group = f"f5vlan:{key}"
            if key in ifaces:
                f.parent = ifaces[key].parent
        for f in parsed.facts:
            if f.kind != "ip_host" or f.iface is None:
                continue
            if f.iface == "mgmt" and "mgmt" not in ifaces:
                ifaces["mgmt"] = _routed_iface("mgmt")
            if f.iface in ifaces:
                ifaces[f.iface].mode = "routed"
        parsed.ifaces = ifaces
        return parsed

    def stanza_span(self, fact: Fact, text: str) -> Span | None:
        """A ``net route`` / ``sys management-route`` command is one line."""
        if fact.rule not in ROUTE_RULES:
            return None
        return line_span(text, fact.span.start)
