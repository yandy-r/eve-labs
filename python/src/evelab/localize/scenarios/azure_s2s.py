"""Azure site-to-site VPN on an ASA (design 10.2, 12.7, 15 #44-#46).

Grounded in ``labs/cloud/azure/azure_asa_vpn.unl`` (ASAv-1): a VTI ``Tunnel1``
(``tunnel destination <Azure public IP>``) with an APIPA ``/30``, the public IP
reused as the ``tunnel-group`` / ``group-policy`` / ``tunnel-group-map`` object
name, a host route to it, BGP over the tunnel toward the Azure BGP address
(``route vti <bgp ip> 255.255.255.255 <tunnel peer>``), and the IKEv2 PSKs
inside ``tunnel-group <public ip> ipsec-attributes``.

Signature: an ``asa`` config whose ``tunnel destination`` is a public address
that is also used as an object name. ``[scenarios.azure_s2s] node = "1"`` in the
manifest pins the node. Gated ("G Scenarios", default no).

Questions (options in ``[labs."<lab_id>".scenarios.azure_s2s]``, the PSK in
``[secrets."azure_s2s.psk"]``): ``peer_ip`` (Azure VPN gateway public IP),
``tunnel_ip`` (local APIPA tunnel address, 169.254.21.0-169.254.22.255; the rest
of the ``/30`` follows by offset), ``azure_bgp_ip``, ``local_asn``, ``azure_asn``,
``psk``. Answers are *targets*: a value equal to the discovered one is a no-op,
so re-planning after apply gives zero edits.

Every claim is scenario-exact (overrides the protected inventory, which holds the
169.254 transfer nets) and limited to the scenario node, except the local ASN,
which changes lab-wide (other nodes peer with it).

Review fixes: the local ASN must differ from the (answered or discovered) Azure
ASN, and the Azure ASN from the local ASN, both at the prompt and in ``plan()``
(``AZURE_ASN_EQUAL`` blocker: equal ASNs turn the eBGP session into iBGP, which
Azure rejects). Azure-reserved ASNs are refused for both, except that the Azure
side may keep Azure's own default 65515. A non-public ``peer_ip`` is accepted (an
in-lab simulated gateway is legitimate) but ``plan()`` warns
(``AZURE_PEER_PRIVATE``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Any

from ..discover.segments import host_network
from ..model import Analysis, Fact, Finding
from ..profile import Profile, SecretRef
from . import register_scenario
from .base import (
    PRIO_SCENARIO_EXACT,
    Answers,
    PlanFragment,
    Question,
    Validator,
    ValueMaps,
    fact_claim,
    render_fact,
    text_index,
)
from .extra_common import (
    gate_question,
    manifest_options,
    node_facts,
    opt_asn,
    opt_ip,
    option_setter,
    parse_ip,
    scenario_options,
)

if TYPE_CHECKING:
    from ..manifest import Manifest

__all__ = [
    "APIPA_RANGE",
    "AZURE_RESERVED_ASNS",
    "PSK_SECRET",
    "AzureS2S",
    "AzureS2SScenario",
    "find_azure",
]

SID = "azure_s2s"
PSK_SECRET = "azure_s2s.psk"
APIPA_RANGE = (IPv4Address("169.254.21.0"), IPv4Address("169.254.22.255"))
AZURE_RESERVED_ASNS = frozenset({8074, 8075, 12076, 23456, *range(65515, 65521)})
IP_KINDS = ("ip_host", "ip_gateway", "peer_ip", "router_id", "ip_route_dst")


@dataclass
class AzureS2S:
    node_id: str
    peer: str  # Azure VPN gateway public IP
    tunnel_iface: str | None = None
    tunnel_net: IPv4Network | None = None
    tunnel_ip: IPv4Address | None = None
    bgp_peer: str | None = None
    local_asn: int | None = None
    azure_asn: int | None = None
    psk_facts: list[Fact] = field(default_factory=list)


NON_PUBLIC = tuple(
    IPv4Network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",
    )
)


def _is_public(value: str) -> bool:
    """Not RFC 1918 / CGNAT / APIPA / loopback / multicast (documentation nets
    such as 198.51.100.0/24 count as public, so localized labs stay detected)."""
    ip = parse_ip(value)
    return ip is not None and not any(ip in n for n in NON_PUBLIC)


def _tunnel_group_block(text: str, peer: str) -> tuple[int, int] | None:
    m = re.search(
        rf"^tunnel-group {re.escape(peer)} ipsec-attributes[ \t]*\r?$", text, re.M
    )
    if m is None:
        return None
    nxt = re.compile(r"^\S", re.M).search(text, m.end() + 1)
    return m.start(), nxt.start() if nxt else len(text)


def _scan_node(a: Analysis, node_id: str, peer: str) -> AzureS2S:
    az = AzureS2S(node_id, peer)
    idx = text_index(a)
    facts = node_facts(a, [node_id])
    for f in facts:
        if f.kind == "peer_ip" and f.rule.endswith("tunnel_dst") and f.value == peer:
            az.tunnel_iface = f.iface
            break
    if az.tunnel_iface is not None:
        for f in facts:
            if f.kind != "ip_host" or f.iface != az.tunnel_iface:
                continue
            text = idx.text(f.store, f.node_id)
            net = host_network(f, text) if text is not None else None
            if net is not None:
                az.tunnel_net, az.tunnel_ip = net, IPv4Address(f.value)
                break
    bgp_peers = [f for f in facts if f.kind == "peer_ip" and "bgp" in f.rule]
    routed: dict[str, str] = {}
    by_line: dict[tuple, list[Fact]] = {}
    for f in facts:
        by_line.setdefault((f.store, f.line), []).append(f)
    for f in facts:
        if f.kind != "ip_route_dst":
            continue
        for g in by_line[(f.store, f.line)]:
            if g.kind == "ip_gateway":
                routed[f.value] = g.value
    for f in bgp_peers:
        ip = parse_ip(f.value)
        via = parse_ip(routed.get(f.value, ""))
        net = az.tunnel_net
        if (
            net is not None
            and ip is not None
            and (ip in net or (via is not None and via in net))
        ):
            az.bgp_peer = f.value
            break
    for f in facts:
        if f.kind == "asn" and f.rule.endswith("bgp_asn") and az.local_asn is None:
            az.local_asn = int(f.value)
        if (
            f.kind == "asn"
            and az.bgp_peer is not None
            and az.azure_asn is None
            and any(
                g.kind == "peer_ip" and g.value == az.bgp_peer
                for g in by_line[(f.store, f.line)]
            )
            and not f.rule.endswith("bgp_asn")
        ):
            az.azure_asn = int(f.value)
    for f in facts:
        if f.kind != "secret":
            continue
        text = idx.text(f.store, f.node_id)
        blk = _tunnel_group_block(text, peer) if text is not None else None
        if blk is None or not blk[0] <= f.span.start < blk[1]:
            continue
        if "pre-shared-key" in text[text.rfind("\n", 0, f.span.start) : f.span.start]:
            az.psk_facts.append(f)
    return az


def find_azure(a: Analysis, m: Manifest | None = None) -> list[AzureS2S]:
    pin = manifest_options(m, SID)
    nodes: set[str] | None = None
    if pin is not None and pin.get("node") is not None:
        raw = pin["node"]
        nodes = {str(n) for n in raw} if isinstance(raw, list) else {str(raw)}
    idx = text_index(a)
    peers: dict[str, set[str]] = {}
    objects: dict[str, set[str]] = {}
    for f in a.facts.values():
        if f.kind != "peer_ip" or f.node_id is None:
            continue
        if nodes is not None and f.node_id not in nodes:
            continue
        ct = idx.config(f.store, f.node_id)
        if ct is None or ct.dialect != "asa":
            continue
        if "object_name" in f.flags:
            objects.setdefault(f.node_id, set()).add(f.value)
        elif f.rule.endswith("tunnel_dst"):
            peers.setdefault(f.node_id, set()).add(f.value)
    out: list[AzureS2S] = []
    for node_id in sorted(peers, key=lambda n: (len(n), n)):
        cands = sorted(
            p
            for p in peers[node_id] & objects.get(node_id, set())
            if nodes is not None or _is_public(p)
        )
        public = [p for p in cands if _is_public(p)] or cands
        if public:
            out.append(_scan_node(a, node_id, public[0]))
    return out


def _no_check(value: str, _ans: Answers) -> str | None:
    return None


def _validate_apipa(value: str, _ans: Answers) -> str | None:
    ip = parse_ip(value)
    if ip is None:
        return None  # the ip kind reports the parse error
    if not APIPA_RANGE[0] <= ip <= APIPA_RANGE[1]:
        return "Azure APIPA BGP addresses must be within 169.254.21.0-169.254.22.255"
    return None


AZURE_DEFAULT_ASN = 65515


def _asn_validator(
    lab_id: str, other_key: str, other_current: int | None, azure_side: bool
) -> Validator:
    """Refuse Azure-reserved ASNs and a value equal to the other side's ASN.

    The other side's ASN is its answer (``[scenarios.azure_s2s] <other_key>``) if
    one is given, else the discovered value.
    """

    def validate(value: str, ans: Answers) -> str | None:
        try:
            v = int(value.strip())
        except ValueError:
            return None  # the asn kind reports the parse error
        if v in AZURE_RESERVED_ASNS and not (azure_side and v == AZURE_DEFAULT_ASN):
            return (
                f"AS {v} is reserved by Azure (8074, 8075, 12076, 23456, "
                "65515-65520)"
            )
        other = opt_asn(scenario_options(ans, SID, lab_id), other_key)
        if other is None:
            other = other_current
        if other is not None and v == other:
            side = "Azure" if other_key == "azure_asn" else "local (ASA)"
            return (
                f"AS {v} equals the {side} AS: the eBGP session to Azure would "
                "become iBGP"
            )
        return None

    return validate


def _psk_setter(ans: Answers, value: Any) -> None:
    if value is None or str(value) == "":
        return  # keep
    ref = ans.secrets.get(PSK_SECRET)
    if ref is None:
        ans.secrets[PSK_SECRET] = SecretRef(value=str(value))
    else:
        ref.value = str(value)


def _offset_map(
    old_net: IPv4Network, old_local: IPv4Address, new_local: IPv4Address
) -> dict[IPv4Address, IPv4Address]:
    """Local address exact, the other addresses of the /30 by offset (swap on clash)."""
    new_net = IPv4Network(f"{new_local}/{old_net.prefixlen}", strict=False)
    out: dict[IPv4Address, IPv4Address] = {}
    base_old, base_new = int(old_net.network_address), int(new_net.network_address)
    local_off = int(new_local) - base_new
    old_local_off = int(old_local) - base_old
    for ip in old_net:
        off = int(ip) - base_old
        if ip == old_local:
            out[ip] = new_local
        elif off == local_off:
            out[ip] = IPv4Address(base_new + old_local_off)
        else:
            out[ip] = IPv4Address(base_new + off)
    return out


@register_scenario
class AzureS2SScenario:
    id = SID
    order = 80
    gated = True

    def applies(self, a: Analysis, m: Manifest | None) -> bool:
        return bool(find_azure(a, m))

    # ------------------------------------------------------------- questions

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]:
        found = find_azure(a, m)
        if not found:
            return []
        az = found[0]
        lab_id = a.lab.lab_id
        opts = scenario_options(prof, SID, lab_id)
        name = a.nodes[az.node_id].name if az.node_id in a.nodes else az.node_id
        gate_id = f"{SID}/enabled"
        notes = [f"node {name}: Azure VPN gateway {az.peer}"]
        if len(found) > 1:
            notes.append(
                "other candidate node(s) ignored: "
                + ", ".join(f.node_id for f in found[1:])
            )
        out = [
            gate_question(
                SID,
                lab_id,
                f"Azure site-to-site VPN on {name} (peer {az.peer}): localize it?",
                notes=notes,
                evidence=[f"node:{az.node_id}"],
            )
        ]

        def q(
            key: str,
            kind: str,
            prompt: str,
            current: str | None,
            validate: Validator | None = None,
            q_notes: list[str] | None = None,
        ) -> None:
            if current is None:
                return
            ans_v = opts.get(key)
            out.append(
                Question(
                    id=f"{SID}/{key}",
                    group="G Scenarios",
                    kind=kind,
                    prompt=prompt,
                    current=current,
                    default=current if ans_v is None else str(ans_v),
                    default_source="keep" if ans_v is None else f"scenarios.{SID}",
                    choices=None,
                    validate=validate or _no_check,
                    depends_on=[gate_id],
                    scenario=SID,
                    apply=option_setter(SID, key, lab_id),
                    notes=q_notes or [],
                )
            )

        q("peer_ip", "ip", "Azure VPN gateway public IP", az.peer)
        q(
            "tunnel_ip",
            "ip",
            f"local APIPA tunnel address ({az.tunnel_net})",
            None if az.tunnel_ip is None else str(az.tunnel_ip),
            _validate_apipa,
            ["the other addresses of the /30 follow by offset"],
        )
        q("azure_bgp_ip", "ip", "Azure BGP peer address", az.bgp_peer)
        q(
            "local_asn",
            "asn",
            "local (ASA) BGP AS",
            None if az.local_asn is None else str(az.local_asn),
            _asn_validator(lab_id, "azure_asn", az.azure_asn, False),
            ["changed lab-wide (peers of this node follow)"],
        )
        q(
            "azure_asn",
            "asn",
            "Azure VPN gateway BGP AS",
            None if az.azure_asn is None else str(az.azure_asn),
            _asn_validator(lab_id, "local_asn", az.local_asn, True),
        )
        if az.psk_facts:
            out.append(
                Question(
                    id=f"{SID}/psk",
                    group="G Scenarios",
                    kind="secret",
                    prompt=f"IPsec pre-shared key for {az.peer} "
                    f"({len(az.psk_facts)} span(s))",
                    current="****",
                    default=None,
                    default_source="keep",
                    choices=None,
                    validate=lambda v, a: None,
                    depends_on=[gate_id],
                    evidence=[f.id for f in az.psk_facts],
                    scenario=SID,
                    apply=_psk_setter,
                    notes=[
                        "read with getpass or {env=...}; never saved unless "
                        "--save-secrets"
                    ],
                )
            )
        return out

    # ------------------------------------------------------------------ plan

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment:
        frag = PlanFragment()
        found = find_azure(a, maps.manifest)
        if not found:
            return frag
        az = found[0]
        opts = scenario_options(ans, SID, a.lab.lab_id)
        ip_map: dict[str, tuple[str, str]] = {}  # old -> (new, question key)
        new_tunnel = opt_ip(opts, "tunnel_ip")
        if (
            new_tunnel is not None
            and az.tunnel_net is not None
            and az.tunnel_ip is not None
            and new_tunnel != az.tunnel_ip
        ):
            for o, n in _offset_map(az.tunnel_net, az.tunnel_ip, new_tunnel).items():
                if o != n:
                    ip_map[str(o)] = (str(n), "tunnel_ip")
        for key, old in (("peer_ip", az.peer), ("azure_bgp_ip", az.bgp_peer)):
            new = opt_ip(opts, key)
            if old is not None and new is not None and str(new) != old:
                ip_map[old] = (str(new), key)
        for f in node_facts(a, [az.node_id], IP_KINDS):
            hit = ip_map.get(f.value)
            if hit is not None:
                self._claim(a, f, hit[0], hit[1], frag, category="ip")
        new_local = opt_asn(opts, "local_asn")
        new_azure = opt_asn(opts, "azure_asn")
        eff_local = az.local_asn if new_local is None else new_local
        eff_azure = az.azure_asn if new_azure is None else new_azure
        if eff_local is not None and eff_local == eff_azure:
            frag.findings.append(
                Finding(
                    "AZURE_ASN_EQUAL",
                    "blocker",
                    f"azure_s2s: local AS {eff_local} equals the Azure AS: the eBGP "
                    "session to Azure would become iBGP (Azure rejects it)",
                    [f"node:{az.node_id}"],
                )
            )
        new_peer = opt_ip(opts, "peer_ip")
        if (
            new_peer is not None
            and str(new_peer) != az.peer
            and not _is_public(str(new_peer))
        ):
            frag.findings.append(
                Finding(
                    "AZURE_PEER_PRIVATE",
                    "warn",
                    f"azure_s2s: Azure VPN gateway address {new_peer} is not "
                    "public (fine for an in-lab simulated gateway; a real Azure "
                    "VPN gateway has a public IP)",
                    [f"node:{az.node_id}"],
                )
            )
        if az.local_asn is not None and new_local not in (None, az.local_asn):
            facts = [
                f
                for f in a.facts.values()
                if f.kind == "asn" and f.value == str(az.local_asn)
            ]
            facts.sort(key=lambda f: (tuple(f.store), f.node_id or "", f.span.start))
            for f in facts:
                self._claim(a, f, str(new_local), "local_asn", frag, category="bgp")
        if az.azure_asn is not None and new_azure not in (None, az.azure_asn):
            for f in node_facts(a, [az.node_id], ["asn"]):
                if f.value == str(az.azure_asn):
                    self._claim(a, f, str(new_azure), "azure_asn", frag, "bgp")
        psk = maps.secrets.get(PSK_SECRET)
        if psk is None:
            psk = ans.secret_value(PSK_SECRET)
        if psk:
            for f in az.psk_facts:
                self._claim(a, f, psk, "psk", frag, category="secret")
            frag.findings.append(
                Finding(
                    "SECRET_HISTORY",
                    "info",
                    "azure_s2s: the old pre-shared key remains in git history; "
                    "rotate it at the provider (Azure VPN gateway)",
                    [f"node:{az.node_id}"],
                )
            )
        if frag.claims:
            frag.findings.append(
                Finding(
                    "AZURE_SIDE",
                    "info",
                    "azure_s2s: update the Azure local network gateway (public IP, "
                    "BGP address/ASN) and the connection PSK to match",
                    [f"node:{az.node_id}"],
                )
            )
        return frag

    def _claim(
        self,
        a: Analysis,
        f: Fact,
        new: str,
        key: str,
        frag: PlanFragment,
        category: str,
    ) -> None:
        edits, finding = render_fact(a, f, new)
        if finding is not None:
            if "secret" in f.flags:  # never echo secret values
                finding.msg = f"{f.rule} {f.id}: secret span could not be rendered"
            frag.findings.append(finding)
        for e in edits:
            c = fact_claim(
                f,
                e,
                category=category,
                group=f"{SID}/{key}",
                question=f"{SID}/{key}",
                priority=PRIO_SCENARIO_EXACT,
                scenario=SID,
            )
            c.exact = True
            if "secret" in f.flags:
                c.secret = True
                c.evidence = ""
            frag.claims.append(c)
