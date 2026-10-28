"""Subnet / gateway / masks / split maps / host overrides (section 11.3 IPv4).

Questions (only when the canonical scheme has a subnet from PROVEN facts):
``<site_key>/subnet``, ``<site_key>/gateway`` (default: same offset in the new
subnet), ``<site_key>/split`` (only when the answered prefix cannot hold every
baseline host offset) and ``<site_key>/legacy`` (``S Scope``, only for segments
with legacy schemes when ``policy.legacy_scopes = "ask"``). DHCP and LABEL_ONLY
segments get no addressing question.

Plan: every attributed ``ip_host`` / ``ip_gateway`` / ``peer_ip`` / ``router_id``
fact is mapped through ``ValueMaps.map_ip`` (exact > per-segment host override >
gateway > subnet offset; the claim priority follows the same order). The mask
token next to a rewritten address is rewritten in its own form when the prefix
length changes (by the same delta as the subnet map, so a split /24 -> /25 map
works). An ACL wildcard (``mask_form == "wildcard"``) only follows the segment
prefix itself. Supernet routes belong to ``site_routes``.

Validators (also run on profile / TOML answers, ``cli._check_answered``): the
subnet must not overlap another segment's baseline or answered subnet; the
gateway must be a host of the new subnet that no mapped baseline host takes;
a split map must leave no baseline host unmapped.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Any

from evelab.common.textutil import mask_prefix_as

from ..model import Analysis, Confidence, Fact, Segment
from ..profile import Profile, ScenarioAnswer, SegmentAnswer
from . import register_scenario
from .base import (
    PRIO_EXACT,
    PRIO_GATEWAY,
    PRIO_MEMBERSHIP,
    Answers,
    ParamKind,
    PlanFragment,
    Question,
    SubnetMap,
    ValueMaps,
    active_fact,
    canonical_scheme,
    fact_claim,
    group_name,
    register_param_kind,
    render_fact,
    seg_answer,
    segment_setter,
    text_index,
)

if TYPE_CHECKING:
    from ..manifest import Manifest

IP_KINDS = frozenset({"ip_host", "ip_gateway", "peer_ip", "router_id"})
CATEGORY = {
    "ip_host": "ip",
    "ip_gateway": "gateway",
    "peer_ip": "derived",
    "router_id": "derived",
}


# ------------------------------------------------------------ param kinds


def _parse_pairs(text: str, conv: Any) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    for part in re.split(r"[,;\s]+", text.strip()):
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"expected OLD=NEW, got {part!r}")
        old, new = part.split("=", 1)
        out[conv(old.strip())] = conv(new.strip())
    return out


def _net(s: str) -> IPv4Network:
    return IPv4Network(s, strict=False)


def _parse_split(text: str) -> dict[IPv4Network, IPv4Network]:
    return _parse_pairs(text, _net)


def _parse_hosts(text: str) -> dict[IPv4Address, IPv4Address]:
    return _parse_pairs(text, IPv4Address)


def _check(parse: Any) -> Any:
    def validate(value: str, _ans: Answers) -> str | None:
        try:
            parse(value)
        except ValueError as exc:
            return str(exc)
        return None

    return validate


register_param_kind(ParamKind("split", _parse_split, _check(_parse_split)))
register_param_kind(ParamKind("hosts", _parse_hosts, _check(_parse_hosts)))
register_param_kind(
    ParamKind(
        "legacy",
        lambda s: s.strip().lower(),
        lambda v, a: (
            None if v.strip().lower() in ("leave", "same") else "leave or same"
        ),
    )
)


# ----------------------------------------------------------------- helpers


def proven_subnet(a: Analysis, seg: Segment) -> IPv4Network | None:
    """Canonical subnet when PROVEN member facts back it."""
    canon = canonical_scheme(seg)
    if canon is None or canon.subnet is None:
        return None
    if seg.status in ("DHCP", "LABEL_ONLY", "CARRIER"):
        return None
    for fid in canon.members:
        f = a.facts.get(fid)
        if f is not None and f.confidence == Confidence.PROVEN and f.kind in IP_KINDS:
            return canon.subnet
    return None


def baseline_hosts(a: Analysis, seg: Segment, subnet: IPv4Network) -> list[IPv4Address]:
    hosts: set[IPv4Address] = set()
    for f in a.facts.values():
        if f.segment != seg.key or f.kind not in IP_KINDS or "outlier" in f.flags:
            continue
        try:
            ip = IPv4Address(f.value)
        except ValueError:
            continue
        if ip in subnet:
            hosts.add(ip)
    return sorted(hosts)


def same_offset(
    ip: IPv4Address | None, old: IPv4Network, new: IPv4Network
) -> IPv4Address | None:
    if ip is None:
        return None
    return SubnetMap(old, new).map_host(ip)


def default_gateway(
    gw: IPv4Address, old: IPv4Network, new: IPv4Network
) -> tuple[str | None, str]:
    """Default gateway in ``new`` for the baseline gateway ``gw`` of ``old``.

    Same offset when it fits; else the same distance from the top of the
    subnet (a ``.254`` style gateway stays near the top), clamped to the last
    or first usable host by the side ``gw`` sat on.  ``(None, "required")``
    when ``new`` has no usable host (/31, /32 with no fitting offset).
    """
    g = same_offset(gw, old, new)
    if g is not None:
        return str(g), "same offset"
    if new.prefixlen >= 31:
        return None, "required"
    first = new.network_address + 1
    last = new.broadcast_address - 1
    from_top = int(old.broadcast_address) - int(gw)
    cand = new.broadcast_address - from_top if from_top < new.num_addresses else None
    if cand is not None and first <= cand <= last:
        return str(cand), "same offset from top"
    top_half = int(gw) - int(old.network_address) >= old.num_addresses // 2
    return (str(last), "last host") if top_half else (str(first), "first host")


def _mapped_hosts(
    a: Analysis,
    seg: Segment,
    old: IPv4Network,
    sa: SegmentAnswer,
    gateway: IPv4Address | None,
) -> dict[IPv4Address, IPv4Address]:
    """New address -> baseline host for every non-gateway baseline host.

    Follows the answers: host overrides, then split pieces, then the answered
    subnet (same offset); an unanswered subnet keeps the host where it is.
    """
    maps = [SubnetMap(o, n) for o, n in (sa.split or {}).items()]
    if sa.subnet is not None:
        maps.append(SubnetMap(old, sa.subnet))
    out: dict[IPv4Address, IPv4Address] = {}
    for h in baseline_hosts(a, seg, old):
        if h == gateway:
            continue
        new: IPv4Address | None = (sa.hosts or {}).get(h)
        if new is None:
            new = _first_map(maps, h) if maps else h
        if new is not None:
            out.setdefault(new, h)
    return out


def _first_map(maps: list[SubnetMap], ip: IPv4Address) -> IPv4Address | None:
    """``ValueMaps.map_ip`` order: the first covering map decides."""
    for sm in maps:
        if sm.covers(ip):
            return sm.map_host(ip)
    return None


def _split_validator(
    a: Analysis,
    seg: Segment,
    old: IPv4Network,
    hosts: list[IPv4Address],
    gateway: IPv4Address | None,
) -> Any:
    """A split map must leave no baseline host without a new address."""

    def validate(value: str, ans: Answers) -> str | None:
        try:
            pairs = _parse_split(value)
        except ValueError as exc:
            return str(exc)
        sa = seg_answer(ans, a, seg)
        maps = [SubnetMap(o, n) for o, n in pairs.items()]
        if sa.subnet is not None:
            maps.append(SubnetMap(old, sa.subnet))
        for o, n in pairs.items():
            if not o.overlaps(old):
                return f"{o} is outside the baseline subnet {old}"
            if sa.subnet is not None and not n.subnet_of(sa.subnet):
                # allowed (the piece lands elsewhere), but must not collide
                for other in a.segments:
                    if other.key == seg.key:
                        continue
                    osa = seg_answer(ans, a, other)
                    onet = osa.subnet or proven_subnet(a, other)
                    if onet is not None and n.overlaps(onet):
                        return f"{n} overlaps segment {other.key} ({onet})"
        over = set(sa.hosts or {})
        if sa.gateway is not None and gateway is not None:
            over.add(gateway)  # mapped by the gateway answer
        left = [h for h in hosts if h not in over and _first_map(maps, h) is None]
        if left:
            return (
                f"{len(left)} baseline host(s) still unmapped: " f"{_host_groups(left)}"
            )
        return None

    return validate


def _host_groups(hosts: list[IPv4Address]) -> str:
    """``10.1.1.5, 10.1.1.9 (10.1.1.0/24: 2), ...`` grouped by /24."""
    groups: dict[IPv4Network, list[IPv4Address]] = {}
    for h in hosts:
        groups.setdefault(IPv4Network(f"{h}/24", strict=False), []).append(h)
    parts = []
    for net, hs in sorted(groups.items()):
        shown = ", ".join(str(h) for h in hs[:4]) + (", ..." if len(hs) > 4 else "")
        parts.append(f"{net}: {len(hs)} ({shown})")
    return "; ".join(parts)


def _legacy_setter(site_key: str) -> Any:
    def setter(ans: Answers, value: Any) -> None:
        sc = ans.scenarios.setdefault("scopes", ScenarioAnswer())
        sc.options[site_key] = value

    return setter


def _fact_prefix(a: Analysis, f: Fact) -> int | None:
    if f.mask_span is None:
        return None
    text = text_index(a).text(f.store, f.node_id)
    if text is None:
        return None
    return mask_prefix_as(text[f.mask_span.start : f.mask_span.end], f.mask_form)


@register_scenario
class SegmentL3Scenario:
    id = "segment_l3"
    order = 30

    def applies(self, a: Analysis, m: Manifest | None) -> bool:
        return any(s.subnet is not None for seg in a.segments for s in seg.schemes)

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]:
        out: list[Question] = []
        for seg in a.segments:
            subnet = proven_subnet(a, seg)
            if subnet is None:
                continue
            canon = canonical_scheme(seg)
            assert canon is not None
            sa = seg_answer(prof, a, seg)
            hosts = baseline_hosts(a, seg, subnet)
            members = [
                f.id
                for f in a.facts.values()
                if f.segment == seg.key and f.kind in IP_KINDS
            ]
            sub_q = f"{seg.site_key}/subnet"
            out.append(
                Question(
                    id=sub_q,
                    group="C Addressing",
                    kind="cidr",
                    prompt=f"{seg.key} subnet {subnet}",
                    current=str(subnet),
                    default=str(sa.subnet) if sa.subnet else str(subnet),
                    default_source=(f"from {seg.site_key}" if sa.subnet else "keep"),
                    choices=None,
                    validate=self._subnet_validator(a, seg),
                    evidence=members[:20],
                    affects=len(members),
                    scenario=self.id,
                    segment=seg.key,
                    apply=segment_setter(seg.site_key, "subnet"),
                    notes=[f"{len(hosts)} baseline host(s)"],
                )
            )
            if canon.gateway is not None:
                new_sub = sa.subnet or subnet
                if sa.gateway is not None:
                    gdef, gsrc = str(sa.gateway), f"from {seg.site_key}"
                else:
                    gdef, gsrc = str(canon.gateway), "keep"
                    if new_sub != subnet:
                        # never the old gateway: it lies outside new_sub
                        gdef, gsrc = default_gateway(canon.gateway, subnet, new_sub)
                out.append(
                    Question(
                        id=f"{seg.site_key}/gateway",
                        group="C Addressing",
                        kind="ip",
                        prompt=f"{seg.key} gateway {canon.gateway}",
                        current=str(canon.gateway),
                        default=gdef,
                        default_source=gsrc,
                        choices=None,
                        validate=self._gateway_validator(a, seg),
                        depends_on=[sub_q],
                        evidence=[
                            f.id
                            for f in a.facts.values()
                            if f.segment == seg.key
                            and f.kind == "ip_gateway"
                            and f.value == str(canon.gateway)
                        ][:20],
                        affects=sum(
                            1
                            for f in a.facts.values()
                            if f.segment == seg.key and f.value == str(canon.gateway)
                        ),
                        scenario=self.id,
                        segment=seg.key,
                        apply=segment_setter(seg.site_key, "gateway"),
                    )
                )
            if sa.subnet is not None:
                sm = SubnetMap(subnet, sa.subnet)
                # the answered gateway maps the old gateway (gateway > offset)
                moved = {canon.gateway} if sa.gateway is not None else set()
                lost = [h for h in hosts if h not in moved and sm.map_host(h) is None]
                if lost and not sa.split and not sa.hosts:
                    out.append(
                        Question(
                            id=f"{seg.site_key}/split",
                            group="C Addressing",
                            kind="split",
                            prompt=(
                                f"{seg.key}: {sa.subnet} cannot hold "
                                f"{len(lost)} host offset(s); split map "
                                "OLD=NEW[, OLD=NEW]"
                            ),
                            current=None,
                            default=None,
                            default_source="required",
                            choices=None,
                            validate=_split_validator(
                                a, seg, subnet, hosts, canon.gateway
                            ),
                            depends_on=[sub_q],
                            evidence=[],
                            affects=len(lost),
                            scenario=self.id,
                            segment=seg.key,
                            apply=segment_setter(seg.site_key, "split"),
                            notes=[f"unmapped: {_host_groups(lost)}"],
                        )
                    )
            if len(seg.schemes) > 1 and prof.policy.legacy_scopes == "ask":
                scopes = sorted({sc for s in seg.schemes[1:] for sc in s.scopes})
                out.append(
                    Question(
                        id=f"{seg.site_key}/legacy",
                        group="S Scope",
                        kind="legacy",
                        prompt=(
                            f"{seg.key}: legacy scheme(s) in {', '.join(scopes)}: "
                            "leave or same"
                        ),
                        current="leave",
                        default="leave",
                        default_source="policy",
                        choices=["leave", "same"],
                        validate=lambda v, ans: None,
                        scenario=self.id,
                        segment=seg.key,
                        apply=_legacy_setter(seg.site_key),
                    )
                )
        return out

    @staticmethod
    def _subnet_validator(a: Analysis, seg: Segment) -> Any:
        def validate(value: str, ans: Answers) -> str | None:
            try:
                net = IPv4Network(value.strip(), strict=False)
            except ValueError as exc:
                return str(exc)
            for p in a.protected_prefixes:
                if net.overlaps(p):
                    return f"{net} overlaps protected internal prefix {p}"
            for other in a.segments:
                if other.key == seg.key:
                    continue
                osa = seg_answer(ans, a, other)
                if osa.skip:
                    osa = SegmentAnswer()
                # the other segment's answered subnet is where it will live
                if osa.subnet is not None and net.overlaps(osa.subnet):
                    return f"{net} overlaps segment {other.key} ({osa.subnet})"
                for sch in other.schemes[:1]:
                    if (
                        sch.subnet is not None
                        and net.overlaps(sch.subnet)
                        and osa.subnet is None
                    ):
                        return f"{net} overlaps segment {other.key}"
            return None

        return validate

    @staticmethod
    def _gateway_validator(a: Analysis, seg: Segment) -> Any:
        def validate(value: str, ans: Answers) -> str | None:
            try:
                gw = IPv4Address(value.strip())
            except ValueError as exc:
                return str(exc)
            canon = canonical_scheme(seg)
            sa = seg_answer(ans, a, seg)
            net = sa.subnet or (canon.subnet if canon else None)
            if net is None:
                return None
            if gw not in net:
                return f"{gw} is outside {net}"
            if net.prefixlen < 31 and gw in (
                net.network_address,
                net.broadcast_address,
            ):
                return f"{gw} is the network or broadcast address of {net}"
            old = proven_subnet(a, seg)
            if old is not None and canon is not None:
                owner = _mapped_hosts(a, seg, old, sa, canon.gateway).get(gw)
                if owner is not None:
                    return f"{gw} is the mapped address of baseline host {owner}"
            return None

        return validate

    # ------------------------------------------------------------------ plan

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment:
        frag = PlanFragment()
        active = (
            set(maps.subnets) | set(maps.gateways) | set(maps.seg_exact)
        ) - maps.skipped
        if not active and not maps.exact_ips:
            return frag
        sites = {s.key: s.site_key for s in a.segments}
        for f in a.facts.values():
            if f.kind not in IP_KINDS or not active_fact(f, maps.include_outliers):
                continue
            seg = f.segment or ""
            if seg not in active and not maps.exact_ips:
                continue
            if seg in maps.skipped:
                continue
            try:
                ip = IPv4Address(f.value)
            except ValueError:
                continue
            new = maps.map_ip(seg, ip)
            if new is None:
                continue
            if ip in maps.exact_ips or ip in maps.seg_exact.get(seg, {}):
                prio = PRIO_EXACT
            elif ip in maps.gateways.get(seg, {}):
                prio = PRIO_GATEWAY
            else:
                prio = PRIO_MEMBERSHIP
            new_prefix = None
            sm = maps.subnet_for(seg, ip)
            cur = _fact_prefix(a, f)
            prim = maps.primary.get(seg)
            if cur is not None and prim is not None and cur == prim.old.prefixlen:
                # the segment mask: the answered subnet's mask (split pieces
                # inside it keep it), else the split piece's own mask
                if new in prim.new:
                    new_prefix = prim.new.prefixlen
                elif sm is not None:
                    new_prefix = sm.new.prefixlen
            elif sm is not None and cur is not None and f.mask_form != "wildcard":
                # an ACL wildcard only follows the segment prefix (above): a
                # host match (0.0.0.0) or a wider summary must keep its width
                delta = sm.new.prefixlen - sm.old.prefixlen
                if delta:
                    new_prefix = max(sm.new.prefixlen, min(32, cur + delta))
            if new_prefix == cur:
                new_prefix = None
            if new == ip and new_prefix is None:
                continue
            edits, err = render_fact(a, f, str(new), new_prefix)
            if err is not None:
                frag.findings.append(err)
                continue
            cat = CATEGORY.get(f.kind, "ip")
            what = {"gateway": "gateway", "derived": "derived"}.get(cat, "ip")
            if f.store.kind == "textobject":
                what = "textobject"
            for te in edits:
                is_mask = f.mask_span is not None and te.start == f.mask_span.start
                frag.claims.append(
                    fact_claim(
                        f,
                        te,
                        category="mask" if is_mask else cat,
                        group=group_name(seg, what),
                        question=f"{sites.get(seg, seg)}/"
                        + ("gateway" if prio == PRIO_GATEWAY else "subnet"),
                        priority=prio,
                        scenario=self.id,
                    )
                )
        for key in sorted(maps.legacy_scopes):
            frag.notes.append(
                f"{key}: legacy scopes {', '.join(sorted(maps.legacy_scopes[key]))} "
                "left unchanged"
            )
        return frag
