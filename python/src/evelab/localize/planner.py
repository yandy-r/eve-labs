"""Planner: answers -> ValueMaps -> scenario claims -> Plan (design 11).

Single pass: every scenario computes its claims from the ORIGINAL texts with the
same :class:`ValueMaps`, so swaps (tag 2<->3, subnet A<->B) cannot chain. Claims
are then resolved together:

* claims on protected facts (unattributed, value-bearing) are dropped with an
  ``error`` finding naming the rule (``PROTECTED_EDIT``);
* identical claims on one span are deduplicated (their provenance merged);
* on one span the highest priority wins (exact > gateway > subnet offset;
  scenario-exact > membership); different replacements at the same priority
  are a ``conflict`` (``CLAIM_CONFLICT``) and the span is left alone;
* overlapping spans are a conflict, except deletions (``new == ""``) that
  contain smaller claims: the deletion wins.

The surviving claims become :class:`~evelab.localize.model.Edit` objects following the
apply offset contract (``apply.py`` module docstring): xml_attr = byte span of
the attribute value; blob/textobject = offsets into the decoded text; sidecar =
offsets into ``apply.sidecar_decode`` text (CRLF files are shown LF-only).
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, replace
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import SCHEMA
from .discover.inventory import protected_fact_ids
from .model import Analysis, Confidence, Edit, Finding, Plan, Segment, Store, TextEdit
from .profile import Answers, SegmentAnswer, parse_ip_range
from .profile import dumps as dump_profile
from .scenarios import ordered
from .scenarios.base import (
    Claim,
    PlanFragment,
    Question,
    SubnetMap,
    ValueMaps,
    canonical_scheme,
    current_bridge,
    is_tagged,
    seg_answer,
    text_index,
)

if TYPE_CHECKING:
    from .manifest import Manifest

__all__ = [
    "PlanOptions",
    "SubnetMap",
    "ValueMaps",
    "build_plan",
    "build_value_maps",
    "collect_questions",
    "dumps_plan",
    "enabled_edits",
    "explain",
    "filter_enabled",
    "loads_plan",
    "plan_from_dict",
    "plan_to_dict",
    "resolve_claims",
]

IP_FACT_KINDS = frozenset({"ip_host", "ip_gateway", "peer_ip", "router_id"})
HEURISTIC_SUFFIX = ":heuristic"
COSMETIC_PREFIX = "cosmetic/"
OUTLIER_PREFIX = "outliers/"


@dataclass
class PlanOptions:
    """Knobs for :func:`build_plan` (None = take the value from the answers)."""

    manifest: Manifest | None = None
    lab_id: str | None = None  # default: the lab's own id
    include_heuristic: bool | None = None  # default ans.policy.include_heuristic
    cosmetic_text: bool | None = None  # default ans.policy.cosmetic_text
    include_outliers: bool = False
    legacy_scopes: str | None = None  # leave | same (default ans.policy / ask)
    scenarios: Collection[str] | None = None  # restrict to these scenario ids
    enable_scenarios: Collection[str] = ()  # force-enable gated scenarios
    extra_groups: Collection[str] = ()  # additionally enabled groups
    disabled_groups: Collection[str] = ()
    # Labels an earlier apply wrote into device text (state.json
    # ``baseline_text_labels`` keys): their references follow a rename even when
    # the label is not distinctive, so revert undoes exactly what apply wrote.
    written_labels: Collection[str] = ()


# --------------------------------------------------------------------------- #
# Value maps
# --------------------------------------------------------------------------- #


def _legacy_policy(ans: Answers, seg: Segment, opts: PlanOptions) -> str:
    if opts.legacy_scopes:
        return opts.legacy_scopes
    sc = ans.scenarios.get("scopes")
    if sc is not None:
        choice = sc.options.get(seg.site_key)
        if isinstance(choice, str) and choice in ("leave", "same"):
            return choice
    if opts.manifest is not None:
        for lg in opts.manifest.legacy:
            if lg.segment == seg.key and lg.policy in ("leave", "same"):
                return lg.policy
    pol = ans.policy.legacy_scopes
    return pol if pol in ("leave", "same") else "leave"


def _carrier_split(
    a: Analysis, answers: dict[str, SegmentAnswer], maps: ValueMaps
) -> list[Finding]:
    """``CARRIER_SPLIT``: a trunk and the segments it carries on different bridges.

    Only reported when the resolved bridges move one of them (a lab that already
    is split stays quiet). A ``conflict`` when the carried segments go to several
    bridges and the carrier has no explicit answer (the tool cannot choose which
    one the trunk follows); otherwise a ``warn``: separate host bridges may be
    joined outside EVE, so an explicit answer is honoured.
    """
    segs = {s.key: s for s in a.segments}
    out: list[Finding] = []
    for seg in a.segments:
        if seg.status != "CARRIER" or not seg.network_ids:
            continue
        carried = [segs[k] for k in seg.carries if k in segs and segs[k].network_ids]
        keys = [seg.key, *(c.key for c in carried)]
        if not carried or not any(k in maps.bridges for k in keys):
            continue

        def final(s: Segment) -> str:
            return maps.bridges.get(s.key, current_bridge(a, s))

        mine = final(seg)
        where = {c.key: final(c) for c in carried}
        if all(b == mine for b in where.values()):
            continue
        detail = ", ".join(f"{k} on {b}" for k, b in where.items())
        site_key = seg.site_key
        explicit = answers[seg.key].bridge is not None
        if len(set(where.values())) > 1 and not explicit:
            out.append(
                Finding(
                    "CARRIER_SPLIT",
                    "conflict",
                    f"{seg.key} carries segments that go to different bridges "
                    f"({detail}); the trunk would stay on {mine}: answer "
                    f"{site_key}/bridge explicitly or put the carried segments on "
                    "one bridge",
                    [f"segment:{seg.key}", *(f"segment:{k}" for k in where)],
                )
            )
            continue
        out.append(
            Finding(
                "CARRIER_SPLIT",
                "warn",
                f"{seg.key} (trunk) on {mine} but {detail}: their VLANs will exist "
                "on more than one bridge (split L2 domain unless the bridges are "
                "joined outside EVE)",
                [f"segment:{seg.key}", *(f"segment:{k}" for k in where)],
            )
        )
    return out


def build_value_maps(
    a: Analysis, ans: Answers, opts: PlanOptions | None = None
) -> tuple[ValueMaps, list[Finding]]:
    """Resolve the answers for every segment into one :class:`ValueMaps`."""
    from .scenarios import labels as labels_mod

    opts = opts or PlanOptions()
    lab_id = opts.lab_id or a.lab.lab_id
    maps = ValueMaps(
        lab_id=lab_id,
        manifest=opts.manifest,
        include_outliers=opts.include_outliers,
        subif_policy=(
            opts.manifest.subif_policy
            if opts.manifest is not None and ans.policy.subif_policy == "rename"
            else ans.policy.subif_policy
        ),
        cosmetic_text=(
            ans.policy.cosmetic_text
            if opts.cosmetic_text is None
            else opts.cosmetic_text
        ),
    )
    findings: list[Finding] = []
    segs = {s.key: s for s in a.segments}
    answers = {s.key: seg_answer(ans, a, s) for s in a.segments}

    # -- bridges (carriers follow the segments they carry)
    for seg in a.segments:
        sa = answers[seg.key]
        if sa.skip:
            maps.skipped.add(seg.key)
            continue
        for nid, name in seg.labels.items():
            maps.old_labels[nid] = name
    for seg in sorted(a.segments, key=lambda s: s.status == "CARRIER"):
        if seg.key in maps.skipped:
            continue
        sa = answers[seg.key]
        cur = current_bridge(a, seg)
        new = sa.bridge
        source = "answer"
        if new is None and seg.status == "CARRIER" and seg.carries:
            follow = {
                maps.bridges.get(k, current_bridge(a, segs[k]))
                for k in seg.carries
                if k in segs and segs[k].network_ids
            }
            if len(follow) == 1:
                new, source = follow.pop(), "carried segments"
        if new is None:
            new, source = ans.role_bridge(seg.role), "role default"
        if new is None or (
            new == cur
            and all(
                a.networks[n].type == new for n in seg.network_ids if n in a.networks
            )
        ):
            continue
        if not ans.bridge_allowed(new):
            findings.append(
                Finding(
                    "BAD_BRIDGE",
                    "error",
                    f"{seg.key}: bridge {new!r} ({source}) is not pnetN/natN/cloudN "
                    "and not declared in [bridges]",
                    [f"segment:{seg.key}"],
                )
            )
            continue
        bp = ans.bridges.get(new)
        if is_tagged(seg) and (
            (bp is not None and bp.mode == "untagged-only") or new.startswith("nat")
        ):
            findings.append(
                Finding(
                    "STRUCTURAL_TAGGING",
                    "blocker",
                    f"{seg.key}: tagged segment cannot move to untagged-only bridge "
                    f"{new!r} ({source})",
                    [f"segment:{seg.key}"],
                )
            )
            continue
        maps.bridges[seg.key] = new
    findings.extend(_carrier_split(a, answers, maps))

    # -- tags / subnets / gateways / hosts
    for seg in a.segments:
        if seg.key in maps.skipped:
            continue
        sa = answers[seg.key]
        canon = canonical_scheme(seg)
        legacy = seg.schemes[1:]
        policy = _legacy_policy(ans, seg, opts) if legacy else "leave"
        if sa.vlan is not None:
            if canon is None or not isinstance(canon.tag, int):
                findings.append(
                    Finding(
                        "TAG_NOT_APPLICABLE",
                        "warn",
                        f"{seg.key}: VLAN answer {sa.vlan} ignored: the segment "
                        "arrives untagged (changing the tagging structure is not "
                        "supported)",
                        [f"segment:{seg.key}"],
                    )
                )
            else:
                if sa.vlan != canon.tag:
                    maps.tags[(seg.key, canon.tag)] = sa.vlan
                if policy == "same":
                    for sch in legacy:
                        if isinstance(sch.tag, int) and sch.tag != sa.vlan:
                            maps.tags.setdefault((seg.key, sch.tag), sa.vlan)
        sub_maps: list[SubnetMap] = []
        scheme_nets = [sch.subnet for sch in seg.schemes if sch.subnet is not None]
        for old, new in (sa.split or {}).items():
            # A split entry outside every discovered subnet is stale (already
            # applied on a re-run): ignore it (T21 fix).
            if any(old.overlaps(net) for net in scheme_nets):
                sub_maps.append(SubnetMap(old, new))
        if sa.subnet is not None:
            if canon is None or canon.subnet is None:
                findings.append(
                    Finding(
                        "SUBNET_NOT_APPLICABLE",
                        "warn",
                        f"{seg.key}: subnet answer {sa.subnet} ignored: no subnet "
                        f"was discovered ({seg.status})",
                        [f"segment:{seg.key}"],
                    )
                )
            else:
                maps.primary[seg.key] = SubnetMap(canon.subnet, sa.subnet)
                if sa.subnet != canon.subnet or sub_maps:
                    sub_maps.append(SubnetMap(canon.subnet, sa.subnet))
                if policy == "same":
                    for sch in legacy:
                        if sch.subnet is not None and sch.subnet != canon.subnet:
                            sub_maps.append(SubnetMap(sch.subnet, sa.subnet))
        sub_maps = [m for m in sub_maps if m.old != m.new]
        if sub_maps:
            maps.subnets[seg.key] = sub_maps
        if sa.gateway is not None:
            if canon is None or canon.gateway is None:
                findings.append(
                    Finding(
                        "GATEWAY_NOT_APPLICABLE",
                        "warn",
                        f"{seg.key}: gateway answer {sa.gateway} ignored: no gateway "
                        "was discovered",
                        [f"segment:{seg.key}"],
                    )
                )
            else:
                gws = {canon.gateway: sa.gateway}
                if policy == "same":
                    for sch in legacy:
                        if sch.gateway is not None:
                            gws.setdefault(sch.gateway, sa.gateway)
                gws = {o: n for o, n in gws.items() if o != n}
                if gws:
                    maps.gateways[seg.key] = gws
        if sa.hosts:
            maps.seg_exact[seg.key] = {o: n for o, n in sa.hosts.items() if o != n}
        if (
            legacy
            and policy == "leave"
            and (
                seg.key in maps.subnets
                or any(k[0] == seg.key for k in maps.tags)
                or seg.key in maps.gateways
            )
        ):
            scopes = sorted({sc for sch in legacy for sc in sch.scopes})
            maps.legacy_scopes[seg.key] = set(scopes)
            findings.append(
                Finding(
                    "LEGACY_LEFT",
                    "warn",
                    f"{seg.key}: legacy scheme(s) left unchanged in scope(s) "
                    f"{', '.join(scopes)} (legacy_scopes=leave)",
                    [f"segment:{seg.key}"],
                )
            )

    # -- labels
    kept_text: set[tuple[str, str]] = set()
    for seg in a.segments:
        if seg.key in maps.skipped:
            continue
        renames = labels_mod.label_renames(a, seg, answers[seg.key], maps)
        for nid, new in renames.items():
            maps.labels[nid] = new
            old = seg.labels.get(nid, "")
            follows = old in opts.written_labels or labels_mod.distinctive(
                old, a, opts.manifest
            )
            if (
                follows
                and old != new
                and not labels_mod.text_safe(new, a, opts.manifest)
            ):
                if (old, new) not in kept_text:
                    kept_text.add((old, new))
                    findings.append(
                        Finding(
                            "LABEL_TEXT_KEPT",
                            "warn",
                            f"{seg.key}: new label {new!r} is not distinctive (needs "
                            "5+ letters/digits/_/- with a digit or '-'): text "
                            f"references to {old!r} are left unchanged so revert "
                            "stays exact",
                            [f"segment:{seg.key}"],
                        )
                    )
                follows = False
            if old and old != new and follows:
                prev = maps.text_labels.get(old)
                if prev is not None and prev != new:
                    findings.append(
                        Finding(
                            "LABEL_AMBIGUOUS",
                            "warn",
                            f"label {old!r} maps to both {prev!r} and {new!r}: text "
                            "references are left unchanged",
                            [f"segment:{seg.key}"],
                        )
                    )
                    maps.text_labels[old] = ""
                elif prev is None:
                    maps.text_labels[old] = new
    maps.text_labels = {o: n for o, n in maps.text_labels.items() if n}

    # -- services / routes / secrets (consumed by the extra scenarios)
    for kind, table in ans.maps.items():
        for old, new in table.items():
            if old != new:
                maps.services[(kind, old)] = new
    for seg in a.segments:
        if seg.site_key in ans.site_routes:
            maps.routes[seg.key] = list(ans.site_routes[seg.site_key])
    for name in ans.secrets:
        value = ans.secret_value(name)
        if value is not None:
            maps.secrets[name] = value

    findings.extend(_validate_maps(a, ans, maps, answers))
    return maps, findings


def _final_subnet(maps: ValueMaps, seg: Segment) -> IPv4Network | None:
    canon = canonical_scheme(seg)
    if canon is None or canon.subnet is None:
        return None
    for sm in maps.subnets.get(seg.key, ()):
        if sm.old == canon.subnet:
            return sm.new
    return canon.subnet


def _segment_hosts(a: Analysis, seg: Segment, maps: ValueMaps) -> set[IPv4Address]:
    canon = canonical_scheme(seg)
    out: set[IPv4Address] = set()
    if canon is None or canon.subnet is None:
        return out
    for f in a.facts.values():
        if f.segment != seg.key or f.kind not in IP_FACT_KINDS:
            continue
        if "outlier" in f.flags and not maps.include_outliers:
            continue
        try:
            ip = IPv4Address(f.value)
        except ValueError:
            continue
        if ip in canon.subnet:
            out.add(ip)
    return out


def _is_manifest_vlan(maps: ValueMaps, key: str, vlan: int) -> bool:
    m = maps.manifest
    seg = m.segment(key) if m is not None else None
    return seg is not None and seg.baseline.vlan == vlan


def _validate_maps(
    a: Analysis, ans: Answers, maps: ValueMaps, answers: dict[str, Any]
) -> list[Finding]:
    out: list[Finding] = []
    # VLANs: protected / duplicate on the target bridge
    for (key, old), new in sorted(maps.tags.items()):
        seg = next(s for s in a.segments if s.key == key)
        scopes = {sc for sch in seg.schemes for sc in sch.scopes} or set(
            a.protected_vlans
        )
        hit = sorted(sc for sc in scopes if new in a.protected_vlans.get(sc, set()))
        if hit and _is_manifest_vlan(maps, key, new):
            # Back to the committed baseline (revert): that VLAN coexisted with the
            # internal reuse by design, so it is not a collision (T21 fix).
            out.append(
                Finding(
                    "VLAN_PROTECTED",
                    "info",
                    f"{key}: new VLAN {new} (was {old}) is the manifest baseline; "
                    f"it is also used internally in scope(s) {', '.join(hit)}",
                    [f"segment:{key}", f"vlan:{new}"],
                )
            )
        elif hit:
            out.append(
                Finding(
                    "VLAN_PROTECTED",
                    "blocker",
                    f"{key}: new VLAN {new} (was {old}) collides with a protected "
                    f"internal or platform-reserved VLAN in scope(s) {', '.join(hit)}",
                    [f"segment:{key}", f"vlan:{new}"],
                )
            )
    final: dict[tuple[str, int], list[str]] = {}
    for seg in a.segments:
        canon = canonical_scheme(seg)
        if seg.status == "CARRIER" or canon is None or not isinstance(canon.tag, int):
            continue
        tag = maps.tags.get((seg.key, canon.tag), canon.tag)
        bridge = maps.bridges.get(seg.key, current_bridge(a, seg))
        final.setdefault((bridge, tag), []).append(seg.key)
    for (bridge, tag), keys in sorted(final.items()):
        if len(keys) > 1 and any(
            (k, canonical_scheme(s).tag) in maps.tags  # type: ignore[union-attr]
            for k in keys
            for s in a.segments
            if s.key == k
        ):
            out.append(
                Finding(
                    "VLAN_DUPLICATE",
                    "conflict",
                    f"VLAN {tag} on bridge {bridge} would carry segments "
                    f"{', '.join(keys)}",
                    [f"segment:{k}" for k in keys],
                )
            )
    # subnets: fit, overlaps, gateway sanity, reserved ranges
    finals: dict[str, IPv4Network] = {}
    for seg in a.segments:
        net = _final_subnet(maps, seg)
        if net is not None:
            finals[seg.key] = net
        if seg.key not in maps.subnets and seg.key not in maps.seg_exact:
            continue
        hosts = _segment_hosts(a, seg, maps)
        lost = sorted(h for h in hosts if maps.map_ip(seg.key, h) is None)
        if lost:
            out.append(
                Finding(
                    "SPLIT_REQUIRED",
                    "blocker",
                    f"{seg.key}: the new prefix cannot hold {len(lost)} baseline "
                    f"host offset(s) ({', '.join(map(str, lost[:8]))}"
                    f"{', ...' if len(lost) > 8 else ''}); answer a split map or "
                    "host overrides",
                    [f"segment:{seg.key}"],
                )
            )
        mapped = {
            m for h in hosts if (m := maps.map_ip(seg.key, h)) is not None and m != h
        }
        sa = answers[seg.key]
        for what, spec in (("reserved", sa.reserved), ("dhcp_pool", sa.dhcp_pool)):
            ranges = spec if isinstance(spec, list) else ([spec] if spec else [])
            for r in ranges:
                try:
                    lo, hi = parse_ip_range(r)
                except ValueError:
                    continue
                inside = sorted(m for m in mapped if lo <= m <= hi)
                if inside:
                    out.append(
                        Finding(
                            "HOST_RESERVED",
                            "warn",
                            f"{seg.key}: mapped host(s) "
                            f"{', '.join(map(str, inside[:8]))} fall inside "
                            f"{what} {r}",
                            [f"segment:{seg.key}"],
                        )
                    )
        for old_gw, new_gw in maps.gateways.get(seg.key, {}).items():
            net = finals.get(seg.key)
            bad = None
            if net is not None and new_gw not in net:
                bad = f"outside {net}"
            elif (
                net is not None
                and net.prefixlen < 31
                and new_gw
                in (
                    net.network_address,
                    net.broadcast_address,
                )
            ):
                bad = "the network or broadcast address"
            elif new_gw in mapped - {maps.map_ip(seg.key, old_gw)}:
                bad = "equal to a mapped host"
            if bad:
                out.append(
                    Finding(
                        "GATEWAY_INVALID",
                        "conflict",
                        f"{seg.key}: gateway {new_gw} is {bad}",
                        [f"segment:{seg.key}"],
                    )
                )
    changed = {k for k in finals if k in maps.subnets}
    for key in sorted(changed):
        net = finals[key]
        for p in a.protected_prefixes:
            if net.overlaps(p):
                out.append(
                    Finding(
                        "SUBNET_OVERLAP",
                        "conflict",
                        f"{key}: new subnet {net} overlaps protected prefix {p}",
                        [f"segment:{key}", f"prefix:{p}"],
                    )
                )
                break
        for other, onet in sorted(finals.items()):
            if other != key and net.overlaps(onet):
                if other in changed and other < key:
                    continue  # reported once
                out.append(
                    Finding(
                        "SUBNET_OVERLAP",
                        "conflict",
                        f"{key}: new subnet {net} overlaps segment {other} ({onet})",
                        [f"segment:{key}", f"segment:{other}"],
                    )
                )
    return out


# --------------------------------------------------------------------------- #
# Claims
# --------------------------------------------------------------------------- #


def _claim_text_ok(a: Analysis, c: Claim) -> bool:
    if c.store.kind == "xml":
        return True
    text = text_index(a).text(c.store, c.node_id)
    return text is not None and text[c.start : c.end] == c.old


def resolve_claims(
    a: Analysis, claims: Iterable[Claim]
) -> tuple[list[Claim], list[Finding]]:
    """Dedupe, apply precedence, drop protected/conflicting claims."""
    findings: list[Finding] = []
    protected = protected_fact_ids(a.facts)
    by_span: dict[tuple[Any, ...], list[Claim]] = {}
    for c in claims:
        if c.old == c.new:
            continue
        if not c.exact and any(fid in protected for fid in c.fact_ids):
            fid = next(fid for fid in c.fact_ids if fid in protected)
            fact = a.facts.get(fid)
            findings.append(
                Finding(
                    "PROTECTED_EDIT",
                    "error",
                    f"{c.scenario or 'scenario'} tried to edit protected fact {fid} "
                    f"(rule {fact.rule if fact else c.rule}, value {c.old!r})",
                    [fid],
                )
            )
            continue
        if not _claim_text_ok(a, c):
            findings.append(
                Finding(
                    "STALE_CLAIM",
                    "error",
                    f"{c.scenario}: span {c.start}:{c.end} of {c.store.kind}:"
                    f"{c.store.name} node {c.node_id} does not hold {c.old!r}",
                    list(c.fact_ids),
                )
            )
            continue
        by_span.setdefault(c.key, []).append(c)
    winners: list[Claim] = []
    for span_claims in by_span.values():
        top = max(c.priority for c in span_claims)
        best = [c for c in span_claims if c.priority == top]
        news = {c.new for c in best}
        if len(news) > 1:
            c0 = best[0]
            findings.append(
                Finding(
                    "CLAIM_CONFLICT",
                    "conflict",
                    f"{c0.store.kind}:{c0.store.name} node {c0.node_id} "
                    f"{c0.old!r}: conflicting replacements "
                    f"{', '.join(sorted(repr(n) for n in news))}",
                    sorted({fid for c in best for fid in c.fact_ids}),
                )
            )
            continue
        merged = best[0]
        extra = [fid for c in best[1:] for fid in c.fact_ids]
        if extra:
            ids = tuple(dict.fromkeys((*merged.fact_ids, *extra)))
            merged = replace(merged, fact_ids=ids)
        winners.append(merged)
    # overlapping spans inside one store text
    winners.sort(key=lambda c: (tuple(c.store), c.node_id or "", c.start, -c.end))
    out: list[Claim] = []
    dropped: set[int] = set()
    for i, c in enumerate(winners):
        if i in dropped:
            continue
        j = i + 1
        while j < len(winners):
            d = winners[j]
            if (d.store, d.node_id or "") != (c.store, c.node_id or ""):
                break
            if d.start >= c.end and not (d.start == c.start == c.end):
                break
            if j not in dropped:
                if c.new == "" and c.start <= d.start and d.end <= c.end:
                    dropped.add(j)  # deletion swallows the smaller claim
                else:
                    findings.append(
                        Finding(
                            "CLAIM_OVERLAP",
                            "conflict",
                            f"{c.store.kind}:{c.store.name} node {c.node_id}: "
                            f"overlapping edits {c.old!r} and {d.old!r}",
                            sorted({*c.fact_ids, *d.fact_ids}),
                        )
                    )
                    dropped.update({i, j})
            j += 1
        if i not in dropped:
            out.append(c)
    return out, findings


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _crlf_shift(text: str) -> list[int] | None:
    """Offsets of every CR of a CRLF-consistent text (None if not CRLF)."""
    lf = text.count("\n")
    if not lf or text.count("\r\n") != lf:
        return None
    return [
        i for i, ch in enumerate(text) if ch == "\r" and text[i + 1 : i + 2] == "\n"
    ]


def _to_lf(pos: int, crs: list[int]) -> int:
    import bisect

    return pos - bisect.bisect_left(crs, pos)


def _edit_id(c: Claim) -> str:
    raw = "\x1f".join(
        (*c.store, c.node_id or "", str(c.start), str(c.end), c.old, c.new)
    )
    return "e" + hashlib.sha1(raw.encode("utf-8", "surrogateescape")).hexdigest()[:11]


def _claim_to_edit(a: Analysis, c: Claim, crlf: dict[str, list[int] | None]) -> Edit:
    lab_name = a.lab.path.name if a.lab.path else "lab.unl"
    start, end, old, new = c.start, c.end, c.old, c.new
    if c.store.kind == "xml":
        target, file = "xml_attr", lab_name
    elif c.store.kind == "sidecar":
        target, file = "sidecar", c.store.name
        if c.store.name not in crlf:
            text = text_index(a).text(c.store, c.node_id) or ""
            crlf[c.store.name] = _crlf_shift(text)
        crs = crlf[c.store.name]
        if crs is not None:
            start, end = _to_lf(start, crs), _to_lf(end, crs)
            old, new = old.replace("\r\n", "\n"), new.replace("\r\n", "\n")
    elif c.store.kind == "textobject":
        target, file = "textobject", lab_name
    else:
        target, file = "blob", lab_name
    group = c.group
    if c.confidence == Confidence.HEURISTIC and not group.endswith(HEURISTIC_SUFFIX):
        group += HEURISTIC_SUFFIX
    prov = [
        c.question,
        ",".join(c.fact_ids),
        c.rule,
        c.evidence,
        f"scenario:{c.scenario}" if c.scenario else "",
    ]
    return Edit(
        id=_edit_id(c),
        file=Path(file),
        target=target,  # type: ignore[arg-type]
        store=c.store,
        node_id=c.node_id,
        text_edit=TextEdit(start, end, old, new),
        category=c.category,
        group=group,
        confidence=c.confidence,
        secret=c.secret,
        provenance=prov,
    )


def _answers_digest(ans: Answers, lab_id: str) -> str:
    try:
        text = dump_profile(ans)
    except Exception:  # noqa: BLE001 - digest must never fail planning
        text = repr(ans)
    return hashlib.sha256(f"{lab_id}\n{text}".encode()).hexdigest()


def _applies(sc: Any, a: Analysis, opts: PlanOptions) -> bool:
    """``sc.applies()``; an exception is not swallowed silently: it becomes a
    ``SCENARIO_FAILED`` error finding on the analysis (shown by scan, carried
    into the plan, blocking apply) and the scenario is skipped (review #32/#39).
    """
    try:
        return bool(sc.applies(a, opts.manifest))
    except Exception as exc:  # noqa: BLE001 - reported as SCENARIO_FAILED
        msg = f"scenario {sc.id}: applies() raised {type(exc).__name__}: {exc}"
        if not any(f.code == "SCENARIO_FAILED" and f.msg == msg for f in a.findings):
            a.findings.append(Finding("SCENARIO_FAILED", "error", msg))
        return False


def _scenario_enabled(sc: Any, a: Analysis, ans: Answers, opts: PlanOptions) -> bool:
    sid = sc.id
    if opts.scenarios is not None and sid not in opts.scenarios:
        return False
    if not _applies(sc, a, opts):
        return False
    if getattr(sc, "gated", False):
        if sid in opts.enable_scenarios:
            return True
        return ans.scenario_enabled(sid, opts.lab_id or a.lab.lab_id) is True
    return True


def collect_questions(
    a: Analysis, ans: Answers, opts: PlanOptions | None = None
) -> list[Question]:
    """Questions of every applicable scenario (gated ones included: they ask)."""
    opts = opts or PlanOptions()
    out: list[Question] = []
    for sc in ordered():
        if opts.scenarios is not None and sc.id not in opts.scenarios:
            continue
        if not _applies(sc, a, opts):
            continue
        out.extend(sc.questions(a, opts.manifest, ans))
    return out


def build_plan(a: Analysis, ans: Answers, opts: PlanOptions | None = None) -> Plan:
    """Section 3.2: the full plan for one analysed lab."""
    opts = opts or PlanOptions()
    lab_id = opts.lab_id or a.lab.lab_id
    maps, findings = build_value_maps(a, ans, opts)
    frag = PlanFragment()
    scenarios = [sc for sc in ordered() if _scenario_enabled(sc, a, ans, opts)]
    for sc in scenarios:
        contribute = getattr(sc, "contribute", None)
        if contribute is not None:
            contribute(a, ans, maps)
    for sc in scenarios:
        part = sc.plan(a, ans, maps)
        for c in part.claims:
            if not c.scenario:
                c.scenario = sc.id
        frag.extend(part)
    claims, cfind = resolve_claims(a, frag.claims)
    findings.extend(frag.findings)
    findings.extend(cfind)
    findings.extend(
        f for f in a.findings if f.severity in ("conflict", "blocker", "error")
    )
    crlf: dict[str, list[int] | None] = {}
    edits = [_claim_to_edit(a, c, crlf) for c in claims]
    edits.sort(
        key=lambda e: (str(e.file), tuple(e.store), e.node_id or "", e.text_edit.start)
    )
    if edits and getattr(a.lab, "read_only", False):
        findings.append(
            Finding(
                "READ_ONLY_LAB",
                "blocker",
                "the lab layout is not fully understood (read-only): "
                + "; ".join(getattr(a.lab, "layout_issues", [])[:3]),
            )
        )
    include_heur = (
        ans.policy.include_heuristic
        if opts.include_heuristic is None
        else opts.include_heuristic
    )
    groups = {e.group for e in edits}
    enabled = {
        g
        for g in groups
        if not (g.endswith(HEURISTIC_SUFFIX) and not include_heur)
        and not (g.startswith(COSMETIC_PREFIX) and not maps.cosmetic_text)
        and not g.startswith(OUTLIER_PREFIX)
        and g not in opts.disabled_groups
    }
    enabled |= set(opts.extra_groups) & groups
    lab_path = Path(a.lab.path) if a.lab.path else Path("lab.unl")
    base: dict[str, str] = {}
    if a.lab.path:
        base[lab_path.name] = getattr(a.lab, "sha256", "") or _sha_file(lab_path)
    for e in edits:
        key = str(e.file)
        if key not in base:
            p = lab_path.parent / key
            base[key] = _sha_file(p) if p.is_file() else ""
    return Plan(
        schema=SCHEMA,
        lab=lab_path,
        lab_id=lab_id,
        base_sha256=base,
        answers_digest=_answers_digest(ans, lab_id),
        edits=edits,
        enabled_groups=enabled,
        findings=_dedupe_findings(findings),
    )


def _dedupe_findings(findings: Sequence[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        sig = (f.code, f.severity, f.msg)
        if sig not in seen:
            seen.add(sig)
            out.append(f)
    return out


def enabled_edits(plan: Plan) -> list[Edit]:
    return [e for e in plan.edits if e.group in plan.enabled_groups]


def filter_enabled(plan: Plan) -> Plan:
    """Copy of ``plan`` holding only the edits of enabled groups (for summaries)."""
    return replace(plan, edits=enabled_edits(plan))


def group_counts(plan: Plan) -> Counter[str]:
    return Counter(e.group for e in plan.edits)


def explain(plan: Plan, edit_id: str) -> list[str]:
    """Human-readable provenance chain of one edit (question -> facts -> rule)."""
    e = next((x for x in plan.edits if x.id == edit_id), None)
    if e is None:
        raise KeyError(edit_id)
    prov = list(e.provenance) + [""] * (5 - len(e.provenance))
    question, facts, rule, evidence, scenario = prov[:5]
    new = "<secret>" if e.secret else e.text_edit.new
    old = "<secret>" if e.secret else e.text_edit.old
    where = f"{e.file} :: {e.store.kind}:{e.store.name}"
    if e.node_id:
        where += f" :: node {e.node_id}"
    lines = [
        f"edit {e.id}: {old!r} -> {new!r}",
        f"where: {where} [{e.target} {e.text_edit.start}:{e.text_edit.end}]",
        f"group: {e.group} ({'enabled' if e.group in plan.enabled_groups else 'off'})"
        f" · category {e.category} · {e.confidence.name}",
    ]
    if scenario:
        lines.append(scenario.replace("scenario:", "scenario: "))
    if question:
        lines.append(f"question: {question}")
    if facts:
        lines.append(f"fact(s): {facts}")
    if rule:
        lines.append(f"rule: {rule}")
    if evidence:
        lines.append(f"evidence: {evidence}")
    return lines


# --------------------------------------------------------------------------- #
# Plan JSON
# --------------------------------------------------------------------------- #

REDACTED = "<redacted>"


def plan_to_dict(plan: Plan, *, include_secrets: bool = False) -> dict[str, Any]:
    """JSON-ready dict; secret replacement text is redacted unless asked."""
    edits = []
    for e in plan.edits:
        te = e.text_edit
        new = te.new
        old = te.old
        if e.secret and not include_secrets:
            new = REDACTED
            old = REDACTED
        edits.append(
            {
                "id": e.id,
                "file": str(e.file),
                "target": e.target,
                "store": list(e.store),
                "node_id": e.node_id,
                "start": te.start,
                "end": te.end,
                "old": old,
                "new": new,
                "category": e.category,
                "group": e.group,
                "confidence": e.confidence.name,
                "secret": e.secret,
                "provenance": list(e.provenance),
            }
        )
    return {
        "schema": plan.schema,
        "lab": str(plan.lab),
        "lab_id": plan.lab_id,
        "base_sha256": dict(sorted(plan.base_sha256.items())),
        "answers_digest": plan.answers_digest,
        "enabled_groups": sorted(plan.enabled_groups),
        "findings": [
            {"code": f.code, "severity": f.severity, "msg": f.msg, "refs": f.refs}
            for f in plan.findings
        ],
        "edits": edits,
    }


def plan_from_dict(data: dict[str, Any]) -> Plan:
    """Inverse of :func:`plan_to_dict`; redacted secret edits are disabled."""
    edits: list[Edit] = []
    findings = [
        Finding(f["code"], f["severity"], f["msg"], list(f.get("refs", [])))
        for f in data.get("findings", [])
    ]
    enabled = set(data.get("enabled_groups", []))
    for d in data.get("edits", []):
        st = d["store"]
        e = Edit(
            id=d["id"],
            file=Path(d["file"]),
            target=d["target"],
            store=Store(st[0], st[1], st[2]),
            node_id=d.get("node_id"),
            text_edit=TextEdit(d["start"], d["end"], d["old"], d["new"]),
            category=d["category"],
            group=d["group"],
            confidence=Confidence[d["confidence"]],
            secret=bool(d.get("secret")),
            provenance=list(d.get("provenance", [])),
        )
        if e.secret and e.text_edit.new == REDACTED and e.group in enabled:
            enabled.discard(e.group)
            findings.append(
                Finding(
                    "SECRET_REDACTED",
                    "warn",
                    f"group {e.group} disabled: the saved plan has no secret values",
                    [e.id],
                )
            )
        edits.append(e)
    return Plan(
        schema=int(data.get("schema", SCHEMA)),
        lab=Path(data["lab"]),
        lab_id=data.get("lab_id", ""),
        base_sha256=dict(data.get("base_sha256", {})),
        answers_digest=data.get("answers_digest", ""),
        edits=edits,
        enabled_groups=enabled,
        findings=findings,
    )


def dumps_plan(plan: Plan, *, include_secrets: bool = False) -> str:
    return json.dumps(
        plan_to_dict(plan, include_secrets=include_secrets),
        indent=2,
        ensure_ascii=False,
    )


def loads_plan(text: str) -> Plan:
    return plan_from_dict(json.loads(text))
