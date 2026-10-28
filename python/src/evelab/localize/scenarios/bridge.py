"""Cloud bridge per segment (+ carrier follow, ``pnetN`` text mentions).

Questions: one ``<site_key>/bridge`` per segment with cloud networks. Defaults
follow the resolution order of section 9 (answer, lab override, carried segments
for a CARRIER, role default, keep).

Plan: the ``type`` attribute of every cloud network of the segment (xml claim on
the attribute value only), plus cosmetic ``cloud_ref`` tokens (``to pnet0:
EVE-MGMT-203``). A ``cloud_ref`` follows the bridge of the segment whose label is
on the same line; without a label it follows the bridge of every segment on that
cloud, and is skipped as ambiguous when those go to different bridges.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from evelab.common.textutil import token_re

from ..model import Analysis, Confidence, Finding, Segment, Store
from ..profile import Profile
from . import register_scenario
from .base import (
    Answers,
    Claim,
    PlanFragment,
    Question,
    ValueMaps,
    context_text,
    current_bridge,
    fact_claim,
    group_name,
    is_tagged,
    render_fact,
    seg_answer,
    segment_setter,
    text_index,
)

if TYPE_CHECKING:
    from ..manifest import Manifest

XML_STORE = Store("xml", "xml", "-")


def xml_claims(
    a: Analysis,
    net_id: str,
    attr: str,
    new: str,
    *,
    category: str,
    group: str,
    question: str,
    scenario: str,
) -> list[Claim]:
    """Claim replacing ``<network id=net_id> attr=`` (byte span of the value)."""
    out: list[Claim] = []
    for el in a.lab.networks():
        if el.id != net_id or attr not in el.attrs:
            continue
        ra = el.attrs[attr]
        if ra.value == new:
            continue
        out.append(
            Claim(
                store=XML_STORE,
                node_id=None,
                start=ra.span.start,
                end=ra.span.end,
                old=ra.value,
                new=new,
                category=category,
                group=group,
                confidence=Confidence.PROVEN,
                question=question,
                fact_ids=(f"network:{net_id}",),
                rule=f"xml.network.{attr}",
                evidence=f"network {net_id} {attr}={ra.value!r}",
                scenario=scenario,
                xml=(net_id, attr),
            )
        )
    return out


def carried_bridges(
    a: Analysis, seg: Segment, prof: Profile, segs: dict[str, Segment]
) -> dict[str, str]:
    """``{carried key: expected bridge}`` (answer, role default, current)."""
    out: dict[str, str] = {}
    for k in seg.carries:
        if k in segs and segs[k].network_ids:
            csa = seg_answer(prof, a, segs[k])
            out[k] = (
                csa.bridge
                or prof.role_bridge(segs[k].role)
                or current_bridge(a, segs[k])
            )
    return out


def default_bridge(
    a: Analysis, seg: Segment, prof: Profile, segs: dict[str, Segment]
) -> tuple[str, str]:
    """(default bridge, source) for the bridge question."""
    sa = seg_answer(prof, a, seg)
    if sa.bridge:
        return sa.bridge, f"from {seg.site_key}"
    if seg.status == "CARRIER" and seg.carries:
        follow = set(carried_bridges(a, seg, prof, segs).values())
        if len(follow) == 1:
            return follow.pop(), "follows carried"
        if len(follow) > 1:
            return current_bridge(a, seg), "keep (carried segments split)"
    role = prof.role_bridge(seg.role)
    if role:
        return role, f"role {seg.role}"
    return current_bridge(a, seg), "keep"


@register_scenario
class BridgeScenario:
    id = "bridge"
    order = 10

    def applies(self, a: Analysis, m: Manifest | None) -> bool:
        return any(s.network_ids for s in a.segments)

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]:
        segs = {s.key: s for s in a.segments}
        out: list[Question] = []
        # Carriers last: their default follows the answers to the carried segments
        # (the question loop re-collects after every answer).
        for seg in sorted(a.segments, key=lambda s: s.status == "CARRIER"):
            if not seg.network_ids:
                continue
            cur = current_bridge(a, seg)
            default, source = default_bridge(a, seg, prof, segs)
            tagged = is_tagged(seg)

            def validate(
                value: str, ans: Answers, tagged: bool = tagged, key: str = seg.key
            ) -> str | None:
                value = value.strip()
                bp = ans.bridges.get(value)
                if tagged and bp is not None and bp.mode == "untagged-only":
                    return f"{key} is tagged: {value} is untagged-only (structural)"
                if tagged and value.startswith("nat"):
                    return f"{key} is tagged: a nat bridge cannot carry VLANs"
                return None

            choices = sorted({cur, default, *prof.bridges, *prof.roles.values()} - {""})
            notes = []
            if seg.status == "CARRIER":
                notes.append(f"carries {', '.join(seg.carries)}")
                split = carried_bridges(a, seg, prof, segs)
                if len(set(split.values())) > 1:
                    notes.append(
                        "carried segments split across "
                        + ", ".join(f"{k} on {b}" for k, b in split.items())
                        + ": the trunk can follow only one (split L2 domain)"
                    )
            if seg.status == "DHCP":
                notes.append("the target bridge must provide DHCP")
            out.append(
                Question(
                    id=f"{seg.site_key}/bridge",
                    group="A Clouds",
                    kind="bridge",
                    prompt=f"{seg.key} bridge",
                    current=cur,
                    default=default,
                    default_source=source,
                    choices=choices,
                    validate=validate,
                    evidence=[f"network:{n}" for n in seg.network_ids],
                    affects=sum(
                        1
                        for n in seg.network_ids
                        if n in a.networks and a.networks[n].type != default
                    ),
                    scenario=self.id,
                    segment=seg.key,
                    apply=segment_setter(seg.site_key, "bridge"),
                    notes=notes,
                )
            )
        return out

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment:
        frag = PlanFragment()
        for seg in a.segments:
            new = maps.bridges.get(seg.key)
            if not new or seg.key in maps.skipped:
                continue
            for nid in seg.network_ids:
                frag.claims.extend(
                    xml_claims(
                        a,
                        nid,
                        "type",
                        new,
                        category="cloud",
                        group=group_name(seg.key, "cloud"),
                        question=f"{seg.site_key}/bridge",
                        scenario=self.id,
                    )
                )
        if maps.bridges:
            self._cloud_text(a, maps, frag)
        return frag

    def _cloud_text(self, a: Analysis, maps: ValueMaps, frag: PlanFragment) -> None:
        idx = text_index(a)
        on_bridge: dict[str, list[Segment]] = {}
        for seg in a.segments:
            types = {a.networks[n].type for n in seg.network_ids if n in a.networks}
            for t in types:
                on_bridge.setdefault(t, []).append(seg)
        label_res = {
            seg.key: [token_re(lbl) for lbl in sorted(set(seg.labels.values())) if lbl]
            for seg in a.segments
        }
        ambiguous: Counter[str] = Counter()
        for f in a.facts.values():
            if f.kind != "cloud_ref":
                continue
            cands = on_bridge.get(f.value)
            if not cands:
                continue
            text = idx.text(f.store, f.node_id)
            if text is None:
                continue
            line = context_text(f.store, text, f.span.start, f.span.end)
            named = [s for s in cands if any(r.search(line) for r in label_res[s.key])]
            pool = named or cands
            news = {maps.bridges.get(s.key, f.value) for s in pool}
            if len(news) != 1:
                ambiguous[f.value] += 1
                continue
            new = news.pop()
            if new == f.value:
                continue
            edits, err = render_fact(a, f, new)
            if err is not None:
                frag.findings.append(err)
                continue
            for te in edits:
                frag.claims.append(
                    fact_claim(
                        f,
                        te,
                        category="cosmetic",
                        group="cosmetic/pnet-text",
                        question=f"{pool[0].site_key}/bridge",
                        confidence=Confidence.CORRELATED,
                        scenario=self.id,
                    )
                )
        for bridge, n in sorted(ambiguous.items()):
            frag.findings.append(
                Finding(
                    "AMBIGUOUS_CLOUD_REF",
                    "info",
                    f"{n} text mention(s) of {bridge!r} skipped: the segments on it "
                    "move to different bridges",
                )
            )
