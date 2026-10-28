"""VLAN tags (+ subif / SVI rename, VLAN lists, ``(VLAN n)`` mentions).

Questions: ``<site_key>/vlan`` only when the canonical scheme tag is numeric and
PROVEN tag-bearing facts carry it (never for untagged/unknown segments, never
for internal-only tags).

Plan (section 11.3):

* ``vlan_tag`` / ``vlan_def`` facts attributed to the segment whose value has a
  tag mapping are re-rendered;
* ``vlan_list`` facts are remapped with ``VlanList.replace`` over every external
  tag of that config (one list may carry several segments; all replacements are
  simultaneous, so swaps work); a collision is a conflict;
* ``subif_policy = "rename"``: a subinterface ``X.<old>`` / SVI ``Vlan<old>``
  becomes ``X.<new>`` / ``Vlan<new>`` together with every whole-token reference
  (full or abbreviated name) in the same config; an existing target name is a
  conflict unless it is itself renamed away (swap);
* cosmetic ``vlan_mention`` tokens are rewritten only on lines (text nodes) that
  also hold one of the segment's old or new labels.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from evelab.common.textutil import VlanList, VlanListError, token_re

from ..discover.l2trace import fact_vlans
from ..model import Analysis, Confidence, Fact, Finding, Store, TextEdit
from ..profile import Profile
from . import register_scenario
from .base import (
    Answers,
    PlanFragment,
    Question,
    ValueMaps,
    active_fact,
    canonical_scheme,
    context_text,
    fact_claim,
    group_name,
    render_fact,
    seg_answer,
    segment_setter,
    text_index,
)

if TYPE_CHECKING:
    from ..manifest import Manifest

TAG_KINDS = frozenset({"vlan_tag", "vlan_def"})
PROVEN_TAG_KINDS = frozenset({"vlan_tag", "subif_name", "vlan_list", "svi_name"})
_NAME_RE = re.compile(r"^([A-Za-z][A-Za-z-]*?)(\d[\d/:.]*)$")


def tag_facts(a: Analysis, seg_key: str, tag: int) -> list[Fact]:
    """Attributed tag-bearing facts of ``seg_key`` that carry ``tag``."""
    out = []
    for f in a.facts.values():
        if f.segment != seg_key or f.kind not in PROVEN_TAG_KINDS | TAG_KINDS:
            continue
        if tag in _fact_tags(f):
            out.append(f)
    return out


def _fact_tags(f: Fact) -> set[int]:
    if f.kind in ("subif_name", "svi_name"):
        m = _NAME_RE.match(f.value)
        if not m:
            return set()
        num = m.group(2)
        tail = num.rsplit(".", 1)[-1] if f.kind == "subif_name" else num
        return {int(tail)} if tail.isdigit() else set()
    try:
        return set(fact_vlans(f))
    except Exception:  # noqa: BLE001 - foreign fact parser: no VLANs
        return set()


def tag_question_needed(a: Analysis, seg_key: str) -> int | None:
    """The canonical tag when a VLAN question is relevant, else None."""
    seg = next((s for s in a.segments if s.key == seg_key), None)
    if seg is None or seg.status == "CARRIER":
        return None
    canon = canonical_scheme(seg)
    if canon is None or not isinstance(canon.tag, int):
        return None
    proven = [
        f for f in tag_facts(a, seg_key, canon.tag) if f.confidence == Confidence.PROVEN
    ]
    return canon.tag if proven else None


# ------------------------------------------------------------- iface names


def _split_name(name: str) -> tuple[str, str] | None:
    m = _NAME_RE.match(name)
    return (m.group(1), m.group(2)) if m else None


def _name_hits(text: str, prefix: str, num: str) -> list[tuple[int, int]]:
    """Spans of ``num`` in whole-token references ``<abbrev><num>`` of an iface."""
    pat = re.compile(
        r"(?<![\w./-])(?P<p>[A-Za-z][A-Za-z-]*)(?P<n>" + re.escape(num) + r")"
        r"(?![\w/:]|\.\d)"
    )
    full = prefix.lower()
    out = []
    for m in pat.finditer(text):
        p = m.group("p").lower()
        if p == full or (len(p) >= 2 and full.startswith(p)):
            out.append((m.start("n"), m.end("n")))
    return out


def _renamed_num(kind: str, num: str, old: int, new: int) -> str | None:
    if kind == "subif_name":
        head, _, tail = num.rpartition(".")
        if not head or tail != str(old):
            return None
        return f"{head}.{new}"
    if num != str(old):
        return None
    return str(new)


@register_scenario
class SegmentL2Scenario:
    id = "segment_l2"
    order = 20

    def applies(self, a: Analysis, m: Manifest | None) -> bool:
        return any(isinstance(s.tag, int) for seg in a.segments for s in seg.schemes)

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]:
        out: list[Question] = []
        for seg in a.segments:
            tag = tag_question_needed(a, seg.key)
            if tag is None:
                continue
            sa = seg_answer(prof, a, seg)
            scopes = {sc for sch in seg.schemes for sc in sch.scopes}
            own = {tag}

            def validate(
                value: str,
                ans: Answers,
                scopes: set[str] = scopes,
                own: set[int] = own,
            ) -> str | None:
                try:
                    v = int(value.strip())
                except ValueError:
                    return f"{value!r} is not a VLAN number"
                if v in own:
                    return None
                hit = sorted(s for s in scopes if v in a.protected_vlans.get(s, set()))
                if hit:
                    return (
                        f"VLAN {v} is protected (internal or reserved) in "
                        f"{', '.join(hit)}"
                    )
                return None

            facts = tag_facts(a, seg.key, tag)
            out.append(
                Question(
                    id=f"{seg.site_key}/vlan",
                    group="B VLAN tags",
                    kind="vlan",
                    prompt=f"{seg.key} tag {tag}",
                    current=str(tag),
                    default=str(sa.vlan) if sa.vlan is not None else str(tag),
                    default_source=(
                        f"from {seg.site_key}" if sa.vlan is not None else "keep"
                    ),
                    choices=None,
                    validate=validate,
                    evidence=[f.id for f in facts[:20]],
                    affects=len(facts),
                    scenario=self.id,
                    segment=seg.key,
                    apply=segment_setter(seg.site_key, "vlan"),
                )
            )
        return out

    # ------------------------------------------------------------------ plan

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment:
        frag = PlanFragment()
        if not maps.tags:
            return frag
        by_seg: dict[str, dict[int, int]] = {}
        for (key, old), new in maps.tags.items():
            if key not in maps.skipped:
                by_seg.setdefault(key, {})[old] = new
        if not by_seg:
            return frag
        sites = {s.key: s.site_key for s in a.segments}
        self._tags(a, maps, by_seg, sites, frag)
        self._lists(a, maps, by_seg, sites, frag)
        if maps.subif_policy == "rename":
            self._renames(a, maps, by_seg, sites, frag)
        self._mentions(a, maps, by_seg, sites, frag)
        return frag

    def _tags(self, a, maps, by_seg, sites, frag) -> None:
        for f in a.facts.values():
            if f.kind not in TAG_KINDS or not active_fact(f, maps.include_outliers):
                continue
            mapping = by_seg.get(f.segment or "")
            if not mapping or not f.value.isdigit():
                continue
            new = mapping.get(int(f.value))
            if new is None:
                continue
            edits, err = render_fact(a, f, str(new))
            if err is not None:
                frag.findings.append(err)
                continue
            for te in edits:
                frag.claims.append(
                    fact_claim(
                        f,
                        te,
                        category="vlan",
                        group=group_name(f.segment or "", "vlan"),
                        question=f"{sites.get(f.segment, f.segment)}/vlan",
                        scenario=self.id,
                    )
                )

    def _lists(self, a, maps, by_seg, sites, frag) -> None:
        ext: dict[tuple[Store, str], dict[int, int]] = {}
        for f in a.facts.values():
            if not active_fact(f, maps.include_outliers):
                continue
            mapping = by_seg.get(f.segment or "")
            if not mapping or f.kind not in PROVEN_TAG_KINDS | TAG_KINDS:
                continue
            for v in _fact_tags(f):
                if v in mapping:
                    ext.setdefault((f.store, f.node_id or ""), {})[v] = mapping[v]
        for f in a.facts.values():
            if f.kind != "vlan_list" or not active_fact(f, maps.include_outliers):
                continue
            mapping = ext.get((f.store, f.node_id or ""))
            if not mapping:
                continue
            try:
                vl = f.list_value or VlanList.parse(f.value)
                if not set(vl.vlans()) & set(mapping):
                    continue
                new = vl.replace(mapping).render()
            except (VlanListError, ValueError) as exc:
                frag.findings.append(
                    Finding("VLAN_LIST", "warn", f"{f.rule} {f.id}: {exc}", [f.id])
                )
                continue
            except Exception as exc:  # noqa: BLE001 - reported as a conflict finding
                frag.findings.append(
                    Finding(
                        getattr(exc, "code", "VLAN_COLLISION"),
                        "conflict",
                        f"{f.rule} node {f.node_id} {f.value!r}: {exc}",
                        [f.id],
                    )
                )
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
                        category="vlan",
                        group=group_name(f.segment or "", "vlan"),
                        question=f"{sites.get(f.segment, f.segment)}/vlan",
                        scenario=self.id,
                    )
                )

    def _renames(self, a, maps, by_seg, sites, frag) -> None:
        idx = text_index(a)
        # (store, node) -> [(fact, prefix, old num, new num)]
        plans: dict[tuple[Store, str], list[tuple[Fact, str, str, str]]] = {}
        for f in a.facts.values():
            if f.kind not in ("subif_name", "svi_name"):
                continue
            if not active_fact(f, maps.include_outliers):
                continue
            mapping = by_seg.get(f.segment or "")
            parts = _split_name(f.value)
            if not mapping or parts is None:
                continue
            prefix, num = parts
            for old, new in mapping.items():
                nn = _renamed_num(f.kind, num, old, new)
                if nn is not None:
                    plans.setdefault((f.store, f.node_id or ""), []).append(
                        (f, prefix, num, nn)
                    )
                    break
        for (store, node), items in plans.items():
            text = idx.text(store, node or None)
            if text is None:
                continue
            olds = {(p.lower(), n) for _f, p, n, _nn in items}
            seen: set[tuple[str, str]] = set()
            for f, prefix, num, nn in items:
                if (prefix.lower(), num) in seen:
                    continue
                seen.add((prefix.lower(), num))
                if (prefix.lower(), nn) not in olds and _name_hits(text, prefix, nn):
                    frag.findings.append(
                        Finding(
                            "SUBIF_EXISTS",
                            "conflict",
                            f"{store.kind}:{store.name} node {node}: cannot rename "
                            f"{prefix}{num} to {prefix}{nn}: the target exists",
                            [f.id],
                        )
                    )
                    continue
                # only the differing tail changes ("16.2" -> "16.20": ".2" stays put)
                cut = len(num) - len(num.rsplit(".", 1)[-1])
                for s, e in _name_hits(text, prefix, num):
                    frag.claims.append(
                        fact_claim(
                            f,
                            TextEdit(s + cut, e, num[cut:], nn[cut:]),
                            category="vlan",
                            group=group_name(f.segment or "", "vlan"),
                            question=f"{sites.get(f.segment, f.segment)}/vlan",
                            confidence=(
                                f.confidence
                                if f.span.start <= s < f.span.end
                                else Confidence.CORRELATED
                            ),
                            scenario=self.id,
                        )
                    )

    def _mentions(self, a, maps, by_seg, sites, frag) -> None:
        idx = text_index(a)
        res = {}
        for seg in a.segments:
            if seg.key not in by_seg:
                continue
            labels = set(seg.labels.values())
            labels |= {maps.labels[n] for n in seg.network_ids if n in maps.labels}
            res[seg.key] = [token_re(x) for x in sorted(labels) if x]
        for f in a.facts.values():
            if f.kind != "vlan_mention" or not f.value.isdigit():
                continue
            text = idx.text(f.store, f.node_id)
            if text is None:
                continue
            line = context_text(f.store, text, f.span.start, f.span.end)
            v = int(f.value)
            hits = [
                k
                for k, mapping in by_seg.items()
                if v in mapping and any(r.search(line) for r in res.get(k, ()))
            ]
            if len(hits) != 1:
                continue
            edits, err = render_fact(a, f, str(by_seg[hits[0]][v]))
            if err is not None:
                frag.findings.append(err)
                continue
            for te in edits:
                frag.claims.append(
                    fact_claim(
                        f,
                        te,
                        category="cosmetic",
                        group="cosmetic/vlan-text",
                        question=f"{sites.get(hits[0], hits[0])}/vlan",
                        confidence=Confidence.CORRELATED,
                        scenario=self.id,
                    )
                )
