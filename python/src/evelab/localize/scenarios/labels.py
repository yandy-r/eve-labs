"""Network names (+ templated suggestions, text propagation, textobjects).

Questions: ``<site_key>/label`` for every segment with cloud networks; the
default is the profile answer, else the label template (manifest
``label_template`` or the NameExplainer suggestion) rendered with the answered
tag / subnet, else the current name.

Renames (section 11.2): by network id, only cloud networks of the segment. A
network named like the segment's primary label gets the new label; any other
network of the segment keeps its own shape through its template (``203-67`` ->
``20-67``). Bridges are never renamed.

Text propagation (section 10.4) only for *distinctive* old labels: containing a
digit or a hyphen, at least 5 characters, not a prefix of a bridge name and not
generic (built-in set + manifest ``generic_labels``). Then ``label_ref`` tokens
(descriptions, aliases, comments, textobject text nodes) and ``vlan_name``
values equal to the old label follow it, provided the *new* label is itself one
findable label token (``text_safe``; else ``LABEL_TEXT_KEPT``) and every field
it lands in accepts it (dialect hook ``label_problem``; else ``BAD_LABEL``).
Labels written into text are recorded in state.json (``baseline_text_labels``)
and always follow back (``PlanOptions.written_labels``).

Without a label answer, networks follow a template that reproduces their name
and changes with the answered tag / subnet (same as the question default, so
``plan`` and ``apply --yes`` agree).
"""

from __future__ import annotations

import re
from dataclasses import replace
from ipaddress import IPv4Network
from typing import TYPE_CHECKING, Any

from evelab.common.unl import check_label

from ..dialects._common import LABEL_TOKEN
from ..discover.names import octets3, render_template, suggest_template
from ..errors import LocalizeError
from ..model import Analysis, Confidence, Fact, Finding, Segment
from ..profile import Profile, SegmentAnswer
from . import register_scenario
from .base import (
    GENERIC_LABELS,
    Answers,
    PlanFragment,
    Question,
    ValueMaps,
    _parse_label,
    canonical_scheme,
    fact_claim,
    group_name,
    primary_label,
    render_fact,
    seg_answer,
    segment_setter,
    text_index,
)
from .bridge import xml_claims

if TYPE_CHECKING:
    from ..manifest import Manifest

MIN_DISTINCT = 5


def generic_set(manifest: Manifest | None) -> set[str]:
    out = set(GENERIC_LABELS)
    if manifest is not None:
        out |= {g.casefold() for g in manifest.generic_labels}
    return out


def distinctive(label: str, a: Analysis, manifest: Manifest | None = None) -> bool:
    """Section 10.4: may ``label`` be propagated into device text?"""
    if not label or len(label) < MIN_DISTINCT:
        return False
    if not any(c.isdigit() or c == "-" for c in label):
        return False
    if label.startswith("Net-"):
        return False
    if label.casefold() in generic_set(manifest):
        return False
    for net in a.networks.values():
        if not net.is_cloud and net.name != label and net.name.startswith(label):
            return False
    return True


def label_error(value: str) -> str | None:
    """Hard rules for a network label, or None when ``value`` is legal.

    Non-empty, no surrounding blanks, none of ``< > & "`` or control characters
    (they break the XML attribute and every quoted device string the label is
    propagated into, e.g. FortiOS ``set alias "..."``), and EVE's own limits
    (``unl.check_label``: printable, at most 64 characters).  Field limits of
    the device texts the label reaches are checked per fact by
    :func:`text_label_problem`.
    """
    if value != value.strip():
        return f"label {value!r} has leading or trailing blanks"
    try:
        _parse_label(value)
        check_label(value)
    except ValueError as exc:
        return f"label {value!r}: {exc}"
    except LocalizeError as exc:
        return str(exc)
    return None


def text_label_problem(a: Analysis, f: Fact, new: str) -> str | None:
    """Why ``new`` cannot replace the label held by fact ``f``, or None.

    Extensible per dialect: a dialect may define ``label_problem(fact, new,
    text) -> str | None`` (FortiOS: ``alias`` at most 25 characters; Cisco:
    ``vlan N / name`` at most 32 characters, no blanks).
    """
    idx = text_index(a)
    text = idx.text(f.store, f.node_id)
    if text is None:
        return None
    hook = getattr(idx.dialect(f.store, f.node_id), "label_problem", None)
    if not callable(hook):
        return None
    problem: str | None = hook(f, new, text)
    return problem


def text_safe(label: str, a: Analysis, manifest: Manifest | None = None) -> bool:
    """May ``label`` *replace* an old label in device text?

    Only when the dialects find it again as one free-text label token
    (``dialects._common.LABEL_TOKEN``) and it is distinctive; otherwise a later
    ``revert`` could not locate the references (``MGMTX``, ``Mgmt B``) and the
    round trip would not be byte-identical.
    """
    return bool(re.fullmatch(LABEL_TOKEN, label)) and distinctive(label, a, manifest)


def _templates_for(seg: Segment, nid: str, manifest: Manifest | None) -> list[str]:
    """Manifest ``label_template`` first, then the NameExplainer suggestion."""
    out: list[str] = []
    if manifest is not None:
        for ms in manifest.segments:
            if ms.key == seg.key and ms.label_template:
                out.append(ms.label_template)
                break
    tokens = list(seg.name_hints.get(nid) or ())
    if tokens and out:
        # A digit run that is both tag and third octet (``mgmt-203`` on VLAN 203
        # / x.x.203.0/24) is "ambiguous"; the manifest template decides.
        pick = set(re.findall(r"\{(tag|octet3)\d*\}", out[0].replace("{{", "")))
        if len(pick) == 1:
            kind = pick.pop()
            tokens = [
                replace(t, kind=kind) if t.kind == "ambiguous" else t for t in tokens
            ]
    if tokens:
        hint = suggest_template(seg.labels.get(nid, ""), tokens)
        if hint and hint not in out:
            out.append(hint)
    return out


def _values(
    seg: Segment, nid: str, new_tag: int | None, new_subnet: IPv4Network | None
) -> dict[str, Any]:
    values: dict[str, Any] = {"netid": nid}
    canon = canonical_scheme(seg)
    if new_tag is None and canon is not None and isinstance(canon.tag, int):
        new_tag = canon.tag
    if new_tag is not None:
        values["tag"] = new_tag
    sub = new_subnet or (canon.subnet if canon is not None else None)
    o3 = sorted(octets3(sub))
    if o3:
        values["octet3"] = o3[0]
    kinds: dict[str, int] = {}
    for t in seg.name_hints.get(nid, []):
        kinds[t.kind] = kinds.get(t.kind, 0) + 1
    seen: dict[str, int] = {}
    for t in sorted(seg.name_hints.get(nid, []), key=lambda t: t.span.start):
        if t.kind in ("host", "netid"):
            seen[t.kind] = seen.get(t.kind, 0) + 1
            key = t.kind if kinds[t.kind] == 1 else f"{t.kind}{seen[t.kind]}"
            values[key] = t.text
    return values


def _render(
    tpl: str,
    seg: Segment,
    nid: str,
    new_tag: int | None,
    new_subnet: IPv4Network | None,
) -> str | None:
    try:
        return render_template(tpl, _values(seg, nid, new_tag, new_subnet))
    except KeyError:
        return None


def derive(
    seg: Segment,
    nid: str,
    new_tag: int | None,
    new_subnet: IPv4Network | None,
    manifest: Manifest | None,
    *,
    strict: bool = False,
) -> tuple[str | None, str | None]:
    """``(new name, template)`` of network ``nid`` for the given tag / subnet.

    A template that reproduces the current name with the current values wins
    (manifest ``label_template`` first, then the NameExplainer suggestion, so
    ``mgmt-203`` follows ``mgmt-{octet3}`` when the manifest's ``{octet3}-{host}``
    does not fit it).  ``strict``: only such a template; otherwise the first one
    that renders at all.
    """
    name = seg.labels.get(nid, "")
    first: tuple[str | None, str | None] = (None, None)
    for tpl in _templates_for(seg, nid, manifest):
        new = _render(tpl, seg, nid, new_tag, new_subnet)
        if new is None:
            continue
        if _render(tpl, seg, nid, None, None) == name:
            return new, tpl
        if first[0] is None:
            first = (new, tpl)
    return (None, None) if strict else first


def templated(
    seg: Segment,
    nid: str,
    new_tag: int | None,
    new_subnet: IPv4Network | None,
    manifest: Manifest | None,
    *,
    strict: bool = False,
) -> str | None:
    return derive(seg, nid, new_tag, new_subnet, manifest, strict=strict)[0]


def _new_tag(seg: Segment, maps: ValueMaps | None, sa: SegmentAnswer) -> int | None:
    canon = canonical_scheme(seg)
    if canon is None or not isinstance(canon.tag, int):
        return None
    if maps is not None:
        return maps.tags.get((seg.key, canon.tag), canon.tag)
    return sa.vlan if sa.vlan is not None else canon.tag


def _primary_nid(seg: Segment) -> str | None:
    primary = primary_label(seg)
    return next((n for n in seg.network_ids if seg.labels.get(n) == primary), None)


def label_renames(
    a: Analysis, seg: Segment, sa: SegmentAnswer, maps: ValueMaps
) -> dict[str, str]:
    """``network id -> new name`` for the segment.

    Without a label answer a network is renamed only through a template that
    reproduces its current name and whose ``{tag}`` / ``{octet3}`` changed with
    the answered VLAN / subnet (``EVE-MGMT-203`` -> ``EVE-MGMT-20``); this is
    exactly what the question default would store, so ``plan`` without
    ``--yes`` and ``apply --yes`` agree.  A label answer equal to that template
    default renames network by network (``mgmt{netid}`` never collapses several
    networks into one name); any other label answer goes to every network named
    like the primary label, the others keep their own template shape.
    """
    primary = primary_label(seg)
    canon = canonical_scheme(seg)
    new_tag = _new_tag(seg, maps, sa)
    new_sub = None
    if canon is not None and canon.subnet is not None:
        for sm in maps.subnets.get(seg.key, ()):
            if sm.old == canon.subnet:
                new_sub = sm.new
    pnid = _primary_nid(seg)
    tpl_default = (
        templated(seg, pnid, new_tag, new_sub, maps.manifest, strict=True)
        if pnid is not None
        else None
    )
    per_net = not sa.label or sa.label == tpl_default
    out: dict[str, str] = {}
    for nid in seg.network_ids:
        name = seg.labels.get(nid)
        net = a.networks.get(nid)
        if name is None or net is None or not net.is_cloud:
            continue
        if not sa.label:
            new = templated(seg, nid, new_tag, new_sub, maps.manifest, strict=True)
            new = new or name
        elif name == primary and per_net:
            new = templated(seg, nid, new_tag, new_sub, maps.manifest, strict=True)
            new = new or sa.label
        elif name == primary:
            new = sa.label
        else:
            new = templated(seg, nid, new_tag, new_sub, maps.manifest) or name
        if new != name:
            out[nid] = new
    return out


def suggest_label(
    a: Analysis, seg: Segment, prof: Profile, manifest: Manifest | None
) -> tuple[str, str]:
    """(default, source) for the label question (= what the plan derives when
    the label is left unanswered, see :func:`label_renames`)."""
    sa = seg_answer(prof, a, seg)
    primary = primary_label(seg)
    if sa.label:
        return sa.label, f"from {seg.site_key}"
    nid = _primary_nid(seg)
    if nid is not None:
        new, tpl = derive(
            seg, nid, _new_tag(seg, None, sa), sa.subnet, manifest, strict=True
        )
        if new and new != primary:
            return new, f"template {tpl}"
    return primary, "keep"


@register_scenario
class LabelsScenario:
    id = "labels"
    order = 40

    def applies(self, a: Analysis, m: Manifest | None) -> bool:
        return any(s.network_ids for s in a.segments)

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]:
        out: list[Question] = []
        for seg in a.segments:
            if not seg.network_ids:
                continue
            primary = primary_label(seg)
            default, source = suggest_label(a, seg, prof, m)
            refs = [
                f.id
                for f in a.facts.values()
                if f.kind in ("label_ref", "vlan_name") and f.value == primary
            ]
            notes = []
            ref_facts: list[Fact] = []
            if not distinctive(primary, a, m):
                notes.append("generic label: only the network name changes")
            else:
                notes.append(f"{len(refs)} text reference(s) follow the label")
                ref_facts = [a.facts[r] for r in refs]

            def validate(
                value: str, ans: Answers, ref_facts: list[Fact] = ref_facts
            ) -> str | None:
                value = value.strip()
                err = label_error(value)
                if err is not None:
                    return err
                if not text_safe(value, a, m):
                    return None  # text references are kept (LABEL_TEXT_KEPT)
                for f in ref_facts:
                    problem = text_label_problem(a, f, value)
                    if problem is not None:
                        return f"{problem} ({f.rule})"
                return None

            out.append(
                Question(
                    id=f"{seg.site_key}/label",
                    group="D Labels",
                    kind="label",
                    prompt=(
                        f"{primary} ({len(seg.network_ids)} network"
                        f"{'s' if len(seg.network_ids) != 1 else ''})"
                    ),
                    current=primary,
                    default=default,
                    default_source=source,
                    choices=None,
                    validate=validate,
                    depends_on=[f"{seg.site_key}/vlan", f"{seg.site_key}/subnet"],
                    evidence=refs[:20],
                    affects=len(seg.network_ids) + len(refs),
                    scenario=self.id,
                    segment=seg.key,
                    apply=segment_setter(seg.site_key, "label"),
                    notes=notes,
                )
            )
        return out

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment:
        frag = PlanFragment()
        nets = {nid: seg for seg in a.segments for nid in seg.network_ids}
        for nid, new in sorted(maps.labels.items()):
            seg = nets.get(nid)
            if seg is None or seg.key in maps.skipped:
                continue
            err = label_error(new)
            if err is not None:
                frag.findings.append(
                    Finding("BAD_LABEL", "error", f"{seg.key}: {err}", [nid])
                )
                continue
            frag.claims.extend(
                xml_claims(
                    a,
                    nid,
                    "name",
                    new,
                    category="label",
                    group=group_name(seg.key, "label"),
                    question=f"{seg.site_key}/label",
                    scenario=self.id,
                )
            )
        if not maps.text_labels:
            return frag
        owner = {seg.labels[n]: seg for seg in a.segments for n in seg.network_ids}
        skipped_f5 = 0
        for f in a.facts.values():
            if f.kind not in ("label_ref", "vlan_name"):
                continue
            new = maps.text_labels.get(f.value)
            if new is None:
                continue
            if f.kind == "vlan_name" and (f.group or "").startswith("f5vlan:"):
                skipped_f5 += 1
                continue
            seg = owner.get(f.value)
            site = seg.site_key if seg is not None else ""
            problem = text_label_problem(a, f, new)
            if problem is not None:
                frag.findings.append(
                    Finding("BAD_LABEL", "error", f"{f.rule} {f.id}: {problem}", [f.id])
                )
                continue
            if f.kind == "vlan_name" and f.segment:
                group, cat, conf = group_name(f.segment, "label"), "label", None
            else:
                group, cat = "cosmetic/label-text", "cosmetic"
                conf = Confidence.CORRELATED
            edits, err = render_fact(a, f, new)
            if err is not None:
                frag.findings.append(err)
                continue
            for te in edits:
                frag.claims.append(
                    fact_claim(
                        f,
                        te,
                        category=cat,
                        group=group,
                        question=f"{site}/label",
                        confidence=conf,
                        scenario=self.id,
                    )
                )
        if skipped_f5:
            frag.findings.append(
                Finding(
                    "F5_VLAN_NAME",
                    "info",
                    f"{skipped_f5} F5 vlan name(s) equal to an old label kept "
                    "(renaming would need every reference)",
                )
            )
        return frag
