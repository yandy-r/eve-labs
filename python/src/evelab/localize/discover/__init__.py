"""Discovery pipeline: ``analyse(lab, manifest, opts) -> Analysis`` (design 7).

topology (clouds, ports, scopes, parsed configs) -> l2trace (per scope) ->
segments (units, merges, schemes, status, attribution) -> inventory (protected
VLANs / prefixes).  Read-only and deterministic: the same lab gives the same
Analysis every run.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .. import dialects, stores
from ..model import CORE_FACT_KINDS, Analysis, ConfigText, Fact, Finding
from . import inventory, l2trace, segments, topology

if TYPE_CHECKING:
    from evelab.common.unl import RawLab

    from ..dialects.base import PatternRule
    from ..manifest import Manifest

__all__ = ["AnalyseOptions", "Discovery", "analyse", "discover", "manifest_rules"]


@dataclass
class AnalyseOptions:
    """Knobs for :func:`analyse` (all default to the documented behaviour)."""

    include_outliers: bool = False  # outlier endpoints join their scheme
    textobjects: bool = True  # parse canvas textobjects (eve_html)
    max_depth: int = l2trace.MAX_DEPTH  # L2 trace bridge hops
    canonical_scope: str | None = None  # overrides manifest canonical_scope


@dataclass
class Discovery:
    """Intermediate results, for tools that need more than :class:`Analysis`."""

    analysis: Analysis
    topology: topology.Topology
    index: topology.ConfigIndex
    traces: dict[str, l2trace.TraceResult]
    build: segments.SegmentBuild


def analyse(
    lab: RawLab, manifest: Manifest | None = None, opts: AnalyseOptions | None = None
) -> Analysis:
    """Analyse ``lab`` (section 3.2 contract)."""
    return discover(lab, manifest, opts).analysis


def _parse_textobjects(
    texts: list[ConfigText],
    findings: list[Finding],
    index: topology.ConfigIndex | None = None,
) -> list[Fact]:
    """Facts of the canvas textobjects.  With ``index`` the dialect is the
    manifest-extended one (``[[rule]]`` tables with ``dialects = []`` or
    naming the textobject dialect apply here too; review fix #40)."""
    out: list[Fact] = []
    for ct in texts:
        if ct.store.kind != "textobject" or ct.opaque or not ct.text:
            continue
        try:
            dialect = (
                index.dialect_for(ct.dialect)
                if index is not None
                else dialects.get(ct.dialect)
            )
            parsed = dialect.parse(ct)
        except Exception as exc:  # noqa: BLE001 - reported as a PARSE_FAILED finding
            findings.append(
                Finding(
                    "PARSE_FAILED",
                    "warn",
                    f"textobject {ct.store.name}: {exc}",
                    [f"textobject:{ct.store.name}"],
                )
            )
            continue
        out.extend(parsed.facts)
    return out


def manifest_rules(
    manifest: Manifest | None, findings: list[Finding] | None = None
) -> dict[str, list[PatternRule]]:
    """Manifest ``[[rule]]`` tables as ``PatternRule`` per dialect name.

    An empty ``dialects`` list means every dialect (key ``"*"``).  A rule that
    is not a valid ``PatternRule`` (unknown fact kind, no ``v`` group, ...) is
    dropped with a ``MANIFEST_RULE`` error finding.
    """
    from ..dialects.base import PatternRule

    out: dict[str, list[PatternRule]] = {}
    if manifest is None:
        return out
    for r in manifest.rules:
        try:
            rule = PatternRule(
                id=r.id,
                pattern=r.pattern,
                kind=r.kind,
                block=r.block,
                l2=r.l2,
                negative=tuple(r.negative),
            )
            if rule.kind and rule.kind not in CORE_FACT_KINDS:
                raise ValueError(f"unregistered fact kind {rule.kind!r}")
        except ValueError as exc:
            if findings is not None:
                findings.append(
                    Finding(
                        "MANIFEST_RULE",
                        "error",
                        f"manifest [[rule]] {r.id}: {exc}",
                        [f"rule:{r.id}"],
                    )
                )
            continue
        for name in r.dialects or ["*"]:
            out.setdefault(name, []).append(rule)
    return out


def discover(
    lab: RawLab, manifest: Manifest | None = None, opts: AnalyseOptions | None = None
) -> Discovery:
    """Run the full pipeline and keep the intermediate results."""
    opts = opts or AnalyseOptions()
    nodes = lab.node_models()
    networks = lab.network_models()
    topo = topology.build(lab, nodes, networks)
    texts, findings = stores.load_texts(
        lab, nodes, manifest, textobjects=opts.textobjects
    )
    findings = list(findings) + list(topo.findings)
    extra_rules = manifest_rules(manifest, findings)
    index = topology.ConfigIndex(topo, texts, extra_rules)
    findings.extend(index.notes)
    noted = len(index.notes)

    facts: dict[str, Fact] = {}
    for nc in index.all_configs():
        for f in nc.parsed.facts:
            facts.setdefault(f.id, f)
    for f in _parse_textobjects(texts, findings, index):
        facts.setdefault(f.id, f)
    findings.extend(index.notes[noted:])

    traces = l2trace.trace_all(topo, index, opts.max_depth)
    seen_codes: set[tuple[str, str]] = set()
    for tr in traces.values():
        for fnd in tr.findings:
            sig = (fnd.code, fnd.msg)
            if sig not in seen_codes:
                seen_codes.add(sig)
                findings.append(fnd)

    if (
        manifest is not None
        and manifest.canonical_scope
        and manifest.canonical_scope not in topo.scopes
    ):
        findings.append(
            Finding(
                "MANIFEST_SCOPE",
                "warn",
                f"manifest canonical_scope {manifest.canonical_scope!r} is not a "
                f"configset of this lab ({', '.join(topo.scopes)})",
            )
        )
    build = segments.build(
        topo,
        index,
        traces,
        facts,
        texts,
        lab_stem=lab.path.stem if lab.path else "lab",
        manifest=manifest,
        canonical_scope=opts.canonical_scope,
        include_outliers=opts.include_outliers,
    )
    findings.extend(build.findings)
    inv = inventory.build(
        facts,
        build.segments,
        index,
        topo.scopes,
        manifest.protect if manifest is not None else (),
    )
    if not topo.clouds:
        findings.append(
            Finding(
                "NO_CLOUDS",
                "info",
                "lab has no cloud network: nothing to localize",
            )
        )
    findings.extend(_config_findings(index, facts))
    pinned = _pinned(manifest, build, topo, findings)
    analysis = Analysis(
        lab=lab,
        nodes=nodes,
        networks=networks,
        texts=texts,
        facts=facts,
        segments=build.segments,
        protected_vlans=inv.vlans,
        protected_prefixes=inv.prefixes,
        active_scope=dict(topo.active_scope),
        findings=findings,
        pinned=pinned,
    )
    return Discovery(analysis, topo, index, traces, build)


def _config_findings(
    index: topology.ConfigIndex, facts: dict[str, Fact]
) -> list[Finding]:
    out: list[Finding] = []
    for nc in index.all_configs():
        if nc.text.mirror_of is not None:
            continue
        ref = f"{nc.store.kind}:{nc.store.name}"
        node = f"node:{nc.node_id}"
        orphans = [i for i in nc.parsed.ifaces.values() if i.orphan]
        if orphans:
            out.append(
                Finding(
                    "CORRUPT_CONFIG_REGION",
                    "info",
                    f"{ref} node {nc.node_id}: {len(orphans)} interface block(s) with "
                    "a broken header; their facts are CORRELATED at most",
                    [node],
                )
            )
        kinds = Counter(f.kind for f in nc.parsed.facts)
        if kinds.get("ipv6_literal"):
            out.append(
                Finding(
                    "IPV6_UNHANDLED",
                    "info",
                    f"{ref} node {nc.node_id}: {kinds['ipv6_literal']} IPv6 literal(s) "
                    "are reported, never rewritten",
                    [node],
                )
            )
        if kinds.get("secret"):
            out.append(
                Finding(
                    "SECRET_COMMITTED",
                    "warn",
                    f"{ref} node {nc.node_id}: {kinds['secret']} committed secret(s)",
                    [node],
                )
            )
    return out


def _pinned(
    manifest: Manifest | None,
    build: segments.SegmentBuild,
    topo: topology.Topology,
    findings: list[Finding],
) -> bool:
    if manifest is None:
        return False
    ok = True
    keys = {s.key for s in build.segments}
    for ms in manifest.segments:
        missing = [n for n in ms.networks if n not in topo.clouds]
        if missing:
            ok = False
            findings.append(
                Finding(
                    "MANIFEST_STALE",
                    "warn",
                    f"manifest segment {ms.key}: network(s) {', '.join(missing)} are "
                    "not cloud networks of this lab",
                    [f"segment:{ms.key}"],
                )
            )
        if ms.key not in keys:
            ok = False
    pinned_nets = {n for ms in manifest.segments for n in ms.networks}
    loose = [n for n in topo.clouds if n not in pinned_nets]
    if loose:
        ok = False
        findings.append(
            Finding(
                "MANIFEST_STALE",
                "warn",
                f"cloud network(s) {', '.join(loose)} are not in any manifest segment",
            )
        )
    return ok
