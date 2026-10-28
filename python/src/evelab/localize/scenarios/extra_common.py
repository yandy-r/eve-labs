"""Helpers shared by the extra scenarios (T17): option storage, gates, facts by node.

Not a scenario module (listed in ``HELPER_MODULES``, never auto-imported).

Scenario options are stored per lab, in ``[labs."<lab_id>".scenarios.<id>]``
(peer addresses and ASNs are lab-specific); reading merges the global
``[scenarios.<id>]`` table under the lab table, so a site-wide profile can still
pre-answer them.
"""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Any

from evelab.common.tomlw import TomlValue

from ..model import Analysis, Fact
from ..profile import Answers, LabOverride, ScenarioAnswer
from .base import Question, Setter, text_index

if TYPE_CHECKING:
    from ..manifest import Manifest

__all__ = [
    "fact_text",
    "gate_question",
    "lab_scenario",
    "manifest_options",
    "node_facts",
    "opt_asn",
    "opt_ip",
    "opt_list",
    "option_setter",
    "parse_ip",
    "scenario_options",
]


def lab_scenario(ans: Answers, sid: str, lab_id: str) -> ScenarioAnswer:
    """The (created on demand) ``[labs."<lab_id>".scenarios.<sid>]`` entry."""
    lab = ans.labs.setdefault(lab_id, LabOverride())
    return lab.scenarios.setdefault(sid, ScenarioAnswer())


def scenario_options(ans: Answers, sid: str, lab_id: str) -> dict[str, TomlValue]:
    """Global ``[scenarios.<sid>]`` options overlaid by the lab override."""
    out: dict[str, TomlValue] = {}
    glob = ans.scenarios.get(sid)
    if glob is not None:
        out.update(glob.options)
    lab = ans.labs.get(lab_id)
    if lab is not None and sid in lab.scenarios:
        out.update(lab.scenarios[sid].options)
    return out


def manifest_options(m: Manifest | None, sid: str) -> dict[str, TomlValue] | None:
    """``[scenarios.<sid>]`` options of the manifest when it enables ``sid``."""
    if m is None:
        return None
    pin = m.scenarios.get(sid)
    if pin is None or not pin.enabled:
        return None
    return dict(pin.options)


def option_setter(sid: str, key: str, lab_id: str) -> Setter:
    """Setter storing ``value`` as option ``key`` (``None`` removes it)."""

    def setter(ans: Answers, value: Any) -> None:
        entry = lab_scenario(ans, sid, lab_id)
        if value is None:
            entry.options.pop(key, None)
        elif isinstance(value, (list, tuple)):
            entry.options[key] = [str(v) for v in value]
        elif isinstance(value, (bool, int, str)):
            entry.options[key] = value
        else:
            entry.options[key] = str(value)

    return setter


def gate_question(
    sid: str, lab_id: str, prompt: str, *, notes: list[str], evidence: list[str]
) -> Question:
    """The "G Scenarios" yes/no gate (default no) for a gated scenario."""

    def setter(ans: Answers, value: Any) -> None:
        lab_scenario(ans, sid, lab_id).enabled = bool(value)

    return Question(
        id=f"{sid}/enabled",
        group="G Scenarios",
        kind="bool",
        prompt=prompt,
        current=None,
        default="no",
        default_source="gate (default no)",
        choices=["yes", "no"],
        validate=lambda v, a: None,
        evidence=evidence,
        scenario=sid,
        apply=setter,
        notes=notes,
    )


def parse_ip(value: object) -> IPv4Address | None:
    try:
        return IPv4Address(str(value).strip())
    except ValueError:
        return None


def opt_ip(opts: dict[str, TomlValue], key: str) -> IPv4Address | None:
    raw = opts.get(key)
    return None if raw is None or raw == "" else parse_ip(raw)


def opt_asn(opts: dict[str, TomlValue], key: str) -> int | None:
    raw = opts.get(key)
    if isinstance(raw, bool) or raw is None or raw == "":
        return None
    try:
        v = int(str(raw).strip())
    except ValueError:
        return None
    return v if 1 <= v <= 4294967295 else None


def opt_list(opts: dict[str, TomlValue], key: str) -> list[IPv4Network] | None:
    """A list option of networks (``None`` = not answered / keep)."""
    raw = opts.get(key)
    if raw is None:
        return None
    items = raw if isinstance(raw, list) else str(raw).replace(",", " ").split()
    out: list[IPv4Network] = []
    for item in items:
        try:
            out.append(IPv4Network(str(item).strip(), strict=False))
        except ValueError:
            continue
    return out


def node_facts(
    a: Analysis, node_ids: Iterable[str], kinds: Iterable[str] | None = None
) -> list[Fact]:
    """Facts of ``node_ids`` (every store), optionally of ``kinds``, in text order."""
    nodes = set(node_ids)
    want = None if kinds is None else set(kinds)
    out = [
        f
        for f in a.facts.values()
        if f.node_id in nodes and (want is None or f.kind in want)
    ]
    out.sort(key=lambda f: (tuple(f.store), f.node_id or "", f.span.start))
    return out


def fact_text(a: Analysis, f: Fact) -> str | None:
    return text_index(a).text(f.store, f.node_id)
