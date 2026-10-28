"""Placeholder replacement of committed secrets (design 12.7, 15 #46).

Asked only when discovery reported ``SECRET_COMMITTED`` (group "H Secrets"):
``secrets/placeholders`` = ``none`` (default) | ``psk`` (IPsec pre-shared keys
only) | ``all``, stored in ``[labs."<lab_id>".scenarios.secrets] placeholders``.

Plan: every selected cleartext ``secret`` fact becomes ``CHANGE-ME-<name>``
(``psk``, ``enable``, ``user``, ``snmp``, ``key``, ``secret``). Hashed or
device-encrypted values (IOS type 5/7/8/9, ASA ``encrypted``/``pbkdf2``, FortiOS
``ENC``, ``$...$`` crypt strings) are left alone: a plaintext placeholder after a
type marker would not load. Claims are flagged ``secret`` (redacted in prompts,
diffs and plan JSON) and no message of this module contains a secret value.
Scenario-exact secret answers (``azure_s2s`` PSK) win over placeholders.

Review fixes: the history note is generic ("rotate it wherever it is used"); the
Azure VPN gateway is named only when the lab carries the ``azure_s2s`` scenario.
``psk`` is offered only when cleartext pre-shared keys exist (choices ``none`` /
``psk`` / ``all`` otherwise ``none`` / ``all``).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING

from ..model import Analysis, Fact, Finding
from ..profile import Profile
from . import register_scenario
from .azure_s2s import find_azure
from .base import (
    PRIO_MEMBERSHIP,
    Answers,
    PlanFragment,
    Question,
    Validator,
    ValueMaps,
    fact_claim,
    render_fact,
    text_index,
)
from .extra_common import option_setter, scenario_options

if TYPE_CHECKING:
    from ..manifest import Manifest

__all__ = [
    "CHOICES",
    "PLACEHOLDER_PREFIX",
    "SecretsScenario",
    "classify",
    "is_hashed",
    "placeholder",
    "secret_facts",
]

SID = "secrets"
CHOICES = ["none", "psk", "all"]
PLACEHOLDER_PREFIX = "CHANGE-ME-"
HISTORY_NOTE = "the old value remains in git history; rotate it wherever it is used"
AZURE_NOTE = (
    "the old value remains in git history; rotate it at the provider "
    "(Azure VPN gateway)"
)
_CLASSES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("psk", re.compile(r"pre-shared-key|psksecret|isakmp key", re.I)),
    ("enable", re.compile(r"^\s*enable\b", re.I)),
    ("user", re.compile(r"^\s*username\b", re.I)),
    ("snmp", re.compile(r"snmp-server community", re.I)),
    ("key", re.compile(r"\bkey(-string)?\b|authentication|md5", re.I)),
)
_TYPE_MARKER = re.compile(r"(?:^|\s)(?:[5789]|ENC)\s+$")
_ENC_AFTER = re.compile(r"^\s+(?:encrypted|pbkdf2)\b")


def _line(text: str, f: Fact) -> tuple[str, str]:
    """(text before the span on its line, text after it on its line)."""
    s = text.rfind("\n", 0, f.span.start) + 1
    e = text.find("\n", f.span.end)
    return text[s : f.span.start], text[f.span.end : e if e >= 0 else len(text)]


def classify(text: str, f: Fact) -> str:
    before, _after = _line(text, f)
    for name, rx in _CLASSES:
        if rx.search(before):
            return name
    return "secret"


def is_hashed(text: str, f: Fact) -> bool:
    before, after = _line(text, f)
    value = text[f.span.start : f.span.end]
    return bool(
        value.startswith("$") or _TYPE_MARKER.search(before) or _ENC_AFTER.match(after)
    )


def placeholder(name: str) -> str:
    return f"{PLACEHOLDER_PREFIX}{name}"


def secret_facts(a: Analysis) -> list[Fact]:
    idx = text_index(a)
    out = [
        f
        for f in a.facts.values()
        if f.kind == "secret" and idx.text(f.store, f.node_id) is not None
    ]
    out.sort(key=lambda f: (tuple(f.store), f.node_id or "", f.span.start))
    return out


def _validator(choices: list[str]) -> Validator:
    def validate(value: str, _ans: Answers) -> str | None:
        if value.strip().lower() not in choices:
            return f"choose one of {', '.join(choices)}"
        return None

    return validate


def _history_note(a: Analysis, m: Manifest | None) -> str:
    return AZURE_NOTE if find_azure(a, m) else HISTORY_NOTE


@register_scenario
class SecretsScenario:
    id = SID
    order = 90

    def applies(self, a: Analysis, m: Manifest | None) -> bool:
        return any(f.code == "SECRET_COMMITTED" for f in a.findings) and bool(
            secret_facts(a)
        )

    def questions(
        self, a: Analysis, m: Manifest | None, prof: Profile
    ) -> list[Question]:
        facts = secret_facts(a)
        if not facts:
            return []
        idx = text_index(a)
        counts: Counter[str] = Counter()
        hashed = 0
        for f in facts:
            text = idx.text(f.store, f.node_id) or ""
            if is_hashed(text, f):
                hashed += 1
            else:
                counts[classify(text, f)] += 1
        opts = scenario_options(prof, SID, a.lab.lab_id)
        choices = [c for c in CHOICES if c != "psk" or counts["psk"]]
        answered = opts.get("placeholders")
        default = str(answered) if answered in choices else "none"
        summary = ", ".join(f"{n} x{c}" for n, c in sorted(counts.items())) or "none"
        notes = [_history_note(a, m)]
        if hashed:
            notes.append(f"{hashed} hashed/encrypted value(s) are never replaced")
        return [
            Question(
                id=f"{SID}/placeholders",
                group="H Secrets",
                kind="choice",
                prompt=(
                    f"committed cleartext secrets ({summary}): replace with "
                    f"{PLACEHOLDER_PREFIX}<name>?"
                ),
                current=None,
                default=default,
                default_source="keep" if answered is None else f"scenarios.{SID}",
                choices=choices,
                validate=_validator(choices),
                evidence=[f.id for f in facts],
                affects=0 if default == "none" else sum(counts.values()),
                scenario=SID,
                apply=option_setter(SID, "placeholders", a.lab.lab_id),
                notes=notes,
            )
        ]

    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment:
        frag = PlanFragment()
        choice = scenario_options(ans, SID, a.lab.lab_id).get("placeholders")
        if choice not in ("psk", "all"):
            return frag
        idx = text_index(a)
        skipped = 0
        chosen = {v for v in maps.secrets.values() if v}
        for f in secret_facts(a):
            text = idx.text(f.store, f.node_id) or ""
            if f.value in chosen:
                continue  # a user-chosen secret (e.g. the azure_s2s PSK)
            if is_hashed(text, f):
                skipped += 1
                continue
            name = classify(text, f)
            if choice == "psk" and name != "psk":
                continue
            new = placeholder(name)
            edits, finding = render_fact(a, f, new)
            if finding is not None:
                finding.msg = f"{f.rule} {f.id}: secret span could not be rendered"
                frag.findings.append(finding)
            for e in edits:
                c = fact_claim(
                    f,
                    e,
                    category="secret",
                    group=f"{SID}/placeholders",
                    question=f"{SID}/placeholders",
                    priority=PRIO_MEMBERSHIP,
                    scenario=SID,
                )
                c.secret = True
                c.evidence = ""
                frag.claims.append(c)
        if frag.claims:
            frag.findings.append(
                Finding(
                    "SECRET_HISTORY",
                    "warn",
                    f"secrets: {len(frag.claims)} committed secret(s) replaced by "
                    f"placeholders; {_history_note(a, maps.manifest)}",
                    [f"scenario:{SID}"],
                )
            )
        if skipped:
            frag.findings.append(
                Finding(
                    "SECRET_HASHED_KEPT",
                    "info",
                    f"secrets: {skipped} hashed/encrypted value(s) left unchanged",
                    [f"scenario:{SID}"],
                )
            )
        return frag
