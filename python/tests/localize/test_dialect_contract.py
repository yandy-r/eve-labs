"""Dialect contract harness (design 13.3, 14.4) and framework tests.

Two things live here:

1. **The reusable contract harness** that every dialect task (T9 ios/iosxe/nxos,
   T10 asa/fortios/f5tmsh, T11 junos/linuxsh/vpcs/eve_html/generic) runs its
   dialects through.  It is *automatic*: for every registered dialect a test
   class ``Contract_<name>`` is generated below, and it picks up
   ``fixtures/snippets/<name>/*.txt`` + ``*.facts.json``.  To add a dialect, add
   snippets; no test code is needed.  For a dedicated test module::

       from tests.localize.test_dialect_contract import DialectContractMixin

       class TestIosContract(DialectContractMixin, unittest.TestCase):
           dialect_name = "ios"
           require_rule_coverage = True      # optional: every rule hit by a snippet

   or call ``check_snippet(dialect, snippet)`` / ``check_static(dialect)``
   yourself; both return a list of problem strings (empty = pass).

2. Tests of the framework itself (``blocks``, ``RuleDialect``, registry, packs).

Snippet fixtures
----------------
``fixtures/snippets/<dialect>/<name>.txt`` is a config excerpt (real lab text,
trimmed; keep the line breaks, CRLF and spacing quirks that matter).
``<name>.facts.json`` describes what ``parse`` must produce.  Generate a first
version with::

    cd python && python3 -m tests.localize.test_dialect_contract skeleton \\
        <dialect> tests/localize/fixtures/snippets/<dialect>/<name>.txt

review it by hand (it is a *proof* only if you checked it), and save it.  Schema
(every key except ``facts`` is optional)::

    {
      "node": {"template": "iol", "image": "i86bi_linux_l3-..."},
      "min_score": 70,
      "facts": [
        {"kind": "vlan_tag", "value": "2", "line": 12, "rule": "ios.encap_dot1q",
         "iface": "gi16.2", "parent": "gi16", "mask": "255.255.255.0",
         "mask_form": "dotted", "orphan": false, "group": "subif:gi16.2",
         "confidence": "PROVEN", "flags": [], "alt": "<replacement for render>"}
      ],
      "allow_extra_facts": false,
      "ifaces": {"gi16.2": {"parent": "gi16", "mode": "routed", "tag": 2,
                            "access_vlan": null, "trunk_vlans": "ALL" | "1,2",
                            "native_vlan": null, "dhcp": false, "orphan": false}},
      "vlan_db": [1, 2], "is_switch": false,
      "secrets": ["hunter2"],
      "iface_keys": {"Gi16.2": "gi16.2"},
      "eve_to_config": {"Gi16": ["GigabitEthernet16"]},
      "notes_contain": ["unparseable"]
    }

``kind``, ``value``, ``line`` and ``rule`` are mandatory per fact; the other
fact keys are compared only when present.  By default the fact list must match
exactly (so a new, unwanted fact fails the test too).

What the harness proves per snippet
-----------------------------------
* facts equal the expected list; every span reads back its value; ids are the
  documented sha1; line numbers are right; masks/lists are consistent;
* parse is deterministic and the same for CRLF and for a missing final newline;
* ``secret_spans`` agree with the ``secret`` facts;
* no-op render is byte identical (no edits);
* render(alt) then parse yields exactly the new value and nothing else changed;
* the inverse render restores the original bytes (list ranges: vlan set);
* a changed prefix rewrites the adjacent mask in its own form, and back;
* a stale fact (text moved under it) is refused;
* every rule's ``negative`` lines do not match that rule.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import textwrap
import unittest
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address
from pathlib import Path
from unittest import mock

from evelab.common.textutil import (
    VlanList,
    mask_form_of,
    mask_prefix,
    mask_prefix_as,
    mask_render,
)
from evelab.localize import dialects
from evelab.localize.dialects import (
    REGISTRY,
    Dialect,
    ParsedConfig,
    PatternRule,
    RenderCtx,
    RuleDialect,
    base,
    blocks,
    load_packs,
    make_fact_id,
    pick,
    register,
)
from evelab.localize.errors import ConflictError, LocalizeError
from evelab.localize.model import (
    CORE_FACT_KINDS,
    Confidence,
    ConfigText,
    Fact,
    Node,
    Span,
    Store,
    TextEdit,
)

from . import realtexts

HERE = Path(__file__).resolve().parent
SNIPPET_ROOT = HERE / "fixtures" / "snippets"
SELFTEST_ROOT = HERE / "fixtures" / "contract_selftest"

STORE = Store("startup", "startup", "startup")
# Kinds whose value cannot be swapped for an arbitrary string and re-parsed.
NO_ROUNDTRIP_KINDS = frozenset({"dhcp", "ipv6_literal"})
SPAN_ONLY_KEYS = ("kind", "value", "line", "rule")
OPTIONAL_FACT_KEYS = (
    "iface",
    "parent",
    "orphan",
    "group",
    "confidence",
    "mask",
    "mask_form",
)


# --------------------------------------------------------------------------- #
# harness: helpers
# --------------------------------------------------------------------------- #


def make_ct(text: str, dialect_name: str, node_id: str = "1") -> ConfigText:
    """A ConfigText as the stores layer would build it for an embedded config."""
    return ConfigText(
        store=STORE,
        node_id=node_id,
        text=text,
        dialect=dialect_name,
        blob=None,
        path=None,
    )


def apply_edits(text: str, edits: Iterable[TextEdit]) -> str:
    """Splice edits (offsets into ``text``); raises ValueError on a bad edit."""
    ordered = sorted(edits, key=lambda e: (e.start, e.end))
    out: list[str] = []
    pos = 0
    for e in ordered:
        if not 0 <= e.start <= e.end <= len(text):
            raise ValueError(f"edit out of bounds: {e}")
        if e.start < pos:
            raise ValueError(f"overlapping edits at {e.start}")
        if text[e.start : e.end] != e.old:
            raise ValueError(
                f"edit.old {e.old!r} != text {text[e.start : e.end]!r} at {e.start}"
            )
        out.append(text[pos : e.start])
        out.append(e.new)
        pos = e.end
    out.append(text[pos:])
    return "".join(out)


@dataclass
class Snippet:
    name: str
    text: str
    expected: dict[str, object]
    path: Path


def load_snippets(dialect_name: str, root: Path | None = None) -> list[Snippet]:
    """All ``*.txt`` snippets (with their ``*.facts.json``) for a dialect."""
    folder = (root or SNIPPET_ROOT) / dialect_name
    out: list[Snippet] = []
    if not folder.is_dir():
        return out
    for txt in sorted(folder.glob("*.txt")):
        facts = txt.with_suffix(".facts.json")
        expected: dict[str, object] = {}
        if facts.exists():
            expected = json.loads(facts.read_text(encoding="utf-8"))
        out.append(Snippet(txt.stem, txt.read_bytes().decode("utf-8"), expected, txt))
    return out


def _key(f: Fact) -> tuple[int, str, str, str]:
    return (f.line, f.kind, f.value, f.rule)


def _sig(f: Fact) -> tuple[str, str, int, str | None]:
    return (f.kind, f.rule, f.line, f.iface)


# --------------------------------------------------------------------------- #
# harness: static checks (no fixtures needed)
# --------------------------------------------------------------------------- #


def check_static(dialect: Dialect) -> list[str]:
    """Declaration-level checks every dialect must pass."""
    p: list[str] = []
    name = getattr(dialect, "name", "")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name):
        p.append(f"bad dialect name {name!r}")
    if not isinstance(dialect, Dialect):
        p.append("does not satisfy the Dialect protocol")
        return p
    for attr in ("templates", "sniff"):
        val = getattr(dialect, attr)
        if not isinstance(val, tuple) or not all(isinstance(v, str) for v in val):
            p.append(f"{attr} must be a tuple of str")
    for rx in dialect.sniff:
        try:
            re.compile(rx, re.MULTILINE)
        except re.error as exc:
            p.append(f"sniff regex {rx!r}: {exc}")
    if dialect.block_style not in blocks.STYLES:
        p.append(f"bad block_style {dialect.block_style!r}")
    if dialect.mask_form not in base.MASK_FORMS:
        p.append(f"bad mask_form {dialect.mask_form!r}")

    # robustness: never raise on empty / odd input
    for label, text in (("empty", ""), ("blank", "\r\n\r\n"), ("noeol", "x")):
        try:
            parsed = dialect.parse(make_ct(text, name))
        except Exception as exc:
            p.append(f"parse({label}) raised {type(exc).__name__}: {exc}")
            continue
        if parsed.dialect != name:
            p.append(f"ParsedConfig.dialect {parsed.dialect!r} != {name!r}")
        if label == "empty" and parsed.facts:
            p.append("parse('') produced facts")
        try:
            dialect.secret_spans(text)
        except Exception as exc:
            p.append(f"secret_spans({label}) raised {type(exc).__name__}: {exc}")
    for node, text in ((None, ""), (None, "hostname x\n")):
        s = dialect.score(node, text)
        if not isinstance(s, int) or not 0 <= s <= 100:
            p.append(f"score out of range: {s!r}")

    rules: tuple[PatternRule, ...] = getattr(dialect, "rules", ())
    ids = Counter(r.id for r in rules)
    p.extend(f"duplicate rule id {i!r}" for i, n in ids.items() if n > 1)
    for rule in rules:
        if rule.kind and rule.kind not in CORE_FACT_KINDS:
            p.append(f"{rule.id}: unregistered fact kind {rule.kind!r}")
        for neg in rule.negative:
            if rule.matches_line(neg):
                p.append(f"{rule.id}: negative example matches: {neg!r}")
    return p


# --------------------------------------------------------------------------- #
# harness: per-snippet checks
# --------------------------------------------------------------------------- #


def _alt_value(f: Fact, override: str | None) -> tuple[str, bool]:
    """A different, valid value for ``f`` and whether the inverse is byte exact."""
    if override is not None:
        return override, True
    v = f.value
    if f.kind in ("subif_name", "svi_name"):
        m = re.search(r"\d+$", v)
        if m:
            return v[: m.start()] + str(int(m.group()) + 1000), True
    if f.kind in base.IPV4_KINDS:
        try:
            ip = IPv4Address(v)
        except AddressValueError:
            return "zz" + v, True
        parts = str(ip).split(".")
        parts[3] = "98" if parts[3] == "99" else "99"
        return ".".join(parts), True
    if f.kind in base.INT_KINDS or (
        v.isdigit() and f.kind not in ("vlan_def", "vlan_list")
    ):
        return ("3998" if v == "3999" else "3999"), True
    if f.kind == "mask":
        prefix = mask_prefix(v)
        form = mask_form_of(v)
        if prefix is not None and form != "none":
            return mask_render(form, 16 if prefix != 16 else 24), True
    if f.kind in ("vlan_list", "vlan_def") or f.list_value is not None:
        try:
            vl = f.list_value or VlanList.parse(v)
        except ValueError:
            return "zz" + v, True
        members = list(vl)
        single = [lo for lo, hi in vl.items if lo == hi]
        target = single[0] if single else members[0]
        new = next(n for n in range(3999, 3900, -1) if n not in members)
        replaced = vl.replace({target: new})
        return replaced.render(), not replaced.splits
    return "zz" + v, True


def _expected_facts(exp: dict[str, object]) -> list[dict[str, object]]:
    raw = exp.get("facts", [])
    return raw if isinstance(raw, list) else []


def check_snippet(dialect: Dialect, snippet: Snippet) -> list[str]:
    """Run every contract check on one snippet; returns problems."""
    p: list[str] = []
    name = dialect.name
    text = snippet.text
    exp = snippet.expected
    if not exp:
        return [f"{snippet.name}: missing {snippet.name}.facts.json"]
    try:
        parsed = dialect.parse(make_ct(text, name))
    except Exception as exc:
        return [f"{snippet.name}: parse raised {type(exc).__name__}: {exc}"]
    tag = snippet.name

    p += [f"{tag}: {m}" for m in _check_expected(parsed, exp, text)]
    p += [f"{tag}: {m}" for m in _check_integrity(text, parsed)]
    p += [f"{tag}: {m}" for m in _check_variants(dialect, text, parsed)]
    p += [f"{tag}: {m}" for m in _check_secrets(dialect, text, parsed, exp)]
    p += [f"{tag}: {m}" for m in _check_extras(dialect, exp)]
    p += [f"{tag}: {m}" for m in _check_render(dialect, text, parsed, exp)]
    return p


def _check_expected(
    parsed: ParsedConfig, exp: dict[str, object], text: str
) -> list[str]:
    p: list[str] = []
    want = _expected_facts(exp)
    for i, w in enumerate(want):
        missing = [k for k in SPAN_ONLY_KEYS if k not in w]
        if missing:
            p.append(f"expected fact #{i} lacks keys {missing}")
    if p:
        return p
    want_keys = Counter((int(w["line"]), str(w["kind"]), str(w["value"]), str(w["rule"])) for w in want)  # type: ignore[call-overload]
    got_keys = Counter(_key(f) for f in parsed.facts)
    for k in sorted((want_keys - got_keys).elements()):
        p.append(f"missing fact line {k[0]} {k[1]}={k[2]!r} ({k[3]})")
    if not exp.get("allow_extra_facts"):
        for k in sorted((got_keys - want_keys).elements()):
            p.append(f"unexpected fact line {k[0]} {k[1]}={k[2]!r} ({k[3]})")
    # optional attributes, matched on (line, kind, value, rule)
    by_key = {_key(f): f for f in parsed.facts}
    for w in want:
        f = by_key.get((int(w["line"]), str(w["kind"]), str(w["value"]), str(w["rule"])))  # type: ignore[call-overload]
        if f is None:
            continue
        tag = f"line {f.line} {f.kind}={f.value!r}"
        for key in OPTIONAL_FACT_KEYS:
            if key not in w:
                continue
            if key == "confidence":
                actual: object = f.confidence.name
            elif key == "mask":
                actual = (
                    None
                    if f.mask_span is None
                    else text[f.mask_span.start : f.mask_span.end]
                )
            else:
                actual = getattr(f, key)
            if actual != w[key]:
                p.append(f"{tag}: {key} is {actual!r}, expected {w[key]!r}")
        if "flags" in w and sorted(f.flags) != sorted(w["flags"]):  # type: ignore[arg-type]
            p.append(f"{tag}: flags {sorted(f.flags)} != {w['flags']}")

    ifaces = exp.get("ifaces")
    if isinstance(ifaces, dict):
        for key, fields in ifaces.items():
            info = parsed.ifaces.get(key)
            if info is None:
                p.append(f"missing iface {key!r}; have {sorted(parsed.ifaces)}")
                continue
            for field_name, value in dict(fields).items():
                if field_name == "trunk_vlans":
                    actual = (
                        "ALL" if info.trunk_vlans is None else info.trunk_vlans.render()
                    )
                else:
                    actual = getattr(info, field_name)
                if actual != value:
                    p.append(
                        f"iface {key}: {field_name} is {actual!r}, expected {value!r}"
                    )
    if "vlan_db" in exp and sorted(parsed.vlan_db) != sorted(exp["vlan_db"]):  # type: ignore[arg-type]
        p.append(f"vlan_db {sorted(parsed.vlan_db)} != {exp['vlan_db']}")
    if "is_switch" in exp and parsed.is_switch != exp["is_switch"]:
        p.append(f"is_switch {parsed.is_switch} != {exp['is_switch']}")
    for needle in exp.get("notes_contain", []):  # type: ignore[attr-defined]
        if not any(needle in n for n in parsed.notes):
            p.append(f"no note containing {needle!r}: {parsed.notes}")
    return p


def _check_integrity(text: str, parsed: ParsedConfig) -> list[str]:
    p: list[str] = []
    seen_ids: set[str] = set()
    seen_spans: set[tuple[str, int, int]] = set()
    prev: tuple[int, int] = (-1, -1)
    for f in parsed.facts:
        tag = f"{f.rule}@{f.line} {f.kind}={f.value!r}"
        s = f.span
        if not 0 <= s.start < s.end <= len(text):
            p.append(f"{tag}: span {s} out of range")
            continue
        if text[s.start : s.end] != f.value:
            p.append(f"{tag}: span text {text[s.start : s.end]!r} != value")
        if "\n" in f.value:
            p.append(f"{tag}: value spans lines")
        if f.line != text.count("\n", 0, s.start) + 1:
            p.append(f"{tag}: wrong line number {f.line}")
        if f.id != make_fact_id(f.store, f.node_id, s.start, f.kind):
            p.append(f"{tag}: id is not sha1(store,node,start,kind)[:12]")
        if f.id in seen_ids:
            p.append(f"{tag}: duplicate fact id")
        seen_ids.add(f.id)
        sk = (f.kind, s.start, s.end)
        if sk in seen_spans:
            p.append(f"{tag}: duplicate (kind, span)")
        seen_spans.add(sk)
        if (s.start, s.end) < prev:
            p.append(f"{tag}: facts not sorted by span")
        prev = (s.start, s.end)
        if f.kind not in CORE_FACT_KINDS:
            p.append(f"{tag}: unregistered kind")
        if f.orphan and (f.iface is not None or f.confidence > Confidence.CORRELATED):
            p.append(
                f"{tag}: orphan fact must have iface=None and confidence<=CORRELATED"
            )
        if f.mask_span is not None:
            m = f.mask_span
            mt = text[m.start : m.end]
            if not 0 <= m.start < m.end <= len(text) or "\n" in mt:
                p.append(f"{tag}: bad mask_span")
            elif mask_prefix_as(mt, f.mask_form) is None:
                p.append(f"{tag}: mask_span text {mt!r} is not a mask")
            elif m.start < s.end and s.start < m.end:
                p.append(f"{tag}: mask_span overlaps value span")
            elif f.mask_form == "none":
                p.append(f"{tag}: mask_span set but mask_form 'none'")
            elif f.mask_form in ("dotted", "prefix", "netmask") and (
                mask_form_of(mt, keyword_before=f.mask_form == "netmask") != f.mask_form
            ):
                p.append(f"{tag}: mask_form {f.mask_form!r} does not describe {mt!r}")
        elif f.mask_form != "none":
            p.append(f"{tag}: mask_form without mask_span")
        if f.list_value is not None:
            try:
                same = VlanList.parse(f.value).vlans() == f.list_value.vlans()
            except ValueError:
                same = False
            if not same:
                p.append(f"{tag}: list_value does not match value")
    return p


def _check_variants(dialect: Dialect, text: str, parsed: ParsedConfig) -> list[str]:
    """Same facts for CRLF text and for text without a final newline."""
    p: list[str] = []
    base_sigs = [_sig(f) for f in parsed.facts]
    base_vals = [f.value for f in parsed.facts]
    again = dialect.parse(make_ct(text, dialect.name))
    if again.facts != parsed.facts or again.ifaces != parsed.ifaces:
        p.append("parse is not deterministic")
    variants = {"CRLF": text.replace("\r\n", "\n").replace("\n", "\r\n")}
    if text.endswith("\n"):
        variants["no final newline"] = text.rstrip("\r\n")
    for label, vtext in variants.items():
        try:
            other = dialect.parse(make_ct(vtext, dialect.name))
        except Exception as exc:
            p.append(f"{label}: parse raised {type(exc).__name__}: {exc}")
            continue
        if [_sig(f) for f in other.facts] != base_sigs or [
            f.value for f in other.facts
        ] != base_vals:
            p.append(f"{label}: facts differ from the LF text")
        for f in other.facts:
            if vtext[f.span.start : f.span.end] != f.value:
                p.append(f"{label}: span of {f.rule}@{f.line} does not read back")
                break
    return p


def _check_secrets(
    dialect: Dialect, text: str, parsed: ParsedConfig, exp: dict[str, object]
) -> list[str]:
    p: list[str] = []
    spans = dialect.secret_spans(text)
    last = -1
    for s in spans:
        if not 0 <= s.start < s.end <= len(text):
            p.append(f"secret span {s} out of range")
        elif s.start < last:
            p.append(f"secret spans overlap or are unsorted at {s}")
        last = s.end
    want = exp.get("secrets")
    if isinstance(want, list):
        got = [text[s.start : s.end] for s in spans]
        if got != want:
            p.append(f"secret_spans read {got}, expected {want}")
    fact_spans = {f.span for f in parsed.facts if f.kind == "secret"}
    for s in spans:
        if s not in fact_spans:
            p.append(f"secret span {s} has no 'secret' fact")
    for f in parsed.facts:
        if f.kind == "secret" and "secret" not in f.flags:
            p.append(f"secret fact {f.rule}@{f.line} lacks the 'secret' flag")
    return p


def _check_extras(dialect: Dialect, exp: dict[str, object]) -> list[str]:
    p: list[str] = []
    for src, want in dict(exp.get("iface_keys", {})).items():  # type: ignore[call-overload]
        got = dialect.iface_key(src)
        if got != want:
            p.append(f"iface_key({src!r}) = {got!r}, expected {want!r}")
        if dialect.iface_key(got) != got:
            p.append(f"iface_key is not idempotent for {src!r}")
    for src, want in dict(exp.get("eve_to_config", {})).items():  # type: ignore[call-overload]
        got = dialect.eve_to_config(src)
        if got != want:
            p.append(f"eve_to_config({src!r}) = {got!r}, expected {want!r}")
    node_spec = exp.get("node")
    if isinstance(node_spec, dict):
        node = Node(
            id="1",
            name="anything",
            type="qemu",
            template=str(node_spec.get("template", "")),
            image=str(node_spec.get("image", "")),
            config_attr="0",
            ifaces=[],
        )
        score = dialect.score(node, "")
        floor = int(exp.get("min_score", 1))  # type: ignore[call-overload]
        if score < floor:
            p.append(f"score {score} < min_score {floor} for node {node_spec}")
        other = Node("2", "ISP-RTR1", "qemu", node.template, node.image, "0", [])
        if dialect.score(other, "") != score:
            p.append("score depends on the node name")
    return p


def _check_render(
    dialect: Dialect, text: str, parsed: ParsedConfig, exp: dict[str, object]
) -> list[str]:
    p: list[str] = []
    overrides: dict[tuple[int, str, str, str], str] = {}
    for w in _expected_facts(exp):
        if "alt" in w:
            overrides[(int(w["line"]), str(w["kind"]), str(w["value"]), str(w["rule"]))] = str(w["alt"])  # type: ignore[call-overload]
    ctx = RenderCtx(text)
    stale_done = False
    for idx, f in enumerate(parsed.facts):
        tag = f"{f.rule}@{f.line} {f.kind}={f.value!r}"
        try:
            noop = dialect.render(f, f.value, ctx)
        except Exception as exc:
            p.append(f"{tag}: no-op render raised {type(exc).__name__}: {exc}")
            continue
        try:
            same = apply_edits(text, noop) == text
        except ValueError as exc:
            same = False
            p.append(f"{tag}: no-op render gave invalid edits: {exc}")
        if noop or not same:
            p.append(f"{tag}: no-op render is not byte identical ({noop})")

        if f.kind in NO_ROUNDTRIP_KINDS:
            continue
        alt, exact = _alt_value(f, overrides.get(_key(f)))

        if not stale_done:
            stale_done = True
            try:
                dialect.render(f, alt, RenderCtx("#" + text))
            except LocalizeError:
                pass
            except Exception as exc:
                p.append(
                    f"{tag}: stale fact raised {type(exc).__name__}, want LocalizeError"
                )
            else:
                p.append(f"{tag}: render accepted a stale fact (text shifted under it)")

        p += _roundtrip_value(dialect, text, parsed, idx, f, alt, exact, tag)
        if f.mask_span is not None:
            p += _roundtrip_mask(dialect, text, parsed, f, tag)
    return p


def _counterpart(parsed: ParsedConfig, f: Fact, other: ParsedConfig) -> Fact | None:
    """The fact of ``other`` that corresponds to ``f`` (same kind/rule/line/n-th)."""

    def occ(pc: ParsedConfig, target: Fact) -> int:
        n = 0
        for x in pc.facts:
            if x is target:
                return n
            if (x.kind, x.rule, x.line) == (target.kind, target.rule, target.line):
                n += 1
        return -1

    n = occ(parsed, f)
    seen = 0
    for x in other.facts:
        if (x.kind, x.rule, x.line) == (f.kind, f.rule, f.line):
            if seen == n:
                return x
            seen += 1
    return None


def _roundtrip_value(
    dialect: Dialect,
    text: str,
    parsed: ParsedConfig,
    idx: int,
    f: Fact,
    alt: str,
    exact: bool,
    tag: str,
) -> list[str]:
    p: list[str] = []
    try:
        edits = dialect.render(f, alt, RenderCtx(text))
        new_text = apply_edits(text, edits)
    except Exception as exc:
        return [f"{tag}: render({alt!r}) failed: {type(exc).__name__}: {exc}"]
    if not edits or not any(
        e.start == f.span.start and e.end == f.span.end and e.new == alt for e in edits
    ):
        p.append(f"{tag}: render({alt!r}) has no edit replacing the fact span: {edits}")
    new = dialect.parse(make_ct(new_text, dialect.name))
    g = _counterpart(parsed, f, new)
    if g is None:
        return [*p, f"{tag}: fact vanished after render({alt!r})"]
    if g.value != alt:
        p.append(f"{tag}: after render the fact reads {g.value!r}, expected {alt!r}")
    if len(new.facts) != len(parsed.facts):
        p.append(f"{tag}: render changed the number of facts")
    else:
        for a, b in zip(parsed.facts, new.facts, strict=True):
            if a is f:
                continue
            if _sig(a)[:3] != _sig(b)[:3] or a.value != b.value:
                p.append(f"{tag}: render disturbed other fact {a.rule}@{a.line}")
                break
    try:
        back_edits = dialect.render(g, f.value, RenderCtx(new_text))
        back = apply_edits(new_text, back_edits)
    except Exception as exc:
        return [*p, f"{tag}: inverse render failed: {type(exc).__name__}: {exc}"]
    if exact:
        if back != text:
            p.append(f"{tag}: inverse render does not restore the original bytes")
    else:
        again = dialect.parse(make_ct(back, dialect.name))
        h = _counterpart(parsed, f, again)
        if (
            h is None
            or VlanList.parse(h.value).vlans() != VlanList.parse(f.value).vlans()
        ):
            p.append(f"{tag}: inverse render does not restore the VLAN set")
    return p


def _roundtrip_mask(
    dialect: Dialect, text: str, parsed: ParsedConfig, f: Fact, tag: str
) -> list[str]:
    p: list[str] = []
    assert f.mask_span is not None
    old_mask = text[f.mask_span.start : f.mask_span.end]
    old_prefix = mask_prefix_as(old_mask, f.mask_form)
    assert old_prefix is not None
    new_prefix = 16 if old_prefix != 16 else 24
    try:
        edits = dialect.render(f, f.value, RenderCtx(text, new_prefix=new_prefix))
        new_text = apply_edits(text, edits)
    except Exception as exc:
        return [f"{tag}: mask render failed: {type(exc).__name__}: {exc}"]
    new = dialect.parse(make_ct(new_text, dialect.name))
    g = _counterpart(parsed, f, new)
    if g is None or g.mask_span is None:
        return [f"{tag}: mask lost after prefix change"]
    mt = new_text[g.mask_span.start : g.mask_span.end]
    if mask_prefix_as(mt, g.mask_form) != new_prefix:
        p.append(f"{tag}: mask reads {mt!r}, expected /{new_prefix}")
    if g.mask_form != f.mask_form:
        p.append(f"{tag}: mask form changed {f.mask_form} -> {g.mask_form}")
    if g.value != f.value:
        p.append(f"{tag}: value changed while rewriting only the mask")
    try:
        back = apply_edits(
            new_text,
            dialect.render(g, g.value, RenderCtx(new_text, new_prefix=old_prefix)),
        )
    except Exception as exc:
        return [*p, f"{tag}: inverse mask render failed: {type(exc).__name__}: {exc}"]
    if back != text:
        p.append(f"{tag}: inverse mask render does not restore the original bytes")
    # unchanged prefix => no edit
    if dialect.render(f, f.value, RenderCtx(text, new_prefix=old_prefix)):
        p.append(f"{tag}: unchanged prefix produced an edit")
    return p


def check_rule_coverage(dialect: Dialect, snippets: list[Snippet]) -> list[str]:
    """Rules that no snippet exercises (opt-in check)."""
    hit: set[str] = set()
    for sn in snippets:
        hit.update(str(w["rule"]) for w in _expected_facts(sn.expected))
    return [
        f"rule {r.id} is not covered by any snippet"
        for r in getattr(dialect, "rules", ())
        if r.kind and r.id not in hit
    ]


def skeleton(dialect: Dialect, text: str) -> dict[str, object]:
    """A starting point for ``<name>.facts.json`` (review before committing)."""
    parsed = dialect.parse(make_ct(text, dialect.name))
    facts: list[dict[str, object]] = []
    for f in parsed.facts:
        item: dict[str, object] = {
            "kind": f.kind,
            "value": f.value,
            "line": f.line,
            "rule": f.rule,
            "iface": f.iface,
        }
        if f.parent:
            item["parent"] = f.parent
        if f.mask_span:
            item["mask"] = text[f.mask_span.start : f.mask_span.end]
            item["mask_form"] = f.mask_form
        if f.orphan:
            item["orphan"] = True
        if f.group:
            item["group"] = f.group
        facts.append(item)
    ifaces: dict[str, object] = {}
    for key, info in parsed.ifaces.items():
        ifaces[key] = {
            "parent": info.parent,
            "mode": info.mode,
            "access_vlan": info.access_vlan,
            "trunk_vlans": (
                "ALL" if info.trunk_vlans is None else info.trunk_vlans.render()
            ),
            "native_vlan": info.native_vlan,
            "tag": info.tag,
            "dhcp": info.dhcp,
            "orphan": info.orphan,
        }
    return {
        "facts": facts,
        "ifaces": ifaces,
        "vlan_db": sorted(parsed.vlan_db),
        "is_switch": parsed.is_switch,
    }


# --------------------------------------------------------------------------- #
# harness: mixin and auto-generated per-dialect classes
# --------------------------------------------------------------------------- #


class DialectContractMixin:
    """Mix into a ``unittest.TestCase`` and set ``dialect_name``."""

    dialect_name: str = ""
    snippet_root: Path = SNIPPET_ROOT
    require_snippets: bool = False
    require_rule_coverage: bool = False

    def get_dialect(self) -> Dialect:
        return dialects.get(self.dialect_name)

    def test_declaration(self) -> None:
        problems = check_static(self.get_dialect())
        self.assertEqual(problems, [], "\n".join(problems))  # type: ignore[attr-defined]

    def test_snippets(self) -> None:
        snippets = load_snippets(self.dialect_name, self.snippet_root)
        if not snippets:
            if self.require_snippets:
                self.fail(f"no snippets under {self.snippet_root / self.dialect_name}")  # type: ignore[attr-defined]
            self.skipTest("no snippets for this dialect")  # type: ignore[attr-defined]
        d = self.get_dialect()
        for sn in snippets:
            with self.subTest(snippet=sn.name):  # type: ignore[attr-defined]
                problems = check_snippet(d, sn)
                self.assertEqual(problems, [], "\n".join(problems))  # type: ignore[attr-defined]

    def test_rule_coverage(self) -> None:
        if not self.require_rule_coverage:
            self.skipTest("rule coverage not required")  # type: ignore[attr-defined]
        problems = check_rule_coverage(
            self.get_dialect(), load_snippets(self.dialect_name, self.snippet_root)
        )
        self.assertEqual(problems, [], "\n".join(problems))  # type: ignore[attr-defined]


def _generate_contract_classes() -> None:
    """One ``Contract_<dialect>`` TestCase per registered dialect."""
    dialects.load_builtin()
    for name in sorted(REGISTRY):
        cls = type(
            f"Contract_{name}",
            (DialectContractMixin, unittest.TestCase),
            {"dialect_name": name, "__module__": __name__},
        )
        globals()[cls.__name__] = cls


_generate_contract_classes()


class TestBuiltinDialectsShipSnippets(unittest.TestCase):
    """Every built-in dialect must have snippet fixtures (13.3)."""

    def test_snippets_exist(self) -> None:
        missing = [
            n
            for n in sorted(REGISTRY)
            if n in dialects.BUILTIN_MODULES and not load_snippets(n)
        ]
        self.assertEqual(missing, [], f"no fixtures/snippets/<dialect> for: {missing}")


# --------------------------------------------------------------------------- #
# framework tests: a toy IOS-like dialect
# --------------------------------------------------------------------------- #


class ToyIOS(RuleDialect):
    """IOS-flavoured data-only dialect used to test the engine and the harness."""

    name = "toyios"
    templates = ("toy*", "i86bi_linux_l2-*")
    sniff = (r"^hostname \S+", r"^interface \S+")
    block_style = "indent"
    mask_form = "dotted"
    iface_aliases = {
        "Gi": "GigabitEthernet",
        "Et": "Ethernet",
        "Vl": "Vlan",
        "Lo": "Loopback",
    }
    rules = (
        PatternRule(
            "toy.subif_name",
            r"^interface (?P<v>(?P<parent>\S+?)\.\d+)$",
            "subif_name",
            block="interface",
        ),
        PatternRule("toy.svi_name", r"^interface (?P<v>Vlan\d+)$", "svi_name"),
        PatternRule(
            "toy.encap",
            r"^\s+encapsulation dot1[Qq] (?P<v>\d+)\b",
            "vlan_tag",
            block="interface",
            role="encap_tag",
            negative=("   rd 2:2", " encapsulation isis 2", "ip domain-list 2"),
        ),
        PatternRule(
            "toy.access",
            r"^\s+switchport access vlan (?P<v>\d+)$",
            "vlan_tag",
            block="interface",
            l2=True,
        ),
        PatternRule(
            "toy.native",
            r"^\s+switchport trunk native vlan (?P<v>\d+)$",
            "vlan_tag",
            block="interface",
            role="native_vlan",
        ),
        PatternRule(
            "toy.allowed",
            r"^\s+switchport trunk allowed vlan (?:(?P<add>add) )?(?P<v>\d[\d,\-]*)$",
            "vlan_list",
            block="interface",
            l2=True,
            list_style="ios",
        ),
        PatternRule(
            "toy.allowed_kw",
            r"^\s+switchport trunk allowed vlan (?P<kw>all|none)$",
            "",
            block="interface",
            role="trunk_allowed",
        ),
        PatternRule(
            "toy.mode_trunk",
            r"^\s+switchport mode trunk$",
            "",
            block="interface",
            role="mode_trunk",
        ),
        PatternRule(
            "toy.mode_access",
            r"^\s+switchport mode access$",
            "",
            block="interface",
            role="mode_access",
        ),
        PatternRule(
            "toy.ip",
            r"^\s+ip address (?P<v>IPV4) (?P<mask>MASK)\s*$",
            "ip_host",
            block="interface",
            negative=(" ip address dhcp", " ip addresses 10.1.1.1 255.255.255.0"),
        ),
        PatternRule(
            "toy.dhcp", r"^\s+ip address (?P<v>dhcp)$", "dhcp", block="interface"
        ),
        PatternRule(
            "toy.vrf_default",
            r"^\s+ip route 0\.0\.0\.0 0\.0\.0\.0 (?P<v>IPV4)$",
            "ip_gateway",
            block="vrf",
        ),
        PatternRule("toy.vlan_def", r"^vlan (?P<v>[\d,\-]+)$", "vlan_def"),
        PatternRule(
            "toy.vlan_name",
            r"^\s+name (?P<v>\S+)$",
            "vlan_name",
            block="vlan",
        ),
        PatternRule(
            "toy.dns",
            r"^ip name-server (?:vrf \S+ )?(?P<many>IPV4(?: IPV4)*)\s*$",
            "dns_server",
            negative=(
                "name servers",
                " name servers",
                "vlan 100",
                "ip name-servers 1.1.1.1",
            ),
        ),
        PatternRule(
            "toy.domain",
            r"^ip domain[- ]name (?P<v>\S+)$",
            "domain",
            block="top",
        ),
        PatternRule(
            "toy.desc_label",
            r"^\s+description to (?P<v>[\w-]+): ",
            "label_ref",
            flags=("cosmetic",),
        ),
    )
    secret_rules = (r"^username \S+ .*(?:password|secret) (?:\d )?(?P<s>\S+)",)
    block_starts = None


TOY_TEXT = textwrap.dedent("""\
    hostname b1-sw1
    !
    username admin privilege 15 secret 9 $9$abcdef
    ip domain name netlab.local
    ip name-server 10.100.51.11 10.100.51.12
    !
    vlan 1,100-101,203
    vlan 203
     name servers
    !
    interface GigabitEthernet0/0
     description to c8kv-75: Gi16.2
     no shutdown
     switchport mode trunk
     switchport trunk allowed vlan 203,3101
     switchport trunk allowed vlan add 100
     switchport trunk native vlan 7
    !
    interface GigabitEthernet0/1
     switchport mode access
     switchport access vlan 203
    !
    interface GigabitEthernet16.2
     encapsulation dot1Q 2
     ip address 10.100.2.14 255.255.255.0
    !
    interface Vlan203
     ip address 10.100.203.5 255.255.252.0
     ip address dhcp
    !
    interface GigabitEthernet3/2
     negotiat
    *Dec 28 18:28:00.651: %SYS-5-CONFIG_I: Configured from console by consoleion auto
    !
    interface GigabitEthernet
     no shutdown
    *Dec 29 01:11:44.205: %SYS-5-CONFIG_I: Configured from console by console3/3
     description Management interface
     switchport trunk allowed vlan 203
     ip address 10.1.1.1 255.255.255.0
    !
    vrf context management
      ip route 0.0.0.0 0.0.0.0 10.100.203.1
      rd 2:2
    end
    interface GigabitEthernet9/9
     switchport access vlan 77
    """)


def toy_ct(text: str = TOY_TEXT) -> ConfigText:
    return make_ct(text, "toyios")


class TestRuleDialectParse(unittest.TestCase):
    def setUp(self) -> None:
        self.d = ToyIOS()
        self.parsed = self.d.parse(toy_ct())

    def facts(self, kind: str) -> list[Fact]:
        return [f for f in self.parsed.facts if f.kind == kind]

    def test_contract_self_check(self) -> None:
        self.assertEqual(check_static(self.d), [])

    def test_encap_and_subif(self) -> None:
        (sub,) = self.facts("subif_name")
        self.assertEqual(sub.value, "GigabitEthernet16.2")
        self.assertEqual(sub.iface, "gi16.2")
        self.assertEqual(sub.parent, "gi16")
        encap = [f for f in self.facts("vlan_tag") if f.rule == "toy.encap"]
        self.assertEqual([f.value for f in encap], ["2"])
        self.assertEqual(encap[0].iface, "gi16.2")
        self.assertEqual(encap[0].group, sub.group)
        self.assertEqual(sub.group, "subif:gi16.2")
        self.assertEqual(self.parsed.ifaces["gi16.2"].tag, 2)
        self.assertEqual(self.parsed.ifaces["gi16.2"].parent, "gi16")
        self.assertEqual(self.parsed.ifaces["gi16.2"].mode, "routed")

    def test_small_numbers_never_become_tags(self) -> None:
        values = [(f.line, f.value) for f in self.facts("vlan_tag")]
        self.assertNotIn("2:2", [v for _, v in values])
        self.assertTrue(all(v.isdigit() for _, v in values))

    def test_ip_mask_forms(self) -> None:
        by_value = {f.value: f for f in self.facts("ip_host")}
        f = by_value["10.100.2.14"]
        assert f.mask_span is not None
        self.assertEqual(f.mask_form, "dotted")
        self.assertEqual(TOY_TEXT[f.mask_span.start : f.mask_span.end], "255.255.255.0")
        self.assertEqual(by_value["10.100.203.5"].mask_form, "dotted")

    def test_dhcp(self) -> None:
        self.assertTrue(self.parsed.ifaces["vl203"].dhcp)
        self.assertEqual([f.value for f in self.facts("dhcp")], ["dhcp"])

    def test_many_group_makes_one_fact_per_ip(self) -> None:
        self.assertEqual(
            [f.value for f in self.facts("dns_server")],
            ["10.100.51.11", "10.100.51.12"],
        )

    def test_name_servers_vlan_name_is_not_dns(self) -> None:
        (name,) = self.facts("vlan_name")
        self.assertEqual(name.value, "servers")
        self.assertEqual(name.iface, None)
        self.assertNotIn("servers", [f.value for f in self.facts("dns_server")])

    def test_block_filter(self) -> None:
        (gw,) = self.facts("ip_gateway")
        self.assertEqual(gw.value, "10.100.203.1")
        (dom,) = self.facts("domain")
        self.assertEqual(dom.value, "netlab.local")

    def test_vlan_lists_and_defs(self) -> None:
        lists = {f.value: f for f in self.facts("vlan_list")}
        self.assertIn("203,3101", lists)
        self.assertEqual(lists["203,3101"].list_value, VlanList.parse("203,3101"))
        defs = {f.value for f in self.facts("vlan_def")}
        self.assertEqual(defs, {"1,100-101,203", "203"})

    def test_iface_info(self) -> None:
        trunk = self.parsed.ifaces["gi0/0"]
        self.assertEqual(trunk.mode, "trunk")
        assert trunk.trunk_vlans is not None
        self.assertEqual(trunk.trunk_vlans.vlans(), [100, 203, 3101])  # add merged
        self.assertEqual(trunk.native_vlan, 7)
        access = self.parsed.ifaces["gi0/1"]
        self.assertEqual((access.mode, access.access_vlan), ("access", 203))
        self.assertTrue(self.parsed.is_switch)

    def test_vlan_db_explicit_and_implicit(self) -> None:
        self.assertEqual(
            self.parsed.vlan_db, {1, 100, 101, 203, 3101}  # explicit + allowed + svi
        )
        self.assertNotIn(77, self.parsed.vlan_db)  # text after `end`
        self.assertNotIn(7, self.parsed.vlan_db)  # native is not implicit

    def test_text_after_end_ignored(self) -> None:
        self.assertFalse(any(f.value == "77" for f in self.parsed.facts))

    def test_syslog_lines_skipped_and_orphan_block(self) -> None:
        orphans = [f for f in self.parsed.facts if f.orphan]
        self.assertEqual(
            sorted((f.kind, f.value) for f in orphans),
            [("ip_host", "10.1.1.1"), ("vlan_list", "203")],
        )
        for f in orphans:
            self.assertIsNone(f.iface)
            self.assertLessEqual(f.confidence, Confidence.CORRELATED)
        orphan_ifaces = [i for i in self.parsed.ifaces.values() if i.orphan]
        self.assertEqual(len(orphan_ifaces), 1)
        self.assertTrue(orphan_ifaces[0].key.startswith("orphan:"))
        # the spliced syslog line itself never yields facts
        self.assertFalse(
            any(
                "SYS-5" in TOY_TEXT[f.span.start : f.span.end]
                for f in self.parsed.facts
            )
        )

    def test_vlan_db_ignores_orphans(self) -> None:
        # vlan 203 only comes from defs / svi / orphan allowed list
        self.assertIn(203, self.parsed.vlan_db)

    def test_secret(self) -> None:
        (sec,) = self.facts("secret")
        self.assertEqual(sec.value, "$9$abcdef")
        self.assertEqual(sec.flags, frozenset({"secret"}))
        self.assertEqual(self.d.secret_spans(TOY_TEXT), [sec.span])

    def test_flags_from_rule(self) -> None:
        (label,) = self.facts("label_ref")
        self.assertEqual(label.value, "c8kv-75")
        self.assertEqual(label.flags, frozenset({"cosmetic"}))

    def test_confidence_default(self) -> None:
        clean = [
            f for f in self.parsed.facts if not f.orphan and f.kind != "ipv6_literal"
        ]
        self.assertTrue(all(f.confidence == Confidence.PROVEN for f in clean))

    def test_facts_sorted_and_ids_unique(self) -> None:
        starts = [(f.span.start, f.span.end) for f in self.parsed.facts]
        self.assertEqual(starts, sorted(starts))
        ids = [f.id for f in self.parsed.facts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_ids_stable_across_runs(self) -> None:
        again = self.d.parse(toy_ct())
        self.assertEqual([f.id for f in again.facts], [f.id for f in self.parsed.facts])
        other_node = self.d.parse(make_ct(TOY_TEXT, "toyios", node_id="2"))
        self.assertNotEqual(other_node.facts[0].id, self.parsed.facts[0].id)

    def test_ipv6_literal_facts(self) -> None:
        text = "interface GigabitEthernet0/0\n ipv6 address 2001:db8::1/64\n rd 2:2\n"
        parsed = self.d.parse(make_ct(text, "toyios"))
        v6 = [f for f in parsed.facts if f.kind == "ipv6_literal"]
        self.assertEqual([f.value for f in v6], ["2001:db8::1"])
        self.assertEqual(v6[0].confidence, Confidence.HEURISTIC)

    def test_negative_examples_do_not_match(self) -> None:
        for rule in ToyIOS.rules:
            for neg in rule.negative:
                self.assertFalse(rule.matches_line(neg), (rule.id, neg))

    def test_empty_and_garbage(self) -> None:
        for text in ("", "\n", "\r\n\r\n", "\x00\x01 binary \xff", "interface\n"):
            parsed = self.d.parse(make_ct(text, "toyios"))
            self.assertIsInstance(parsed, ParsedConfig)

    def test_crlf_gives_same_facts(self) -> None:
        crlf = self.d.parse(make_ct(TOY_TEXT.replace("\n", "\r\n"), "toyios"))
        self.assertEqual(
            [_sig(f) for f in crlf.facts], [_sig(f) for f in self.parsed.facts]
        )
        self.assertEqual(
            [f.value for f in crlf.facts], [f.value for f in self.parsed.facts]
        )

    def test_duplicate_span_kept_once(self) -> None:
        class Dup(RuleDialect):
            name = "dupkind"
            rules = (
                PatternRule("d.a", r"^ip domain-name (?P<v>\S+)$", "domain"),
                PatternRule("d.b", r"^ip domain-name (?P<v>\S+)$", "domain"),
            )

        parsed = Dup().parse(make_ct("ip domain-name a.b\n", "dupkind"))
        self.assertEqual([f.rule for f in parsed.facts], ["d.a"])

    def test_list_parse_failure_is_noted(self) -> None:
        class L(RuleDialect):
            name = "listfail"
            rules = (
                PatternRule(
                    "l.x", r"^vlans (?P<v>\S+)$", "vlan_list", list_style="ios"
                ),
            )

        parsed = L().parse(make_ct("vlans 5-3\nvlans 1,2\n", "listfail"))
        self.assertEqual([f.value for f in parsed.facts], ["1,2"])
        self.assertTrue(any("line 1" in n for n in parsed.notes))


class TestIfaceNames(unittest.TestCase):
    def setUp(self) -> None:
        self.d = ToyIOS()

    def test_iface_key(self) -> None:
        for name, key in (
            ("GigabitEthernet16.2", "gi16.2"),
            ("Gi16.2", "gi16.2"),
            ("Gig16.2", "gi16.2"),
            ("gigabitethernet0/1", "gi0/1"),
            ("Ethernet1/6", "et1/6"),
            ("e0/1", "et0/1"),
            ("Vlan 203", "vl203"),
            ("mgmt0", "mgmt0"),
            ("fxp0.0", "fxp0.0"),
            ("ge-0/0/1.0", "ge-0/0/1.0"),
            ("lan_port1", "lan_port1"),
            ("1/1", "1/1"),
        ):
            with self.subTest(name=name):
                self.assertEqual(self.d.iface_key(name), key)
                self.assertEqual(self.d.iface_key(key), key)  # idempotent

    def test_eve_to_config(self) -> None:
        self.assertEqual(self.d.eve_to_config("Gi16"), ["GigabitEthernet16"])
        self.assertEqual(self.d.eve_to_config("e0/1"), ["Ethernet0/1"])
        self.assertEqual(self.d.eve_to_config("Gi0/0"), ["GigabitEthernet0/0"])
        self.assertEqual(self.d.eve_to_config("port8"), ["port8"])
        self.assertEqual(self.d.eve_to_config("5"), ["5"])

    def test_no_aliases(self) -> None:
        class Plain(RuleDialect):
            name = "plainif"

        p = Plain()
        self.assertEqual(p.iface_key("Port 8"), "port8")
        self.assertEqual(p.eve_to_config("port8"), ["port8"])


class TestScoreAndPick(unittest.TestCase):
    def node(self, template: str = "", image: str = "", name: str = "n") -> Node:
        return Node("1", name, "qemu", template, image, "0", [])

    def test_score_levels(self) -> None:
        d = ToyIOS()
        self.assertEqual(d.score(self.node("toy-router"), ""), 70)
        self.assertEqual(d.score(self.node("toy-router"), "hostname x\n"), 100)
        self.assertEqual(
            d.score(self.node(image="I86BI_LINUX_L2-ADVENTERPRISEK9"), ""), 70
        )
        self.assertEqual(d.score(None, "hostname x\n"), 30)
        self.assertEqual(d.score(None, "hostname x\ninterface Gi0/0\n"), 40)
        self.assertEqual(d.score(None, "nothing here"), 0)
        self.assertEqual(d.score(self.node("other"), ""), 0)

    def test_score_ignores_node_name(self) -> None:
        d = ToyIOS()
        self.assertEqual(
            d.score(self.node("other", name="toy-router"), ""),
            d.score(self.node("other", name="zzz"), ""),
        )

    def _fresh(self):
        return mock.patch.multiple(dialects, _loaded=True)

    def test_pick_highest_score_then_generic_fallback_then_override(self) -> None:
        class A(RuleDialect):
            name = "pick_a"
            templates = ("aaa*",)

        class B(RuleDialect):
            name = "pick_b"
            templates = ("aaa*",)
            sniff = (r"^marker",)

        class G(RuleDialect):
            name = "generic"

        with self._fresh(), mock.patch.dict(REGISTRY, clear=True):
            for cls in (A, B, G):
                register(cls)
            n = self.node("aaa-1")
            self.assertEqual(pick(n, "marker\n").name, "pick_b")  # 100 vs 70
            self.assertEqual(pick(n, "").name, "pick_a")  # tie: name order
            self.assertEqual(pick(self.node("zzz"), "plain").name, "generic")
            self.assertEqual(pick(None, "marker").name, "pick_b")  # sniff-only
            self.assertEqual(pick(n, "marker", override="pick_a").name, "pick_a")
            with self.assertRaises(LocalizeError) as ctx:
                pick(n, "", override="nope")
            self.assertEqual(ctx.exception.code, "UNKNOWN_DIALECT")

    def test_pick_priority_breaks_ties(self) -> None:
        class P1(RuleDialect):
            name = "tie_a"
            templates = ("t*",)

        class P2(RuleDialect):
            name = "tie_b"
            templates = ("t*",)
            priority = 5

        with self._fresh(), mock.patch.dict(REGISTRY, clear=True):
            register(P1)
            register(P2)
            self.assertEqual(pick(self.node("t1"), "").name, "tie_b")

    def test_pick_without_generic_raises(self) -> None:
        with self._fresh(), mock.patch.dict(REGISTRY, clear=True):
            with self.assertRaises(LocalizeError) as ctx:
                pick(self.node("x"), "")
            self.assertEqual(ctx.exception.code, "NO_DIALECT")


class TestRegister(unittest.TestCase):
    def test_register_returns_class_and_stores_instance(self) -> None:
        class R(RuleDialect):
            name = "reg_one"

        with mock.patch.dict(REGISTRY, clear=True):
            self.assertIs(register(R), R)
            self.assertIsInstance(REGISTRY["reg_one"], R)

    def test_same_class_reregisters_different_class_conflicts(self) -> None:
        class R(RuleDialect):
            name = "reg_two"

        class Other(RuleDialect):
            name = "reg_two"

        with mock.patch.dict(REGISTRY, clear=True):
            register(R)
            register(R)  # idempotent
            with self.assertRaises(LocalizeError) as ctx:
                register(Other)
            self.assertEqual(ctx.exception.code, "DIALECT_DUPLICATE")

    def test_nameless_rejected(self) -> None:
        class N(RuleDialect):
            pass

        with mock.patch.dict(REGISTRY, clear=True), self.assertRaises(LocalizeError):
            register(N)

    def test_bad_declarations_fail_at_class_creation(self) -> None:
        with self.assertRaises(ValueError):

            class BadStyle(RuleDialect):
                name = "bad_style"
                block_style = "weird"  # type: ignore[assignment]

        with self.assertRaises(ValueError):

            class BadKind(RuleDialect):
                name = "bad_kind"
                rules = (PatternRule("x.y", r"(?P<v>a)", "no_such_kind"),)

        with self.assertRaises(ValueError):

            class DupId(RuleDialect):
                name = "dup_id"
                rules = (
                    PatternRule("x.y", r"(?P<v>a)", "domain"),
                    PatternRule("x.y", r"(?P<v>b)", "domain"),
                )

    def test_pattern_rule_validation(self) -> None:
        with self.assertRaises(ValueError):
            PatternRule("", r"(?P<v>a)", "domain")
        with self.assertRaises(ValueError):
            PatternRule("x", r"(unclosed", "domain")
        with self.assertRaises(ValueError):
            PatternRule("x", r"abc", "domain")  # no v group
        with self.assertRaises(ValueError):
            PatternRule("x", r"(?P<v>a)", "domain", list_style="bad")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            PatternRule("x", r"abc", "")  # role-only needs a role
        with self.assertRaises(ValueError):
            PatternRule("x", r"(?P<v>a)", "domain", role="bogus")
        PatternRule("x", r"abc", "", role="mode_trunk")  # ok

    def test_ipv4_placeholder_boundaries(self) -> None:
        rx = PatternRule("x", r"^gw (?P<v>IPV4)$", "ip_gateway").regex()
        self.assertTrue(rx.search("gw 172.31.240.1"))
        self.assertFalse(rx.search("gw 172.31.240.1x"))
        self.assertFalse(rx.search("gw 1172.31.240.1.5"))
        m = (
            PatternRule("x", r"^a (?P<v>IPV4)(?P<mask>/\d+)$", "ip_host")
            .regex()
            .search("a 10.1.1.1/24")
        )
        assert m is not None
        self.assertEqual((m.group("v"), m.group("mask")), ("10.1.1.1", "/24"))
        mask_rx = PatternRule("x", r"^a (?P<v>IPV4) (?P<mask>MASK)$", "ip_host").regex()
        self.assertTrue(mask_rx.search("a 10.1.1.1 255.255.255.0"))
        self.assertTrue(mask_rx.search("a 10.1.1.1 /24"))

    def test_placeholders_do_not_touch_lowercase_words(self) -> None:
        rx = PatternRule("x", r"^netmask (?P<v>\S+)$", "domain").regex()
        self.assertTrue(rx.search("netmask foo"))


class TestRender(unittest.TestCase):
    def setUp(self) -> None:
        self.d = ToyIOS()
        self.parsed = self.d.parse(toy_ct())
        self.ctx = RenderCtx(TOY_TEXT)

    def fact(self, kind: str, value: str | None = None) -> Fact:
        for f in self.parsed.facts:
            if f.kind == kind and (value is None or f.value == value):
                return f
        raise AssertionError((kind, value))

    def test_noop_is_empty(self) -> None:
        for f in self.parsed.facts:
            self.assertEqual(self.d.render(f, f.value, self.ctx), [], f.rule)

    def test_value_edit(self) -> None:
        f = self.fact("vlan_tag", "2")
        (e,) = self.d.render(f, "20", self.ctx)
        self.assertEqual(
            (e.start, e.end, e.old, e.new), (f.span.start, f.span.end, "2", "20")
        )

    def test_ip_with_prefix_change_gives_two_edits_in_own_form(self) -> None:
        f = self.fact("ip_host", "10.100.2.14")
        edits = self.d.render(f, "10.200.0.14", RenderCtx(TOY_TEXT, new_prefix=20))
        self.assertEqual([e.new for e in edits], ["10.200.0.14", "255.255.240.0"])
        self.assertEqual([e.old for e in edits], ["10.100.2.14", "255.255.255.0"])
        out = apply_edits(TOY_TEXT, edits)
        self.assertIn(" ip address 10.200.0.14 255.255.240.0\n", out)

    def test_mask_unchanged_prefix_no_edit(self) -> None:
        f = self.fact("ip_host", "10.100.2.14")
        self.assertEqual(
            self.d.render(f, f.value, RenderCtx(TOY_TEXT, new_prefix=24)), []
        )

    def test_prefix_and_netmask_forms(self) -> None:
        class Forms(RuleDialect):
            name = "forms"
            rules = (
                PatternRule("f.slash", r"^addr (?P<v>IPV4)(?P<mask>/\d+)$", "ip_host"),
                PatternRule("f.bare", r"^bare (?P<v>IPV4)/(?P<mask>\d+)$", "ip_host"),
                PatternRule(
                    "f.nm",
                    r"^ifconfig eth0 (?P<v>IPV4) netmask (?P<mask>MASK)$",
                    "ip_host",
                ),
            )

        text = "addr 10.0.0.1/24\nbare 10.0.1.1/24\nifconfig eth0 10.0.2.1 netmask 255.255.255.0\n"
        d = Forms()
        parsed = d.parse(make_ct(text, "forms"))
        forms = {f.rule: f.mask_form for f in parsed.facts}
        self.assertEqual(
            forms, {"f.slash": "prefix", "f.bare": "prefix", "f.nm": "netmask"}
        )
        edits: list[TextEdit] = []
        for f in parsed.facts:
            edits += d.render(f, f.value, RenderCtx(text, new_prefix=16))
        self.assertEqual(
            apply_edits(text, edits),
            "addr 10.0.0.1/16\nbare 10.0.1.1/16\nifconfig eth0 10.0.2.1 netmask 255.255.0.0\n",
        )

    def test_many_group_masks(self) -> None:
        class Many(RuleDialect):
            name = "manymask"
            rules = (PatternRule("m.x", r"^net (?P<many>.+)$", "ip_host"),)

        text = "net 10.0.0.0/8 10.1.0.0 255.255.0.0\n"
        parsed = Many().parse(make_ct(text, "manymask"))
        self.assertEqual([f.value for f in parsed.facts], ["10.0.0.0", "10.1.0.0"])
        self.assertEqual([f.mask_form for f in parsed.facts], ["prefix", "dotted"])

    def test_stale_fact_refused(self) -> None:
        f = self.fact("vlan_tag", "2")
        with self.assertRaises(ConflictError) as ctx:
            self.d.render(f, "20", RenderCtx("#" + TOY_TEXT))
        self.assertEqual(ctx.exception.code, "STALE_FACT")

    def test_value_validation(self) -> None:
        for kind, bad in (
            ("ip_host", "999.1.1.1"),
            ("ip_host", "abc"),
            ("vlan_tag", "x"),
            ("vlan_tag", "5000"),
        ):
            f = self.fact(kind)
            with (
                self.subTest(kind=kind, bad=bad),
                self.assertRaises(LocalizeError) as ctx,
            ):
                self.d.render(f, bad, self.ctx)
            self.assertEqual(ctx.exception.code, "BAD_VALUE")
        lst = self.fact("vlan_list", "203,3101")
        with self.assertRaises(LocalizeError):
            self.d.render(lst, "1,,x", self.ctx)

    def test_list_edit_via_vlanlist(self) -> None:
        f = self.fact("vlan_list", "203,3101")
        assert f.list_value is not None
        new = f.list_value.replace({203: 20}).render()
        (e,) = self.d.render(f, new, self.ctx)
        self.assertIn(
            " switchport trunk allowed vlan 20,3101\n", apply_edits(TOY_TEXT, [e])
        )

    def test_swap_edits_apply_in_one_pass(self) -> None:
        text = " encapsulation dot1Q 2\n encapsulation dot1Q 3\n"
        parsed = self.d.parse(make_ct("interface Gi0.2\n" + text, "toyios"))
        tags = [f for f in parsed.facts if f.kind == "vlan_tag"]
        full = "interface Gi0.2\n" + text
        edits = []
        for f, new in zip(tags, ("3", "2"), strict=True):
            edits += self.d.render(f, new, RenderCtx(full))
        self.assertEqual(
            apply_edits(full, edits),
            "interface Gi0.2\n encapsulation dot1Q 3\n encapsulation dot1Q 2\n",
        )


class TestApplyEdits(unittest.TestCase):
    def test_apply_and_errors(self) -> None:
        self.assertEqual(
            apply_edits("abcdef", [TextEdit(1, 3, "bc", "X"), TextEdit(4, 4, "", "Y")]),
            "aXdYef",
        )
        with self.assertRaises(ValueError):
            apply_edits("abc", [TextEdit(0, 2, "ab", "x"), TextEdit(1, 3, "bc", "y")])
        with self.assertRaises(ValueError):
            apply_edits("abc", [TextEdit(0, 1, "z", "x")])
        with self.assertRaises(ValueError):
            apply_edits("abc", [TextEdit(2, 9, "c", "x")])


# --------------------------------------------------------------------------- #
# the harness run on the toy dialect (also proves the harness catches bugs)
# --------------------------------------------------------------------------- #


class TestHarnessOnToyDialect(DialectContractMixin, unittest.TestCase):
    dialect_name = "toyios"
    snippet_root = SELFTEST_ROOT
    require_snippets = True
    require_rule_coverage = True

    def setUp(self) -> None:
        patcher = mock.patch.dict(REGISTRY, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        flag = mock.patch.object(dialects, "_loaded", True)
        flag.start()
        self.addCleanup(flag.stop)
        register(ToyIOS)

    def test_skeleton_round_trips_through_the_checker(self) -> None:
        d = self.get_dialect()
        sk = skeleton(d, TOY_TEXT)
        sn = Snippet("gen", TOY_TEXT, sk, Path("gen.txt"))
        self.assertEqual(check_snippet(d, sn), [])


class TestHarnessCatchesBugs(unittest.TestCase):
    """The harness must fail on broken dialects, not just pass good ones."""

    def snippet(self, d: Dialect, text: str, **extra: object) -> Snippet:
        exp = skeleton(d, text)
        exp.update(extra)
        return Snippet("bug", text, exp, Path("bug.txt"))

    def test_clean_dialect_passes(self) -> None:
        d = ToyIOS()
        self.assertEqual(check_snippet(d, self.snippet(d, TOY_TEXT)), [])

    def test_missing_and_extra_facts_detected(self) -> None:
        d = ToyIOS()
        sn = self.snippet(d, TOY_TEXT)
        facts = sn.expected["facts"]
        assert isinstance(facts, list)
        sn.expected["facts"] = [
            *facts[1:],
            {"kind": "domain", "value": "nope", "line": 1, "rule": "toy.domain"},
        ]
        problems = check_snippet(d, sn)
        self.assertTrue(
            any(p.startswith("bug: missing fact") for p in problems), problems
        )
        self.assertTrue(any("unexpected fact" in p for p in problems), problems)
        sn.expected["allow_extra_facts"] = True
        self.assertFalse(any("unexpected fact" in p for p in check_snippet(d, sn)))

    def test_wrong_attributes_detected(self) -> None:
        d = ToyIOS()
        sn = self.snippet(d, TOY_TEXT)
        facts = sn.expected["facts"]
        assert isinstance(facts, list)
        facts[0] = dict(facts[0], iface="bogus")
        sn.expected["ifaces"] = {"gi0/1": {"mode": "trunk"}}
        sn.expected["vlan_db"] = [1]
        problems = check_snippet(d, sn)
        self.assertTrue(any("iface is" in p for p in problems), problems)
        self.assertTrue(any("mode is" in p for p in problems), problems)
        self.assertTrue(any("vlan_db" in p for p in problems), problems)

    def test_missing_facts_json(self) -> None:
        d = ToyIOS()
        problems = check_snippet(d, Snippet("x", "hostname a\n", {}, Path("x.txt")))
        self.assertIn("missing x.facts.json", problems[0])

    def test_render_that_changes_neighbours_is_caught(self) -> None:
        class Sloppy(ToyIOS):
            name = "sloppy"

            def render(self, fact: Fact, new: str, ctx: RenderCtx) -> list[TextEdit]:
                edits = super().render(fact, new, ctx)
                if edits and fact.kind == "domain":  # also clobbers the DNS list
                    i = ctx.text.index("10.100.51.11")
                    return [*edits, TextEdit(i, i + 12, "10.100.51.11", "10.100.51.99")]
                return edits

        d = Sloppy()
        problems = check_snippet(d, self.snippet(d, TOY_TEXT))
        self.assertTrue(problems)

    def test_noop_render_that_edits_is_caught(self) -> None:
        class Eager(ToyIOS):
            name = "eager"

            def render(self, fact: Fact, new: str, ctx: RenderCtx) -> list[TextEdit]:
                if fact.kind == "domain":
                    return [TextEdit(fact.span.start, fact.span.end, fact.value, new)]
                return super().render(fact, new, ctx)

        d = Eager()
        problems = check_snippet(d, self.snippet(d, TOY_TEXT))
        self.assertTrue(any("no-op render" in p for p in problems), problems)

    def test_non_restoring_inverse_is_caught(self) -> None:
        class Lossy(ToyIOS):
            name = "lossy"

            def render(self, fact: Fact, new: str, ctx: RenderCtx) -> list[TextEdit]:
                if fact.kind == "domain" and new == "netlab.local" != fact.value:
                    upper = new.upper()
                    return [TextEdit(fact.span.start, fact.span.end, fact.value, upper)]
                return super().render(fact, new, ctx)

        d = Lossy()
        problems = check_snippet(d, self.snippet(d, TOY_TEXT))
        self.assertTrue(any("inverse" in p for p in problems), problems)

    def test_stale_acceptance_is_caught(self) -> None:
        class Blind(ToyIOS):
            name = "blind"

            def render(self, fact: Fact, new: str, ctx: RenderCtx) -> list[TextEdit]:
                if new == fact.value:
                    return []
                return [TextEdit(fact.span.start, fact.span.end, fact.value, new)]

        d = Blind()
        problems = check_snippet(d, self.snippet(d, TOY_TEXT))
        self.assertTrue(any("stale" in p for p in problems), problems)

    def test_bad_spans_caught_by_integrity(self) -> None:
        class OffByOne(ToyIOS):
            name = "offbyone"

            def parse(self, ct: ConfigText) -> ParsedConfig:
                parsed = super().parse(ct)
                f = parsed.facts[0]
                f.span = Span(f.span.start + 1, f.span.end + 1)
                return parsed

        d = OffByOne()
        sn = self.snippet(ToyIOS(), TOY_TEXT)
        problems = check_snippet(d, sn)
        self.assertTrue(
            any(
                "span text" in p or "wrong line" in p or "id is not" in p
                for p in problems
            ),
            problems,
        )

    def test_negative_example_check(self) -> None:
        class BadNeg(RuleDialect):
            name = "badneg"
            rules = (
                PatternRule(
                    "b.x", r"^domain (?P<v>\S+)$", "domain", negative=("domain x",)
                ),
            )

        problems = check_static(BadNeg())
        self.assertTrue(
            any("negative example matches" in p for p in problems), problems
        )

    def test_static_catches_bad_declaration(self) -> None:
        class NoSniffTuple(ToyIOS):
            name = "sniffy"
            sniff = ["a"]  # type: ignore[assignment]

        problems = check_static(NoSniffTuple())
        self.assertTrue(any("sniff must be a tuple" in p for p in problems), problems)

    def test_rule_coverage_reports_unused_rules(self) -> None:
        d = ToyIOS()
        sn = self.snippet(d, "ip domain-name a.b\n")
        problems = check_rule_coverage(d, [sn])
        self.assertTrue(any("toy.encap" in p for p in problems))
        self.assertFalse(any("toy.domain" in p for p in problems))


class TestLoadSnippets(unittest.TestCase):
    def test_loads_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "d").mkdir()
            (root / "d" / "a.txt").write_bytes(b"hostname x\r\n")
            (root / "d" / "a.facts.json").write_text('{"facts": []}')
            (root / "d" / "b.txt").write_bytes(b"y")
            got = load_snippets("d", root)
            self.assertEqual([s.name for s in got], ["a", "b"])
            self.assertEqual(got[0].text, "hostname x\r\n")  # bytes preserved
            self.assertEqual(got[1].expected, {})
            self.assertEqual(load_snippets("nope", root), [])


# --------------------------------------------------------------------------- #
# blocks
# --------------------------------------------------------------------------- #


def kinds(layout: blocks.Layout) -> list[tuple[str, str, bool]]:
    return [(b.kind, b.name, b.orphan) for b in layout.blocks]


class TestBlocksIndent(unittest.TestCase):
    def test_basic_blocks_and_chain(self) -> None:
        text = "hostname x\n!\ninterface Gi0/0\n ip address 1.1.1.1 255.0.0.0\n!\nvlan 10\n name a\nip route 0.0.0.0 0.0.0.0 1.1.1.2\n"
        lay = blocks.split(text, "indent")
        self.assertEqual(
            kinds(lay), [("interface", "Gi0/0", False), ("vlan", "10", False)]
        )
        chain = {ln.no: [b.kind for b in ln.chain] for ln in lay.lines}
        self.assertEqual(chain[1], [])
        self.assertEqual(chain[3], ["interface"])  # header is inside its block
        self.assertEqual(chain[4], ["interface"])
        self.assertEqual(chain[5], [])  # "!" ends it
        self.assertEqual(chain[7], ["vlan"])
        self.assertEqual(chain[8], [])
        iface = lay.blocks[0]
        self.assertEqual(
            text[iface.start : iface.end],
            "interface Gi0/0\n ip address 1.1.1.1 255.0.0.0",
        )
        self.assertEqual(iface.header_line, 3)
        assert iface.name_span is not None
        self.assertEqual(text[iface.name_span.start : iface.name_span.end], "Gi0/0")
        self.assertEqual(iface.path, "interface/Gi0/0")

    def test_blank_lines_do_not_end_blocks_nxos_style(self) -> None:
        text = "interface mgmt0\n  ip address 1.1.1.1/24\n\n  no shutdown\n\ninterface Ethernet1/1\n"
        lay = blocks.split(text, "indent")
        self.assertEqual([b.name for b in lay.blocks], ["mgmt0", "Ethernet1/1"])
        self.assertEqual(
            text[lay.blocks[0].start : lay.blocks[0].end],
            "interface mgmt0\n  ip address 1.1.1.1/24\n\n  no shutdown",
        )

    def test_vrf_router_and_interface_range(self) -> None:
        text = "vrf context management\n  ip route 0.0.0.0/0 1.1.1.1\nrouter bgp 65001\n neighbor 1.1.1.1\nip vrf FOO\ninterface range gi0/1 - 2\n"
        lay = blocks.split(text, "indent")
        self.assertEqual(
            [(b.kind, b.name) for b in lay.blocks],
            [
                ("vrf", "management"),
                ("router bgp", "65001"),
                ("vrf", "FOO"),
                ("interface range", ""),
            ],
        )
        self.assertFalse(any(b.orphan for b in lay.blocks))

    def test_orphan_headers(self) -> None:
        for header in (
            "interface GigabitEthernet",
            "interface",
            "interface Vlan",
            "interface Gi0/",
        ):
            with self.subTest(header=header):
                lay = blocks.split(f"{header}\n no shutdown\n", "indent")
                self.assertEqual(len(lay.blocks), 1)
                self.assertTrue(lay.blocks[0].orphan)
        lay = blocks.split("interface Loopback0\n", "indent")
        self.assertFalse(lay.blocks[0].orphan)

    def test_syslog_splice_skipped_and_block_continues(self) -> None:
        text = (
            "interface Gi0/1\n negotiat\n"
            "*Dec 28 18:28:00.651: %SYS-5-CONFIG_I: Configured from console by consoleion auto\n"
            " switchport access vlan 5\n!\n"
        )
        lay = blocks.split(text, "indent")
        skipped = [ln for ln in lay.lines if ln.skip]
        self.assertEqual([(ln.no, ln.skip) for ln in skipped], [(3, "syslog")])
        self.assertEqual(
            [b.kind for b in lay.lines[3].chain], ["interface"]
        )  # still in block
        self.assertEqual(len(lay.blocks), 1)

    def test_text_after_end_ignored(self) -> None:
        lay = blocks.split(
            "interface Gi0/1\n shutdown\nend\ninterface Gi0/2\n shutdown\n", "indent"
        )
        self.assertEqual([b.name for b in lay.blocks], ["Gi0/1"])
        self.assertEqual(
            [ln.skip for ln in lay.lines], [None, None, None, "after-end", "after-end"]
        )

    def test_crlf_offsets_and_line_ends(self) -> None:
        text = "interface Gi0/1\r\n shutdown\r\n!\r\nvlan 10\r\n"
        lay = blocks.split(text, "indent")
        first = lay.lines[0]
        self.assertEqual(text[first.start : first.end], "interface Gi0/1")
        self.assertEqual([b.name for b in lay.blocks], ["Gi0/1", "10"])
        self.assertEqual(
            text[lay.blocks[0].start : lay.blocks[0].end],
            "interface Gi0/1\r\n shutdown",
        )

    def test_no_trailing_newline_and_empty(self) -> None:
        lay = blocks.split("interface Gi0/1\n shutdown", "indent")
        self.assertEqual(lay.lines[-1].end, len("interface Gi0/1\n shutdown"))
        self.assertEqual(blocks.split("", "indent").lines, [])
        self.assertEqual(len(blocks.split("\n\n", "indent").lines), 2)

    def test_custom_starts(self) -> None:
        lay = blocks.split(
            "policy X\n a\n", "indent", starts=(("policy", r"policy (?P<name>\S+)"),)
        )
        self.assertEqual(kinds(lay), [("policy", "X", False)])

    def test_line_at_and_block_lines(self) -> None:
        text = "interface Gi0/1\n shutdown\nvlan 3\n"
        lay = blocks.split(text, "indent")
        ln = lay.line_at(text.index("shutdown"))
        assert ln is not None
        self.assertEqual(ln.no, 2)
        self.assertEqual([x.no for x in lay.block_lines(lay.blocks[0])], [1, 2])
        self.assertEqual(lay.line_text(lay.lines[0]), "interface Gi0/1")


class TestBlocksFortios(unittest.TestCase):
    TEXT = textwrap.dedent("""\
        config system interface
            edit "port8"
                set vdom "root"
                set ip 10.100.51.8 255.255.255.0
            next
            edit "oob-mgmt"
                set vlanid 203
                set interface "port8"
                config secondaryip
                    edit 1
                        set ip 10.9.9.9 255.255.255.0
                    next
                end
            next
        end
        config system dns
            set primary 10.100.51.11
        end
        config system ntp
            config ntpserver
                edit 1
                    set server "pool.ntp.org"
        """)

    def test_stack_paths_and_kinds(self) -> None:
        lay = blocks.split(self.TEXT, "fortios")
        got = [(b.kind, b.name, b.path) for b in lay.blocks]
        self.assertEqual(
            got[:5],
            [
                ("system interface", "system interface", "system interface"),
                ("edit:system interface", "port8", "system interface/port8"),
                ("edit:system interface", "oob-mgmt", "system interface/oob-mgmt"),
                ("secondaryip", "secondaryip", "system interface/oob-mgmt/secondaryip"),
                ("edit:secondaryip", "1", "system interface/oob-mgmt/secondaryip/1"),
            ],
        )
        self.assertIn("system dns", [b.kind for b in lay.blocks])

    def test_lines_know_their_edit(self) -> None:
        lay = blocks.split(self.TEXT, "fortios")
        by_text = {
            lay.line_text(ln).strip(): [b.kind for b in ln.chain] for ln in lay.lines
        }
        self.assertEqual(by_text["set vlanid 203"][-1], "edit:system interface")
        self.assertEqual(by_text["set primary 10.100.51.11"], ["system dns"])
        self.assertEqual(
            by_text["set ip 10.9.9.9 255.255.255.0"][-1], "edit:secondaryip"
        )
        self.assertIn("edit:system interface", by_text["set ip 10.9.9.9 255.255.255.0"])
        self.assertEqual(by_text["next"][-1], "edit:system interface")

    def test_edit_name_span_excludes_quotes(self) -> None:
        lay = blocks.split(self.TEXT, "fortios")
        blk = lay.blocks[2]
        assert blk.name_span is not None
        self.assertEqual(self.TEXT[blk.name_span.start : blk.name_span.end], "oob-mgmt")

    def test_missing_next_and_truncated_tolerated(self) -> None:
        lay = blocks.split(self.TEXT, "fortios")
        ntp = [b for b in lay.blocks if b.kind == "edit:ntpserver"]
        self.assertEqual(len(ntp), 1)  # truncated at EOF, still closed
        lay2 = blocks.split("config a\nedit 1\nedit 2\nend\nend\nnext\n", "fortios")
        self.assertEqual([b.name for b in lay2.blocks], ["a", "1", "2"])

    def test_block_end_covers_content(self) -> None:
        lay = blocks.split(self.TEXT, "fortios")
        blk = lay.blocks[2]
        self.assertTrue(self.TEXT[blk.start : blk.end].endswith("next"))


class TestBlocksBrace(unittest.TestCase):
    TEXT = textwrap.dedent("""\
        system {
            name-server {
                10.100.51.11;
            }
            host-name "a { b";  # comment {
        }
        interfaces {
            fxp0 {
                unit 0 {
                    family inet {
                        address 10.100.51.5/20;
                    }
                }
            }
            ge-0/0/3 { unit 1240 { vlan-id 1240; } }
        }""")

    def test_paths(self) -> None:
        lay = blocks.split(self.TEXT, "brace")
        paths = [b.path for b in lay.blocks]
        self.assertIn("system/name-server", paths)
        self.assertIn("interfaces/fxp0/unit 0/family inet", paths)
        self.assertIn("interfaces/ge-0/0/3/unit 1240", paths)

    def test_lines_in_block(self) -> None:
        lay = blocks.split(self.TEXT, "brace")
        by = {lay.line_text(ln).strip(): ln for ln in lay.lines}
        self.assertEqual(
            by["address 10.100.51.5/20;"].chain[-1].path,
            "interfaces/fxp0/unit 0/family inet",
        )
        self.assertEqual(
            [b.path for b in by["10.100.51.11;"].chain],
            ["system", "system/name-server"],
        )
        self.assertEqual(
            [b.path for b in by['host-name "a { b";  # comment {'].chain], ["system"]
        )
        self.assertEqual(by["}"].chain[0].path, "interfaces")

    def test_header_line_inside_block_and_name_span(self) -> None:
        lay = blocks.split(self.TEXT, "brace")
        blk = next(b for b in lay.blocks if b.path == "interfaces/fxp0")
        hdr = lay.lines[blk.header_line - 1]
        self.assertIn(blk, hdr.chain)
        assert blk.name_span is not None
        self.assertEqual(self.TEXT[blk.name_span.start : blk.name_span.end], "fxp0")

    def test_unbalanced_tolerated(self) -> None:
        lay = blocks.split("a {\n b {\n c;\n", "brace")
        self.assertEqual([b.path for b in lay.blocks], ["a", "a/b"])
        lay = blocks.split("}\n}\nx;\n", "brace")
        self.assertEqual(lay.blocks, [])

    def test_block_comment_braces_ignored(self) -> None:
        lay = blocks.split("a {\n /* } */ x;\n}\n", "brace")
        self.assertEqual(len(lay.blocks), 1)
        self.assertEqual([b.path for b in lay.lines[1].chain], ["a"])


class TestBlocksFlat(unittest.TestCase):
    TEXT = textwrap.dedent("""\
        #!/bin/sh
        ip addr add 10.100.51.5/24 dev eth0
        cat << EOF > /etc/resolv.conf
        search netlab.local
        nameserver 10.100.51.11
        EOF
        cat > /etc/hosts <<'END'
        127.0.0.1 localhost
        END
        echo done | tee -a /tmp/log <<-EOT
        x
        EOT
        route add default gw 10.100.51.1
        """)

    def test_heredocs(self) -> None:
        lay = blocks.split(self.TEXT, "flat")
        self.assertEqual(
            [b.kind for b in lay.blocks],
            ["heredoc:/etc/resolv.conf", "heredoc:/etc/hosts", "heredoc:/tmp/log"],
        )
        by = {lay.line_text(ln): [b.kind for b in ln.chain] for ln in lay.lines}
        self.assertEqual(by["nameserver 10.100.51.11"], ["heredoc:/etc/resolv.conf"])
        self.assertEqual(by["EOF"], ["heredoc:/etc/resolv.conf"])
        self.assertEqual(by["ip addr add 10.100.51.5/24 dev eth0"], [])
        self.assertEqual(by["route add default gw 10.100.51.1"], [])

    def test_unterminated_heredoc_runs_to_eof(self) -> None:
        lay = blocks.split("cat <<EOF >/etc/x\na\nb\n", "flat")
        self.assertEqual(len(lay.blocks), 1)
        self.assertEqual([len(ln.chain) for ln in lay.lines], [1, 1, 1])

    def test_heredoc_without_target(self) -> None:
        lay = blocks.split("python3 - <<PY\nprint(1)\nPY\n", "flat")
        self.assertEqual([b.kind for b in lay.blocks], ["heredoc"])

    def test_rule_block_matching_for_heredoc(self) -> None:
        lay = blocks.split(self.TEXT, "flat")
        ns = next(ln for ln in lay.lines if lay.line_text(ln).startswith("nameserver"))
        self.assertTrue(base.rule_applies("heredoc:/etc/resolv.conf", ns.chain))
        self.assertTrue(base.rule_applies("heredoc", ns.chain))
        self.assertTrue(base.rule_applies("heredoc:*", ns.chain))
        self.assertFalse(base.rule_applies("heredoc:/etc/hosts", ns.chain))
        self.assertFalse(base.rule_applies("top", ns.chain))
        self.assertTrue(base.rule_applies(None, ns.chain))


class TestBlocksHtml(unittest.TestCase):
    def test_only_text_nodes_are_lines(self) -> None:
        html = '<div style="width:203px"><p>10.100.51.1</p>\n<svg><text>203</text></svg>\n<b>VLAN 3</b></div>'
        lay = blocks.split(html, "html")
        texts = [lay.line_text(ln) for ln in lay.lines]
        self.assertEqual(texts, ["10.100.51.1", "VLAN 3"])
        self.assertEqual([ln.no for ln in lay.lines], [1, 3])
        self.assertEqual(lay.blocks, [])

    def test_multiline_text_node(self) -> None:
        html = "<p>a 1.1.1.1\r\nb 2.2.2.2\n\n c</p>"
        lay = blocks.split(html, "html")
        self.assertEqual(
            [lay.line_text(ln) for ln in lay.lines], ["a 1.1.1.1", "b 2.2.2.2", " c"]
        )

    def test_rules_in_html_style_only_see_text(self) -> None:
        class Html(RuleDialect):
            name = "htmltoy"
            block_style = "html"
            rules = (PatternRule("h.ip", r"(?P<many>IPV4)", "ip_host"),)

        html = '<a title="10.9.9.9">10.1.1.1</a><style>.x{ip:10.8.8.8}</style>'
        parsed = Html().parse(make_ct(html, "htmltoy"))
        self.assertEqual([f.value for f in parsed.facts], ["10.1.1.1"])


class TestBlocksMisc(unittest.TestCase):
    def test_unknown_style(self) -> None:
        with self.assertRaises(ValueError):
            blocks.split("x", "yaml")

    def test_iter_lines(self) -> None:
        self.assertEqual(
            list(blocks.iter_lines("a\r\nb\n\nc")),
            [(1, 0, 1), (2, 3, 4), (3, 5, 5), (4, 6, 7)],
        )
        self.assertEqual(list(blocks.iter_lines("")), [])


# --------------------------------------------------------------------------- #
# real data: block parsers on the decoded configs
# --------------------------------------------------------------------------- #


def dump_sections(name: str) -> list[tuple[str, str]]:
    """Decoded config blobs of a real lab (unl + codec), see ``realtexts``."""
    return realtexts.sections(name)


class TestBlocksRealData(unittest.TestCase):
    def check_layout(self, text: str, style: str) -> blocks.Layout:
        lay = blocks.split(text, style)
        prev_end = -1
        for ln in lay.lines:
            self.assertGreaterEqual(ln.start, prev_end)
            self.assertLessEqual(ln.start, ln.end)
            self.assertNotIn("\n", text[ln.start : ln.end])
            prev_end = ln.end
        for b in lay.blocks:
            self.assertLessEqual(b.start, b.end)
            self.assertLessEqual(b.end, len(text))
        return lay

    def test_all_sections_all_styles(self) -> None:
        count = 0
        for name in (
            "sdwan.txt",
            "bb.txt",
            "junos.txt",
            "azure_asa_vpn.txt",
            "lab1-ei-v01.txt",
            "cisco_nexus_9000v_vpc_concept_lab.txt",
        ):
            for _header, text in dump_sections(name):
                for style in blocks.STYLES:
                    self.check_layout(text, style)
                count += 1
        self.assertGreater(count, 20)

    def test_backbone_orphan_interface_and_syslog(self) -> None:
        found_orphan = found_syslog = False
        for _, text in dump_sections("bb.txt"):
            lay = self.check_layout(text, "indent")
            found_orphan |= any(b.orphan for b in lay.blocks)
            found_syslog |= any(ln.skip == "syslog" for ln in lay.lines)
            for b in lay.blocks:
                if b.orphan:
                    self.assertEqual(b.kind, "interface")
        self.assertTrue(found_orphan, "backbone dump has a truncated interface header")
        self.assertTrue(found_syslog)

    def test_clean_sections_have_no_orphans(self) -> None:
        for header, text in dump_sections("sdwan.txt"):
            lay = blocks.split(text, "indent")
            self.assertFalse(any(b.orphan for b in lay.blocks), header)

    def test_nxos_interface_blocks(self) -> None:
        for header, text in dump_sections("sdwan.txt"):
            lay = blocks.split(text, "indent")
            names = [b.name for b in lay.blocks if b.kind == "interface"]
            if "dc1-leaf2" in header:
                self.assertIn("mgmt0", names)
                self.assertIn("Ethernet1/1", names)

    def test_junos_paths(self) -> None:
        paths: set[str] = set()
        for _, text in dump_sections("junos.txt"):
            paths.update(b.path for b in blocks.split(text, "brace").blocks)
        self.assertTrue(
            any(p.startswith("interfaces/") and "/unit " in p for p in paths)
        )

    def test_fortios_blocks_on_forti_sidecar_like_text(self) -> None:
        forti = [
            t
            for h, t in dump_sections("sdwan.txt") + dump_sections("azure_asa_vpn.txt")
            if "config system interface" in t
        ]
        for text in forti:
            lay = blocks.split(text, "fortios")
            self.assertTrue(any(b.kind == "edit:system interface" for b in lay.blocks))

    def test_toy_dialect_parses_real_ios_without_error(self) -> None:
        d = ToyIOS()
        n = 0
        for _, text in dump_sections("bb.txt"):
            parsed = d.parse(make_ct(text, "toyios"))
            for f in parsed.facts:
                self.assertEqual(text[f.span.start : f.span.end], f.value)
            n += len(parsed.facts)
        self.assertGreater(n, 100)


SIDECARS = Path(__file__).resolve().parents[3] / "labs" / "datacenter" / "cisco"


class ToyForti(RuleDialect):
    """Forti-flavoured toy: vlan interfaces inside ``edit`` with a parent."""

    name = "toyforti"
    block_style = "fortios"
    iface_block_kinds = ("edit:system interface",)
    block_parent_re = r"^\s*set interface \"?(?P<parent>[^\"\s]+)\"?"
    subif_re = None
    rules = (
        PatternRule(
            "tf.vlanid",
            r"^\s+set vlanid (?P<v>\d+)$",
            "vlan_tag",
            block="edit:system interface",
            role="encap_tag",
            negative=("    edit 2", "set ike-version 2", "set community 204:204"),
        ),
        PatternRule(
            "tf.ip",
            r"^\s+set ip (?P<v>IPV4) (?P<mask>MASK)$",
            "ip_host",
            block="edit:system interface",
        ),
        PatternRule(
            "tf.dns",
            r"^\s+set (?:primary|secondary) (?P<v>IPV4)$",
            "dns_server",
            block="system dns",
        ),
        PatternRule(
            "tf.health",
            r"^\s+set server (?P<many>.+)$",
            "probe_target",
            block="edit:system link-monitor",
        ),
    )


@unittest.skipUnless(SIDECARS.is_dir(), "lab sidecars not present")
class TestRealSidecars(unittest.TestCase):
    def read(self, rel: str) -> str:
        path = SIDECARS / rel
        if not path.exists():
            self.skipTest(f"{rel} missing")
        return path.read_bytes().decode("utf-8")

    FGT = "vxlan_evpn_multi-site_sdwan_only_cfgs/7_dc1-fgt1.txt"

    def test_forti_vlan_interface_parent_and_tag(self) -> None:
        text = self.read(self.FGT)
        d = ToyForti()
        parsed = d.parse(make_ct(text, "toyforti"))
        tags = {
            (f.iface, f.value, f.parent) for f in parsed.facts if f.kind == "vlan_tag"
        }
        self.assertIn(("oob-mgmt", "3", "port8"), tags)
        # lab rework 32d9b62: one wan leg per provider (VLAN 3201/3202)
        self.assertIn(("wan1-bgw1", "3201", "port1"), tags)
        self.assertIn(("wan2-bgw2", "3202", "port2"), tags)
        self.assertIn(("t1-bgw1", "3101", "port1"), tags)
        self.assertEqual(parsed.ifaces["oob-mgmt"].parent, "port8")
        self.assertEqual(parsed.ifaces["oob-mgmt"].tag, 3)
        # `edit 2`-style small numbers and the physical ports never become tags
        self.assertTrue(
            all(
                f.span.end - f.span.start <= 4
                for f in parsed.facts
                if f.kind == "vlan_tag"
            )
        )
        ips = {f.value: f for f in parsed.facts if f.kind == "ip_host"}
        self.assertEqual(ips["10.100.204.31"].iface, "oob-mgmt")
        self.assertEqual(ips["10.100.204.31"].mask_form, "dotted")
        self.assertEqual(ips["169.13.7.2"].parent, "port1")

    def test_forti_contract_roundtrip(self) -> None:
        text = self.read(self.FGT)
        d = ToyForti()
        sn = Snippet("fgt", text, skeleton(d, text), Path("fgt.txt"))
        self.assertEqual(check_snippet(d, sn), [])

    def test_forti_dns_is_block_scoped(self) -> None:
        text = self.read(self.FGT)
        parsed = ToyForti().parse(make_ct(text, "toyforti"))
        dns = [f for f in parsed.facts if f.kind == "dns_server"]
        for f in dns:
            self.assertIn("config system dns", text[: f.span.start])

    def test_all_forti_sidecars_split(self) -> None:
        for path in sorted(SIDECARS.glob("*_cfgs/*fgt*.txt")):
            text = path.read_bytes().decode("utf-8")
            lay = blocks.split(text, "fortios")
            self.assertTrue(
                any(b.kind == "edit:system interface" for b in lay.blocks), path.name
            )
            for b in lay.blocks:
                self.assertTrue(b.start <= b.end <= len(text))

    def test_linux_heredoc_resolv_conf(self) -> None:
        text = self.read(
            "vxlan_evpn_multi-site_with_backbone_dmvpn_cfgs/33_dc1-srv33.txt"
        )
        lay = blocks.split(text, "flat")
        res = [b for b in lay.blocks if b.kind == "heredoc:/etc/resolv.conf"]
        self.assertEqual(len(res), 1)
        body = [lay.line_text(ln) for ln in lay.lines if res[0] in ln.chain]
        self.assertTrue(any(ln.startswith("nameserver 1.1.1.1") for ln in body))
        self.assertTrue(any(ln.startswith("search ") for ln in body))

    def test_f5_sidecar_is_flat_without_blocks(self) -> None:
        text = self.read("vxlan_evpn_multi-site_sdwan_only_cfgs/38_dc1-f5-1.txt")
        lay = blocks.split(text, "flat")
        self.assertEqual(lay.blocks, [])
        self.assertTrue(all(ln.chain == () for ln in lay.lines))
        self.assertEqual(len(lay.lines), len(text.splitlines()))

    def test_f5_replace_all_with_via_many(self) -> None:
        class F5(RuleDialect):
            name = "toyf5"
            block_style = "flat"
            rules = (
                PatternRule(
                    "f5.dns",
                    r"^tmsh modify sys dns name-servers replace-all-with \{ (?P<many>[^}]*) \}",
                    "dns_server",
                    anchored_keywords=("name-servers replace-all-with",),
                ),
                PatternRule(
                    "f5.mgmt",
                    r"^tmsh create sys management-ip (?P<v>IPV4)(?P<mask>/\d+)$",
                    "ip_host",
                ),
            )

        text = self.read("vxlan_evpn_multi-site_sdwan_only_cfgs/38_dc1-f5-1.txt")
        parsed = F5().parse(make_ct(text, "toyf5"))
        self.assertEqual(
            [(f.kind, f.value) for f in parsed.facts],
            [
                ("ip_host", "10.100.203.38"),
                ("dns_server", "1.1.1.1"),
                ("dns_server", "1.0.0.1"),
            ],
        )
        self.assertEqual(parsed.facts[0].mask_form, "prefix")


# --------------------------------------------------------------------------- #
# packs and plugins
# --------------------------------------------------------------------------- #

EXAMPLE_PACK = """\
dialect = "eospack"
templates = ["veos*", "ceos*"]
sniff = ['^! device: .* EOS']
block_style = "indent"
mask_form = "prefix"
secret_rules = ['^username \\S+ .*secret (?:\\d )?(?P<s>\\S+)']

[iface_aliases]
Et = "Ethernet"
Ma = "Management"

[[rule]]
id = "eos.encap"
pattern = '^\\s+encapsulation dot1q vlan (?P<v>\\d+)$'
kind = "vlan_tag"
block = "interface"
role = "encap_tag"
negative = ["   rd 2:2"]

[[rule]]
id = "eos.ip"
pattern = '^\\s+ip address (?P<v>IPV4)(?P<mask>/\\d+)$'
kind = "ip_host"
block = "interface"

[[rule]]
id = "eos.access"
pattern = '^\\s+switchport access vlan (?P<v>\\d+)$'
kind = "vlan_tag"
block = "interface"
l2 = true

[[rule]]
id = "eos.ns"
pattern = '^ip name-server vrf \\S+ (?P<v>IPV4)$'
kind = "dns_server"
"""

EOS_TEXT = textwrap.dedent("""\
    ! device: sw1 (cEOS, EOS-4.30)
    username admin secret 0 hunter2
    ip name-server vrf MGMT 10.1.1.53
    interface Ethernet1.7
       encapsulation dot1q vlan 7
       ip address 10.7.0.1/24
    interface Ethernet2
       switchport access vlan 12
    """)


class TestPacks(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(REGISTRY, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        flag = mock.patch.object(dialects, "_loaded", True)
        flag.start()
        self.addCleanup(flag.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def write(self, name: str, body: str) -> Path:
        p = self.dir / name
        p.write_text(body, encoding="utf-8")
        return p

    def test_toml_pack_registers_and_parses(self) -> None:
        self.write("eos.toml", EXAMPLE_PACK)
        load_packs([self.dir])
        d = REGISTRY["eospack"]
        self.assertIsInstance(d, RuleDialect)
        parsed = d.parse(make_ct(EOS_TEXT, "eospack"))
        self.assertEqual(
            [(f.kind, f.value, f.iface) for f in parsed.facts if f.kind != "secret"],
            [
                ("dns_server", "10.1.1.53", None),
                ("vlan_tag", "7", "et1.7"),
                ("ip_host", "10.7.0.1", "et1.7"),
                ("vlan_tag", "12", "et2"),
            ],
        )
        self.assertEqual(parsed.ifaces["et1.7"].tag, 7)
        self.assertEqual(parsed.ifaces["et1.7"].parent, "et1")
        self.assertEqual(parsed.ifaces["et2"].mode, "access")
        self.assertEqual(d.iface_key("Ethernet1.7"), "et1.7")
        self.assertEqual(d.eve_to_config("Et2"), ["Ethernet2"])
        self.assertEqual(
            [EOS_TEXT[s.start : s.end] for s in d.secret_spans(EOS_TEXT)], ["hunter2"]
        )
        node = Node("1", "n", "qemu", "ceos", "", "0", [])
        self.assertEqual(d.score(node, "! device: x EOS"), 100)

    def test_pack_passes_the_contract_harness(self) -> None:
        self.write("eos.toml", EXAMPLE_PACK)
        load_packs([self.dir])
        d = REGISTRY["eospack"]
        self.assertEqual(check_static(d), [])
        sn = Snippet("eos", EOS_TEXT, skeleton(d, EOS_TEXT), Path("eos.txt"))
        self.assertEqual(check_snippet(d, sn), [])

    def test_pack_selected_by_pick(self) -> None:
        self.write("eos.toml", EXAMPLE_PACK)

        class G(RuleDialect):
            name = "generic"

        register(G)
        load_packs([self.dir])
        self.assertEqual(pick(None, EOS_TEXT).name, "eospack")
        self.assertEqual(
            pick(Node("1", "n", "q", "veos", "", "0", []), "").name, "eospack"
        )

    def test_reloading_same_pack_is_idempotent(self) -> None:
        self.write("eos.toml", EXAMPLE_PACK)
        load_packs([self.dir])
        load_packs([self.dir])
        self.assertEqual(list(REGISTRY), ["eospack"])

    def test_pack_cannot_shadow_another_dialect(self) -> None:
        class Mine(RuleDialect):
            name = "eospack"

        register(Mine)
        self.write("eos.toml", EXAMPLE_PACK)
        with self.assertRaises(LocalizeError) as ctx:
            load_packs([self.dir])
        self.assertEqual(ctx.exception.code, "DIALECT_DUPLICATE")

    def test_pack_extra_fact_kinds(self) -> None:
        body = (
            'dialect = "kindpack"\nfact_kinds = ["mac_addr_test"]\n'
            '[[rule]]\nid = "k.mac"\npattern = \'^mac (?P<v>\\S+)$\'\nkind = "mac_addr_test"\n'
        )
        self.write("k.toml", body)
        try:
            load_packs([self.dir])
            parsed = REGISTRY["kindpack"].parse(make_ct("mac aa:bb\n", "kindpack"))
            self.assertEqual(parsed.facts[0].kind, "mac_addr_test")
        finally:
            CORE_FACT_KINDS.discard("mac_addr_test")

    def test_invalid_packs_are_errors_naming_the_file(self) -> None:
        bad_cases = {
            "syntax.toml": "dialect = ",
            "nokey.toml": '[[rule]]\nid = "a"\n',
            "unknown.toml": 'dialect = "u1"\nbogus = 1\n',
            "badname.toml": 'dialect = "Bad Name"\n',
            "badrule.toml": 'dialect = "u2"\n[[rule]]\nid="a"\npattern="(?P<v>x)"\nkind="nope"\n',
            "ruleunk.toml": 'dialect = "u3"\n[[rule]]\nid="a"\npattern="(?P<v>x)"\nkind="domain"\nzzz=1\n',
            "badre.toml": 'dialect = "u4"\n[[rule]]\nid="a"\npattern="(x"\nkind="domain"\n',
            "badstyle.toml": 'dialect = "u5"\nblock_style = "weird"\n',
        }
        for name, body in bad_cases.items():
            with self.subTest(name=name):
                for old in self.dir.iterdir():
                    old.unlink()
                self.write(name, body)
                with self.assertRaises(LocalizeError) as ctx:
                    load_packs([self.dir])
                self.assertIn(name, str(ctx.exception))
                self.assertEqual(ctx.exception.code, "PACK_INVALID")

    def test_missing_dir(self) -> None:
        with self.assertRaises(LocalizeError) as ctx:
            load_packs([self.dir / "nope"])
        self.assertEqual(ctx.exception.code, "PLUGIN_DIR")

    def test_python_plugin_registers_dialect(self) -> None:
        self.write(
            "myplugin.py",
            textwrap.dedent("""\
                from evelab.localize.dialects import PatternRule, RuleDialect, register

                @register
                class FromPlugin(RuleDialect):
                    name = "plugged"
                    templates = ("plug*",)
                    rules = (PatternRule("p.dom", r"^domain (?P<v>\\S+)$", "domain"),)
                """),
        )
        load_packs([self.dir])
        parsed = REGISTRY["plugged"].parse(make_ct("domain a.b\n", "plugged"))
        self.assertEqual([f.value for f in parsed.facts], ["a.b"])
        load_packs([self.dir])  # second load: same origin, replaced quietly

    def test_plugin_errors_are_wrapped(self) -> None:
        self.write("boom.py", "raise RuntimeError('kaput')\n")
        with self.assertRaises(LocalizeError) as ctx:
            load_packs([self.dir])
        self.assertEqual(ctx.exception.code, "PLUGIN_ERROR")
        self.assertIn("kaput", str(ctx.exception))
        self.assertIn("boom.py", str(ctx.exception))

    def test_underscore_and_other_files_ignored(self) -> None:
        self.write("_skip.toml", "dialect = ")
        self.write("_skip.py", "raise SystemExit(1)")
        self.write("notes.txt", "hello")
        self.write(".hidden.toml", "dialect = ")
        load_packs([self.dir])
        self.assertEqual(list(REGISTRY), [])

    def test_toml_loaded_before_python(self) -> None:
        self.write(
            "a_plugin.py",
            "from evelab.localize import dialects\nassert 'eospack' in dialects.REGISTRY\n",
        )
        self.write("z.toml", EXAMPLE_PACK)
        load_packs([self.dir])

    def test_shipped_packs_dir_loads(self) -> None:
        load_packs([dialects.PACKS_DIR])  # must not raise (README only, or valid packs)


class TestLoadBuiltin(unittest.TestCase):
    def test_load_builtin_is_idempotent_and_tolerates_missing_modules(self) -> None:
        with mock.patch.dict(REGISTRY), mock.patch.object(dialects, "_loaded", False):
            dialects.load_builtin()
            first = dict(REGISTRY)
            dialects.load_builtin()
            self.assertEqual(dict(REGISTRY), first)

    def test_names_and_get(self) -> None:
        self.assertEqual(dialects.names(), sorted(REGISTRY))
        with self.assertRaises(LocalizeError):
            dialects.get("definitely-not-registered")

    def test_every_registered_dialect_is_a_dialect(self) -> None:
        for name, d in REGISTRY.items():
            self.assertEqual(d.name, name)
            self.assertIsInstance(d, Dialect)


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "skeleton":
        _d = dialects.get(sys.argv[2])
        _text = Path(sys.argv[3]).read_bytes().decode("utf-8")
        print(json.dumps(skeleton(_d, _text), indent=2))
    else:
        unittest.main()
