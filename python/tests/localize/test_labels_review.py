"""Regression tests for the review findings on network labels (group "labels").

* labels are validated: strict charset + per-dialect field limits through the
  ``label_problem`` dialect hook (FortiOS ``alias`` <= 25, Cisco ``vlan name``
  <= 32 without blanks), on the answers-file path and in the plan;
* label text propagation is reversible: a non-distinctive new label never
  replaces text references, and the labels apply wrote into text are recorded
  in ``state.json`` (``baseline_text_labels``) and followed back by revert;
* IOS / IOS-XE descriptions carry the label anywhere (``EVE-INET-201 (ISP1)``);
* template-derived labels: the same answers give the same plan with or without
  ``--yes``; templates are applied per network and only when their
  ``{tag}``/``{octet3}`` changed; an ambiguous tag/octet3 digit run follows the
  manifest template (``mgmt-203`` -> ``mgmt-0``).
"""

from __future__ import annotations

import json
import re
import unittest

from evelab.localize import dialects, manifest, planner, profile
from evelab.localize.model import Fact, Span, Store
from evelab.localize.scenarios import labels
from evelab.localize.scenarios.base import ValueMaps

from .goldlib import Tree, real_stems
from .test_dialect_contract import make_ct

SDWAN = "vxlan_evpn_multi-site_sdwan_only"
JUNOS = "vxlan_evpn_multi-site_junos"
BACKBONE = "vxlan_evpn_multi-site_with_backbone"
PLAN_RE = re.compile(r"Plan: \d+ files?, (\d+) edits")


def _need(stem: str) -> None:
    if stem not in real_stems():
        raise unittest.SkipTest(f"{stem} not present")


class TreeCase(unittest.TestCase):
    maxDiff = None

    def tree(self, stem: str) -> Tree:
        _need(stem)
        t = Tree(stem)
        self.addCleanup(t.cleanup)
        return t

    def answers(self, t: Tree, text: str, ext: str = "toml") -> str:
        p = t.tmp / f"answers.{ext}"
        p.write_text(text)
        return str(p)

    def edits(self, out: str) -> int:
        m = PLAN_RE.search(out)
        self.assertIsNotNone(m, out)
        assert m is not None
        return int(m.group(1))

    def build_plan(self, t: Tree, stem: str, ans_path: str):
        a = t.analysis(stem)
        prof = profile.load_profile([ans_path])
        m = manifest.find_for(t.labs[stem])
        opts = planner.PlanOptions(manifest=m)
        return a, planner.build_plan(a, prof, opts), opts, prof


# --------------------------------------------------------------------------- #
# finding 0: validation
# --------------------------------------------------------------------------- #


class LabelValidationTest(TreeCase):
    def test_label_error_strict_charset(self) -> None:
        self.assertIsNone(labels.label_error("SITE-B-MGMT-77"))
        self.assertIsNone(labels.label_error("Mgmt B"))
        for bad in ('Mgmt "B" & <x>', "a<b", "x&y", "", " lead", "C\x01", "x" * 65):
            self.assertIsNotNone(labels.label_error(bad), bad)

    def _fortios_fact(self, text: str, value: str) -> Fact:
        start = text.index(value)
        return Fact(
            id="f1",
            kind="label_ref",
            value=value,
            store=Store("sidecar", "x.txt", "sidecar"),
            node_id="1",
            span=Span(start, start + len(value)),
            line=1,
            rule="fortios.text_label",
            iface=None,
            parent=None,
        )

    def test_fortios_alias_limit_hook(self) -> None:
        d = dialects.get("fortios")
        text = '    edit "port8"\n        set alias "EVE-MGMT-204"\n    next\n'
        f = self._fortios_fact(text, "EVE-MGMT-204")
        self.assertIsNone(d.label_problem(f, "SITE-B-MGMT-77", text))
        problem = d.label_problem(f, "EVE-MGMT-SITE-B-ALIAS-LONG-1", text)
        self.assertIsNotNone(problem)
        self.assertIn("alias", problem or "")
        self.assertIn("25", problem or "")
        text = '        set comment "LAN-WIFI via EVE-MGMT-204"\n'
        f = self._fortios_fact(text, "EVE-MGMT-204")
        self.assertIsNone(d.label_problem(f, "EVE-MGMT-SITE-B-ALIAS-LONG-1", text))
        self.assertIsNotNone(d.label_problem(f, 'a"b', text))

    def test_cisco_vlan_name_hook(self) -> None:
        d = dialects.get("ios")
        text = "vlan 3\n name EVE-MGMT-204\n"
        parsed = d.parse(make_ct(text, "ios"))
        f = next(f for f in parsed.facts if f.kind == "vlan_name")
        self.assertIsNone(d.label_problem(f, "SITE-B-MGMT-77", text))
        self.assertIn("32", d.label_problem(f, "X" * 33, text) or "")
        self.assertIn("blank", d.label_problem(f, "MGMT B-1", text) or "")

    def test_answers_file_quote_label_rejected(self) -> None:
        t = self.tree(SDWAN)
        before = t.lab_files(SDWAN)
        ans = self.answers(
            t, 'schema = 1\n[segments."site.mgmt_b"]\nlabel = \'Mgmt "B" & <x>\'\n'
        )
        code, out, err = t.run(
            "apply", "--lab", SDWAN, "--answers", ans, "--non-interactive", "--yes"
        )
        self.assertNotEqual(code, 0, out)
        self.assertIn('< > & "', out + err)
        self.assertEqual(before, t.lab_files(SDWAN))

    def test_answers_file_label_too_long_for_fortios_alias(self) -> None:
        t = self.tree(SDWAN)
        ans = self.answers(
            t,
            'schema = 1\n[segments."site.mgmt_b"]\n'
            'label = "EVE-MGMT-SITE-B-ALIAS-LONG-1"\n',
        )
        code, out, err = t.run("plan", "--lab", SDWAN, "--answers", ans)
        self.assertNotEqual(code, 0, out)
        self.assertIn("FortiOS alias would be 28 characters (max 25)", out + err)

    def test_plan_rejects_bad_label_without_question_validation(self) -> None:
        # the plan stage checks on its own (profiles loaded programmatically)
        t = self.tree(SDWAN)
        ans = self.answers(
            t,
            'schema = 1\n[segments."site.mgmt_b"]\n'
            'label = "EVE-MGMT-SITE-B-ALIAS-LONG-1"\n',
        )
        _a, plan, _o, _p = self.build_plan(t, SDWAN, ans)
        bad = [f for f in plan.findings if f.code == "BAD_LABEL"]
        self.assertTrue(bad, plan.findings)
        self.assertTrue(plan.blocked)
        self.assertTrue(any("alias" in f.msg for f in bad), bad)


# --------------------------------------------------------------------------- #
# finding 1: reversibility of text propagation
# --------------------------------------------------------------------------- #


class LabelRevertTest(TreeCase):
    def roundtrip(self, label: str) -> tuple[str, str]:
        t = self.tree(SDWAN)
        before = t.lab_files(SDWAN)
        ans = self.answers(
            t, f'schema = 1\n[segments."site.mgmt_b"]\nlabel = "{label}"\n'
        )
        code, out, err = t.run(
            "apply", "--lab", SDWAN, "--answers", ans, "--non-interactive", "--yes"
        )
        self.assertEqual(code, 0, out + err)
        self.assertNotEqual(before, t.lab_files(SDWAN))
        state = json.loads((t.root / ".localize" / "state.json").read_text())
        entry = next(iter(state.values()))
        code, rout, err = t.run("revert", "--lab", SDWAN, "--yes")
        self.assertEqual(code, 0, rout + err)
        after = t.lab_files(SDWAN)
        self.assertEqual(
            [k for k in before if before[k] != after.get(k)], [], f"{label}: revert"
        )
        return out, json.dumps(entry)

    def test_non_distinctive_label_round_trip_is_byte_identical(self) -> None:
        out, entry = self.roundtrip("MGMTX")
        self.assertIn("LABEL_TEXT_KEPT", out)
        self.assertEqual(self.edits(out), 5, out)  # network names only
        self.assertNotIn("MGMTX", json.loads(entry).get("baseline_text_labels", {}))

    def test_distinctive_label_recorded_in_state(self) -> None:
        out, entry = self.roundtrip("SITE-B-MGMT-77")
        self.assertNotIn("LABEL_TEXT_KEPT", out)
        self.assertEqual(
            json.loads(entry)["baseline_text_labels"],
            {"SITE-B-MGMT-77": "EVE-MGMT-204"},
        )

    def test_written_labels_follow_back_even_when_not_distinctive(self) -> None:
        # a label recorded as written into text follows a rename regardless of
        # the distinctiveness rule (generic "mgmt"-like shapes, manifest changes)
        _need(SDWAN)
        t = self.tree(SDWAN)
        a = t.analysis(SDWAN)
        seg = next(s for s in a.segments if s.site_key == "site.mgmt_b")
        old = labels.primary_label(seg)
        ans = self.answers(
            t, 'schema = 1\n[segments."site.mgmt_b"]\nlabel = "SITE-B-MGMT-77"\n'
        )
        prof = profile.load_profile([ans])
        m = manifest.find_for(t.labs[SDWAN])
        maps, _ = planner.build_value_maps(a, prof, planner.PlanOptions(manifest=m))
        self.assertEqual(maps.text_labels.get(old), "SITE-B-MGMT-77")
        # pretend the old label is not distinctive: only the state record helps
        orig = labels.distinctive
        try:
            labels.distinctive = lambda *_a, **_k: False  # type: ignore[assignment]
            maps, _ = planner.build_value_maps(a, prof, planner.PlanOptions(manifest=m))
            self.assertNotIn(old, maps.text_labels)
            labels.distinctive = lambda lbl, *_a, **_k: lbl != old  # type: ignore[assignment]
            maps, _ = planner.build_value_maps(
                a, prof, planner.PlanOptions(manifest=m, written_labels=(old,))
            )
            self.assertEqual(maps.text_labels.get(old), "SITE-B-MGMT-77")
        finally:
            labels.distinctive = orig  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# finding 7: IOS-XE description label anywhere
# --------------------------------------------------------------------------- #


class IosDescriptionLabelTest(TreeCase):
    SNIP = (
        "interface GigabitEthernet3\n"
        " description to pnet0: EVE-INET-201\n"
        "!\n"
        "interface GigabitEthernet3.201\n"
        " description EVE-INET-201 (ISP1)\n"
        " encapsulation dot1Q 201\n"
        "!\n"
    )

    def test_subif_description_label_is_a_fact(self) -> None:
        for name in ("ios", "iosxe"):
            parsed = dialects.get(name).parse(make_ct(self.SNIP, name))
            refs = [
                (f.line, f.value, f.rule) for f in parsed.facts if f.kind == "label_ref"
            ]
            self.assertEqual(
                refs,
                [
                    (2, "EVE-INET-201", f"{name}.desc_label"),
                    (5, "EVE-INET-201", f"{name}.desc_label"),
                ],
                name,
            )

    def test_c8kv_subif_description_follows_the_label(self) -> None:
        t = self.tree(SDWAN)
        ans = self.answers(t, 'schema = 1\n[segments."site.inet_a"]\nvlan = 2111\n')
        _a, plan, _o, _p = self.build_plan(t, SDWAN, ans)
        subif = [
            e
            for e in planner.enabled_edits(plan)
            if e.text_edit.old == "EVE-INET-201"
            and any(p.endswith(".desc_label") for p in e.provenance)
            and e.node_id in ("75", "77")
        ]
        self.assertTrue(subif, "no c8kv description edits")
        self.assertEqual({e.text_edit.new for e in subif}, {"EVE-INET-2111"})
        # parent "to pnet0:" and the "(ISP1)" subif description, per node/store
        self.assertGreaterEqual(len(subif), 4)


# --------------------------------------------------------------------------- #
# findings 8 / 17: template-derived labels
# --------------------------------------------------------------------------- #


class TemplateLabelTest(TreeCase):
    def test_plan_without_yes_matches_apply(self) -> None:
        t = self.tree(JUNOS)
        ans = self.answers(t, 'schema = 1\n[segments."junos.inet_a"]\nvlan = 1300\n')
        runs = []
        for extra in ((), ("--yes",)):
            code, out, err = t.run(
                "plan", "--lab", JUNOS, "--answers", ans, "--non-interactive", *extra
            )
            self.assertEqual(code, 0, out + err)
            runs.append(self.edits(out))
        code, out, err = t.run(
            "apply", "--lab", JUNOS, "--answers", ans, "--non-interactive", "--yes"
        )
        self.assertEqual(code, 0, out + err)
        runs.append(self.edits(out))
        self.assertEqual(len(set(runs)), 1, runs)
        self.assertIn('name="INET-1300"', t.labs[JUNOS].read_text())

    def test_subnet_change_does_not_collapse_generic_labels(self) -> None:
        t = self.tree(JUNOS)
        ans = self.answers(t, '{"junos.mgmt/subnet":"10.50.0.0/20"}', "json")
        counts = []
        for extra in ((), ("--yes",)):
            code, out, err = t.run(
                "plan", "--lab", JUNOS, "--answers", ans, "--non-interactive", *extra
            )
            self.assertEqual(code, 0, out + err)
            counts.append(self.edits(out))
        self.assertEqual(counts[0], counts[1])
        toml = self.answers(
            t, 'schema = 1\n[segments."junos.mgmt"]\nsubnet = "10.50.0.0/20"\n'
        )
        a, plan, opts, prof = self.build_plan(t, JUNOS, toml)
        maps, _ = planner.build_value_maps(a, prof, opts)
        seg = next(s for s in a.segments if s.site_key == "junos.mgmt")
        self.assertEqual(
            {nid: n for nid, n in maps.labels.items() if nid in seg.network_ids}, {}
        )
        self.assertFalse(
            [e for e in plan.edits if e.target == "xml_attr" and e.category == "label"]
        )

    def test_backbone_mgmt_follows_template_per_network(self) -> None:
        t = self.tree(BACKBONE)
        ans = self.answers(
            t,
            'schema = 1\n[segments."backbone.mgmt"]\nvlan = 3333\n'
            'subnet = "10.0.0.0/23"\n',
        )
        a, _plan, opts, prof = self.build_plan(t, BACKBONE, ans)
        maps, _ = planner.build_value_maps(a, prof, opts)
        seg = next(s for s in a.segments if s.site_key == "backbone.mgmt")
        renames = {
            seg.labels[nid]: new
            for nid, new in maps.labels.items()
            if nid in seg.network_ids
        }
        self.assertEqual(renames.get("mgmt-203"), "mgmt-0")
        self.assertEqual(renames.get("203-67"), "0-67")
        self.assertEqual(renames.get("mgmt-203_111_121"), "mgmt-0_111_121")
        default, source = labels.suggest_label(a, seg, prof, opts.manifest)
        self.assertEqual(default, "mgmt-0")
        self.assertIn("mgmt-{octet3}", source)

    def test_template_default_answer_renames_per_network(self) -> None:
        # an explicit label equal to the template default must not copy one
        # segment-wide name onto networks whose template carries {netid}
        _need(JUNOS)
        t = self.tree(JUNOS)
        a = t.analysis(JUNOS)
        seg = next(s for s in a.segments if s.site_key == "junos.inet_a")
        m = manifest.find_for(t.labs[JUNOS])
        pnid = labels._primary_nid(seg)
        assert pnid is not None
        default = labels.templated(seg, pnid, 1300, None, m, strict=True)
        self.assertEqual(default, "INET-1300")
        sa = profile.SegmentAnswer(vlan=1300, label=default)
        maps = ValueMaps(lab_id=a.lab.lab_id, manifest=m)
        canon = labels.canonical_scheme(seg)
        assert canon is not None and isinstance(canon.tag, int)
        maps.tags[(seg.key, canon.tag)] = 1300
        renames = labels.label_renames(a, seg, sa, maps)
        unanswered = labels.label_renames(
            a, seg, profile.SegmentAnswer(vlan=1300), maps
        )
        self.assertEqual(renames, unanswered)
        self.assertTrue(renames)


if __name__ == "__main__":
    unittest.main()
