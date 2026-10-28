"""Regression tests for the "bridges" review fixes.

* CARRIER_SPLIT: a trunk and the segments it carries on different bridges
  (findings 5 and 18).
* hostenv: carrier/operstate, host bridges in the choices, warnings for missing
  or link-less target bridges (finding 23).
* Manifest ``baseline.bridge``: revert without state.json, ``check`` (finding 34).
* Copy mode: source owner on created files/dirs, ``--fix-perms`` (finding 14).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from evelab.common import hostenv
from evelab.common.unl import RawLab
from evelab.localize import cli, manifest, planner
from evelab.localize.discover import analyse
from evelab.localize.model import Analysis
from evelab.localize.profile import Profile, SegmentAnswer
from evelab.localize.scenarios.bridge import BridgeScenario

from . import disco
from .labfiles import REPO, minilab_path
from .test_cli import AZURE, Tree


def _answers(a: Analysis, **per_key: dict) -> Profile:
    prof = Profile()
    for key, fields in per_key.items():
        seg = next(s for s in a.segments if s.key == key)
        sa = prof.segments.setdefault(seg.site_key, SegmentAnswer())
        for name, value in fields.items():
            setattr(sa, name, value)
    return prof


def _split(plan_findings: list) -> list:
    return [f for f in plan_findings if f.code == "CARRIER_SPLIT"]


class CarrierSplitTest(unittest.TestCase):
    """l2lab: TRUNK (pnet0) carries EXT-MGMT and SRV-NET (both pnet0)."""

    def setUp(self) -> None:
        self.a = analyse(RawLab.read(minilab_path("l2lab")))

    def test_carried_split_unanswered_trunk_is_conflict(self) -> None:
        # finding 18: carried segments to two bridges, trunk silently kept
        ans = _answers(
            self.a, **{"EXT-MGMT": {"bridge": "pnet2"}, "SRV-NET": {"bridge": "pnet3"}}
        )
        maps, findings = planner.build_value_maps(self.a, ans)
        self.assertNotIn("TRUNK", maps.bridges)
        split = _split(findings)
        self.assertEqual([f.severity for f in split], ["conflict"], findings)
        self.assertIn("l2lab.TRUNK/bridge", split[0].msg)
        self.assertTrue(planner.build_plan(self.a, ans).blocked)

    def test_explicit_trunk_on_other_bridge_warns(self) -> None:
        # finding 5: answers taken literally, but the split L2 domain is reported
        ans = _answers(
            self.a, **{"TRUNK": {"bridge": "pnet3"}, "EXT-MGMT": {"bridge": "pnet5"}}
        )
        maps, findings = planner.build_value_maps(self.a, ans)
        self.assertEqual(maps.bridges["TRUNK"], "pnet3")
        split = _split(findings)
        self.assertEqual([f.severity for f in split], ["warn"], findings)
        self.assertIn("EXT-MGMT on pnet5", split[0].msg)
        self.assertIn("SRV-NET on pnet0", split[0].msg)
        self.assertFalse(planner.build_plan(self.a, ans).blocked)

    def test_explicit_trunk_with_split_carried_warns(self) -> None:
        ans = _answers(
            self.a,
            **{
                "TRUNK": {"bridge": "pnet2"},
                "EXT-MGMT": {"bridge": "pnet2"},
                "SRV-NET": {"bridge": "pnet3"},
            },
        )
        _maps, findings = planner.build_value_maps(self.a, ans)
        self.assertEqual([f.severity for f in _split(findings)], ["warn"])

    def test_consistent_moves_are_quiet(self) -> None:
        ans = _answers(
            self.a, **{"EXT-MGMT": {"bridge": "pnet2"}, "SRV-NET": {"bridge": "pnet2"}}
        )
        maps, findings = planner.build_value_maps(self.a, ans)
        self.assertEqual(maps.bridges.get("TRUNK"), "pnet2", "carrier follows")
        self.assertEqual(_split(findings), [])
        _maps, findings = planner.build_value_maps(self.a, Profile())
        self.assertEqual(_split(findings), [])

    def test_question_order_default_and_note(self) -> None:
        sc = BridgeScenario()
        ans = _answers(
            self.a, **{"EXT-MGMT": {"bridge": "pnet2"}, "SRV-NET": {"bridge": "pnet3"}}
        )
        qs = sc.questions(self.a, None, ans)
        ids = [q.id for q in qs]
        self.assertEqual(ids[-1], "l2lab.TRUNK/bridge", "carrier asked last")
        trunk = qs[-1]
        self.assertEqual(trunk.default, "pnet0")
        self.assertEqual(trunk.default_source, "keep (carried segments split)")
        self.assertTrue(any("split L2 domain" in n for n in trunk.notes), trunk.notes)
        # once the carried segments agree, the default follows them again
        ans = _answers(
            self.a, **{"EXT-MGMT": {"bridge": "pnet2"}, "SRV-NET": {"bridge": "pnet2"}}
        )
        trunk = sc.questions(self.a, None, ans)[-1]
        self.assertEqual(
            (trunk.default, trunk.default_source), ("pnet2", "follows carried")
        )

    def test_real_sdwan_split(self) -> None:
        d = disco.real(disco.SDWAN)
        if d is None:
            self.skipTest("sdwan lab not present")
        a = d.analysis
        ans = _answers(
            a, **{"MGMT-204": {"bridge": "pnet2"}, "MGMT-203": {"bridge": "pnet3"}}
        )
        _maps, findings = planner.build_value_maps(a, ans)
        self.assertEqual([f.severity for f in _split(findings)], ["conflict"])


class HostBridgeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sys_net = Path(tempfile.mkdtemp(prefix="evelab-localize-sysnet-"))
        self.addCleanup(shutil.rmtree, self.sys_net, True)

    def add(self, name: str, flags: str, oper: str, carrier: str | None) -> None:
        d = self.sys_net / name
        (d / "bridge").mkdir(parents=True)
        (d / "brif").mkdir()
        (d / "flags").write_text(flags + "\n")
        (d / "operstate").write_text(oper + "\n")
        if carrier is not None:
            (d / "carrier").write_text(carrier + "\n")

    def test_no_carrier_state_and_findings(self) -> None:
        self.add("pnet0", "0x1003", "up", "1")
        self.add("pnet3", "0x1003", "down", "0")  # <NO-CARRIER,UP> state DOWN
        self.add("pnet4", "0x1002", "down", None)
        info = hostenv.bridge_info("pnet3", sys_net=self.sys_net)
        self.assertIs(info.carrier, False)
        self.assertEqual(info.state, "no-carrier")
        self.assertTrue(info.note.startswith("no-carrier"), info.note)
        self.assertEqual(hostenv.bridge_info("pnet0", sys_net=self.sys_net).state, "up")
        summary = hostenv.bridges_summary(hostenv.list_bridges(sys_net=self.sys_net))
        self.assertIn("pnet3 no-carrier", summary)
        self.assertIn("pnet4 down", summary)
        got = hostenv.bridge_findings(
            ["pnet0", "pnet3", "pnet4", "pnet99"], sys_net=self.sys_net
        )
        self.assertEqual(
            [(f.code, f.refs[0]) for f in got],
            [
                ("BRIDGE_NO_CARRIER", "bridge:pnet3"),
                ("BRIDGE_NO_CARRIER", "bridge:pnet4"),
                ("BRIDGE_NOT_ON_HOST", "bridge:pnet99"),
            ],
        )

    def test_silent_off_eve_host(self) -> None:
        self.assertEqual(hostenv.bridge_findings(["pnet99"], sys_net=self.sys_net), [])

    def test_choices_include_host_bridges(self) -> None:
        self.add("pnet0", "0x1003", "up", "1")
        self.add("pnet2", "0x1003", "up", "1")
        self.add("nat0", "0x1003", "unknown", "1")
        sess = SimpleNamespace(rt=SimpleNamespace(sys_net=self.sys_net))
        q = SimpleNamespace(choices=["pnet0"])
        got = cli._bridge_choices(sess, q)  # type: ignore[arg-type]
        self.assertEqual(got, ["pnet0", "nat0", "pnet2"])

    def test_plan_warns_on_missing_bridge(self) -> None:
        t = Tree(AZURE)
        self.addCleanup(t.cleanup)
        d = t.tmp / "sys_net" / "pnet0"
        (d / "bridge").mkdir(parents=True)
        (d / "flags").write_text("0x1003\n")
        (d / "operstate").write_text("up\n")
        answers = t.write(
            "a.json", json.dumps({"azure_asa_vpn.MGMT-104/bridge": "pnet99"})
        )
        _code, out, err = t.run(
            "plan", "--lab", AZURE, "--answers", str(answers), "--allow-unpinned", "-v"
        )
        self.assertIn("BRIDGE_NOT_ON_HOST", out + err)


def _copy_manifest(lab: Path) -> Path:
    """Copy the committed manifest of ``lab`` next to its temp copy."""
    real = next(
        p
        for p in (REPO / "labs").rglob("*.localize.toml")
        if p.name == lab.stem + ".localize.toml"
    )
    dst = lab.with_name(real.name)
    shutil.copyfile(real, dst)
    return dst


class ManifestBridgeBaselineTest(unittest.TestCase):
    def test_discovered_and_roundtrip(self) -> None:
        a = analyse(RawLab.read(minilab_path("l2lab")))
        seg = next(s for s in a.segments if s.key == "INTERNET")
        self.assertEqual(manifest.discovered_baseline(seg, a).bridge, "nat0")
        self.assertIsNone(manifest.discovered_baseline(seg).bridge)
        m = manifest.build_manifest(a)
        ms = next(s for s in m.segments if s.key == "INTERNET")
        self.assertEqual(ms.baseline.bridge, "nat0")
        text = manifest.generate(a)
        self.assertIn('bridge = "nat0"', text)

    def test_check_flags_changed_bridge(self) -> None:
        a = analyse(RawLab.read(minilab_path("l2lab")))
        m = manifest.build_manifest(a)
        ms = next(s for s in m.segments if s.key == "INTERNET")
        ms.baseline.bridge = "nat1"
        got = [f for f in manifest.check(a, m) if f.code == "NOT_AT_BASELINE"]
        self.assertTrue(any("bridge 'nat1'" in f.msg for f in got), got)
        loc = {"INTERNET": manifest.Baseline(bridge="nat0")}
        got = manifest.check(a, m, localized=loc)
        self.assertFalse(
            [f for f in got if f.code == "NOT_AT_BASELINE" and "INTERNET" in f.msg]
        )

    def test_revert_and_check_without_state(self) -> None:
        t = Tree(AZURE)
        self.addCleanup(t.cleanup)
        lab = t.labs[AZURE]
        mpath = _copy_manifest(lab)
        if 'bridge = "pnet0"' not in mpath.read_text():
            self.skipTest("manifest has no bridge baseline")
        before = lab.read_bytes()
        prof = t.write(
            "br.toml", 'schema = 1\n[segments."azure.inet"]\nbridge = "pnet4"\n'
        )
        code, out, err = t.run("apply", "--lab", AZURE, "--profile", str(prof), "--yes")
        self.assertEqual(code, 0, out + err)
        self.assertIn('type="pnet4"', lab.read_text())
        # with state.json the localized bridge is accepted
        code, out, err = t.run("check", "--lab", AZURE, "--strict")
        self.assertEqual(code, 0, out + err)
        shutil.rmtree(t.root / ".localize")  # fresh clone / other machine
        code, out, err = t.run("check", "--lab", AZURE, "--strict")
        self.assertNotEqual(code, 0, out + err)
        self.assertIn("NOT_AT_BASELINE", out + err)
        self.assertIn("bridge", out + err)
        code, out, err = t.run("revert", "--lab", AZURE, "--yes")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(before, lab.read_bytes())


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root")
class CopyModeOwnershipTest(unittest.TestCase):
    def test_copy_gets_source_owner_and_dirs(self) -> None:
        t = Tree(AZURE)
        self.addCleanup(t.cleanup)
        lab = t.labs[AZURE]
        uid, gid = 4242, 4343
        os.chown(lab, uid, gid)
        os.chmod(lab, 0o664)
        users = t.tmp / "Users"  # like /opt/unetlab/labs/Users (exists)
        users.mkdir()
        out_dir = users / "me"
        answers = t.write(
            "a.json", json.dumps({"azure_asa_vpn.MGMT-104/bridge": "pnet3"})
        )
        code, out, err = t.run(
            "apply", "--lab", AZURE, "--answers", str(answers), "--allow-unpinned",
            "--yes", "--out", str(out_dir),
        )  # fmt: skip
        self.assertEqual(code, 0, out + err)
        copy = out_dir / lab.name
        st = copy.stat()
        self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o7777), (uid, gid, 0o664))
        self.assertEqual((out_dir.stat().st_uid, out_dir.stat().st_gid), (uid, gid))

    def test_fix_perms_runs_on_out_dir(self) -> None:
        t = Tree(AZURE)
        self.addCleanup(t.cleanup)
        out_dir = t.tmp / "copies"
        answers = t.write(
            "a.json", json.dumps({"azure_asa_vpn.MGMT-104/bridge": "pnet3"})
        )
        calls: list[list[str]] = []

        def fake_run(argv, **_kw):  # type: ignore[no-untyped-def]
            calls.append(list(argv))
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        with mock.patch.object(cli.subprocess, "run", side_effect=fake_run):
            code, out, err = t.run(
                "apply", "--lab", AZURE, "--answers", str(answers),
                "--allow-unpinned", "--yes", "--out", str(out_dir), "--fix-perms",
            )  # fmt: skip
        self.assertEqual(code, 0, out + err)
        fp = [c for c in calls if c and c[-1] == str(out_dir.resolve())]
        self.assertTrue(fp, calls)
        self.assertTrue(fp[0][1].endswith("fix-lab-permissions.sh"))


if __name__ == "__main__":
    unittest.main()
