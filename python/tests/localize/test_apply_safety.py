"""Regression tests for the apply-safety review fixes (apply.py, cli.py).

Each test reproduces one confirmed review finding on temp copies only: minilab
copies (via :class:`Env`) or a repo-like temp tree of real labs (via ``Tree``).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from evelab.common.unl import RawLab
from evelab.localize import apply as ap
from evelab.localize.errors import PreconditionError
from evelab.localize.model import Edit, Plan

from .test_apply import Env, sha
from .test_cli import AZURE, SCRIPTS, Tree


def _files(d: Path) -> dict[Path, bytes]:
    return {p: p.read_bytes() for p in d.rglob("*") if p.is_file()}


class ShaRecheckTest(unittest.TestCase):
    """Finding 9: a save during validation must not be overwritten."""

    def test_save_during_validation_is_refused(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        plan = env.plan()

        def eve_saves(staged: Path, p: Plan) -> list[Edit]:
            data = env.lab.read_bytes().replace(b'lock="0"', b'lock="1"', 1)
            env.lab.write_bytes(data)
            return []

        rec = ap.apply_plan(plan, env.opts(rescan=eve_saves))
        res = rec.labs[0]
        self.assertEqual(res.status, "skipped")
        self.assertEqual(rec.exit_code, 4)
        self.assertIn("SHA_DRIFT", [f.code for f in res.findings])
        self.assertIn(b'lock="1"', env.lab.read_bytes())  # EVE edit survived
        env.raw = RawLab.read(env.lab)
        self.assertIn("dot1Q 1240", env.blob_text("startup", "1"))  # not localized
        self.assertFalse(rec.journaled)
        self.assertFalse((env.state / "journal.json").exists())

    def test_drift_right_before_replace_rolls_back(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        env.sidecar("basic_cfgs/3_fw1.txt", "10.100.51.21", "10.9.9.21")
        plan = env.plan()
        side = env.dir / "basic_cfgs/3_fw1.txt"
        real = os.replace
        calls = {"n": 0}

        def replace_then_eve(src: object, dst: object) -> None:
            real(src, dst)  # type: ignore[arg-type]
            calls["n"] += 1
            if calls["n"] == 1:  # EVE touches the second file meanwhile
                side.write_bytes(side.read_bytes() + b"! eve\n")

        lab_before = env.lab.read_bytes()
        with mock.patch.object(ap.os, "replace", replace_then_eve):
            rec = ap.apply_plan(plan, env.opts())
        self.assertEqual(rec.labs[0].status, "skipped")
        self.assertIn("SHA_DRIFT", [f.code for f in rec.findings])
        self.assertEqual(env.lab.read_bytes(), lab_before)  # rolled back
        self.assertTrue(side.read_bytes().endswith(b"! eve\n"))  # kept
        self.assertFalse(rec.journaled)

    def test_rollback_keeps_files_changed_after_write(self) -> None:
        env = Env(self)
        fc = ap.FileChange(env.lab, env.lab, "unl", b"old", b"new")
        env.lab.write_bytes(b"someone else")
        found = ap._rollback([fc], {}, "r1", {ap._key(env.lab): "/b/x"})
        self.assertEqual([f.code for f in found], ["ROLLBACK_FAILED"])
        self.assertIn("/b/x", found[0].msg)
        self.assertEqual(env.lab.read_bytes(), b"someone else")

    def test_undo_checks_backup_sha_before_writing(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        env.sidecar("basic_cfgs/3_fw1.txt", "10.100.51.21", "10.9.9.21")
        rec = ap.apply_plan(env.plan(), env.opts())
        self.assertTrue(rec.ok, rec.findings)
        entry = ap.list_runs(env.opts())[-1]["labs"][env.raw.lab_id]
        side_key = str((env.dir / "basic_cfgs/3_fw1.txt").resolve())
        Path(entry["files"][side_key]["backup"]).write_bytes(b"wrong")
        localized = _files(env.dir)
        with self.assertRaises(PreconditionError) as cm:
            ap.undo(None, env.opts())
        self.assertEqual(cm.exception.code, "UNDO_REFUSED")
        self.assertIn("before_sha", str(cm.exception))
        self.assertEqual(_files(env.dir), localized)  # nothing restored
        self.assertNotIn("undone", ap.list_runs(env.opts())[-1])


class CopyModeSafetyTest(unittest.TestCase):
    """Findings 10, 11 and 16: --out must never hit the source or collide."""

    def test_out_is_source_dir_blocked(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        before = _files(env.dir)
        opts = env.opts(out_dir=env.dir)
        self.assertIn(
            "OUT_IS_SOURCE", [f.code for f in ap.preflight([env.plan()], opts)]
        )
        rec = ap.apply_plan(env.plan(), opts)
        self.assertEqual(rec.labs[0].status, "skipped")
        self.assertEqual(rec.exit_code, 4)
        self.assertIn("OUT_IS_SOURCE", [f.code for f in rec.findings])
        self.assertEqual(_files(env.dir), before)
        self.assertFalse(rec.journaled)

    def test_existing_running_dest_blocked(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        out = env.tmp / "out"
        out.mkdir()
        dest = out / env.lab.name
        other = "11111111-2222-4333-8444-555555555555"
        dest.write_bytes(
            env.lab.read_bytes().replace(env.raw.lab_id.encode(), other.encode())
        )
        env.add_proc(4242, ["qemu-system-x86_64", f"/opt/unetlab/tmp/0/{other}/1"])
        dest_before = dest.read_bytes()
        rec = ap.apply_plan(env.plan(), env.opts(out_dir=out))
        self.assertEqual(rec.labs[0].status, "skipped", rec.findings)
        self.assertIn("RUNNING_NODES", [f.code for f in rec.findings])
        self.assertEqual(dest.read_bytes(), dest_before)
        rec = ap.apply_plan(env.plan(), env.opts(out_dir=out, force_running=True))
        self.assertTrue(rec.ok, rec.findings)
        self.assertEqual(RawLab.read(dest).lab_id, other)  # re-run keeps its id

    def test_same_basename_collision_writes_nothing(self) -> None:
        a, b = Env(self), Env(self)  # two dirs, both hold basic.unl
        a.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        b.blob("startup", "1", "dot1Q 1240", "dot1Q 1260")
        out = a.tmp / "out"
        opts = a.opts(out_dir=out, continue_on_error=True)
        self.assertIn(
            "DEST_COLLISION", [f.code for f in ap.preflight([a.plan(), b.plan()], opts)]
        )
        rec = ap.apply_plans([a.plan(), b.plan()], opts)
        self.assertEqual([r.status for r in rec.labs], ["skipped", "skipped"])
        self.assertEqual(rec.exit_code, 4)
        self.assertIn("DEST_COLLISION", [f.code for f in rec.findings])
        self.assertFalse(out.exists() and any(out.iterdir()))
        self.assertFalse(rec.journaled)

    def test_copy_never_reuses_an_id_used_in_this_run(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        out = env.tmp / "out"
        out.mkdir()
        used = "11111111-2222-4333-8444-555555555555"
        dest = out / env.lab.name
        dest.write_bytes(
            env.lab.read_bytes().replace(env.raw.lab_id.encode(), used.encode())
        )
        opts = env.opts(out_dir=out)
        ch = ap.build_changes(env.plan(), opts, avoid_ids=[used])
        self.assertNotIn(ch.lab_id, (used, env.raw.lab_id))
        self.assertIn("DEST_ID_DUPLICATE", [f.code for f in ch.findings])
        self.assertEqual(ap.build_changes(env.plan(), opts).lab_id, used)

    def test_plain_copy_in_out_dir_gets_new_id(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        out = env.tmp / "out"
        out.mkdir()
        shutil.copyfile(env.lab, out / env.lab.name)  # plain copy: same id
        opts = env.opts(out_dir=out, check_labs_peers=[env.lab])
        rec = ap.apply_plan(env.plan(), opts)
        self.assertTrue(rec.ok, rec.findings)
        self.assertIn("DEST_ID_DUPLICATE", [f.code for f in rec.findings])
        new_id = RawLab.read(out / env.lab.name).lab_id
        self.assertNotEqual(new_id, env.raw.lab_id)
        rc, msg = ap.run_check_labs([env.lab, out / env.lab.name])
        self.assertEqual(rc, 0, msg)


class PerLabJournalTest(unittest.TestCase):
    """Finding 12: labs written before an interrupt stay journaled/undoable."""

    def test_interrupt_on_second_lab_keeps_first_undoable(self) -> None:
        a, b = Env(self), Env(self, "crlf_sidecar")
        a.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        b.sidecar("crlf_sidecar_cfgs/2_fw1.txt", "10.100.51.21", "10.9.9.21", "2")
        pa, pb = a.plan(), b.plan()
        a_before, b_before = a.lab.read_bytes(), _files(b.dir)

        def rescan(staged: Path, p: Plan) -> list[Edit]:
            if p is pb:
                raise KeyboardInterrupt
            return []

        opts = a.opts(rescan=rescan)
        with self.assertRaises(KeyboardInterrupt):
            ap.apply_plans([pa, pb], opts)
        self.assertNotEqual(a.lab.read_bytes(), a_before)
        self.assertEqual(_files(b.dir), b_before)
        self.assertIn(a.raw.lab_id, ap.load_state(opts))
        restored = ap.undo(None, opts)
        self.assertEqual(restored, [a.lab.resolve()])
        self.assertEqual(a.lab.read_bytes(), a_before)

    def test_interrupt_during_replace_rolls_back(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        env.sidecar("basic_cfgs/3_fw1.txt", "10.100.51.21", "10.9.9.21")
        before = _files(env.dir)
        real = os.replace
        calls = {"n": 0}

        def interrupted(src: object, dst: object) -> None:
            calls["n"] += 1
            if calls["n"] == 2:
                raise KeyboardInterrupt
            real(src, dst)  # type: ignore[arg-type]

        with (
            mock.patch.object(ap.os, "replace", interrupted),
            self.assertRaises(KeyboardInterrupt),
        ):
            ap.apply_plan(env.plan(), env.opts())
        self.assertEqual(_files(env.dir), before)


class StateMergeTest(unittest.TestCase):
    """Findings 13/33 (engine side): baseline keys survive a later apply."""

    def test_baseline_kept_when_caller_does_not_recompute_it(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        lid = env.raw.lab_id
        extra = {lid: {"baseline": {"s": {"bridge": "pnet0"}}, "baseline_maps": {}}}
        ap.apply_plan(env.plan(), env.opts(state_extra=extra))
        env2 = Env.__new__(Env)
        env2.__dict__.update(env.__dict__)
        env2.raw = RawLab.read(env.lab)
        env2.edits, env2.n = [], 0
        env2.blob("startup", "1", "dot1Q 1250", "dot1Q 1260")
        rec = ap.apply_plan(env2.plan(), env.opts())
        self.assertTrue(rec.ok, rec.findings)
        entry = ap.load_state(env.opts())[lid]
        self.assertEqual(entry["baseline"], {"s": {"bridge": "pnet0"}})
        self.assertIn("baseline_maps", entry)
        self.assertEqual(entry["after_sha"], sha(env.lab))


class SavedPlanRevertTest(unittest.TestCase):
    """Findings 13/33 (CLI): apply --plan records a baseline revert can use."""

    def setUp(self) -> None:
        self.t = Tree(AZURE)
        self.addCleanup(self.t.cleanup)

    def test_apply_plan_then_revert_restores_bridge(self) -> None:
        lab = self.t.labs[AZURE]
        original = lab.read_bytes()
        answers = self.t.write(
            "a.json", json.dumps({"azure_asa_vpn.MGMT-104/bridge": "pnet4"})
        )
        plan_file = self.t.tmp / "p.json"
        common = ("--lab", AZURE, "--allow-unpinned", "--non-interactive", "--yes")
        code, out, err = self.t.run(
            "plan", *common, "--answers", str(answers), "--save-plan", str(plan_file)
        )
        self.assertEqual(code, 0, out + err)
        code, out, err = self.t.run(
            "apply", "--plan", str(plan_file), "--yes", "--non-interactive"
        )
        self.assertEqual(code, 0, out + err)
        self.assertIn(b'type="pnet4"', lab.read_bytes())
        state = json.loads((self.t.root / ".localize/state.json").read_text())
        entry = state[RawLab.read(lab).lab_id]
        self.assertTrue(entry.get("baseline"), entry)
        self.assertIn("pnet4", json.dumps(entry["values"]))
        code, out, err = self.t.run("revert", *common)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(lab.read_bytes(), original)


class RelativeBackupDirTest(unittest.TestCase):
    """Finding 15: a relative --backup-dir is journaled absolute."""

    def test_undo_from_another_cwd(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        before = env.lab.read_bytes()
        work = env.tmp / "work"
        (work / "sub").mkdir(parents=True)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(work)
        rec = ap.apply_plan(
            env.plan(), env.opts(backup_dir=Path("bk"), state_dir=Path("st"))
        )
        self.assertTrue(rec.ok, rec.findings)
        state_dir = work / "st"
        run = ap.list_runs(ap.ApplyOptions(state_dir=state_dir))[-1]
        info = run["labs"][env.raw.lab_id]["files"][str(env.lab.resolve())]
        self.assertTrue(Path(info["backup"]).is_absolute(), info["backup"])
        os.chdir(work / "sub")
        restored = ap.undo(None, env.opts(state_dir=state_dir))
        self.assertEqual(len(restored), 1)
        self.assertEqual(env.lab.read_bytes(), before)


class PythonVersionGuardTest(unittest.TestCase):
    """Finding 41: old Pythons get a clear message, not an ImportError."""

    def test_guard_runs_before_evelab_import(self) -> None:
        shim = str(SCRIPTS / "eve-localize")
        code = (
            "import runpy, sys\n"
            "sys.version_info = (3, 10, 0, 'final', 0)\n"
            f"runpy.run_path({shim!r}, run_name='__main__')\n"
        )
        res = subprocess.run(
            [sys.executable, "-c", code, "--help"],
            capture_output=True,
            text=True,
            env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
            check=False,
            timeout=60,
        )
        self.assertEqual(res.returncode, 1, res.stderr)
        self.assertIn("needs Python 3.11+ (found 3.10)", res.stderr)
        self.assertNotIn("Traceback", res.stderr)


if __name__ == "__main__":
    unittest.main()
