"""Tests for evelab.localize.apply (design section 12) on minilab temp copies.

Host probes always point at fake /proc and /opt/unetlab/tmp trees (this host may
run a real EVE lab), and the state dir is a temp dir.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evelab.common.codec import decode_blob
from evelab.common.hostenv import Lock
from evelab.common.unl import RawLab
from evelab.localize import apply as ap
from evelab.localize.errors import ConflictError, LocalizeError, PreconditionError
from evelab.localize.model import Confidence, Edit, Finding, Plan, Store, TextEdit

from .labfiles import minilab_path, real_lab_paths

GROUP = "seg/ip"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def no_docker() -> list[str]:
    return []


class Env:
    """A minilab copy plus fake host trees and a temp state dir."""

    def __init__(self, test: unittest.TestCase, stem: str = "basic") -> None:
        self.lab = minilab_path(stem)
        self.dir = self.lab.parent
        tmp = Path(tempfile.mkdtemp(prefix="evelab-localize-apply-"))
        test.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.tmp = tmp
        self.proc = tmp / "proc"
        self.tmp_root = tmp / "unetlab-tmp"
        self.proc.mkdir()
        self.tmp_root.mkdir()
        self.state = tmp / "state"
        self.raw = RawLab.read(self.lab)
        self.n = 0
        self.edits: list[Edit] = []

    def opts(self, **kw: object) -> ap.ApplyOptions:
        base: dict[str, object] = {
            "state_dir": self.state,
            "repo_root": self.tmp,  # not a git checkout
            "proc": self.proc,
            "tmp_root": self.tmp_root,
            "docker_names": no_docker,
            "check_labs_peers": [],
            "run_id": None,
        }
        base.update(kw)
        return ap.ApplyOptions(**base)  # type: ignore[arg-type]

    # -- edit builders -------------------------------------------------------

    def _edit(
        self,
        target: str,
        store: Store,
        node: str | None,
        te: TextEdit,
        file: Path | None = None,
        group: str = GROUP,
    ) -> Edit:
        self.n += 1
        e = Edit(
            id=f"e{self.n}",
            file=file or Path(self.lab.name),
            target=target,  # type: ignore[arg-type]
            store=store,
            node_id=node,
            text_edit=te,
            category="ip",
            group=group,
            confidence=Confidence.PROVEN,
            secret=False,
            provenance=["test"],
        )
        self.edits.append(e)
        return e

    def blob_text(self, scope: str, bid: str) -> str:
        if scope == "-":
            blob = next(b for b in self.raw.textobjects() if b.id == bid)
        else:
            blob = next(
                b for b in self.raw.config_blobs() if b.scope == scope and b.id == bid
            )
        dec = decode_blob(blob.b64)
        assert dec is not None
        return dec.text

    @staticmethod
    def _te(text: str, old: str, new: str) -> TextEdit:
        i = text.index(old)
        return TextEdit(i, i + len(old), old, new)

    def blob(self, scope: str, node: str, old: str, new: str, **kw: object) -> Edit:
        text = self.blob_text(scope, node)
        if scope == "startup":
            store = Store("startup", "startup", "startup")
        else:
            name = scope[3:]
            store = Store("configset", name, name)
        return self._edit("blob", store, node, self._te(text, old, new), **kw)  # type: ignore[arg-type]

    def textobject(self, tid: str, old: str, new: str) -> Edit:
        text = self.blob_text("-", tid)
        return self._edit(
            "textobject", Store("textobject", tid, "-"), None, self._te(text, old, new)
        )

    def net_name(self, net_id: str, new: str, old: str | None = None) -> Edit:
        el = next(e for e in self.raw.networks() if e.id == net_id)
        a = el.attrs["name"]
        te = TextEdit(a.span.start, a.span.end, a.value if old is None else old, new)
        return self._edit("xml_attr", Store("xml", "xml", "-"), None, te)

    def sidecar(self, rel: str, old: str, new: str, node: str = "3") -> Edit:
        path = self.dir / rel
        text, _ = ap.sidecar_decode(path.read_bytes())
        return self._edit(
            "sidecar",
            Store("sidecar", rel, "startup"),
            node,
            self._te(text, old, new),
            file=Path(rel),
        )

    def plan(
        self, edits: list[Edit] | None = None, groups: set[str] | None = None
    ) -> Plan:
        edits = self.edits if edits is None else edits
        files = {self.lab.name} | {str(e.file) for e in edits}
        return Plan(
            schema=1,
            lab=self.lab,
            lab_id=self.raw.lab_id,
            base_sha256={f: sha(self.dir / f) for f in files},
            answers_digest="sha256:test",
            edits=list(edits),
            enabled_groups={GROUP} if groups is None else groups,
            findings=[],
        )

    def add_proc(self, pid: int, argv: list[str]) -> None:
        d = self.proc / str(pid)
        d.mkdir()
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")


def blocking(findings: list) -> list[str]:
    return [f.code for f in findings if f.severity in ("conflict", "blocker", "error")]


class SidecarCodecTest(unittest.TestCase):
    def test_crlf_roundtrip(self) -> None:
        raw = b"a\r\nb\r\n"
        text, nl = ap.sidecar_decode(raw)
        self.assertEqual((text, nl), ("a\nb\n", "\r\n"))
        self.assertEqual(ap.sidecar_encode(text, nl), raw)

    def test_mixed_and_lf(self) -> None:
        for raw in (b"a\nb", b"a\r\nb\n", b"\xff\xfeodd\n"):
            text, nl = ap.sidecar_decode(raw)
            self.assertEqual(nl, "\n")
            self.assertEqual(ap.sidecar_encode(text, nl), raw)


class BuildChangesTest(unittest.TestCase):
    def test_all_targets(self) -> None:
        env = Env(self)
        env.net_name("2", "EVE-MGMT-303 & co")
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        env.blob("cs:alt-scheme", "2", "vlan 204\n", "vlan 304\n")
        env.textobject("1", "VLAN 203", "VLAN 303")
        env.sidecar("basic_cfgs/3_fw1.txt", "10.100.51.21", "10.9.9.21")
        ch = ap.build_changes(env.plan(), env.opts())
        self.assertEqual(len(ch.files), 2)
        after = RawLab.from_bytes(ch.unl.after)
        names = {n.id: n.name for n in after.network_models().values()}
        self.assertEqual(names["2"], "EVE-MGMT-303 & co")
        self.assertIn(b'name="EVE-MGMT-303 &amp; co"', ch.unl.after)
        self.assertEqual(
            sorted(ch.edited_blobs),
            [("-", "1"), ("cs:alt-scheme", "2"), ("startup", "1")],
        )
        side = ch.files[1].after.decode()
        self.assertIn("10.9.9.21", side)
        self.assertIn("—", side)

    def test_stale_attr_is_conflict(self) -> None:
        env = Env(self)
        env.net_name("2", "X", old="NOT-THE-NAME")
        with self.assertRaises(ConflictError) as cm:
            ap.build_changes(env.plan(), env.opts())
        self.assertEqual(cm.exception.code, "STALE_EDIT")

    def test_disabled_group_ignored(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250", group="other")
        ch = ap.build_changes(env.plan(), env.opts())
        self.assertEqual(ch.unl.after, ch.unl.before)
        self.assertEqual(ch.edited_blobs, [])

    def test_noncanonical_refused(self) -> None:
        env = Env(self, "noncanonical_b64")
        blob = next(b for b in env.raw.config_blobs() if b.id == "1")
        text = decode_blob(blob.b64).text  # type: ignore[union-attr]
        env._edit(
            "blob",
            Store("startup", "startup", "startup"),
            "1",
            TextEdit(0, 1, text[0], "#"),
        )
        with self.assertRaises(LocalizeError) as cm:
            ap.build_changes(env.plan(), env.opts())
        self.assertEqual(cm.exception.code, "NONCANONICAL_BLOB")


class ValidateWrittenTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(self)
        self.env.blob("startup", "1", "172.31.240.11", "172.31.250.11")
        self.plan = self.env.plan()
        self.ch = ap.build_changes(self.plan, self.env.opts())
        self.out = self.env.tmp / "written.unl"

    def check(self, data: bytes, **kw: object) -> list[str]:
        self.out.write_bytes(data)
        return [
            f.code
            for f in ap.validate_written(
                self.out, self.plan, self.env.raw, changes=self.ch, **kw  # type: ignore[arg-type]
            )
        ]

    def test_good(self) -> None:
        self.assertEqual(self.check(self.ch.unl.after), [])

    def test_good_without_changes(self) -> None:
        self.out.write_bytes(self.ch.unl.after)
        self.assertEqual(ap.validate_written(self.out, self.plan, self.env.raw), [])

    def test_byte_outside_span(self) -> None:
        bad = self.ch.unl.after.replace(b'author="eve', b'author="EVE')
        self.assertIn("VALIDATION_SPANS", self.check(bad))

    def test_broken_xml(self) -> None:
        self.assertEqual(self.check(self.ch.unl.after[:-20]), ["VALIDATION_XML"])

    def test_count_change(self) -> None:
        bad = self.ch.unl.after.replace(b"  <objects/>\n", b"", 1)
        codes = self.check(bad)
        self.assertIn("VALIDATION_COUNTS", codes)
        self.assertIn("VALIDATION_SPANS", codes)

    def test_check_labs_duplicate_id(self) -> None:
        twin = self.env.tmp / "twin.unl"
        shutil.copyfile(self.env.lab, twin)
        codes = self.check(self.ch.unl.after, peers=[twin])
        self.assertEqual(codes, ["VALIDATION_CHECK_LABS"])

    def test_noncanonical_written_blob(self) -> None:
        blob = next(
            b
            for b in RawLab.from_bytes(self.ch.unl.after).config_blobs()
            if b.id == "1" and b.scope == "startup"
        )
        wrapped = blob.b64[:40] + b"\n" + blob.b64[40:]
        bad = self.ch.unl.after.replace(blob.b64, wrapped)
        codes = self.check(bad)
        self.assertIn("VALIDATION_BLOB", codes)


class PreflightTest(unittest.TestCase):
    def test_clean(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "172.31.240.11", "172.31.250.11")
        found = ap.preflight([env.plan()], env.opts())
        self.assertEqual(blocking(found), [])
        self.assertIn("EVE_SAVE_RACE", [f.code for f in found])

    def test_sha_drift(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "172.31.240.11", "172.31.250.11")
        plan = env.plan()
        with open(env.lab, "ab") as fh:
            fh.write(b"\n")
        self.assertIn("SHA_DRIFT", blocking(ap.preflight([plan], env.opts())))

    def test_missing_base_sha(self) -> None:
        env = Env(self)
        env.sidecar("basic_cfgs/3_fw1.txt", "10.100.51.21", "10.9.9.21")
        plan = env.plan()
        del plan.base_sha256["basic_cfgs/3_fw1.txt"]
        self.assertIn("MISSING_BASE_SHA", blocking(ap.preflight([plan], env.opts())))

    def test_running_nodes(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "172.31.240.11", "172.31.250.11")
        env.add_proc(
            4242,
            [
                "/opt/unetlab/wrappers/qemu_wrapper",
                "-T",
                "0",
                "-D",
                "1",
                "-t",
                "x",
                "-F",
                f"/opt/unetlab/tmp/0/{env.raw.lab_id}/1/x",
            ],
        )
        found = ap.preflight([env.plan()], env.opts())
        self.assertIn("RUNNING_NODES", blocking(found))
        forced = ap.preflight([env.plan()], env.opts(force_running=True))
        self.assertNotIn("RUNNING_NODES", blocking(forced))

    def test_tmp_leftover_is_info(self) -> None:
        env = Env(self)
        (env.tmp_root / "0" / env.raw.lab_id).mkdir(parents=True)
        found = ap.preflight([env.plan()], env.opts())
        self.assertEqual(blocking(found), [])
        self.assertIn("NODES_NOT_WIPED", [f.code for f in found])

    def test_lock_held(self) -> None:
        env = Env(self)
        with Lock(env.state / "lock"):
            found = ap.preflight([env.plan()], env.opts())
        self.assertIn("LOCK_HELD", blocking(found))

    def test_read_only_layout(self) -> None:
        env = Env(self, "unknown_layout")
        blob = env.raw.config_blobs()[0]
        text = decode_blob(blob.b64).text  # type: ignore[union-attr]
        env._edit(
            "blob",
            Store("startup", "startup", "startup"),
            blob.id,
            TextEdit(0, 1, text[0], text[0]),
        )
        found = ap.preflight([env.plan()], env.opts())
        self.assertIn("UNSUPPORTED_LAYOUT", blocking(found))

    def test_blocked_plan(self) -> None:
        env = Env(self)
        plan = env.plan()
        plan.findings.append(Finding("PROTECTED", "blocker", "x"))
        self.assertIn("PLAN_BLOCKED", blocking(ap.preflight([plan], env.opts())))


class ApplyTest(unittest.TestCase):
    def full_plan(self, env: Env) -> Plan:
        env.net_name("2", "EVE-MGMT-303")
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        env.textobject("1", "VLAN 203", "VLAN 303")
        env.sidecar("basic_cfgs/3_fw1.txt", "10.100.51.21", "10.9.9.21")
        # mirror pair: node 4 startup blob and basic_cfgs/4_srv1.txt
        env.blob("startup", "4", "10.100.51.31/24", "10.9.9.31/24")
        env.sidecar("basic_cfgs/4_srv1.txt", "10.100.51.31/24", "10.9.9.31/24", "4")
        return env.plan()

    def test_apply_success_and_journal(self) -> None:
        env = Env(self)
        os.chmod(env.lab, 0o640)
        if os.geteuid() == 0:
            os.chown(env.lab, 33, 33)
        plan = self.full_plan(env)
        before = env.lab.read_bytes()
        side_before = (env.dir / "basic_cfgs/3_fw1.txt").read_bytes()
        seen: list[Path] = []

        def rescan(staged: Path, p: Plan) -> list[Edit]:
            seen.append(staged)
            self.assertTrue((staged.parent / "basic_cfgs" / "3_fw1.txt").is_file())
            self.assertIn(
                b"10.9.9.21", (staged.parent / "basic_cfgs/3_fw1.txt").read_bytes()
            )
            return []

        rec = ap.apply_plan(
            plan,
            env.opts(rescan=rescan, state_extra={env.raw.lab_id: {"values": {"a": 1}}}),
        )
        self.assertTrue(rec.ok, rec.findings)
        self.assertEqual(rec.exit_code, 0)
        self.assertTrue(rec.journaled)
        self.assertEqual(len(seen), 1)
        after = env.lab.read_bytes()
        self.assertNotEqual(after, before)
        new = RawLab.read(env.lab)
        self.assertFalse(new.read_only)
        self.assertEqual(new.network_models()["2"].name, "EVE-MGMT-303")
        st = env.lab.stat()
        self.assertEqual(st.st_mode & 0o777, 0o640)
        if os.geteuid() == 0:
            self.assertEqual((st.st_uid, st.st_gid), (33, 33))
        # no temp files left behind
        self.assertEqual([p for p in env.dir.iterdir() if p.name.startswith(".")], [])
        # backups
        journal = ap.load_journal(env.opts())
        run = journal["runs"][-1]
        entry = run["labs"][env.raw.lab_id]
        self.assertEqual(len(entry["files"]), 3)
        info = entry["files"][str(env.lab.resolve())]
        self.assertEqual(Path(info["backup"]).read_bytes(), before)
        self.assertEqual(info["after_sha"], sha(env.lab))
        self.assertEqual(info["mode"], 0o640)
        side_info = entry["files"][str((env.dir / "basic_cfgs/3_fw1.txt").resolve())]
        self.assertEqual(Path(side_info["backup"]).read_bytes(), side_before)
        state = ap.load_state(env.opts())
        self.assertTrue(state[env.raw.lab_id]["localized"])
        self.assertEqual(state[env.raw.lab_id]["after_sha"], sha(env.lab))
        self.assertEqual(state[env.raw.lab_id]["values"], {"a": 1})
        self.assertEqual(ap.list_runs(env.opts())[-1]["run_id"], rec.run_id)

    def test_second_run_same_answers_is_noop(self) -> None:
        env = Env(self)
        ap.apply_plan(self.full_plan(env), env.opts())
        env2 = Env.__new__(Env)
        env2.__dict__.update(env.__dict__)
        env2.raw = RawLab.read(env.lab)
        env2.edits, env2.n = [], 0
        env2.blob("startup", "1", "dot1Q 1250", "dot1Q 1250")
        rec = ap.apply_plan(env2.plan(), env.opts())
        self.assertEqual(rec.labs[0].status, "unchanged")
        self.assertFalse(rec.journaled)

    def test_stale_plan_skipped(self) -> None:
        env = Env(self)
        plan = self.full_plan(env)
        with open(env.lab, "ab") as fh:
            fh.write(b"\n")
        before = env.lab.read_bytes()
        rec = ap.apply_plan(plan, env.opts())
        self.assertEqual(rec.labs[0].status, "skipped")
        self.assertEqual(rec.exit_code, 4)
        self.assertEqual(env.lab.read_bytes(), before)
        self.assertFalse((env.state / "journal.json").exists())

    def test_rescan_residual_rolls_back(self) -> None:
        env = Env(self)
        plan = self.full_plan(env)
        before = {p: p.read_bytes() for p in env.dir.rglob("*") if p.is_file()}
        rec = ap.apply_plan(plan, env.opts(rescan=lambda staged, p: 2))
        self.assertEqual(rec.labs[0].status, "failed")
        self.assertEqual(rec.exit_code, 5)
        self.assertIn("VALIDATION_RESCAN", [f.code for f in rec.findings])
        after = {p: p.read_bytes() for p in env.dir.rglob("*") if p.is_file()}
        self.assertEqual(after, before)

    def test_mirror_broken(self) -> None:
        env = Env(self)
        env.blob("startup", "4", "10.100.51.31/24", "10.9.9.31/24")
        rec = ap.apply_plan(env.plan(), env.opts())
        self.assertEqual(rec.labs[0].status, "failed")
        self.assertIn("VALIDATION_MIRROR", [f.code for f in rec.findings])

    def test_check_labs_duplicate_rolls_back(self) -> None:
        env = Env(self)
        twin = env.tmp / "twin.unl"
        shutil.copyfile(env.lab, twin)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        before = env.lab.read_bytes()
        rec = ap.apply_plan(env.plan(), env.opts(check_labs_peers=[twin]))
        self.assertIn("VALIDATION_CHECK_LABS", [f.code for f in rec.findings])
        self.assertEqual(env.lab.read_bytes(), before)

    def test_replace_failure_rolls_back(self) -> None:
        env = Env(self)
        plan = self.full_plan(env)
        before = {p: p.read_bytes() for p in env.dir.rglob("*") if p.is_file()}
        real = os.replace
        calls = {"n": 0}

        def flaky(src: object, dst: object) -> None:
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("disk full")
            real(src, dst)  # type: ignore[arg-type]

        with mock.patch.object(ap.os, "replace", flaky):
            rec = ap.apply_plan(plan, env.opts())
        self.assertEqual(rec.labs[0].status, "failed")
        self.assertIn("WRITE_FAILED", [f.code for f in rec.findings])
        after = {p: p.read_bytes() for p in env.dir.rglob("*") if p.is_file()}
        self.assertEqual(after, before)

    def test_crlf_sidecar_preserved(self) -> None:
        env = Env(self, "crlf_sidecar")
        env.sidecar("crlf_sidecar_cfgs/2_fw1.txt", "10.100.51.21", "10.9.9.21", "2")
        rec = ap.apply_plan(env.plan(), env.opts())
        self.assertTrue(rec.ok, rec.findings)
        data = (env.dir / "crlf_sidecar_cfgs/2_fw1.txt").read_bytes()
        self.assertIn(b"10.9.9.21 255.255.255.0\r\n", data)
        self.assertEqual(data.count(b"\n"), data.count(b"\r\n"))
        self.assertTrue(data.endswith(b"\r\n"))

    def test_multi_lab_stop_and_continue(self) -> None:
        a, b = Env(self), Env(self, "crlf_sidecar")
        a.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        pa = a.plan()
        with open(a.lab, "ab") as fh:
            fh.write(b"\n")  # stale -> skipped
        b.sidecar("crlf_sidecar_cfgs/2_fw1.txt", "10.100.51.21", "10.9.9.21", "2")
        pb = b.plan()
        rec = ap.apply_plans([pa, pb], a.opts())
        self.assertEqual([r.status for r in rec.labs], ["skipped", "untouched"])
        rec = ap.apply_plans([pa, pb], a.opts(continue_on_error=True))
        self.assertEqual([r.status for r in rec.labs], ["skipped", "localized"])
        self.assertEqual(rec.exit_code, 4)

    def test_lock_held_raises(self) -> None:
        env = Env(self)
        with Lock(env.state / "lock"), self.assertRaises(PreconditionError):
            ap.apply_plan(env.plan(), env.opts())


class UndoTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(self)
        self.env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        self.env.sidecar("basic_cfgs/3_fw1.txt", "10.100.51.21", "10.9.9.21")
        self.before = {
            p: p.read_bytes() for p in self.env.dir.rglob("*") if p.is_file()
        }
        os.chmod(self.env.lab, 0o640)
        self.rec = ap.apply_plan(self.env.plan(), self.env.opts())
        self.assertTrue(self.rec.ok, self.rec.findings)

    def test_undo_restores(self) -> None:
        restored = ap.undo(None, self.env.opts())
        self.assertEqual(len(restored), 2)
        after = {p: p.read_bytes() for p in self.env.dir.rglob("*") if p.is_file()}
        self.assertEqual(after, self.before)
        self.assertEqual(self.env.lab.stat().st_mode & 0o777, 0o640)
        self.assertNotIn(self.env.raw.lab_id, ap.load_state(self.env.opts()))
        run = ap.list_runs(self.env.opts())[-1]
        self.assertIn("undone", run)
        with self.assertRaises(PreconditionError):
            ap.undo(None, self.env.opts())
        with self.assertRaises(PreconditionError) as cm:
            ap.undo(self.rec.run_id, self.env.opts())
        self.assertEqual(cm.exception.code, "ALREADY_UNDONE")

    def test_undo_refuses_after_eve_resave(self) -> None:
        data = self.env.lab.read_bytes().replace(b'lock="0"', b'lock="1"')
        self.env.lab.write_bytes(data)
        with self.assertRaises(PreconditionError) as cm:
            ap.undo(self.rec.run_id, self.env.opts())
        self.assertEqual(cm.exception.code, "UNDO_REFUSED")
        self.assertIn("git restore", str(cm.exception))
        # nothing restored (sidecar still localized)
        side = (self.env.dir / "basic_cfgs/3_fw1.txt").read_bytes()
        self.assertIn(b"10.9.9.21", side)

    def test_unknown_run(self) -> None:
        with self.assertRaises(PreconditionError):
            ap.undo("nope", self.env.opts())


class CopyModeTest(unittest.TestCase):
    def test_out_dir(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        env.sidecar("basic_cfgs/3_fw1.txt", "10.100.51.21", "10.9.9.21")
        out = env.tmp / "out"
        out.mkdir()
        before = {p: p.read_bytes() for p in env.dir.rglob("*") if p.is_file()}
        opts = env.opts(out_dir=out, check_labs_peers=[env.lab])
        rec = ap.apply_plan(env.plan(), opts)
        self.assertTrue(rec.ok, rec.findings)
        self.assertEqual(rec.mode, "out")
        after = {p: p.read_bytes() for p in env.dir.rglob("*") if p.is_file()}
        self.assertEqual(after, before)
        copy = RawLab.read(out / env.lab.name)
        self.assertNotEqual(copy.lab_id, env.raw.lab_id)
        self.assertEqual(len(copy.lab_id), 36)
        self.assertIn(b"10.9.9.21", (out / "basic_cfgs/3_fw1.txt").read_bytes())
        self.assertEqual(
            (out / "basic_cfgs/4_srv1.txt").read_bytes(),
            (env.dir / "basic_cfgs/4_srv1.txt").read_bytes(),
        )
        self.assertNotIn(env.raw.lab_id, ap.load_state(opts))
        # re-run: same id reused, nothing to do
        rec2 = ap.apply_plan(env.plan(), opts)
        self.assertEqual(rec2.labs[0].status, "unchanged")
        self.assertEqual(RawLab.read(out / env.lab.name).lab_id, copy.lab_id)
        # undo deletes created copies
        removed = ap.undo(rec.run_id, opts)
        self.assertIn(out / env.lab.name, removed)
        self.assertFalse((out / env.lab.name).exists())


@unittest.skipIf(shutil.which("git") is None, "git not installed")
class GitStateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(self)
        repo = self.env.dir

        def run(*a: str) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                ["git", "-C", str(repo), *a], check=True, capture_output=True
            )

        run("init", "-q")
        run("add", "-A")
        run(
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "init",
        )
        self.opts = self.env.opts(repo_root=repo)

    def test_dirty_warn_and_require_clean(self) -> None:
        self.env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        with open(self.env.lab, "ab") as fh:
            fh.write(b"\n")
        plan = self.env.plan()
        codes = {f.code: f.severity for f in ap.preflight([plan], self.opts)}
        self.assertEqual(codes.get("DIRTY"), "warn")
        strict = ap.ApplyOptions(**{**self.opts.__dict__, "require_clean": True})
        self.assertIn("DIRTY", blocking(ap.preflight([plan], strict)))

    def test_own_localization_counts_clean(self) -> None:
        self.env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        rec = ap.apply_plan(self.env.plan(), self.opts)
        self.assertTrue(rec.ok, rec.findings)
        env2 = Env.__new__(Env)
        env2.__dict__.update(self.env.__dict__)
        env2.raw, env2.edits, env2.n = RawLab.read(self.env.lab), [], 0
        env2.blob("startup", "1", "dot1Q 1250", "dot1Q 1260")
        strict = ap.ApplyOptions(**{**self.opts.__dict__, "require_clean": True})
        self.assertEqual(blocking(ap.preflight([env2.plan()], strict)), [])

    def test_no_backup_needs_clean(self) -> None:
        self.env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        plan = self.env.plan()
        nob = ap.ApplyOptions(**{**self.opts.__dict__, "no_backup": True})
        self.assertEqual(blocking(ap.preflight([plan], nob)), [])
        rec = ap.apply_plan(plan, nob)
        self.assertTrue(rec.ok, rec.findings)
        info = next(iter(rec.labs[0].files.values()))
        self.assertIsNone(info["backup"])
        with self.assertRaises(PreconditionError):
            ap.undo(None, nob)


class PlanDigestTest(unittest.TestCase):
    def test_stable_and_group_sensitive(self) -> None:
        env = Env(self)
        env.blob("startup", "1", "dot1Q 1240", "dot1Q 1250")
        p1, p2 = env.plan(), env.plan()
        self.assertEqual(ap.plan_digest(p1), ap.plan_digest(p2))
        p2.enabled_groups = set()
        self.assertNotEqual(ap.plan_digest(p1), ap.plan_digest(p2))
        self.assertRegex(ap.plan_digest(p1), r"^[0-9a-f]{64}$")


class RealLabsTest(unittest.TestCase):
    """Copy-mode id rewrite validates on every real lab (temp copies only)."""

    def test_id_rewrite_validates(self) -> None:
        paths = real_lab_paths()
        if not paths:
            self.skipTest("no real labs")
        with tempfile.TemporaryDirectory() as tmp:
            for src in paths:
                lab = RawLab.read(src)
                if lab.read_only:
                    continue
                with self.subTest(lab=src.name):
                    plan = Plan(1, src, lab.lab_id, {}, "", [], set(), [])
                    new_id = "00000000-0000-4000-8000-000000000001"
                    ch = ap.build_changes(plan, lab=lab, new_lab_id=new_id)
                    out = Path(tmp) / "copy.unl"
                    out.write_bytes(ch.unl.after)
                    found = ap.validate_written(
                        out, plan, lab, expect_lab_id=new_id, peers=paths
                    )
                    self.assertEqual(found, [])
                    self.assertEqual(
                        len(ch.unl.after) - len(lab.raw), 36 - len(lab.lab_id)
                    )


if __name__ == "__main__":
    unittest.main()
