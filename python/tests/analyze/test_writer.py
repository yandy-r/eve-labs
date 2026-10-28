import unittest

from evelab.analyze.checks import KEEP, analyse_lab
from evelab.analyze.writer import Change, apply_changes, plan_changes, write_lab
from evelab.common.errors import EveLabError
from evelab.common.unl import RawLab

from .helpers import Repo

NX = "image/qemu/nxosv9k/nxosv9k-9300v-10.3.3.F"


class WriterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo(origin=None, use_git=False)
        self.addCleanup(self.repo.cleanup)
        self.lab = RawLab.read(self.repo.lab)
        self.rep = analyse_lab(self.lab, "labs/mini.unl", self.repo.inventory())

    def test_plan_changes_skips_keep_and_current(self) -> None:
        answers = {NX: "nxosv9k-9300v-10.5.1.F", "ram/16384": KEEP, "cpu/8": "8"}
        changes = plan_changes(self.rep, answers)
        self.assertEqual(
            {(c.node_name, c.attr, c.new) for c in changes},
            {
                ("leaf1", "image", "nxosv9k-9300v-10.5.1.F"),
                ("leaf2", "image", "nxosv9k-9300v-10.5.1.F"),
            },
        )

    def test_write_only_touches_the_attributes(self) -> None:
        changes = plan_changes(
            self.rep, {NX: "nxosv9k-9300v-10.5.1.F", "qemu_version/4.1.0": "6.0.0"}
        )
        backup = self.repo.root / ".analyze" / "backups" / "r1" / "labs" / "mini.unl"
        before = self.repo.lab.read_bytes()
        self.repo.lab.chmod(0o664)
        write_lab(self.lab, changes, backup=backup)
        after = self.repo.lab.read_bytes()
        self.assertEqual(backup.read_bytes(), before)
        self.assertEqual(self.repo.lab.stat().st_mode & 0o777, 0o664)
        diff = [
            (a, b)
            for a, b in zip(
                before.decode().splitlines(), after.decode().splitlines(), strict=True
            )
            if a != b
        ]
        self.assertEqual(len(diff), 2)  # leaf1 and leaf2 lines only
        self.assertEqual(after.count(b'image="nxosv9k-9300v-10.5.1.F"'), 2)
        self.assertEqual(after.count(b'qemu_version="6.0.0"'), 3)

    def test_sha_drift_refuses(self) -> None:
        changes = plan_changes(self.rep, {NX: "nxosv9k-9300v-10.5.1.F"})
        self.repo.lab.write_bytes(self.repo.lab.read_bytes() + b"\n")
        with self.assertRaises(EveLabError) as cm:
            write_lab(self.lab, changes, backup=None)
        self.assertEqual(cm.exception.code, "SHA_DRIFT")
        self.assertEqual(cm.exception.exit_code, 4)

    def test_stale_value_refuses(self) -> None:
        bad = [Change("1", "leaf1", "image", "something-else", "x", NX)]
        with self.assertRaises(EveLabError) as cm:
            apply_changes(self.repo.lab.read_bytes(), bad, self.repo.lab)
        self.assertEqual(cm.exception.code, "STALE")

    def test_escapes_values(self) -> None:
        ch = [Change("1", "leaf1", "image", "nxosv9k-9300v-10.3.3.F", 'a&"b', NX)]
        out = apply_changes(self.repo.lab.read_bytes(), ch, self.repo.lab)
        self.assertIn(b'image="a&amp;&quot;b"', out)
        self.assertEqual(RawLab.from_bytes(out).node_models()["1"].image, 'a&"b')


if __name__ == "__main__":
    unittest.main()
