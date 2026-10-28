import os
import tempfile
import unittest
from pathlib import Path

from evelab.common.checklabs import run_check_labs
from evelab.common.errors import EveLabError
from evelab.common.fsutil import atomic_write
from evelab.common.labfiles import resolve_lab_names


class AtomicWriteTest(unittest.TestCase):
    def test_keeps_mode_and_leaves_no_temp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "a.unl"
            f.write_bytes(b"old")
            os.chmod(f, 0o664)
            atomic_write(f, b"new")
            self.assertEqual(f.read_bytes(), b"new")
            self.assertEqual(f.stat().st_mode & 0o777, 0o664)
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ["a.unl"])


class ResolveLabNamesTest(unittest.TestCase):
    def test_substring_exact_stem_and_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for rel in ("labs/a/sdwan.unl", "labs/b/sdwan_only.unl", "labs/c/x.unl"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("<lab/>")
            self.assertEqual(
                resolve_lab_names(root, ["sdwan"]), [root / "labs/a/sdwan.unl"]
            )
            self.assertEqual(
                resolve_lab_names(root, ["labs/c/x.unl", "x"]), [root / "labs/c/x.unl"]
            )
            for name, code in (("nope", "NO_LAB"), ("labs", "AMBIGUOUS_LAB")):
                with self.assertRaises(EveLabError) as cm:
                    resolve_lab_names(root, [name])
                self.assertEqual(cm.exception.code, code)


class CheckLabsTest(unittest.TestCase):
    def test_duplicate_ids_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a.unl", Path(tmp) / "b.unl"
            a.write_text('<lab id="1"/>')
            b.write_text('<lab id="1"/>')
            self.assertEqual(run_check_labs([a])[0], 0)
            rc, text = run_check_labs([a, b])
            self.assertEqual(rc, 1)
            self.assertIn("duplicate lab id", text)


if __name__ == "__main__":
    unittest.main()
