"""Golden discovery for every real lab (design section 14, item 7).

``scan --json`` of all 9 labs (segments, schemes, status, question ids, defaults,
findings) plus the protected inventory and look-alikes must equal
``golden/<stem>.scan.json``. Regenerate after an intended change with
``UPDATE_GOLDEN=1 make localize-test`` and review the diff.

Also checks that each ``golden/<stem>.answers.toml`` (synthetic site B) is a valid
profile that still matches the lab: every answered site key exists, and each
answered segment changes its bridge and label (VLAN/subnet/gateway wherever the
lab has one).

Read-only: everything runs on a temp copy with fake host probes.
"""

from __future__ import annotations

import difflib
import json
import unittest

from evelab.localize import profile

from .goldlib import (
    UPDATE,
    Tree,
    answers_path,
    dumps,
    golden_docs,
    real_stems,
    scan_path,
)


def _missing(stem: str) -> str:
    return (
        f"{stem}: no golden/{answers_path(stem).name} or golden/"
        f"{scan_path(stem).name} - add the answers, then run with "
        "UPDATE_GOLDEN=1 (localize/README.md 'Onboarding a new lab', step 5)"
    )


class TestGoldenDiscovery(unittest.TestCase):
    docs: dict = {}

    @classmethod
    def setUpClass(cls) -> None:
        cls.tree = Tree(*real_stems())
        cls.addClassCleanup(cls.tree.cleanup)
        cls.docs = golden_docs(cls.tree)

    def test_all_labs_have_goldens(self) -> None:
        # The lab list comes from the tree (review fix #28): a new lab without
        # goldens is skipped with a message naming the files to add.
        self.assertEqual(set(self.docs), set(real_stems()))
        self.assertGreaterEqual(len(self.docs), 9)
        for stem in real_stems():
            with self.subTest(stem=stem):
                if not answers_path(stem).is_file():
                    self.skipTest(_missing(stem))
                if not UPDATE and not scan_path(stem).is_file():
                    self.skipTest(_missing(stem))

    def test_scan_equals_golden(self) -> None:
        for stem, doc in sorted(self.docs.items()):
            with self.subTest(stem=stem):
                text = dumps(doc)
                path = scan_path(stem)
                if UPDATE:
                    path.write_text(text, encoding="utf-8")
                    continue
                if not path.is_file():
                    self.skipTest(_missing(stem))
                want = path.read_text(encoding="utf-8")
                if want != text:
                    diff = "".join(
                        difflib.unified_diff(
                            want.splitlines(keepends=True),
                            text.splitlines(keepends=True),
                            f"golden/{path.name}",
                            "scan",
                            n=2,
                        )
                    )
                    self.fail(
                        f"{stem}: discovery differs from golden "
                        f"(UPDATE_GOLDEN=1 regenerates):\n{diff[:6000]}"
                    )

    def test_golden_files_are_json(self) -> None:
        for stem in real_stems():
            path = scan_path(stem)
            if path.is_file():
                with self.subTest(stem=stem):
                    data = json.loads(path.read_text(encoding="utf-8"))
                    self.assertEqual(data["lab_id"], self.docs[stem]["lab_id"])

    def test_site_b_answers_match_the_labs(self) -> None:
        for stem, doc in sorted(self.docs.items()):
            with self.subTest(stem=stem):
                if not answers_path(stem).is_file():
                    self.skipTest(_missing(stem))
                prof = profile.load_profile([answers_path(stem)])
                self.assertEqual(prof.site, "site-b")
                segs = {s["site_key"]: s for s in doc["segments"]}
                if doc["nothing_to_localize"]:
                    self.assertFalse(prof.segments)
                    continue
                self.assertEqual(set(prof.segments), set(segs), stem)
                for key, sa in prof.segments.items():
                    seg = segs[key]
                    self.assertIsNotNone(sa.bridge, key)
                    self.assertNotEqual(sa.bridge, seg["bridge"], key)
                    self.assertIsNotNone(sa.label, key)
                    self.assertNotIn(sa.label, seg["labels"].values(), key)
                    if not seg["schemes"]:
                        continue
                    canon = seg["schemes"][0]
                    if isinstance(canon["tag"], int):
                        self.assertNotIn(sa.vlan, (None, canon["tag"]), key)
                    if canon["subnet"]:
                        self.assertNotIn(str(sa.subnet), ("None", canon["subnet"]))
                    if canon["gateway"]:
                        self.assertNotIn(
                            str(sa.gateway), ("None", canon["gateway"]), key
                        )


if __name__ == "__main__":
    unittest.main()
