"""Golden round-trip, the core acceptance test (design section 14, item 8).

For every real lab with cloud networks, on a TEMP COPY (lab + ``*_cfgs`` sidecars +
committed manifest), driven through the CLI with fake host probes:

1. ``apply`` the synthetic site B (``golden/<stem>.answers.toml``: every bridge,
   VLAN tag, subnet (incl. prefix-length changes and the junos split map),
   gateway, label and service changed);
2. the lab changed, its XML element counts did not, check-labs passes, ``check``
   passes, the segment structure and protected inventory (internal VLANs and
   prefixes, look-alike facts such as junos ``Gi3.1240``) are unchanged;
3. no baseline external value is left over: no ``LEAK`` from the manifest leak
   scan, no IPv4 token inside an answered segment's baseline subnet, no service
   fact with a mapped old value, no network still named by a replaced label;
4. re-running ``apply`` with the same answers plans 0 edits;
5. ``revert`` restores the ``.unl`` and every sidecar BYTE-IDENTICALLY.

Labs without clouds: ``apply`` with their answers writes nothing (zero diff).
"""

from __future__ import annotations

import re
import unittest
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterable
from ipaddress import IPv4Address

from evelab.common.textutil import find_ipv4
from evelab.localize import apply, manifest, profile
from evelab.localize.discover.inventory import lookalikes
from evelab.localize.model import Analysis, Fact
from evelab.localize.scenarios.base import current_bridge

from .goldlib import Tree, answers_path, protected_doc, real_stems
from .labfiles import cloud_lab_stems, no_cloud_lab_stems

SERVICE_KINDS = frozenset(
    {"dns_server", "ntp_server", "probe_target", "domain", "search_list", "log_server"}
)
# Derived from the tree (review fix #28): every tracked lab is covered without
# editing a list here.  A lab without ``golden/<stem>.answers.toml`` is skipped
# with a message naming the file to add (README "Onboarding a new lab", step 5).
NO_CLOUD = no_cloud_lab_stems()
WITH_CLOUDS = cloud_lab_stems()
EDITS_RE = re.compile(r"Plan: \d+ files?, (\d+) edits")


def element_counts(raw: bytes) -> Counter[str]:
    return Counter(el.tag for el in ET.fromstring(raw).iter())


def fact_keys(facts: Iterable[Fact]) -> set[tuple[str, ...]]:
    return {(f.kind, f.value, f.node_id, f.store.kind, f.store.name) for f in facts}


class RoundTripCase(unittest.TestCase):
    maxDiff = None

    def run_cli(self, tree: Tree, *argv: str) -> str:
        code, out, err = tree.run(*argv)
        self.assertEqual(code, 0, f"{' '.join(argv)} -> {code}\n{out}\n{err}")
        return out

    def planned_edits(self, out: str) -> int:
        m = EDITS_RE.search(out)
        self.assertIsNotNone(m, out)
        assert m is not None
        return int(m.group(1))

    # ------------------------------------------------------------------ #

    def need_answers(self, stem: str) -> None:
        if not answers_path(stem).is_file():
            self.skipTest(
                f"{stem}: no golden/{answers_path(stem).name} - add one to cover "
                "this lab (localize/README.md 'Onboarding a new lab', step 5)"
            )

    def roundtrip(self, stem: str) -> None:
        if stem not in real_stems():
            self.skipTest(f"{stem} not present")
        self.need_answers(stem)
        tree = Tree(stem)
        self.addCleanup(tree.cleanup)
        lab = tree.labs[stem]
        ans_path = answers_path(stem)
        prof = profile.load_profile([ans_path])
        before = tree.lab_files(stem)
        base = tree.analysis(stem)
        common = ("--lab", stem, "--profile", str(ans_path))

        # 1. localize to site B
        out = self.run_cli(tree, "apply", *common, "--yes")
        self.assertGreater(self.planned_edits(out), 0, out)
        self.assertIn("localized", out)
        after = tree.lab_files(stem)
        self.assertNotEqual(before[str(lab.relative_to(tree.root))], lab.read_bytes())
        self.assertEqual(set(before), set(after), "files created or removed")
        rel = str(lab.relative_to(tree.root))
        self.assertEqual(element_counts(before[rel]), element_counts(after[rel]))

        # 2. validity, structure, protected inventory
        rc, msg = apply.run_check_labs([lab])
        self.assertEqual(rc, 0, msg)
        self.run_cli(tree, "check", "--lab", stem)
        loc = tree.analysis(stem)
        self.assertEqual(
            [s.key for s in base.segments], [s.key for s in loc.segments], stem
        )
        self.assertFalse(
            [f.msg for f in loc.findings if f.code == "MERGE_UNKNOWN_UNIT"]
        )
        pb, pa = protected_doc(base), protected_doc(loc)
        self.assertEqual(pb["vlans"], pa["vlans"])
        self.assertEqual(pb["prefixes"], pa["prefixes"])
        for seg in base.segments:
            looks = fact_keys(lookalikes(base.facts, seg))
            self.assertLessEqual(looks, fact_keys(loc.facts.values()), seg.key)

        # 3. the site B values are in place, no baseline external value is left
        self.assert_site_b(stem, loc, prof)
        self.assert_no_leftovers(stem, loc, prof)

        # 4. idempotent
        out = self.run_cli(tree, "apply", *common, "--yes")
        self.assertIn("0 edits", out)
        self.assertEqual(after, tree.lab_files(stem))

        # 5. revert -> byte-identical .unl and sidecars
        out = self.run_cli(tree, "revert", "--lab", stem, "--yes")
        self.assertIn("reverted", out)
        restored = tree.lab_files(stem)
        changed = sorted(k for k in before if before[k] != restored.get(k))
        self.assertEqual(changed, [], f"{stem}: revert is not byte-identical")
        self.assertEqual(before, restored)

    def assert_site_b(self, stem: str, a: Analysis, prof: profile.Profile) -> None:
        for seg in a.segments:
            sa = prof.segments.get(seg.site_key)
            if sa is None:
                continue
            with self.subTest(stem=stem, segment=seg.key):
                if sa.bridge:
                    self.assertEqual(current_bridge(a, seg), sa.bridge)
                if sa.label:
                    self.assertIn(sa.label, seg.labels.values())
                canon = seg.schemes[0] if seg.schemes else None
                if canon is None:
                    continue
                if sa.vlan is not None and isinstance(canon.tag, int):
                    self.assertEqual(canon.tag, sa.vlan)
                if sa.subnet is not None and canon.subnet is not None:
                    self.assertEqual(canon.subnet, sa.subnet)
                if sa.gateway is not None and canon.gateway is not None:
                    self.assertEqual(canon.gateway, sa.gateway)

    def assert_no_leftovers(
        self, stem: str, a: Analysis, prof: profile.Profile
    ) -> None:
        m = manifest.find_for(a.lab.path)
        self.assertIsNotNone(m)
        assert m is not None
        leaks = [f.msg for f in manifest.leak_scan(a, m) if f.code == "LEAK"]
        self.assertEqual(leaks, [], stem)
        old_nets = []
        old_labels: dict[str, str] = {}
        for ms in m.segments:
            sa = prof.segments.get(ms.site_key or "")
            if sa is None:
                continue
            if sa.subnet is not None and ms.baseline.subnet is not None:
                old_nets.append(ms.baseline.subnet)
            if sa.label is not None and ms.baseline.label:
                old_labels[ms.key] = ms.baseline.label
        hits: Counter[str] = Counter()
        for ct in a.texts:
            if ct.opaque or not ct.text:
                continue
            for tok in find_ipv4(ct.text):
                if any(IPv4Address(tok.value) in n for n in old_nets):
                    hits[f"{ct.store.kind}:{ct.store.name} {tok.value}"] += 1
        self.assertEqual(dict(hits), {}, f"{stem}: baseline subnet tokens left")
        olds = {old for table in prof.maps.values() for old in table}
        svc = sorted(
            f"{f.kind} {f.value}"
            for f in a.facts.values()
            if f.kind in SERVICE_KINDS and f.value in olds
        )
        self.assertEqual(svc, [], f"{stem}: mapped service values left")
        for seg in a.segments:
            if seg.key in old_labels:
                self.assertNotIn(old_labels[seg.key], seg.labels.values(), seg.key)

    def no_cloud(self, stem: str) -> None:
        if stem not in real_stems():
            self.skipTest(f"{stem} not present")
        self.need_answers(stem)
        tree = Tree(stem)
        self.addCleanup(tree.cleanup)
        before = tree.lab_files(stem)
        common = ("--lab", stem, "--profile", str(answers_path(stem)))
        out = self.run_cli(tree, "apply", *common, "--yes")
        self.assertNotIn("localized", out)
        self.run_cli(tree, "revert", "--lab", stem, "--yes")
        self.assertEqual(before, tree.lab_files(stem))
        self.assertFalse((tree.root / ".localize" / "state.json").exists())


def _make(kind: str, stem: str):
    def test(self: RoundTripCase) -> None:
        getattr(self, kind)(stem)

    test.__doc__ = f"{kind}: {stem}"
    return test


for _stem in WITH_CLOUDS:
    setattr(RoundTripCase, f"test_roundtrip_{_stem}", _make("roundtrip", _stem))
for _stem in NO_CLOUD:
    setattr(RoundTripCase, f"test_no_cloud_{_stem}", _make("no_cloud", _stem))


class TestCoverage(unittest.TestCase):
    def test_every_real_lab_is_covered(self) -> None:
        self.assertEqual(set(real_stems()), set(WITH_CLOUDS) | set(NO_CLOUD))
        self.assertFalse(set(WITH_CLOUDS) & set(NO_CLOUD))
        for stem in real_stems():
            with self.subTest(stem=stem):
                self.assertTrue(
                    hasattr(RoundTripCase, f"test_roundtrip_{stem}")
                    or hasattr(RoundTripCase, f"test_no_cloud_{stem}"),
                    stem,
                )


if __name__ == "__main__":
    unittest.main()
