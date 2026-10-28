"""Committed real-lab manifests (T20) and manifest ``[[rule]]`` wiring.

* every real lab with cloud networks has a ``<stem>.localize.toml`` that loads,
  pins the analysis and checks clean under ``--strict`` rules (no error, no warn);
* ``localize/site.example.toml`` is current (``check`` reports ``STALE_EXAMPLE``);
* manifest ``[[rule]]`` tables are parsed into extra dialect rules
  (``discover.manifest_rules`` / ``topology.with_rules``) and turn the sdwan
  internet-edge NAT/PBR addresses into segment facts.

Read-only: real labs are only read; the CLI runs with a temp state dir and fake
host probes.
"""

from __future__ import annotations

import io
import shutil
import tempfile
import unittest
from pathlib import Path

from evelab.localize import cli, dialects, manifest
from evelab.localize.discover import analyse, manifest_rules
from evelab.localize.discover.topology import with_rules
from evelab.localize.manifest import LocalRule, Manifest
from evelab.localize.model import ConfigText, Store

from .disco import NO_CLOUD, SDWAN, real_path
from .labfiles import REPO, cloud_lab_stems, read_real, real_lab_paths

WITH_CLOUDS = cloud_lab_stems()  # derived from the tree (review fix #28)


def _has_clouds(path: Path) -> bool:
    lab = read_real(path)
    return any(n.get("type", "bridge") != "bridge" for n in lab.networks())


class TestRealManifests(unittest.TestCase):
    def test_every_cloud_lab_has_a_manifest(self) -> None:
        stems = set()
        for path in real_lab_paths():
            mpath = manifest.manifest_path_for(path)
            if _has_clouds(path):
                stems.add(path.stem)
                self.assertTrue(mpath.is_file(), f"{path.name}: no manifest")
                self.assertIsNotNone(manifest.find_for(path), path.name)
            else:
                self.assertFalse(mpath.exists(), f"{path.name}: needs no manifest")
        present = {s for s in WITH_CLOUDS if real_path(s) is not None}
        self.assertEqual(stems & set(WITH_CLOUDS), present)
        for stem in NO_CLOUD:
            self.assertNotIn(stem, stems)

    def test_no_draft_left_next_to_labs(self) -> None:
        self.assertEqual(sorted((REPO / "labs").rglob("*.localize.toml.draft")), [])

    def test_manifests_check_clean(self) -> None:
        for path in real_lab_paths():
            m = manifest.find_for(path)
            if m is None:
                continue
            with self.subTest(lab=path.stem):
                a = analyse(read_real(path), m)
                self.assertTrue(a.pinned, path.stem)
                bad = [
                    f"{f.code}: {f.msg}"
                    for f in manifest.check(a, m)
                    if f.severity in ("error", "warn")
                ]
                self.assertEqual(bad, [])
                # every manifest segment carries an explicit site_key
                self.assertTrue(all(s.site_key for s in m.segments))

    def test_author_decisions(self) -> None:
        def load(stem: str) -> Manifest | None:
            p = real_path(stem)
            return manifest.find_for(p) if p is not None else None

        ei = load("ccie_enterprise_infrastructure_practice_lab")
        if ei is not None:
            seg = ei.segment("SDWAN-CTRL")
            assert seg is not None
            self.assertEqual(seg.site_key, "site.sdwan_ctrl")
            self.assertEqual(seg.status, "LABEL_ONLY")
            self.assertIn("Net", ei.generic_labels)
        bb = load("vxlan_evpn_multi-site_with_backbone")
        if bb is not None:
            self.assertEqual(bb.canonical_scope, "vxlan-dmvpn-backbone")
            self.assertTrue(bb.legacy)
            self.assertTrue(all(lg.policy == "leave" for lg in bb.legacy))
            self.assertEqual(
                {(o.scope, o.node) for o in bb.outliers},
                {
                    ("vxlan-vpc", "74"),
                    ("vxlan-vpc", "84"),
                },
            )
        az = load("azure_asa_vpn")
        if az is not None:
            self.assertTrue(az.scenarios["azure_s2s"].enabled)
            self.assertEqual(az.scenarios["azure_s2s"].options.get("node"), "1")
        jn = load("vxlan_evpn_multi-site_junos")
        if jn is not None:
            pin = jn.scenarios["bgp_upstream"]
            self.assertEqual(pin.options.get("nodes"), ["9", "18"])

    def test_cli_check_strict_and_example_current(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="evelab-localize-t20-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        out, err = io.StringIO(), io.StringIO()
        rt = cli.Runtime(
            stdin=io.StringIO(""),
            stdout=out,
            stderr=err,
            env={"NO_COLOR": "1"},
            interactive=False,
            getpass_fn=lambda _prompt: "",
            proc=tmp / "proc",
            tmp_root=tmp / "unetlab_tmp",
            docker_names=list,
            sys_net=tmp / "sys_net",
            check_labs_peers=[],
        )
        argv = ["check", "--all", "--strict", "--root", str(REPO)]
        code = cli.main([*argv, "--state-dir", str(tmp / "state"), "--no-color"], rt)
        text = out.getvalue() + err.getvalue()
        self.assertEqual(code, 0, text)
        self.assertNotIn("STALE_EXAMPLE", text)
        self.assertTrue((REPO / cli.EXAMPLE_PROFILE).is_file())


class TestManifestRules(unittest.TestCase):
    def _manifest(self, *rules: LocalRule) -> Manifest:
        return Manifest(
            lab="x.unl",
            lab_id="00000000-0000-4000-8000-000000000000",
            rules=list(rules),
        )

    def test_manifest_rules_by_dialect(self) -> None:
        m = self._manifest(
            LocalRule("a.one", "ip_host", r"^x (?P<v>IPV4)$", ["iosxe"]),
            LocalRule("a.all", "ip_host", r"^y (?P<v>IPV4)$"),
        )
        rules = manifest_rules(m)
        self.assertEqual([r.id for r in rules["iosxe"]], ["a.one"])
        self.assertEqual([r.id for r in rules["*"]], ["a.all"])
        self.assertEqual(manifest_rules(None), {})

    def test_invalid_rule_is_a_finding(self) -> None:
        m = self._manifest(
            LocalRule("bad.kind", "no_such_kind", r"^x (?P<v>IPV4)$"),
            LocalRule("bad.group", "ip_host", r"^x IPV4$"),
        )
        findings: list = []
        self.assertEqual(manifest_rules(m, findings), {})
        self.assertEqual([f.code for f in findings], ["MANIFEST_RULE"] * 2)
        self.assertTrue(all(f.severity == "error" for f in findings))

    def test_with_rules_extends_a_copy(self) -> None:
        base = dialects.get("iosxe")
        before = tuple(base.rules)
        extra = manifest_rules(
            self._manifest(
                LocalRule(
                    "t.nat",
                    "ip_host",
                    r"^ip nat inside source static IPV4 (?P<v>IPV4)\s*$",
                    ["iosxe"],
                )
            )
        )["iosxe"]
        ext = with_rules(base, extra)
        self.assertEqual(tuple(base.rules), before)
        self.assertIs(dialects.get("iosxe"), base)
        self.assertEqual(ext.name, base.name)
        text = "hostname r1\nip nat inside source static 10.0.0.5 198.51.100.7\n"
        ct = ConfigText(
            Store("startup", "startup", "startup"), "1", text, "iosxe", None, None
        )
        got = [(f.rule, f.value) for f in ext.parse(ct).facts if f.rule == "t.nat"]
        self.assertEqual(got, [("t.nat", "198.51.100.7")])
        self.assertFalse([f for f in base.parse(ct).facts if f.rule == "t.nat"])

    def test_sdwan_edge_rules_make_segment_facts(self) -> None:
        path = real_path(SDWAN)
        if path is None:
            self.skipTest("sdwan lab absent")
        m = manifest.find_for(path)
        assert m is not None
        if not m.rules:
            self.skipTest("sdwan manifest has no [[rule]]")
        a = analyse(read_real(path), m)
        by_rule: dict[str, set[tuple[str | None, str | None]]] = {}
        for f in a.facts.values():
            if f.rule.startswith("sdwan."):
                by_rule.setdefault(f.rule, set()).add((f.node_id, f.segment))
        self.assertIn(("75", "INET-201"), by_rule.get("sdwan.nat_static_global", set()))
        self.assertIn(("77", "INET-202"), by_rule.get("sdwan.nat_static_global", set()))
        # lab rework 32d9b62: per-provider NAT notes, loopback aliases and routes
        self.assertIn(("7", "INET-201"), by_rule.get("sdwan.fgt_nat_note_a", set()))
        self.assertIn(("8", "INET-202"), by_rule.get("sdwan.fgt_nat_note_b", set()))
        self.assertIn(("7", "INET-202"), by_rule.get("sdwan.fgt_lo_alias_nat", set()))
        self.assertIn(("8", "INET-201"), by_rule.get("sdwan.fgt_provider_route", set()))
        # route destinations captured as ip_host+mask never become protected
        # interface prefixes (10.100.0.0/16 would fence off every 10.100.x answer)
        shown = {str(n) for n in a.protected_prefixes}
        self.assertNotIn("10.100.0.0/16", shown)
        self.assertNotIn("10.200.0.0/16", shown)
        # without the manifest the rules are not applied
        plain = analyse(read_real(path), None)
        self.assertFalse(
            [f for f in plain.facts.values() if f.rule.startswith("sdwan.")]
        )


if __name__ == "__main__":
    unittest.main()
