"""T15: manifest.generate() / manifest.check() on minilabs and the real labs.

Real labs are only read; leak injection works on a temp copy of a minilab.
"""

from __future__ import annotations

import tomllib
import unittest
import uuid
from dataclasses import replace
from functools import cache
from ipaddress import IPv4Network
from pathlib import Path

from evelab.common import codec
from evelab.common.unl import RawLab, splice
from evelab.localize import manifest as M
from evelab.localize.discover import analyse
from evelab.localize.manifest import Baseline, Manifest, Param
from evelab.localize.model import Analysis, Finding

from .labfiles import minilab_path, read_real, real_lab_paths

BAD = ("warn", "conflict", "blocker", "error")


def _load_text(text: str, lab_path: Path) -> Manifest:
    m = M.parse(tomllib.loads(text), source="test")
    m.path = M.manifest_path_for(lab_path)
    return m


def _codes(findings: list[Finding], severities=BAD) -> list[str]:
    return [f.code for f in findings if f.severity in severities]


def _without_generated(m: Manifest) -> dict:
    d = M.to_dict(m)
    d.pop("generated", None)
    return d


@cache
def _basic() -> tuple[RawLab, Analysis, str, Manifest, Analysis]:
    """basic minilab: (lab, unpinned analysis, draft text, manifest, pinned)."""
    path = minilab_path("basic")
    lab = RawLab.read(path)
    a = analyse(lab)
    text = M.generate(a)
    m = _load_text(text, path)
    return lab, a, text, m, analyse(lab, m)


def _copy(m: Manifest) -> Manifest:
    return M.parse(tomllib.loads(M.dumps(m)), source="copy")


def _inject(node_id: str, extra: str) -> RawLab:
    """Fresh temp copy of the basic minilab with ``extra`` appended to the startup
    config of ``node_id`` (same file name and sidecars, so the manifest applies)."""
    path = minilab_path("basic")
    lab = RawLab.read(path)
    blob = next(
        b for b in lab.config_blobs() if b.node_id == node_id and b.scope == "startup"
    )
    dec = codec.decode_blob(blob.b64)
    assert dec is not None
    new_b64 = codec.encode_blob(dec.text.replace("\nend", extra + "\nend", 1), dec)
    path.write_bytes(splice(lab.raw, [lab.blob_edit(blob, new_b64)]))
    return RawLab.read(path)


class TestHelpers(unittest.TestCase):
    def test_param_fact_kinds(self) -> None:
        def kinds(key: str, kind: str) -> set[str]:
            return set(M.param_fact_kinds(Param(key=key, kind=kind)))

        self.assertEqual(kinds("dns_public", "ipv4_list"), {"dns_server"})
        self.assertEqual(kinds("sla_targets", "host_list"), {"probe_target"})
        self.assertEqual(kinds("ntp_upstream", "ipv4_list"), {"ntp_server"})
        self.assertEqual(kinds("mgmt_routes", "prefix_list"), {"ip_route_dst"})
        self.assertEqual(kinds("search_extra", "domain"), {"domain", "search_list"})
        self.assertEqual(kinds("x", "ntp_server"), {"ntp_server"})
        self.assertEqual(kinds("x", "domain_list"), {"domain", "search_list"})
        self.assertIn("dns_server", kinds("whatever", "custom"))


class TestGenerateMinilab(unittest.TestCase):
    def test_draft_content(self) -> None:
        lab, a, text, m, _ = _basic()
        self.assertIn("DRAFT", text.splitlines()[1])
        self.assertEqual(m.lab, "basic.unl")
        self.assertEqual(m.lab_id, lab.lab_id)
        self.assertEqual(m.sidecar_dirs, ["basic_cfgs"])
        self.assertEqual(m.canonical_scope, "startup")
        self.assertIn("discover --write", m.generated)
        self.assertEqual([s.key for s in m.segments], ["MGMT-203", "INET-1240"])
        inet = m.segment("INET-1240")
        assert inet is not None
        self.assertEqual(inet.networks, ["3"])
        self.assertEqual(inet.baseline.vlan, 1240)
        self.assertEqual(inet.baseline.subnet, IPv4Network("172.31.240.0/24"))
        self.assertEqual(str(inet.baseline.gateway), "172.31.240.1")
        self.assertEqual(inet.label_template, "INET-{tag}")
        self.assertEqual(inet.expect, M.segment_counts(a, "INET-1240", inet.baseline))
        self.assertEqual(inet.expect["vlan"], 2)  # subif header + encapsulation
        mgmt = m.segment("MGMT-203")
        assert mgmt is not None
        self.assertIsNone(mgmt.baseline.vlan)  # untagged on the cloud wire
        self.assertEqual(mgmt.baseline.label, "EVE-MGMT-203")
        self.assertEqual(mgmt.expect["label"], 2)
        # configset alt-scheme -> legacy rows with policy leave
        self.assertEqual(
            sorted((x.segment, x.policy, str(x.baseline.subnet)) for x in m.legacy),
            [
                ("INET-1240", "leave", "172.31.241.0/24"),
                ("MGMT-203", "leave", "10.100.52.0/24"),
            ],
        )
        params = {p.key: p for p in m.params}
        self.assertEqual(params["dns"].baseline, ["10.100.51.2"])
        self.assertEqual(params["domain"].baseline, ["lab.example"])
        for p in m.params:
            self.assertEqual(p.expect, M.param_count(a, p))

    def test_generate_is_deterministic(self) -> None:
        _, a, text, _, _ = _basic()
        self.assertEqual(M.generate(a), text)

    def test_update_is_idempotent_and_keeps_decisions(self) -> None:
        _, _, _, m, pinned = _basic()
        prev = _copy(m)
        mgmt = prev.segment("MGMT-203")
        assert mgmt is not None
        mgmt.site_key = "site.mgmt_a"
        mgmt.role = "oob"
        mgmt.status = "CONFIGURABLE"
        mgmt.label_template = "EVE-MGMT-{octet3}"
        mgmt.expect["subnet"] = 999  # stale count is refreshed
        prev.protect = [IPv4Network("10.200.0.0/16")]
        prev.generic_labels = ["Net"]
        prev.outliers = [M.Outlier(scope="startup", node="4", note="x")]
        prev.scenarios = {"services": M.ScenarioPin(True, {"x": 1})}
        prev.params = [
            Param(key="dns_mgmt", kind="ipv4_list", baseline=["10.100.51.2"], expect=0)
        ]
        text = M.generate(pinned, prev)
        self.assertIn("discover --update", text)
        new = M.parse(tomllib.loads(text))
        seg = new.segment("MGMT-203")
        assert seg is not None
        self.assertEqual(seg.site_key, "site.mgmt_a")
        self.assertEqual(seg.role, "oob")
        self.assertEqual(seg.status, "CONFIGURABLE")
        self.assertEqual(seg.label_template, "EVE-MGMT-{octet3}")
        self.assertEqual(seg.expect["subnet"], 7)
        self.assertEqual(new.protect, prev.protect)
        self.assertEqual(new.generic_labels, ["Net"])
        self.assertEqual(new.outliers, prev.outliers)
        self.assertEqual(new.scenarios["services"].options, {"x": 1})
        keys = [p.key for p in new.params]
        self.assertEqual(keys[0], "dns_mgmt")  # kept, recounted
        self.assertEqual(new.params[0].expect, 5)
        self.assertNotIn("dns", keys)  # covered by dns_mgmt
        self.assertIn("ntp", keys)  # uncovered value appended
        # a second update changes nothing
        again = M.parse(tomllib.loads(M.generate(pinned, new)))
        self.assertEqual(_without_generated(again), _without_generated(new))

    def test_update_drops_unknown_segments(self) -> None:
        _, _, _, m, pinned = _basic()
        prev = _copy(m)
        prev.segments.append(M.ManifestSegment(key="GONE", networks=["77"]))
        text = M.generate(pinned, prev)
        self.assertIn("Dropped (no longer discovered): GONE", text)
        self.assertIsNone(M.parse(tomllib.loads(text)).segment("GONE"))


class TestCheckMinilab(unittest.TestCase):
    def test_fresh_draft_is_clean(self) -> None:
        _, _, _, m, pinned = _basic()
        self.assertTrue(pinned.pinned)
        self.assertEqual(_codes(M.check(pinned, m)), [])

    def test_unpinned(self) -> None:
        _, a, _, _, _ = _basic()
        found = M.check(a, None)
        self.assertEqual([(f.code, f.severity) for f in found], [("UNPINNED", "warn")])

    def test_stale_counts(self) -> None:
        _, _, _, m, pinned = _basic()
        bad = _copy(m)
        seg = bad.segment("INET-1240")
        assert seg is not None
        seg.expect["vlan"] += 1
        bad.params[0].expect = (bad.params[0].expect or 0) + 3
        found = M.check(pinned, bad)
        mism = [f for f in found if f.code == "COUNT_MISMATCH"]
        self.assertEqual(len(mism), 2)
        self.assertTrue(all(f.severity == "error" for f in mism))
        self.assertIn("segment:INET-1240", mism[0].refs)
        self.assertIn(f"param:{bad.params[0].key}", mism[1].refs)

    def test_not_at_baseline_and_localized_state(self) -> None:
        _, _, _, m, pinned = _basic()
        bad = _copy(m)
        seg = bad.segment("INET-1240")
        assert seg is not None
        seg.baseline = Baseline(
            label="INET-1240",
            vlan=1250,
            subnet=IPv4Network("172.31.250.0/24"),
            gateway=None,
        )
        found = M.check(pinned, bad)
        nab = [f for f in found if f.code == "NOT_AT_BASELINE"]
        self.assertEqual(len(nab), 1)
        self.assertIn("vlan 1250", nab[0].msg)
        self.assertIn("COUNT_MISMATCH", _codes(found))
        # the lab is "localized" to the discovered values (state.json): accepted
        cur = m.segment("INET-1240")
        assert cur is not None
        found = M.check(pinned, bad, localized={"INET-1240": cur.baseline})
        self.assertEqual(_codes(found), [])

    def test_legacy_baseline(self) -> None:
        _, _, _, m, pinned = _basic()
        bad = _copy(m)
        bad.legacy[0].baseline = replace(
            bad.legacy[0].baseline, subnet=IPv4Network("10.100.99.0/24")
        )
        found = M.check(pinned, bad)
        self.assertEqual(_codes(found), ["NOT_AT_BASELINE"])
        self.assertIn("legacy", found[0].msg)

    def test_param_missing_value(self) -> None:
        _, _, _, m, pinned = _basic()
        bad = _copy(m)
        bad.params[0].baseline.append("192.0.2.53")
        found = M.check(pinned, bad)
        self.assertIn("PARAM_MISSING", _codes(found))
        self.assertIn("192.0.2.53", found[-1].msg if found else "")

    def test_coverage(self) -> None:
        lab, _, _, m, _ = _basic()
        partial = _copy(m)
        partial.segments = [s for s in partial.segments if s.key != "INET-1240"]
        partial.legacy = [x for x in partial.legacy if x.segment != "INET-1240"]
        found = M.check(analyse(lab, partial), partial)
        cov = [f for f in found if f.code == "MANIFEST_COVERAGE"]
        self.assertEqual(len(cov), 1)
        self.assertIn("network:3", cov[0].refs)
        extra = _copy(m)
        extra.segments[0].networks.append("999")
        found = M.check(analyse(lab, extra), extra)
        self.assertTrue(
            any("999" in f.msg for f in found if f.code == "MANIFEST_COVERAGE")
        )

    def test_lab_id_and_name_mismatch(self) -> None:
        _, _, _, m, pinned = _basic()
        bad = _copy(m)
        bad.lab_id = str(uuid.uuid4())
        bad.lab = "other.unl"
        bad.path = m.path
        codes = _codes(M.check(pinned, bad))
        self.assertIn("MANIFEST_LAB_ID", codes)
        self.assertIn("MANIFEST_LAB", codes)

    def test_injected_old_values_leak(self) -> None:
        _, _, _, base, pinned = _basic()
        self.assertEqual(M.leak_scan(pinned, base), [])
        leaky = _inject(
            "1",
            "\nip host leak1 10.100.51.77\nip host lab.example 192.0.2.10",
        )
        m = _copy(base)
        m.path = M.manifest_path_for(leaky.path)
        a = analyse(leaky, m)
        found = M.check(a, m)
        leaks = [f for f in found if f.code == "LEAK"]
        self.assertEqual({f.severity for f in leaks}, {"warn"})
        seg_leak = [f for f in leaks if "segment:MGMT-203" in f.refs]
        self.assertEqual(len(seg_leak), 1)
        self.assertIn("10.100.51.77", seg_leak[0].msg)
        self.assertIn("node:1", seg_leak[0].refs)
        param_leak = [f for f in leaks if "params" in f.refs]
        self.assertEqual(len(param_leak), 1)
        self.assertIn("lab.example", param_leak[0].msg)
        # nothing else changed: no other error/warn
        self.assertEqual(set(_codes(found)), {"LEAK"})

    def test_unpinned_leak_scan_uses_discovered_subnets(self) -> None:
        leaky = _inject("1", "\nip host leak2 172.31.240.200")
        found = M.leak_scan(analyse(leaky), None)
        inet = [f for f in found if "segment:INET-1240" in f.refs]
        self.assertEqual(len(inet), 1)
        self.assertIn("172.31.240.200", inet[0].msg)
        # without params, service values inside the MGMT subnet are leaks too
        self.assertTrue(any("10.100.51.2 " in f.msg for f in found))


@cache
def _real(stem: str) -> tuple[Path, RawLab, Analysis, str, Manifest, Analysis] | None:
    for path in real_lab_paths():
        if path.stem == stem:
            lab = read_real(path)
            a = analyse(lab)
            text = M.generate(a)
            m = _load_text(text, path)
            return path, lab, a, text, m, analyse(lab, m)
    return None


class TestRealLabs(unittest.TestCase):
    """Draft -> pinned analysis -> check must be clean on every real lab."""

    def test_all_real_labs_roundtrip(self) -> None:
        paths = real_lab_paths()
        if not paths:
            self.skipTest("no real labs")
        for path in paths:
            with self.subTest(lab=path.stem):
                got = _real(path.stem)
                assert got is not None
                _, _, a, _, m, pinned = got
                self.assertTrue(pinned.pinned)
                # LEAK warnings are real gaps (NAT / ACL / comments) for the
                # author to resolve in T20; nothing else may be reported.
                self.assertEqual(
                    set(_codes(M.check(pinned, m))) - {"LEAK"}, set(), path.stem
                )
                has_clouds = any(n.is_cloud for n in a.networks.values())
                self.assertEqual(bool(M.check(a, None)), has_clouds)
                self.assertEqual(bool(m.segments), has_clouds)
                again = M.parse(tomllib.loads(M.generate(pinned, m)))
                self.assertEqual(_without_generated(again), _without_generated(m))

    def _get(self, stem: str):
        got = _real(stem)
        if got is None:
            self.skipTest(f"{stem} not present")
        return got

    def test_sdwan_baselines(self) -> None:
        _, _, _, _, m, _ = self._get("vxlan_evpn_multi-site_sdwan_only")
        self.assertEqual(
            [s.key for s in m.segments],
            ["TRUNK", "MGMT-204", "MGMT-203", "INET-201", "INET-202"],
        )
        mgmt = m.segment("MGMT-203")
        assert mgmt is not None
        self.assertEqual(mgmt.networks, ["74", "76", "91", "54", "55", "165"])
        self.assertEqual(
            (mgmt.baseline.label, mgmt.baseline.vlan, str(mgmt.baseline.subnet)),
            ("EVE-MGMT-203", 2, "10.100.203.0/24"),
        )
        self.assertEqual(str(mgmt.baseline.gateway), "10.100.203.1")
        trunk = m.segment("TRUNK")
        assert trunk is not None
        self.assertEqual(sorted(trunk.carries), ["MGMT-203", "MGMT-204"])
        self.assertEqual(trunk.baseline.subnet, None)
        self.assertEqual(m.canonical_scope, "sdwan-vxlan-evpn")
        self.assertEqual(m.sidecar_dirs, ["vxlan_evpn_multi-site_sdwan_only_cfgs"])
        dns = next(p for p in m.params if p.key == "dns")
        self.assertEqual(dns.baseline, ["1.1.1.1", "1.0.0.1"])

    def test_junos_mgmt(self) -> None:
        _, _, _, _, m, _ = self._get("vxlan_evpn_multi-site_junos")
        mgmt = m.segment("MGMT")
        assert mgmt is not None
        self.assertEqual(str(mgmt.baseline.subnet), "10.100.240.0/20")
        self.assertEqual(str(mgmt.baseline.gateway), "10.100.255.254")
        self.assertEqual(mgmt.expect["subnet"], 16)
        self.assertEqual(mgmt.expect["gateway"], 16)

    def test_backbone_legacy(self) -> None:
        _, _, _, text, m, _ = self._get("vxlan_evpn_multi-site_with_backbone")
        mgmt = m.segment("MGMT-203")
        assert mgmt is not None
        self.assertEqual(
            (mgmt.baseline.vlan, str(mgmt.baseline.subnet), str(mgmt.baseline.gateway)),
            (203, "172.21.203.0/24", "172.21.203.254"),
        )
        self.assertEqual(m.canonical_scope, "vxlan-dmvpn-backbone")
        legacy = [
            (x.segment, x.baseline.vlan, str(x.baseline.subnet)) for x in m.legacy
        ]
        self.assertEqual(
            legacy,
            [
                ("MGMT-203", 1103, "10.100.103.0/24"),
                ("MGMT-203", None, "10.100.103.0/24"),
            ],
        )
        self.assertIn("MERGE_HINT", text)  # discovery notes in the header
        self.assertIn("TRUNK-204-1102", text)  # carried-only segment noted

    def test_lab1_protected_values_not_params(self) -> None:
        _, _, _, _, m, _ = self._get("lab1-ei-v01")
        values = {v for p in m.params for v in p.baseline}
        self.assertIn("34.202.215.187", values)
        self.assertNotIn("27.27.27.27", values)  # simulated internet: protected


if __name__ == "__main__":
    unittest.main()
