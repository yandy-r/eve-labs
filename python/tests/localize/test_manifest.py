"""Tests for evelab.localize.manifest (schema, strict loader, find_for, serialiser)."""

import copy
import tempfile
import tomllib
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from evelab.localize import manifest
from evelab.localize.manifest import Manifest, ManifestError

FIXTURES = Path(__file__).parent / "fixtures" / "toml"
LAB_ID = "2fd99c11-2334-45b3-ac61-ee23ab5c9d38"


def base_doc() -> dict[str, object]:
    return {
        "schema": 1,
        "lab": "x.unl",
        "lab_id": LAB_ID,
        "segment": [{"key": "MGMT", "networks": ["1", "2"]}],
    }


def parse_doc(doc: dict[str, object]) -> Manifest:
    return manifest.parse(doc, source="test.toml")


class LoadTests(unittest.TestCase):
    def test_backbone_fixture(self) -> None:
        m = manifest.load(FIXTURES / "manifest_backbone.toml")
        self.assertEqual(m.path, FIXTURES / "manifest_backbone.toml")
        self.assertEqual(m.lab_id, LAB_ID)
        self.assertEqual(m.canonical_scope, "vxlan-dmvpn-backbone")
        self.assertEqual(
            m.protect, [IPv4Network("10.200.0.0/16"), IPv4Network("169.0.0.0/8")]
        )
        self.assertEqual(m.nodes["29"].dialect, "f5tmsh")
        self.assertEqual(len(m.sidecar_map), 1)
        mgmt = m.segment("MGMT")
        assert mgmt is not None
        self.assertEqual(mgmt.site_key, "site.mgmt_a")
        self.assertEqual(mgmt.role, "mgmt")
        self.assertEqual(mgmt.networks, ["74", "76", "91"])
        self.assertEqual(mgmt.baseline.vlan, 203)
        self.assertEqual(mgmt.baseline.subnet, IPv4Network("172.21.203.0/24"))
        self.assertEqual(mgmt.baseline.gateway, IPv4Address("172.21.203.254"))
        self.assertEqual(
            mgmt.expect, {"vlan": 41, "subnet": 92, "gateway": 18, "label": 30}
        )
        trunk = m.segment("TRUNK")
        assert trunk is not None
        self.assertEqual(trunk.status, "CARRIER")
        self.assertEqual(trunk.carries, ["MGMT", "INET-201"])
        self.assertIsNone(trunk.site_key)
        self.assertEqual(m.merges[0].units, ["204-31", "trunk:204"])
        self.assertEqual(m.legacy[0].segment, "MGMT")
        self.assertEqual(m.legacy[0].baseline.vlan, 1103)
        self.assertEqual(m.outliers[0].node, "74")
        self.assertEqual(m.label_values[0].fields["subnet"], "192.168.13.0/24")
        self.assertTrue(m.scenario_enabled("azure_s2s"))
        self.assertFalse(m.scenario_enabled("bgp_upstream"))
        self.assertFalse(m.scenario_enabled("nope"))
        self.assertEqual(m.scenarios["azure_s2s"].options, {"node": "1"})
        self.assertEqual(m.scenarios["bgp_upstream"].options["peer_group"], "HOME")
        dns = m.param("dns_public")
        assert dns is not None
        self.assertEqual(dns.baseline, ["1.1.1.1", "1.0.0.1"])
        self.assertEqual(dns.expect, 46)
        ntp = m.param("ntp_upstream")
        assert ntp is not None
        self.assertEqual((ntp.baseline, ntp.group), (["34.202.215.187"], "advanced"))
        self.assertEqual(m.rules[0].dialects, ["fortios"])
        self.assertEqual(m.segment_for_network("25"), m.segment("INET-201"))
        self.assertIsNone(m.segment_for_network("9999"))

    def test_minimal_fixture(self) -> None:
        m = manifest.load(FIXTURES / "manifest_minimal.toml")
        self.assertEqual(m.generic_labels, ["Net"])
        self.assertEqual(m.segments[0].status, "LABEL_ONLY")
        self.assertEqual(m.subif_policy, "rename")
        self.assertEqual(m.protect, [])

    def test_missing_file(self) -> None:
        with self.assertRaisesRegex(ManifestError, "cannot read"):
            manifest.load(FIXTURES / "nope.toml")

    def test_invalid_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.localize.toml"
            path.write_text("schema = [")
            with self.assertRaisesRegex(ManifestError, "invalid TOML"):
                manifest.load(path)

    def test_errors_are_localize_errors(self) -> None:
        from evelab.localize.errors import LocalizeError

        self.assertTrue(issubclass(ManifestError, LocalizeError))
        self.assertEqual(ManifestError.code, "MANIFEST")


class StrictnessTests(unittest.TestCase):
    def assert_rejects(self, doc: dict[str, object], pattern: str) -> None:
        with self.assertRaisesRegex(ManifestError, pattern):
            parse_doc(doc)

    def test_valid_base(self) -> None:
        parse_doc(base_doc())

    def test_unknown_top_level_key_with_suggestion(self) -> None:
        doc = base_doc()
        doc["generic_label"] = []
        self.assert_rejects(doc, r"generic_label: unknown key")
        doc2 = base_doc()
        doc2["canonical_scop"] = "x"
        self.assert_rejects(doc2, r"did you mean 'canonical_scope'")

    def test_unknown_nested_keys(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = [
            ("segment[0]", {"colour": "red"}),
            ("segment[0].baseline", {"mtu": 1500}),
        ]
        for where, extra in cases:
            with self.subTest(where):
                doc = base_doc()
                seg = doc["segment"][0]  # type: ignore[index]
                if "baseline" in where:
                    seg["baseline"] = extra
                else:
                    seg.update(extra)
                self.assert_rejects(doc, "unknown key")

    def test_unknown_expect_param(self) -> None:
        doc = base_doc()
        doc["segment"][0]["expect"] = {"mtu": 1}  # type: ignore[index]
        self.assert_rejects(doc, "segment\\[0\\].expect.mtu: unknown key")

    def test_unknown_keys_in_other_tables(self) -> None:
        for table, row in [
            ("merge", {"units": ["a", "b"], "x": 1}),
            ("legacy", {"segment": "MGMT", "scopes": ["s"], "x": 1}),
            ("outlier", {"scope": "s", "node": "1", "x": 1}),
            ("label_value", {"textobject": "1", "fields": {"a": "b"}, "x": 1}),
            ("param", {"key": "k", "kind": "ipv4", "x": 1}),
            ("rule", {"id": "r", "kind": "k", "pattern": "x", "x": 1}),
        ]:
            with self.subTest(table):
                doc = base_doc()
                doc[table] = [row]
                self.assert_rejects(doc, "unknown key")

    def test_unknown_node_key(self) -> None:
        doc = base_doc()
        doc["nodes"] = {"1": {"dialekt": "ios"}}
        self.assert_rejects(doc, "nodes.1.dialekt: unknown key")

    def test_schema(self) -> None:
        for bad in (None, 2, "1"):
            doc = base_doc()
            if bad is None:
                del doc["schema"]
            else:
                doc["schema"] = bad
            with self.subTest(bad), self.assertRaises(ManifestError):
                parse_doc(doc)

    def test_lab_id_must_be_uuid(self) -> None:
        doc = base_doc()
        doc["lab_id"] = "not-a-uuid"
        self.assert_rejects(doc, "not a UUID")

    def test_required_keys(self) -> None:
        for key in ("lab", "lab_id"):
            doc = base_doc()
            del doc[key]
            with self.subTest(key):
                self.assert_rejects(doc, f"{key}: required")
        doc = base_doc()
        del doc["segment"][0]["networks"]  # type: ignore[index]
        self.assert_rejects(doc, "networks")

    def test_type_errors(self) -> None:
        doc = base_doc()
        doc["segment"][0]["networks"] = [1, 2]  # type: ignore[index]
        self.assert_rejects(doc, r"networks\[0\]: expected a string")
        doc = base_doc()
        doc["generic_labels"] = "x"
        self.assert_rejects(doc, "expected an array of strings")
        doc = base_doc()
        doc["segment"] = {"key": "A"}
        self.assert_rejects(doc, "expected an array of tables")

    def test_bad_enumerations(self) -> None:
        doc = base_doc()
        doc["segment"][0]["role"] = "dmz"  # type: ignore[index]
        self.assert_rejects(doc, "role: 'dmz' is not one of")
        doc = base_doc()
        doc["segment"][0]["status"] = "weird"  # type: ignore[index]
        self.assert_rejects(doc, "status")
        doc = base_doc()
        doc["subif_policy"] = "delete"
        self.assert_rejects(doc, "subif_policy")
        doc = base_doc()
        doc["legacy"] = [{"segment": "MGMT", "scopes": ["s"], "policy": "x"}]
        self.assert_rejects(doc, "policy")

    def test_bad_values(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = [
            ("protect", {"protect": ["10.0.0.1/8"]}, "invalid IPv4 network"),
            ("protect-v6", {"protect": ["fe80::/10"]}, "invalid IPv4 network"),
            ("abs-sidecar", {"sidecar_dirs": ["/etc"]}, "relative path"),
            ("dotdot", {"sidecar_dirs": ["../x"]}, "relative path"),
            ("abs-lab", {"lab": "/x.unl"}, "relative path"),
            ("sidecar_map", {"sidecar_map": {"a.txt": "x"}}, "numeric"),
            ("node-id", {"nodes": {"x": {"dialect": "ios"}}}, "numeric"),
            ("scn-id", {"scenarios": {"1bad": {"enabled": True}}}, "scenario id"),
        ]
        for name, extra, pattern in cases:
            with self.subTest(name):
                doc = base_doc()
                doc.update(extra)
                self.assert_rejects(doc, pattern)

    def test_bad_segment_values(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = [
            ("key", {"key": "has space"}, "identifier"),
            ("net-id", {"networks": ["x"]}, "numeric"),
            ("net-dup", {"networks": ["1", "1"]}, "duplicate network"),
            ("net-empty", {"networks": []}, "at least 1"),
            ("vlan", {"baseline": {"vlan": 4095}}, "above the maximum"),
            ("vlan-bool", {"baseline": {"vlan": True}}, "expected an integer"),
            ("subnet", {"baseline": {"subnet": "10.0.0.1/24"}}, "invalid IPv4"),
            (
                "gw",
                {"baseline": {"subnet": "10.0.0.0/24", "gateway": "10.0.1.1"}},
                "outside",
            ),
            ("expect-neg", {"expect": {"vlan": -1}}, "below the minimum"),
            ("site_key", {"site_key": "bad key"}, "identifier"),
        ]
        for name, extra, pattern in cases:
            with self.subTest(name):
                doc = base_doc()
                doc["segment"][0].update(extra)  # type: ignore[index]
                self.assert_rejects(doc, pattern)

    def test_unknown_references(self) -> None:
        doc = base_doc()
        doc["segment"][0]["carries"] = ["GHOST"]  # type: ignore[index]
        self.assert_rejects(doc, "carries unknown segment 'GHOST'")
        doc = base_doc()
        doc["segment"][0]["carries"] = ["MGMT"]  # type: ignore[index]
        self.assert_rejects(doc, "carries itself")
        doc = base_doc()
        doc["legacy"] = [{"segment": "GHOST", "scopes": ["s"]}]
        self.assert_rejects(doc, "legacy refers to unknown segment")
        doc = base_doc()
        doc["label_value"] = [
            {"textobject": "1", "segment": "GHOST", "fields": {"a": "b"}}
        ]
        self.assert_rejects(doc, "label_value 1 refers to unknown segment")

    def test_duplicates(self) -> None:
        doc = base_doc()
        segs = doc["segment"]
        assert isinstance(segs, list)
        segs.append({"key": "MGMT", "networks": ["9"]})
        self.assert_rejects(doc, "duplicate segment key")
        doc = base_doc()
        segs = doc["segment"]
        assert isinstance(segs, list)
        segs.append({"key": "OTHER", "networks": ["2"]})
        self.assert_rejects(doc, "network 2 is in both")
        doc = base_doc()
        doc["param"] = [{"key": "k", "kind": "a"}, {"key": "k", "kind": "a"}]
        self.assert_rejects(doc, "duplicate \\[\\[param\\]\\]")
        doc = base_doc()
        rule = {"id": "r", "kind": "k", "pattern": "x"}
        doc["rule"] = [rule, dict(rule)]
        self.assert_rejects(doc, "duplicate \\[\\[rule\\]\\]")

    def test_bad_rule_pattern(self) -> None:
        doc = base_doc()
        doc["rule"] = [{"id": "r", "kind": "k", "pattern": "(unclosed"}]
        self.assert_rejects(doc, "invalid regular expression")

    def test_merge_needs_two_units(self) -> None:
        doc = base_doc()
        doc["merge"] = [{"units": ["only"]}]
        self.assert_rejects(doc, "at least 2")

    def test_param_baseline_type(self) -> None:
        doc = base_doc()
        doc["param"] = [{"key": "k", "kind": "a", "baseline": [1]}]
        self.assert_rejects(doc, "baseline")
        doc["param"] = [{"key": "k", "kind": "a", "group": "weird"}]
        self.assert_rejects(doc, "group")

    def test_label_value_needs_fields(self) -> None:
        doc = base_doc()
        doc["label_value"] = [{"textobject": "1", "fields": {}}]
        self.assert_rejects(doc, "at least one field")

    def test_error_names_source(self) -> None:
        doc = base_doc()
        doc["bogus"] = 1
        with self.assertRaisesRegex(ManifestError, "^test.toml: bogus: unknown key"):
            parse_doc(doc)


class SerialiseTests(unittest.TestCase):
    def test_fixture_roundtrip(self) -> None:
        for name in ("manifest_backbone.toml", "manifest_minimal.toml"):
            with self.subTest(name):
                original = manifest.load(FIXTURES / name)
                text = manifest.dumps(original, header="generated by test")
                again = manifest.parse(tomllib.loads(text))
                again.path = original.path
                self.assertEqual(again, original)
                self.assertEqual(
                    manifest.dumps(again, header="generated by test"), text
                )

    def test_default_omissions(self) -> None:
        m = parse_doc(base_doc())
        data = manifest.to_dict(m)
        self.assertEqual(set(data), {"schema", "lab", "lab_id", "segment"})

    def test_dumps_does_not_mutate(self) -> None:
        m = manifest.load(FIXTURES / "manifest_backbone.toml")
        before = copy.deepcopy(m)
        manifest.dumps(m)
        self.assertEqual(m, before)


LAB_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<lab name="x" id="{lab_id}" version="1" scripttimeout="300"><topology/></lab>\n'
)


class FindForTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def write_lab(self, lab_id: str = LAB_ID, name: str = "x.unl") -> Path:
        path = self.dir / name
        path.write_text(LAB_XML.format(lab_id=lab_id))
        return path

    def write_manifest(self, lab: str = "x.unl", lab_id: str = LAB_ID) -> Path:
        path = self.dir / "x.localize.toml"
        path.write_text(
            f'schema = 1\nlab = "{lab}"\nlab_id = "{lab_id}"\n'
            '[[segment]]\nkey = "A"\nnetworks = ["1"]\n'
        )
        return path

    def test_paths(self) -> None:
        lab = Path("/a/b/x.unl")
        self.assertEqual(manifest.manifest_path_for(lab), Path("/a/b/x.localize.toml"))
        self.assertEqual(
            manifest.draft_path_for(lab), Path("/a/b/x.localize.toml.draft")
        )

    def test_no_manifest(self) -> None:
        self.assertIsNone(manifest.find_for(self.write_lab()))

    def test_draft_is_ignored(self) -> None:
        lab = self.write_lab()
        manifest.draft_path_for(lab).write_text("schema = 1\n")
        self.assertIsNone(manifest.find_for(lab))

    def test_found(self) -> None:
        lab = self.write_lab()
        self.write_manifest()
        found = manifest.find_for(lab)
        assert found is not None
        self.assertEqual(found.segments[0].key, "A")
        self.assertEqual(found.path, self.dir / "x.localize.toml")

    def test_lab_id_mismatch_is_ignored(self) -> None:
        lab = self.write_lab(lab_id="66a315e7-90d2-492f-bb7c-9d6b395e5f8d")
        self.write_manifest()
        self.assertIsNone(manifest.find_for(lab))

    def test_lab_name_mismatch_raises(self) -> None:
        lab = self.write_lab()
        self.write_manifest(lab="other.unl")
        with self.assertRaisesRegex(ManifestError, "does not name x.unl"):
            manifest.find_for(lab)

    def test_invalid_manifest_raises(self) -> None:
        lab = self.write_lab()
        (self.dir / "x.localize.toml").write_text("schema = 1\nbogus = 1\n")
        with self.assertRaises(ManifestError):
            manifest.find_for(lab)

    def test_unreadable_lab_id_keeps_manifest(self) -> None:
        lab = self.dir / "x.unl"
        lab.write_text("not xml")
        self.write_manifest()
        self.assertIsNotNone(manifest.find_for(lab))
        self.assertIsNone(manifest.read_lab_id(lab))

    def test_read_lab_id(self) -> None:
        self.assertEqual(manifest.read_lab_id(self.write_lab()), LAB_ID)
        self.assertIsNone(manifest.read_lab_id(self.dir / "missing.unl"))

    def test_matches_lab_id_case_insensitive(self) -> None:
        m = parse_doc(base_doc())
        self.assertTrue(m.matches_lab_id(LAB_ID.upper()))
        self.assertFalse(m.matches_lab_id("0ca56f43-8e11-44ca-a007-a6dce53df987"))


# generate() / check() are tested in test_manifest_check.py (T15).


if __name__ == "__main__":
    unittest.main()
