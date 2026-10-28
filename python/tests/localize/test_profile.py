"""Tests for evelab.localize.profile (load/merge, answers save, secrets)."""

import os
import stat
import tempfile
import tomllib
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from evelab.localize import profile
from evelab.localize.profile import (
    BridgeProfile,
    Profile,
    ProfileError,
    ScenarioAnswer,
    SecretRef,
    SegmentAnswer,
)

FIXTURES = Path(__file__).parent / "fixtures" / "toml"
SITE = FIXTURES / "profile_site.toml"
OVERRIDE = FIXTURES / "profile_override.toml"
LAB = "0ca56f43-8e11-44ca-a007-a6dce53df987"


class TempDirCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def write(self, text: str, name: str = "p.toml") -> Path:
        path = self.dir / name
        path.write_text(text)
        return path


class LoadTests(unittest.TestCase):
    def test_site_fixture(self) -> None:
        p = profile.load_profile([SITE])
        self.assertEqual(p.site, "alice-homelab")
        self.assertEqual(p.sources, [SITE])
        self.assertEqual(
            p.bridges["pnet0"],
            BridgeProfile(roles=["mgmt"], mode="untagged-only", native_vlan=1),
        )
        self.assertEqual(p.bridges["pnet1"].mode, "trunk")
        self.assertEqual(p.roles["inet"], "pnet3")
        mgmt = p.segments["site.mgmt_a"]
        self.assertEqual(mgmt.bridge, "pnet1")
        self.assertEqual(mgmt.vlan, 20)
        self.assertEqual(mgmt.subnet, IPv4Network("192.168.20.0/24"))
        self.assertEqual(mgmt.gateway, IPv4Address("192.168.20.254"))
        self.assertEqual(mgmt.reserved, ["192.168.20.1-192.168.20.10"])
        junos = p.segments["junos.mgmt"]
        self.assertEqual(
            junos.split,
            {
                IPv4Network("10.100.241.0/24"): IPv4Network("192.168.48.0/25"),
                IPv4Network("10.100.243.0/24"): IPv4Network("192.168.48.128/25"),
            },
        )
        self.assertIsNone(junos.vlan)
        self.assertEqual(p.maps["dns"]["1.1.1.1"], "9.9.9.9")
        self.assertEqual(p.maps["domain"]["yandy.dev"], "")
        self.assertEqual(p.site_routes["site.mgmt_a"], [IPv4Network("192.168.0.0/16")])
        self.assertEqual(p.site_routes["site.mgmt_b"], [])
        self.assertIs(p.scenarios["azure_s2s"].enabled, False)
        self.assertEqual(p.secrets["azure_s2s.psk"], SecretRef(env="EVELOCAL_TEST_PSK"))
        self.assertTrue(p.policy.include_heuristic)
        self.assertTrue(p.policy.cosmetic_text)
        self.assertEqual(p.policy.legacy_scopes, "ask")
        self.assertEqual(p.labs[LAB].segments["INET-105"].bridge, "pnet3")

    def test_no_paths_gives_defaults(self) -> None:
        p = profile.load_profile([])
        self.assertEqual(p, Profile())
        self.assertTrue(p.policy.cosmetic_text)
        self.assertFalse(p.policy.include_heuristic)
        self.assertEqual(
            (p.policy.legacy_scopes, p.policy.subif_policy), ("leave", "rename")
        )

    def test_merge_later_wins(self) -> None:
        p = profile.load_profile([SITE, OVERRIDE])
        self.assertEqual(p.sources, [SITE, OVERRIDE])
        self.assertEqual(
            p.roles, {"mgmt": "pnet1", "inet": "pnet4", "trunk": "pnet1", "nat": "nat0"}
        )
        mgmt = p.segments["site.mgmt_a"]
        self.assertEqual(mgmt.vlan, 21)  # replaced
        self.assertEqual(mgmt.subnet, IPv4Network("192.168.20.0/24"))  # kept
        self.assertEqual(p.maps["dns"]["1.1.1.1"], "8.8.8.8")  # replaced
        self.assertEqual(p.maps["dns"]["10.100.51.11"], "192.168.1.53")  # kept
        self.assertEqual(p.site_routes["site.mgmt_a"], [])  # [] replaces the list
        self.assertFalse(p.policy.include_heuristic)
        self.assertEqual(p.policy.legacy_scopes, "ask")
        lab_seg = p.labs[LAB].segments["INET-105"]
        self.assertEqual((lab_seg.bridge, lab_seg.vlan), ("pnet3", 305))

    def test_merge_order_matters(self) -> None:
        p = profile.load_profile([OVERRIDE, SITE])
        self.assertEqual(p.roles["inet"], "pnet3")
        self.assertEqual(p.segments["site.mgmt_a"].vlan, 20)
        self.assertTrue(p.policy.include_heuristic)

    def test_loading_does_not_leak_between_calls(self) -> None:
        first = profile.load_profile([SITE, OVERRIDE])
        first.roles["mgmt"] = "changed"
        again = profile.load_profile([SITE])
        self.assertEqual(again.roles["mgmt"], "pnet1")

    def test_load_answers(self) -> None:
        self.assertEqual(profile.load_answers(SITE), profile.load_profile([SITE]))


class ValidationTests(TempDirCase):
    def rejects(self, text: str, pattern: str) -> None:
        with self.assertRaisesRegex(ProfileError, pattern):
            profile.load_profile([self.write(text)])

    def test_missing_and_invalid_file(self) -> None:
        with self.assertRaisesRegex(ProfileError, "cannot read"):
            profile.load_profile([self.dir / "nope.toml"])
        self.rejects("a = [", "invalid TOML")

    def test_unknown_keys(self) -> None:
        self.rejects("bogus = 1\n", "bogus: unknown key")
        self.rejects('[segments."a"]\nvlann = 3\n', r"segments\.a\.vlann: unknown key")
        self.rejects("[policy]\ncosmetic = true\n", "policy.cosmetic: unknown key")
        self.rejects('[bridges.pnet1]\nrole = ["mgmt"]\n', "unknown key")
        self.rejects('[labs."x"]\nbogus = 1\n', "unknown key")
        self.rejects('[secrets]\n"a.b" = { envv = "X" }\n', "unknown key")

    def test_errors_name_the_file(self) -> None:
        path = self.write("bogus = 1\n")
        with self.assertRaisesRegex(ProfileError, f"^{path}: bogus"):
            profile.load_profile([path])

    def test_error_in_second_file_is_attributed(self) -> None:
        good = self.write("site = 'a'\n", "good.toml")
        bad = self.write("bogus = 1\n", "bad.toml")
        with self.assertRaisesRegex(ProfileError, "bad.toml"):
            profile.load_profile([good, bad])

    def test_bad_values(self) -> None:
        cases = [
            ("schema = 2\n", "schema"),
            ('[segments."a"]\nvlan = 0\n', "below the minimum"),
            ('[segments."a"]\nvlan = 4095\n', "above the maximum"),
            ('[segments."a"]\nsubnet = "192.168.20.5/24"\n', "invalid IPv4 network"),
            ('[segments."a"]\ngateway = "300.1.1.1"\n', "invalid IPv4 address"),
            (
                '[segments."a"]\nsubnet = "10.0.0.0/24"\ngateway = "10.0.1.1"\n',
                "outside",
            ),
            ('[segments."a"]\nlabel = ""\n', "printable"),
            ('[segments."a"]\nlabel = "' + "x" * 65 + '"\n', "printable"),
            ('[segments."a"]\nlabel = "tab\\there"\n', "printable"),
            ('[segments."a"]\nreserved = ["10.0.0.9-10.0.0.1"]\n', "ends before"),
            ('[segments."a"]\nreserved = ["nonsense"]\n', "invalid address range"),
            ('[segments."a"]\ndhcp_pool = "x-y"\n', "invalid address range"),
            ('[segments."a"]\nbridge = "9bad"\n', "not a valid name"),
            ('[segments."a".split]\n"10.0.0.1/24" = "10.1.0.0/24"\n', "invalid IPv4"),
            ('[roles]\ndmz = "pnet1"\n', "unknown role"),
            ('[bridges.pnet1]\nmode = "access"\n', "mode"),
            ('[bridges.pnet1]\nroles = ["dmz"]\n', "dmz"),
            ("[policy]\nlegacy_scopes = 'maybe'\n", "legacy_scopes"),
            ("[policy]\ncosmetic_text = 'yes'\n", "true/false"),
            ('[site_routes]\n"a" = ["10.0.0.1/8"]\n', "invalid IPv4 network"),
            ('[map.dns]\n"1.1.1.1" = 9\n', "expected a string"),
            ('[map."bad kind"]\n"a" = "b"\n', "identifier"),
            ('[secrets]\n"a" = { env = "bad-name" }\n', "environment variable"),
            ('[scenarios.azure_s2s]\nenabled = "no"\n', "true/false"),
        ]
        for text, pattern in cases:
            with self.subTest(text):
                self.rejects(text, pattern)

    def test_unknown_bridge_reference(self) -> None:
        self.rejects('[roles]\nmgmt = "br-foo"\n', "neither a built-in bridge")
        self.rejects('[segments."a"]\nbridge = "foo"\n', "neither a built-in bridge")
        self.rejects(
            '[labs."x".segments."k"]\nbridge = "foo"\n', "neither a built-in bridge"
        )

    def test_declared_bridge_reference_ok(self) -> None:
        text = '[bridges.br-foo]\nroles = ["mgmt"]\n[roles]\nmgmt = "br-foo"\n'
        self.assertEqual(
            profile.load_profile([self.write(text)]).roles, {"mgmt": "br-foo"}
        )

    def test_bridge_declared_in_another_file(self) -> None:
        decl = self.write('[bridges.br-foo]\nmode = "trunk"\n', "a.toml")
        use = self.write('[segments."k"]\nbridge = "br-foo"\n', "b.toml")
        p = profile.load_profile([decl, use])
        self.assertEqual(p.segments["k"].bridge, "br-foo")
        with self.assertRaises(ProfileError):  # alone, the reference dangles
            profile.load_profile([use])

    def test_scenario_options_kept(self) -> None:
        p = profile.load_profile(
            [self.write("[scenarios.bgp_upstream]\nenabled = true\npeer_as = 65000\n")]
        )
        self.assertEqual(
            p.scenarios["bgp_upstream"], ScenarioAnswer(True, {"peer_as": 65000})
        )

    def test_scenario_without_enabled_is_unanswered(self) -> None:
        p = profile.load_profile([self.write("[scenarios.x]\nnode = '1'\n")])
        self.assertIsNone(p.scenarios["x"].enabled)
        self.assertIsNone(p.scenario_enabled("x"))


class ResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.p = profile.load_profile([SITE, OVERRIDE])

    def test_segment_answer_site_key(self) -> None:
        a = self.p.segment_answer("site.mgmt_a")
        self.assertEqual(a.vlan, 21)
        self.assertEqual(self.p.segment_answer("unknown.key"), SegmentAnswer())

    def test_segment_answer_lab_override_wins_fieldwise(self) -> None:
        site = profile.load_profile([SITE])
        extra = SegmentAnswer(vlan=999)
        site.labs[LAB].segments["site-key-segment"] = extra
        site.segments["site.x"] = SegmentAnswer(bridge="pnet2", vlan=5, label="L")
        merged = site.segment_answer("site.x", LAB, "site-key-segment")
        self.assertEqual(
            (merged.bridge, merged.vlan, merged.label), ("pnet2", 999, "L")
        )
        # other lab or no lab -> the site_key answer only
        self.assertEqual(
            site.segment_answer("site.x", "other", "site-key-segment").vlan, 5
        )
        self.assertEqual(site.segment_answer("site.x").vlan, 5)

    def test_role_bridge(self) -> None:
        self.assertEqual(self.p.role_bridge("inet"), "pnet4")
        self.assertIsNone(self.p.role_bridge("oob"))
        self.assertIsNone(self.p.role_bridge(None))

    def test_map_value(self) -> None:
        self.assertEqual(self.p.map_value("dns", "1.1.1.1"), "8.8.8.8")
        self.assertEqual(self.p.map_value("domain", "yandy.dev"), "")
        self.assertIsNone(self.p.map_value("dns", "4.4.4.4"))
        self.assertIsNone(self.p.map_value("ntp", "x"))

    def test_scenario_enabled_lab_override(self) -> None:
        p = profile.load_profile([SITE])
        self.assertIs(p.scenario_enabled("azure_s2s"), False)
        p.labs[LAB].scenarios["azure_s2s"] = ScenarioAnswer(enabled=True)
        self.assertIs(p.scenario_enabled("azure_s2s", LAB), True)
        self.assertIs(p.scenario_enabled("azure_s2s", "other"), False)
        self.assertIsNone(p.scenario_enabled("never_asked"))

    def test_bridge_allowed(self) -> None:
        self.assertTrue(self.p.bridge_allowed("pnet9"))
        self.assertTrue(self.p.bridge_allowed("nat0"))
        self.assertTrue(self.p.bridge_allowed("cloud3"))
        self.assertFalse(self.p.bridge_allowed("br0"))

    def test_parse_ip_range(self) -> None:
        a = IPv4Address
        self.assertEqual(
            profile.parse_ip_range("10.0.0.1-10.0.0.9"), (a("10.0.0.1"), a("10.0.0.9"))
        )
        self.assertEqual(
            profile.parse_ip_range("10.0.0.0/30"), (a("10.0.0.0"), a("10.0.0.3"))
        )
        self.assertEqual(
            profile.parse_ip_range("10.0.0.7"), (a("10.0.0.7"), a("10.0.0.7"))
        )
        with self.assertRaises(ValueError):
            profile.parse_ip_range("10.0.0.9-10.0.0.1")


class SecretTests(TempDirCase):
    def test_env_resolution(self) -> None:
        ref = SecretRef(env="EVELOCAL_TEST_PSK")
        self.assertEqual(ref.resolve({"EVELOCAL_TEST_PSK": "s3cret"}), "s3cret")
        self.assertIsNone(ref.resolve({}))
        self.assertIsNone(ref.resolve({"EVELOCAL_TEST_PSK": ""}))

    def test_inline_value_is_fallback(self) -> None:
        ref = SecretRef(env="X", value="typed")
        self.assertEqual(ref.resolve({}), "typed")
        self.assertEqual(ref.resolve({"X": "fromenv"}), "fromenv")

    def test_default_environ_is_os_environ(self) -> None:
        os.environ["EVELOCAL_TEST_PSK_2"] = "abc"
        self.addCleanup(os.environ.pop, "EVELOCAL_TEST_PSK_2")
        self.assertEqual(SecretRef(env="EVELOCAL_TEST_PSK_2").resolve(), "abc")

    def test_profile_secret_value(self) -> None:
        p = profile.load_profile([SITE])
        self.assertEqual(
            p.secret_value("azure_s2s.psk", {"EVELOCAL_TEST_PSK": "pw"}), "pw"
        )
        self.assertIsNone(p.secret_value("missing", {}))

    def test_repr_hides_value(self) -> None:
        self.assertNotIn("hunter2", repr(SecretRef(env="E", value="hunter2")))

    def test_inline_string_secret_loads_as_value(self) -> None:
        p = profile.load_profile([self.write('[secrets]\n"a.b" = "plain"\n')])
        self.assertEqual(p.secrets["a.b"], SecretRef(value="plain"))


class SaveTests(TempDirCase):
    def full(self) -> Profile:
        p = profile.load_profile([SITE, OVERRIDE])
        p.segments["site.inet_a"] = SegmentAnswer(
            bridge="pnet3",
            vlan=301,
            dhcp_pool="198.51.100.100-198.51.100.200",
            hosts={IPv4Address("10.0.0.5"): IPv4Address("192.168.0.5")},
            skip=False,
        )
        p.scenarios["bgp_upstream"] = ScenarioAnswer(True, {"peer_as": 65000})
        p.policy.subif_policy = "keep-name"
        return p

    def test_save_load_roundtrip(self) -> None:
        p = self.full()
        path = self.dir / "answers.toml"
        profile.save_answers(path, p)
        again = profile.load_profile([path])
        again.sources = []
        p.sources = []
        self.assertEqual(again, p)

    def test_saved_file_is_valid_toml_with_header(self) -> None:
        path = self.dir / "answers.toml"
        profile.save_answers(path, self.full())
        text = path.read_text()
        self.assertTrue(text.startswith("# eve-localize site answers"))
        tomllib.loads(text)

    def test_save_is_deterministic(self) -> None:
        a, b = self.dir / "a.toml", self.dir / "b.toml"
        profile.save_answers(a, self.full())
        profile.save_answers(b, self.full())
        self.assertEqual(a.read_bytes(), b.read_bytes())
        # and stable across a load/save cycle
        c = self.dir / "c.toml"
        profile.save_answers(c, profile.load_profile([a]))
        self.assertEqual(a.read_bytes(), c.read_bytes())

    def test_env_reference_written_but_never_its_resolved_value(self) -> None:
        env = {"EVELOCAL_TEST_PSK": "ENV-SECRET-VALUE"}
        p = profile.load_profile([SITE])
        self.assertEqual(p.secret_value("azure_s2s.psk", env), "ENV-SECRET-VALUE")
        path = self.dir / "answers.toml"
        profile.save_answers(path, p, include_secrets=True)
        text = path.read_text()
        self.assertIn('env = "EVELOCAL_TEST_PSK"', text)
        self.assertNotIn("ENV-SECRET-VALUE", text)

    def test_inline_secret_dropped_by_default(self) -> None:
        p = Profile()
        p.secrets["a.psk"] = SecretRef(value="TYPED-SECRET")
        p.secrets["b.psk"] = SecretRef(env="B_PSK", value="OTHER-SECRET")
        path = self.dir / "answers.toml"
        profile.save_answers(path, p)
        text = path.read_text()
        self.assertNotIn("SECRET", text)
        self.assertNotIn("a.psk", text)
        self.assertIn('env = "B_PSK"', text)

    def test_inline_secret_with_include_secrets_is_0600(self) -> None:
        p = Profile()
        p.secrets["a.psk"] = SecretRef(value="TYPED-SECRET")
        path = self.dir / "answers.toml"
        profile.save_answers(path, p, include_secrets=True)
        self.assertIn("TYPED-SECRET", path.read_text())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        again = profile.load_profile([path])
        self.assertEqual(again.secrets["a.psk"].value, "TYPED-SECRET")

    def test_to_dict_excludes_secrets_by_default(self) -> None:
        p = Profile()
        p.secrets["a"] = SecretRef(value="v")
        self.assertNotIn("secrets", profile.to_dict(p))
        self.assertIn("secrets", profile.to_dict(p, include_secrets=True))

    def test_empty_profile_roundtrip(self) -> None:
        path = self.dir / "empty.toml"
        profile.save_answers(path, Profile())
        self.assertEqual(profile.load_profile([path]), Profile())

    def test_defaults_not_written(self) -> None:
        data = profile.to_dict(Profile())
        self.assertEqual(data, {"schema": 1})

    def test_dumps_matches_saved_text(self) -> None:
        p = self.full()
        path = self.dir / "answers.toml"
        profile.save_answers(path, p)
        self.assertEqual(path.read_text(), profile.dumps(p))


if __name__ == "__main__":
    unittest.main()
