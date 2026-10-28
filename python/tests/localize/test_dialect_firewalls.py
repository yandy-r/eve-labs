"""ASA / FortiOS / F5 tmsh dialects (T10): real-lab facts, stanza deletion,
host-name services, context rules.  Snippet contracts run through
``test_dialect_contract`` (``fixtures/snippets/{asa,fortios,f5tmsh}``)."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from evelab.common.codec import decode_blob
from evelab.localize.dialects import RenderCtx
from evelab.localize.dialects._common import (
    CLOUD_TOKEN,
    LABEL_TOKEN,
    VLAN_MENTION_TOKEN,
    ContextRule,
)
from evelab.localize.dialects.asa import ASA
from evelab.localize.dialects.base import ParsedConfig
from evelab.localize.dialects.f5tmsh import F5Tmsh
from evelab.localize.dialects.fortios import FortiOS
from evelab.localize.errors import ConflictError, LocalizeError
from evelab.localize.model import ConfigText, Fact, Node, Store, TextEdit
from tests.localize.labfiles import REPO, read_real

STORE = Store("startup", "startup", "startup")
SDWAN_CFGS = REPO / "labs/datacenter/cisco/vxlan_evpn_multi-site_sdwan_only_cfgs"
AZURE = REPO / "labs/cloud/azure/azure_asa_vpn.unl"
LAB1 = REPO / "labs/ccie/lab1-ei-v01.unl"

ASA_D, FGT_D, F5_D = ASA(), FortiOS(), F5Tmsh()


def ct(text: str, dialect: str) -> ConfigText:
    return ConfigText(STORE, "1", text, dialect, None, None)


def splice(text: str, edits: list[TextEdit]) -> str:
    for e in sorted(edits, key=lambda e: e.start, reverse=True):
        assert text[e.start : e.end] == e.old
        text = text[: e.start] + e.new + text[e.end :]
    return text


def facts(parsed: ParsedConfig, kind: str, rule: str | None = None) -> list[Fact]:
    return [
        f for f in parsed.facts if f.kind == kind and (rule is None or f.rule == rule)
    ]


def node(template: str, image: str = "") -> Node:
    return Node("1", "whatever", "qemu", template, image, "0", [])


def blob_text(lab: Path, node_id: str) -> str:
    raw = read_real(lab)
    for b in raw.config_blobs():
        if b.node_id == node_id and b.scope == "startup":
            dec = decode_blob(b.b64)
            assert dec is not None
            return dec.text
    raise AssertionError(f"no startup config for node {node_id} in {lab}")


def sidecars(pattern: str) -> list[Path]:
    paths = sorted(SDWAN_CFGS.glob(pattern))
    assert paths, f"no sidecars {pattern} in {SDWAN_CFGS}"
    return paths


# --------------------------------------------------------------------------- #
# selection
# --------------------------------------------------------------------------- #


class TestScoring(unittest.TestCase):
    def test_templates(self) -> None:
        self.assertGreaterEqual(ASA_D.score(node("asav", "asav-918-2"), ""), 70)
        self.assertGreaterEqual(
            FGT_D.score(node("fortinet", "fortinet-FGT-v7-build3744"), ""), 70
        )
        self.assertGreaterEqual(
            F5_D.score(node("bigip", "bigip-17.5.0-0.0.15"), ""), 70
        )
        self.assertEqual(ASA_D.score(node("fortinet"), ""), 0)

    def test_content_sniff_picks_the_right_one(self) -> None:
        texts = {
            "asa": blob_text(AZURE, "1"),
            "fortios": (SDWAN_CFGS / "10_b1-fgt1.txt").read_text(),
            "f5tmsh": (SDWAN_CFGS / "38_dc1-f5-1.txt").read_text(),
        }
        ds = {"asa": ASA_D, "fortios": FGT_D, "f5tmsh": F5_D}
        for want, text in texts.items():
            scores = {name: d.score(None, text) for name, d in ds.items()}
            self.assertEqual(max(scores, key=lambda k: scores[k]), want, scores)
            self.assertGreater(scores[want], 0)


# --------------------------------------------------------------------------- #
# ASA (real configs embedded in the labs)
# --------------------------------------------------------------------------- #


class TestAsaReal(unittest.TestCase):
    def setUp(self) -> None:
        self.text = blob_text(AZURE, "1")
        self.parsed = ASA_D.parse(ct(self.text, "asa"))

    def test_leading_newline_and_trailing_space(self) -> None:
        self.assertTrue(self.text.startswith("\n"))
        (outside,) = [
            f for f in facts(self.parsed, "ip_host") if f.value == "10.100.105.21"
        ]
        self.assertEqual(outside.iface, "gi0/0")
        assert outside.mask_span is not None
        line = self.text.splitlines()[outside.line - 1]
        self.assertTrue(line.endswith("255.255.255.0 "))
        # a prefix change keeps the trailing space
        edits = ASA_D.render(outside, "10.20.30.21", RenderCtx(self.text, 16))
        new = splice(self.text, edits)
        self.assertIn(" ip address 10.20.30.21 255.255.0.0 \n", new)

    def test_routes(self) -> None:
        gws = [f.value for f in facts(self.parsed, "ip_gateway")]
        self.assertEqual(
            gws,
            [
                "10.100.105.1",
                "10.100.104.1",
                "10.100.104.1",
                "169.254.21.2",
                "10.100.105.1",
            ],
        )
        dsts = [f.value for f in facts(self.parsed, "ip_route_dst")]
        self.assertNotIn("0.0.0.0", dsts)  # default route: gateway only
        self.assertIn("10.25.0.0", dsts)

    def test_object_names_are_flagged(self) -> None:
        obj = [f for f in facts(self.parsed, "peer_ip") if "object_name" in f.flags]
        self.assertEqual(
            {f.value for f in obj}, {"172.173.204.134", "169.254.0.2"}, obj
        )
        self.assertEqual(len(obj), 13)
        tunnel = facts(self.parsed, "peer_ip", "asa.tunnel_dst")
        self.assertEqual([f.value for f in tunnel], ["172.173.204.134", "169.254.0.2"])
        self.assertTrue(all("object_name" not in f.flags for f in tunnel))

    def test_secrets_and_checksum_note(self) -> None:
        secrets = [f.value for f in facts(self.parsed, "secret")]
        self.assertEqual(secrets.count("admin123"), 2)
        self.assertIn("4wmzNmmufPMg277VCDpcsryPHt", secrets)
        self.assertTrue(any("Cryptochecksum" in n for n in self.parsed.notes))
        self.assertFalse(
            any(f.line == len(self.text.splitlines()) - 1 for f in self.parsed.facts)
        )

    def test_no_tags_no_ipv6_in_real_asa(self) -> None:
        for node_id in ("1", "3"):
            parsed = ASA_D.parse(ct(blob_text(AZURE, node_id), "asa"))
            self.assertEqual(facts(parsed, "vlan_tag"), [])
            self.assertEqual(facts(parsed, "ipv6_literal"), [])

    def test_lab1_standby_addresses(self) -> None:
        parsed = ASA_D.parse(ct(blob_text(LAB1, "70"), "asa"))
        standby = facts(parsed, "ip_host", "asa.ip_standby")
        self.assertIn("10.20.10.2", [f.value for f in standby])
        # failover link addressing is not an interface address
        self.assertNotIn("192.168.1.1", [f.value for f in facts(parsed, "ip_host")])

    def test_route_line_deletion(self) -> None:
        self.assertTrue(ASA_D.supports_stanza_delete)
        (dst,) = [
            f for f in facts(self.parsed, "ip_route_dst") if f.value == "10.25.0.0"
        ]
        edits = ASA_D.delete_stanza(dst, RenderCtx(self.text))
        new = splice(self.text, edits)
        self.assertNotIn("route mgmt 10.25.0.0", new)
        self.assertEqual(len(new.splitlines()), len(self.text.splitlines()) - 1)
        with self.assertRaises(LocalizeError) as cm:
            ASA_D.delete_stanza(facts(self.parsed, "ip_host")[0], RenderCtx(self.text))
        self.assertEqual(cm.exception.code, "NO_STANZA")
        with self.assertRaises(ConflictError):
            ASA_D.delete_stanza(dst, RenderCtx("#" + self.text))


# --------------------------------------------------------------------------- #
# FortiOS (real sidecars)
# --------------------------------------------------------------------------- #


class TestFortiReal(unittest.TestCase):
    def test_every_vlanid_has_parent_and_tag(self) -> None:
        for path in sidecars("*fgt*.txt"):
            text = path.read_text()
            parsed = FGT_D.parse(ct(text, "fortios"))
            n_lines = len(re.findall(r"^\s*set vlanid \d+\s*$", text, re.M))
            tags = facts(parsed, "vlan_tag")
            with self.subTest(path=path.name):
                self.assertEqual(len(tags), n_lines)
                for f in tags:
                    self.assertIsNotNone(f.parent, f)
                    info = parsed.ifaces[f.iface or ""]
                    self.assertEqual(info.tag, int(f.value))
                    self.assertEqual(info.parent, f.parent)
                mgmt = parsed.ifaces["oob-mgmt"]
                self.assertEqual((mgmt.parent, mgmt.tag), ("port8", 3))

    def test_small_numbers_never_tags(self) -> None:
        for path in sidecars("*fgt*.txt"):
            text = path.read_text()
            parsed = FGT_D.parse(ct(text, "fortios"))
            lines = text.splitlines()
            for f in facts(parsed, "vlan_tag"):
                self.assertIn("set vlanid", lines[f.line - 1])

    def test_services_and_probes(self) -> None:
        text = (SDWAN_CFGS / "10_b1-fgt1.txt").read_text()
        parsed = FGT_D.parse(ct(text, "fortios"))
        self.assertEqual(
            [f.value for f in facts(parsed, "dns_server")], ["1.1.1.1", "1.0.0.1"]
        )
        probes = [f.value for f in facts(parsed, "probe_target")]
        self.assertEqual(probes, ["10.200.255.251", "1.1.1.1", "8.8.8.8"])
        # 1.1.1.1 as a probe is never a dns_server fact
        dns_lines = {f.line for f in facts(parsed, "dns_server")}
        self.assertTrue(
            all(f.line not in dns_lines for f in facts(parsed, "probe_target"))
        )
        peers = [f.value for f in facts(parsed, "peer_ip", "fortios.remote_gw")]
        self.assertEqual(
            peers, ["10.100.201.31", "10.100.202.31", "10.100.201.41", "10.100.202.41"]
        )
        self.assertEqual(len(facts(parsed, "secret")), 4)

    def test_labels_and_mentions(self) -> None:
        text = (SDWAN_CFGS / "10_b1-fgt1.txt").read_text()
        parsed = FGT_D.parse(ct(text, "fortios"))
        labels = [f.value for f in facts(parsed, "label_ref")]
        self.assertIn("EVE-MGMT-204", labels)
        self.assertNotIn("pnet0-trunk", labels)
        clouds = facts(parsed, "cloud_ref")
        self.assertTrue(clouds and all(f.value == "pnet0" for f in clouds))
        mentions = {f.value for f in facts(parsed, "vlan_mention")}
        self.assertEqual(mentions, {"3", "201", "202"})
        for f in (*clouds, *facts(parsed, "label_ref")):
            self.assertIn("cosmetic", f.flags)

    def test_static_route_stanza_deletion(self) -> None:
        text = (SDWAN_CFGS / "10_b1-fgt1.txt").read_text()
        parsed = FGT_D.parse(ct(text, "fortios"))
        (dst,) = [f for f in facts(parsed, "ip_route_dst") if f.value == "10.25.0.0"]
        edits = FGT_D.delete_stanza(dst, RenderCtx(text))
        (edit,) = edits
        self.assertTrue(edit.old.startswith("    edit 3\n"))
        self.assertTrue(edit.old.endswith("    next\n"))
        new = splice(text, edits)
        reparsed = FGT_D.parse(ct(new, "fortios"))
        self.assertEqual(
            [f.value for f in facts(reparsed, "ip_route_dst")],
            ["10.100.0.0", "192.168.0.0"],
        )
        # the gateway of the same stanza deletes the same span
        gw = next(
            f
            for f in facts(parsed, "ip_gateway")
            if f.line == dst.line + 1 and f.value == "10.100.204.1"
        )
        self.assertEqual(FGT_D.delete_stanza(gw, RenderCtx(text)), edits)
        # SD-WAN member gateways are not inside a static-route stanza
        member = facts(parsed, "ip_gateway")[0]
        self.assertEqual(member.value, "10.100.201.1")
        with self.assertRaises(LocalizeError) as cm:
            FGT_D.delete_stanza(member, RenderCtx(text))
        self.assertEqual(cm.exception.code, "NO_STANZA")

    def test_crlf_stanza_deletion(self) -> None:
        text = (
            "config router static\r\n    edit 1\r\n"
            "        set dst 10.1.0.0 255.255.0.0\r\n    next\r\nend\r\n"
        )
        parsed = FGT_D.parse(ct(text, "fortios"))
        (dst,) = facts(parsed, "ip_route_dst")
        new = splice(text, FGT_D.delete_stanza(dst, RenderCtx(text)))
        self.assertEqual(new, "config router static\r\nend\r\n")


# --------------------------------------------------------------------------- #
# F5 (real sidecars)
# --------------------------------------------------------------------------- #


class TestF5Real(unittest.TestCase):
    def test_real_sidecars(self) -> None:
        for path in sidecars("*f5*.txt"):
            text = path.read_text()
            parsed = F5_D.parse(ct(text, "f5tmsh"))
            with self.subTest(path=path.name):
                (mgmt,) = facts(parsed, "ip_host", "f5.mgmt_ip")
                self.assertTrue(mgmt.value.startswith("10.100.203."))
                self.assertEqual(mgmt.iface, "mgmt")
                self.assertEqual(
                    [f.value for f in facts(parsed, "ip_gateway", "f5.mgmt_route_gw")],
                    ["10.100.203.1"],
                )
                self.assertEqual(
                    [f.value for f in facts(parsed, "dns_server")],
                    ["1.1.1.1", "1.0.0.1"],
                )
                self.assertEqual(
                    [f.value for f in facts(parsed, "search_list")], ["netlab.local"]
                )
                self.assertEqual(
                    [f.value for f in facts(parsed, "domain")], ["netlab.local"]
                )
                self.assertEqual(
                    [f.value for f in facts(parsed, "ntp_server")], ["pool.ntp.org"]
                )
                self.assertEqual(facts(parsed, "vlan_tag"), [])  # untagged VLANs
                ext = parsed.ifaces["ext-tenant1"]
                self.assertEqual(
                    (ext.parent, ext.tag, ext.mode), ("1.1", None, "routed")
                )
                self.assertEqual(
                    [f.value for f in facts(parsed, "vlan_mention")], ["2"]
                )

    def test_ntp_hostname_render(self) -> None:
        text = (SDWAN_CFGS / "38_dc1-f5-1.txt").read_text()
        parsed = F5_D.parse(ct(text, "f5tmsh"))
        (ntp,) = facts(parsed, "ntp_server")
        ctx = RenderCtx(text)
        new = splice(text, F5_D.render(ntp, "ntp.example.net", ctx))
        self.assertIn("servers replace-all-with { ntp.example.net }", new)
        new = splice(text, F5_D.render(ntp, "10.9.9.9", ctx))
        self.assertIn("servers replace-all-with { 10.9.9.9 }", new)
        for bad in ("10.9.9.999", "bad host", "-x.example"):
            with self.subTest(bad=bad), self.assertRaises(LocalizeError) as cm:
                F5_D.render(ntp, bad, ctx)
            self.assertEqual(cm.exception.code, "BAD_VALUE")
        dns, _ = facts(parsed, "dns_server")
        self.assertEqual(F5_D.render(dns, dns.value, ctx), [])

    def test_eve_names_and_route_deletion(self) -> None:
        self.assertEqual(F5_D.eve_to_config("E1.2"), ["1.2"])
        self.assertEqual(F5_D.eve_to_config("Mgmt"), ["mgmt"])
        text = (SDWAN_CFGS / "38_dc1-f5-1.txt").read_text()
        parsed = F5_D.parse(ct(text, "f5tmsh"))
        (dst,) = facts(parsed, "ip_route_dst")
        new = splice(text, F5_D.delete_stanza(dst, RenderCtx(text)))
        self.assertNotIn("TENANT2-SERVERS", new)
        self.assertIn("tmsh create net route default gw", new)


# --------------------------------------------------------------------------- #
# context rules and tokens
# --------------------------------------------------------------------------- #


class TestContextTokens(unittest.TestCase):
    def tokens(self, token: str, text: str) -> list[str]:
        rule = ContextRule("t", r"^(?P<ctx>.*)$", token, "label_ref")
        return [text[s.start : s.end] for s in rule.tokens(text, 0, len(text))]

    def test_label_tokens(self) -> None:
        got = self.tokens(
            LABEL_TOKEN,
            "EVE-MGMT-204 arrives (VLAN 3) on pnet0-trunk via 10.100.204.1, AS 65101, "
            "host dc1-f5-1.netlab.local, sdwan- x-1 203-67 H1_INET1",
        )
        self.assertEqual(got, ["EVE-MGMT-204", "203-67", "H1_INET1"])

    def test_cloud_and_vlan_tokens(self) -> None:
        self.assertEqual(
            self.tokens(CLOUD_TOKEN, "pnet0-trunk, cloud1 and xpnet2, pnet3.5"),
            ["pnet0", "cloud1"],
        )
        self.assertEqual(
            self.tokens(
                VLAN_MENTION_TOKEN,
                "(VLAN 3) VLANs 1240-1243, (802.1Q trunk, VLAN 201) vlan 4 VLAN 5-6",
            ),
            ["3", "201", "4"],
        )

    def test_negatives(self) -> None:
        for d in (ASA_D, FGT_D, F5_D):
            for rule in d.context_rules:
                for neg in rule.negative:
                    with self.subTest(dialect=d.name, rule=rule.id, line=neg):
                        self.assertFalse(rule.matches_line(neg))

    def test_bad_context_rule(self) -> None:
        with self.assertRaises(ValueError):
            ContextRule("x", r"^(?P<nope>.*)$", LABEL_TOKEN, "label_ref")
        with self.assertRaises(ValueError):
            ContextRule("x", r"^(?P<ctx>.*)$", r"\w+", "label_ref")


class TestRuleCoverage(unittest.TestCase):
    """Every PatternRule of the three dialects is exercised by a snippet."""

    def test_coverage(self) -> None:
        from tests.localize.test_dialect_contract import (
            check_rule_coverage,
            load_snippets,
        )

        for d in (ASA_D, FGT_D, F5_D):
            with self.subTest(dialect=d.name):
                problems = check_rule_coverage(d, load_snippets(d.name))
                self.assertEqual(problems, [], "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
