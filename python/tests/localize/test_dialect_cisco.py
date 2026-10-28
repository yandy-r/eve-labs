"""Cisco dialects (T9): ios, iosxe, nxos.

The generic contract (``test_dialect_contract``) already runs every snippet in
``fixtures/snippets/{ios,iosxe,nxos}``.  This module adds:

* rule coverage (every fact rule is exercised by a snippet of its family);
* selection by template / image / content, never by node name;
* targeted behaviour: banners, implicit ``vlan_db``, orphan blocks, NX-OS
  ``mgmt0`` + ``vrf context management``, ``log_server`` validation;
* a sweep over every Cisco config of the real labs (decoded through
  ``evelab.common.unl`` + ``evelab.common.codec``; read-only).
"""

from __future__ import annotations

import re
import textwrap
import unittest
from functools import cache

from evelab.common.codec import decode_blob
from evelab.common.textutil import VlanList
from evelab.localize import dialects
from evelab.localize.dialects import RenderCtx
from evelab.localize.dialects.base import RuleDialect
from evelab.localize.dialects.ios import LOG_SERVER, ios_rules
from evelab.localize.errors import LocalizeError
from evelab.localize.model import CORE_FACT_KINDS, ConfigText, Node, Store

from .labfiles import read_real, real_lab_paths
from .test_dialect_contract import (
    DialectContractMixin,
    load_snippets,
    make_ct,
)

CISCO = ("ios", "iosxe", "nxos")
TEMPLATE_DIALECT = {
    "iol": "ios",
    "vios": "ios",
    "viosl2": "ios",
    "c8000v": "iosxe",
    "csr1000vng": "iosxe",
    "nxosv9k": "nxos",
}


def node(template: str = "", image: str = "", name: str = "R1") -> Node:
    return Node("1", name, "qemu", template, image, "1", [])


def parse(dialect: str, text: str):
    return dialects.get(dialect).parse(make_ct(text, dialect))


@cache
def real_cisco_configs() -> tuple[tuple[str, str, Node, str], ...]:
    """(lab stem, scope, node, text) for every Cisco node config in labs/."""
    out: list[tuple[str, str, Node, str]] = []
    for path in real_lab_paths():
        lab = read_real(path)
        nodes = lab.node_models()
        for blob in lab.config_blobs():
            n = nodes.get(blob.node_id)
            if n is None or n.template not in TEMPLATE_DIALECT:
                continue
            decoded = decode_blob(blob.b64)
            if decoded is None:
                continue
            out.append((path.stem, blob.scope, n, decoded.text))
    return tuple(out)


def real_config(stem: str, scope: str, node_name: str) -> tuple[Node, str]:
    for s, sc, n, text in real_cisco_configs():
        if s == stem and sc == scope and n.name == node_name:
            return n, text
    raise unittest.SkipTest(f"real config {stem} {scope} {node_name} not present")


# --------------------------------------------------------------------------- #
# contract (strict: snippets required)
# --------------------------------------------------------------------------- #


class TestIosContract(DialectContractMixin, unittest.TestCase):
    dialect_name = "ios"
    require_snippets = True


class TestIosxeContract(DialectContractMixin, unittest.TestCase):
    dialect_name = "iosxe"
    require_snippets = True


class TestNxosContract(DialectContractMixin, unittest.TestCase):
    dialect_name = "nxos"
    require_snippets = True
    require_rule_coverage = True


class TestRuleCoverage(unittest.TestCase):
    def test_ios_family_rules_all_exercised(self) -> None:
        """ios and iosxe share one rule table: the union of snippets covers it."""
        hit: set[str] = set()
        for name in ("ios", "iosxe"):
            for sn in load_snippets(name):
                for f in sn.expected.get("facts", []):
                    hit.add(str(f["rule"]).split(".", 1)[1])
        missing = [
            r.id for r in ios_rules("x") if r.kind and r.id.split(".", 1)[1] not in hit
        ]
        self.assertEqual(missing, [])

    def test_snippets_come_from_real_labs(self) -> None:
        for name in CISCO:
            for sn in load_snippets(name):
                with self.subTest(snippet=f"{name}/{sn.name}"):
                    self.assertIn("source", sn.expected)
                    if "synthetic" in sn.text:
                        self.assertIn("synthetic", str(sn.expected["source"]))


# --------------------------------------------------------------------------- #
# selection
# --------------------------------------------------------------------------- #


class TestSelection(unittest.TestCase):
    def test_by_template_and_image(self) -> None:
        cases = {
            ("iol", ""): "ios",
            (
                "iol",
                "i86bi_linux_l2-adventerprisek9-ms.SSA.high_iron_20190423.bin",
            ): "ios",
            ("vios", "vios-adventerprisek9-m.spa.159-3.m6"): "ios",
            ("viosl2", "viosl2-adventerprisek9-m.ssa.high_iron_20200929"): "ios",
            ("c8000v", "c8000v-17.11.01a"): "iosxe",
            ("csr1000vng", "csr1000vng-universalk9.17.03.06.Amsterdam"): "iosxe",
            ("nxosv9k", "nxosv9k-9300v-10.3.3.F"): "nxos",
            ("", "nxosv9k-9500v-10.3.3.F"): "nxos",
            ("", "c8000v-17.11.01a"): "iosxe",
        }
        for (tpl, img), want in cases.items():
            with self.subTest(template=tpl, image=img):
                self.assertEqual(dialects.pick(node(tpl, img), "").name, want)

    def test_node_name_is_ignored(self) -> None:
        # ISP-RTR9 runs a C8000v; "R2"-style names on L2 images stay ios.
        for name in ("ISP-RTR9", "R2", "nxos-switch", "c8kv"):
            self.assertEqual(
                dialects.pick(node("c8000v", "", name), "").name,
                "iosxe",
            )
            self.assertEqual(dialects.pick(node("iol", "", name), "").name, "ios")

    def test_content_only(self) -> None:
        """Without node data the sniff patterns alone pick the right family."""
        for stem, scope, n, text in real_cisco_configs():
            with self.subTest(lab=stem, scope=scope, node=n.name):
                self.assertEqual(
                    dialects.pick(None, text).name, TEMPLATE_DIALECT[n.template]
                )

    def test_real_labs_pick_by_node(self) -> None:
        seen = set()
        for stem, scope, n, text in real_cisco_configs():
            with self.subTest(lab=stem, scope=scope, node=n.name):
                self.assertEqual(
                    dialects.pick(n, text).name, TEMPLATE_DIALECT[n.template]
                )
            seen.add(n.template)
        if not seen:
            self.skipTest("no Cisco nodes in labs/")


# --------------------------------------------------------------------------- #
# targeted behaviour
# --------------------------------------------------------------------------- #

BANNER = textwrap.dedent("""\
    hostname r1
    banner motd ^C
    ip name-server 10.9.9.9
    interface Vlan77
     ip address 10.7.7.7 255.255.255.0
    vlan 99
    ^C
    banner login ^C one-line 10.8.8.8 ^C
    ip domain-name netlab.local
    interface Vlan5
     ip address 10.5.5.5 255.255.255.0
    """)


class TestBanners(unittest.TestCase):
    def test_banner_text_is_masked(self) -> None:
        for name in CISCO:
            with self.subTest(dialect=name):
                pc = parse(name, BANNER)
                values = [(f.kind, f.value) for f in pc.facts]
                self.assertNotIn(("dns_server", "10.9.9.9"), values)
                self.assertNotIn(("svi_name", "Vlan77"), values)
                self.assertNotIn(("vlan_def", "99"), values)
                self.assertFalse(any("10.8.8.8" in v for _, v in values))
                self.assertIn(("domain", "netlab.local"), values)
                self.assertIn("vl5", pc.ifaces)
                self.assertNotIn("vl77", pc.ifaces)
                self.assertNotIn(99, pc.vlan_db)

    def test_unterminated_banner_is_not_masked(self) -> None:
        text = "banner motd ^C\nip name-server 10.9.9.9\n"
        pc = parse("ios", text)
        self.assertEqual([f.value for f in pc.facts], ["10.9.9.9"])

    def test_real_viosl2_banners_produce_no_facts(self) -> None:
        _n, text = real_config("vxlan_evpn_multi-site_sdwan_only", "startup", "sw-48")
        pc = parse("ios", text)
        banner_lines = {
            i + 1
            for i, ln in enumerate(text.split("\n"))
            if "Cisco" in ln or "IOSv" in ln
        }
        self.assertTrue(banner_lines)
        self.assertFalse([f for f in pc.facts if f.line in banner_lines])


class TestSwitching(unittest.TestCase):
    def test_implicit_vlan_db_backbone_mgmt79(self) -> None:
        """dmvpn-backbone mgmt-79: access vlan 203 without a ``vlan 203`` line."""
        _n, text = real_config(
            "vxlan_evpn_multi-site_with_backbone", "cs:vxlan-dmvpn-backbone", "mgmt-79"
        )
        pc = parse("ios", text)
        self.assertFalse([f for f in pc.facts if f.kind == "vlan_def"])
        self.assertIn(203, pc.vlan_db)
        uplink = pc.ifaces["et0/0"]
        self.assertEqual(uplink.mode, "trunk")
        self.assertIsNone(uplink.trunk_vlans)  # no allowed list = ALL of vlan_db
        self.assertEqual(pc.ifaces["et0/1"].access_vlan, 203)
        self.assertTrue(pc.is_switch)

    def test_sdwan_mgmt80_names_and_trunks(self) -> None:
        _n, text = real_config("vxlan_evpn_multi-site_sdwan_only", "startup", "mgmt-80")
        pc = parse("ios", text)
        names = {f.value for f in pc.facts if f.kind == "vlan_name"}
        self.assertEqual(names, {"EVE-MGMT-203", "EVE-MGMT-204"})
        self.assertEqual(pc.vlan_db, {2, 3})
        self.assertEqual(pc.ifaces["et1/0"].trunk_vlans, VlanList.parse("3"))
        self.assertEqual(pc.ifaces["et0/1"].access_vlan, 2)

    def test_orphan_block_b1_sw1(self) -> None:
        _n, text = real_config(
            "vxlan_evpn_multi-site_with_backbone", "cs:vxlan-dmvpn-backbone", "b1-sw1"
        )
        pc = parse("ios", text)
        orphans = [i for i in pc.ifaces.values() if i.orphan]
        self.assertEqual(len(orphans), 1)
        self.assertEqual(orphans[0].trunk_vlans, VlanList.parse("203"))
        tag_facts = [f for f in pc.facts if f.orphan]
        self.assertTrue(tag_facts)
        for f in tag_facts:
            self.assertIsNone(f.iface)
            self.assertLessEqual(f.confidence.value, 2)
        # The orphan list is not a VLAN definition; Vlan203 (SVI) is.
        self.assertIn(203, pc.vlan_db)
        self.assertIn("vl203", pc.ifaces)

    def test_allowed_add_all_none(self) -> None:
        text = textwrap.dedent("""\
            interface Ethernet0/0
             switchport trunk allowed vlan 10,201-203
             switchport trunk allowed vlan add 300
             switchport mode trunk
            interface Ethernet0/1
             switchport trunk allowed vlan 10
             switchport trunk allowed vlan all
            interface Ethernet0/2
             switchport trunk allowed vlan none
            """)
        for name in CISCO:
            with self.subTest(dialect=name):
                pc = parse(name, text)
                ifs = pc.ifaces
                k0, k1, k2 = (
                    dialects.get(name).iface_key(f"Ethernet0/{i}") for i in range(3)
                )
                self.assertEqual(ifs[k0].trunk_vlans.vlans(), [10, 201, 202, 203, 300])
                self.assertIsNone(ifs[k1].trunk_vlans)
                self.assertEqual(ifs[k2].trunk_vlans.vlans(), [])
                self.assertEqual(ifs[k2].mode, "trunk")

    def test_native_vlan_not_in_vlan_db(self) -> None:
        text = (
            "interface Ethernet0/0\n switchport trunk native vlan 99\n"
            " switchport trunk allowed vlan 10\n"
        )
        pc = parse("ios", text)
        self.assertEqual(pc.vlan_db, {10})
        self.assertEqual(pc.ifaces["et0/0"].native_vlan, 99)

    def test_never_tag_facts(self) -> None:
        text = textwrap.dedent("""\
            vrf definition Mgmt-vrf
             rd 2:2
             address-family ipv4
              route-target export 204:204
            spanning-tree vlan 1-4094 priority 61440
            router isis UNDERLAY
             net 49.0000.0000.0000.0048.00
            interface Tunnel1001
             tunnel key 1001
            interface Ethernet0/0
             switchport trunk encapsulation dot1q
            vlan 100
             name servers
            """)
        for name in CISCO:
            with self.subTest(dialect=name):
                pc = parse(name, text)
                kinds = sorted((f.kind, f.value) for f in pc.facts)
                self.assertEqual(kinds, [("vlan_def", "100"), ("vlan_name", "servers")])


class TestNxosSpecifics(unittest.TestCase):
    def test_mgmt0_vrf_management(self) -> None:
        _n, text = real_config(
            "vxlan_evpn_multi-site_sdwan_only", "startup", "dc1-leaf1"
        )
        pc = parse("nxos", text)
        ip = next(f for f in pc.facts if f.kind == "ip_host")
        self.assertEqual(
            (ip.value, ip.iface, ip.mask_form), ("10.100.203.13", "mgmt0", "prefix")
        )
        gw = next(f for f in pc.facts if f.kind == "ip_gateway")
        self.assertEqual(gw.value, "10.100.203.1")
        self.assertNotIn("nexthop", gw.flags)
        d = dialects.get("nxos")
        self.assertEqual(d.eve_to_config("Mgmt0"), ["mgmt0"])
        self.assertEqual(d.eve_to_config("E1/6"), ["Ethernet1/6"])
        self.assertEqual(d.iface_key("Ethernet1/6"), d.iface_key("Eth1/6"))

    def test_mask_rewrite_keeps_prefix_form(self) -> None:
        text = "interface mgmt0\n  ip address 10.100.203.13/24\n"
        d = dialects.get("nxos")
        f = d.parse(make_ct(text, "nxos")).facts[0]
        edits = d.render(f, "10.100.20.13", RenderCtx(text, new_prefix=20))
        self.assertEqual(
            [(e.old, e.new) for e in edits],
            [("10.100.203.13", "10.100.20.13"), ("/24", "/20")],
        )

    def test_vlan_range_list_and_name(self) -> None:
        _n, text = real_config(
            "vxlan_evpn_multi-site_sdwan_only", "cs:sdwan-vxlan-evpn", "dc1-bgw2"
        )
        pc = parse("nxos", text)
        defs = [f for f in pc.facts if f.kind == "vlan_def"]
        # lab rework 32d9b62: VLAN 3001 (VRF OUTSIDE) -> 3201-3202 (per provider)
        self.assertEqual(defs[0].value, "1,100-101,501-502,3101,3201-3202")
        self.assertEqual(
            defs[0].list_value, VlanList.parse("1,100-101,501-502,3101,3201-3202")
        )
        names = {f.value for f in pc.facts if f.kind == "vlan_name"}
        self.assertIn("INET-201-to-dc1-fgt1", names)
        self.assertFalse([f for f in pc.facts if f.kind == "dns_server"])


class TestIosSpecifics(unittest.TestCase):
    def test_eve_names(self) -> None:
        ios = dialects.get("ios")
        self.assertEqual(ios.eve_to_config("e0/1"), ["Ethernet0/1"])
        self.assertEqual(ios.eve_to_config("Gi0/1"), ["GigabitEthernet0/1"])
        self.assertEqual(
            dialects.get("iosxe").eve_to_config("Gi16"), ["GigabitEthernet16"]
        )
        self.assertEqual(ios.iface_key("Gi16.2"), ios.iface_key("GigabitEthernet16.2"))
        self.assertEqual(ios.iface_key("Vlan 203"), "vl203")

    def test_routes(self) -> None:
        text = textwrap.dedent("""\
            ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 10.100.203.1
            ip route 10.0.0.0 255.0.0.0 GigabitEthernet1 10.100.51.254 name HOME
            ip default-gateway 10.100.51.1
            """)
        pc = parse("iosxe", text)
        got = [(f.kind, f.value, sorted(f.flags)) for f in pc.facts]
        self.assertEqual(
            got,
            [
                ("ip_gateway", "10.100.203.1", []),
                ("ip_route_dst", "10.0.0.0", []),
                ("ip_gateway", "10.100.51.254", ["nexthop"]),
                ("ip_gateway", "10.100.51.1", []),
            ],
        )

    def test_secrets_real_c8kv(self) -> None:
        _n, text = real_config(
            "vxlan_evpn_multi-site_with_backbone", "cs:vxlan-dmvpn-backbone", "c8kv-30"
        )
        d = dialects.get("iosxe")
        values = {text[s.start : s.end] for s in d.secret_spans(text)}
        self.assertEqual(values, {"admin123", "C1sco123!", "C1sco123", "NETBRAIN"})


class TestLogServerKind(unittest.TestCase):
    def test_registered(self) -> None:
        self.assertIn(LOG_SERVER, CORE_FACT_KINDS)

    def test_render_validates(self) -> None:
        text = "logging host 10.100.51.20\n"
        for name in ("ios", "iosxe"):
            d = dialects.get(name)
            f = d.parse(make_ct(text, name)).facts[0]
            self.assertEqual(f.kind, LOG_SERVER)
            with self.assertRaises(LocalizeError) as cm:
                d.render(f, "not-an-ip", RenderCtx(text))
            self.assertEqual(cm.exception.code, "BAD_VALUE")
            (edit,) = d.render(f, "10.1.2.3", RenderCtx(text))
            self.assertEqual(edit.new, "10.1.2.3")


# --------------------------------------------------------------------------- #
# real-lab sweep
# --------------------------------------------------------------------------- #

TAG_LINE = re.compile(
    r"^(?:interface \S+\.\d+|interface Vlan\d+|vlan [\d,\-]+"
    r"|\s+(?:encapsulation dot1[Qq]"
    r"|switchport (?:access|trunk native|trunk allowed) vlan(?: add)?) )",
)


class TestRealLabSweep(unittest.TestCase):
    def setUp(self) -> None:
        if not real_cisco_configs():
            self.skipTest("no Cisco configs in labs/")

    def test_parse_all_real_configs(self) -> None:
        for stem, scope, n, text in real_cisco_configs():
            name = TEMPLATE_DIALECT[n.template]
            with self.subTest(lab=stem, scope=scope, node=n.name):
                d = dialects.get(name)
                assert isinstance(d, RuleDialect)
                ct = ConfigText(
                    Store("startup", "startup", scope), n.id, text, name, None, None
                )
                pc = d.parse(ct)
                self.assertEqual(pc.notes, [])
                for f in pc.facts:
                    self.assertEqual(text[f.span.start : f.span.end], f.value)
                    if f.kind in (
                        "vlan_tag",
                        "vlan_list",
                        "vlan_def",
                        "subif_name",
                        "svi_name",
                    ):
                        ls = text.rfind("\n", 0, f.span.start) + 1
                        self.assertRegex(text[ls : f.span.end], TAG_LINE)
                # no-op render is always empty
                for f in pc.facts[:50]:
                    self.assertEqual(d.render(f, f.value, RenderCtx(text)), [])

    def test_every_mgmt_subif_has_tag_and_address(self) -> None:
        """Routed Cisco nodes reach the management cloud through ``X.N`` subifs."""
        count = 0
        for _stem, _scope, n, text in real_cisco_configs():
            name = TEMPLATE_DIALECT[n.template]
            if name == "nxos":
                continue
            pc = parse(name, text)
            for info in pc.ifaces.values():
                if info.parent and info.tag is not None:
                    count += 1
                    self.assertTrue(
                        any(
                            f.kind == "subif_name" and f.iface == info.key
                            for f in pc.facts
                        )
                    )
        self.assertGreater(count, 0)


if __name__ == "__main__":
    unittest.main()
