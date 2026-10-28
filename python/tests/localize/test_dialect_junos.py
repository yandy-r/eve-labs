"""Junos dialect (T11): real vJunos configs, brace/set interfaces, rules."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Interface

from evelab.localize import dialects
from evelab.localize.dialects import RenderCtx

from .t11_real import configs_with_template
from .test_dialect_contract import DialectContractMixin, apply_edits, make_ct


def parse(text: str):
    return dialects.get("junos").parse(make_ct(text, "junos"))


class TestJunosContract(DialectContractMixin, unittest.TestCase):
    dialect_name = "junos"
    require_snippets = True
    require_rule_coverage = True


class TestJunosRealLab(unittest.TestCase):
    """Every vJunos config of vxlan_evpn_multi-site_junos (16 nodes)."""

    def setUp(self) -> None:
        self.texts = list(configs_with_template("vjunosswitch"))

    def test_found_the_junos_nodes(self) -> None:
        self.assertGreaterEqual(len(self.texts), 16)

    def test_pick_selects_junos(self) -> None:
        for rt in self.texts:
            with self.subTest(node=rt.node.name if rt.node else rt.ident):
                self.assertEqual(dialects.pick(rt.node, rt.text).name, "junos")
                # content alone (no node) is enough too
                self.assertEqual(dialects.pick(None, rt.text).name, "junos")

    def test_mgmt_facts(self) -> None:
        mgmt = IPv4Interface("10.100.240.0/20").network
        for rt in self.texts:
            with self.subTest(node=rt.node.name if rt.node else rt.ident):
                pc = dialects.get("junos").parse(rt.ct("junos"))
                by_kind: dict[str, list] = {}
                for f in pc.facts:
                    by_kind.setdefault(f.kind, []).append(f)
                (addr,) = by_kind["ip_host"]
                self.assertEqual((addr.iface, addr.parent), ("fxp0.0", "fxp0"))
                mask = rt.text[addr.mask_span.start : addr.mask_span.end]
                self.assertIn(IPv4Interface(f"{addr.value}{mask}").ip, mgmt)
                self.assertEqual(mask, "/20")
                self.assertEqual(
                    [f.value for f in by_kind["ip_gateway"]], ["10.100.255.254"]
                )
                self.assertEqual(
                    [f.value for f in by_kind["dns_server"]], ["10.100.51.11"]
                )
                self.assertEqual(
                    [f.value for f in by_kind["domain"]], ["plsnetlab.local"]
                )
                self.assertEqual(pc.ifaces["fxp0"].mode, "routed")
                self.assertNotIn("vlan_tag", by_kind)
                self.assertEqual(len(by_kind["secret"]), 2)

    def test_render_address_keeps_everything_else(self) -> None:
        rt = self.texts[0]
        d = dialects.get("junos")
        pc = d.parse(rt.ct("junos"))
        addr = next(f for f in pc.facts if f.kind == "ip_host")
        edits = d.render(addr, "10.200.241.11", RenderCtx(rt.text, new_prefix=24))
        new = apply_edits(rt.text, edits)
        self.assertIn("address 10.200.241.11/24;", new)
        self.assertEqual(len(new), len(rt.text))  # only the two tokens changed
        self.assertFalse(new.endswith("\n"))  # no trailing newline is added


class TestJunosInterfaces(unittest.TestCase):
    def test_units_are_ifaces_with_parent(self) -> None:
        pc = parse(
            "interfaces {\n    ge-0/0/1 {\n        unit 1240 {\n"
            "            vlan-id 1240;\n            family inet {\n"
            "                address 172.31.240.2/30;\n            }\n        }\n"
            "    }\n}\n"
        )
        info = pc.ifaces["ge-0/0/1.1240"]
        self.assertEqual(
            (info.parent, info.tag, info.mode), ("ge-0/0/1", 1240, "routed")
        )
        self.assertEqual(pc.ifaces["ge-0/0/1"].mode, "unknown")  # tagged unit only
        unit = next(f for f in pc.facts if f.kind == "subif_name")
        tag = next(f for f in pc.facts if f.kind == "vlan_tag")
        self.assertEqual(unit.value, "1240")
        self.assertEqual(unit.group, tag.group)
        self.assertEqual(unit.group, "subif:ge-0/0/1.1240")

    def test_untagged_unit_has_no_subif_name(self) -> None:
        pc = parse(
            "interfaces {\n    em0 {\n        unit 0 {\n            family inet {\n"
            "                dhcp;\n            }\n        }\n    }\n}\n"
        )
        self.assertFalse([f for f in pc.facts if f.kind == "subif_name"])
        self.assertTrue(pc.ifaces["em0"].dhcp)
        self.assertEqual(pc.ifaces["em0"].mode, "routed")

    def test_interface_keywords_under_protocols_are_not_ifaces(self) -> None:
        pc = parse(
            "protocols {\n    router-advertisement {\n        interface fxp0.0 {\n"
            "            managed-configuration;\n        }\n    }\n}\n"
        )
        self.assertEqual(pc.ifaces, {})

    def test_set_style(self) -> None:
        pc = parse(
            "set interfaces ge-0/0/2 unit 1242 vlan-id 1242\n"
            "set interfaces ge-0/0/2 unit 1242 family inet address 172.31.242.2/30\n"
            "set interfaces fxp0 unit 0 family inet address 10.100.241.12/20\n"
        )
        self.assertEqual(pc.ifaces["ge-0/0/2.1242"].tag, 1242)
        self.assertEqual(pc.ifaces["fxp0"].mode, "routed")  # synthesised physical
        kinds = sorted((f.kind, f.iface) for f in pc.facts)
        self.assertEqual(
            kinds,
            [
                ("ip_host", "fxp0.0"),
                ("ip_host", "ge-0/0/2.1242"),
                ("vlan_tag", "ge-0/0/2.1242"),
            ],
        )

    def test_members_and_rd_never_tags(self) -> None:
        pc = parse(
            "vlans {\n    T {\n        members 1 2;\n        vlan-id-list 100-200;\n"
            "    }\n}\nrouting-instances {\n    X {\n        rd 2:2;\n    }\n}\n"
        )
        self.assertFalse([f for f in pc.facts if f.kind.startswith("vlan")])

    def test_route_outside_static_is_ignored(self) -> None:
        pc = parse("policy-options {\n    route 10.0.0.0/8 next-hop 1.1.1.1;\n}\n")
        self.assertEqual(pc.facts, [])


if __name__ == "__main__":
    unittest.main()
