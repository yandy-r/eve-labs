"""Topology + L2 trace (design 7.1 / 7.2): minilab ``l2lab`` and the real labs."""

from __future__ import annotations

import unittest

from evelab.localize import stores
from evelab.localize.discover import l2trace, topology

from . import disco
from .labfiles import minilab


def _eps(trace, analysis):
    """``{(node name, iface): endpoint}`` for a trace."""
    return {(analysis.nodes[e.node_id].name, e.iface): e for e in trace.endpoints}


class TopologyMinilabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = minilab("l2lab")
        cls.topo = topology.build(cls.lab)
        texts, _ = stores.load_texts(cls.lab, cls.topo.nodes)
        cls.index = topology.ConfigIndex(cls.topo, texts)

    def test_clouds_and_ports(self) -> None:
        self.assertEqual(
            sorted(self.topo.clouds, key=int), ["1", "5", "7", "8", "9", "10", "11"]
        )
        self.assertEqual(self.topo.status, "CLOUDS")
        ports = {(p.node_id, p.eve_name) for p in self.topo.cloud_ports()}
        self.assertIn(("1", "e0/0"), ports)  # sw1 trunk on EVE-TRUNK
        self.assertNotIn(("1", "e0/1"), ports)  # bridge port
        self.assertEqual(self.topo.scopes, ["startup", "alt"])

    def test_active_scope(self) -> None:
        self.assertEqual(self.topo.active_scope["1"], "alt")  # config="2" + blob
        self.assertEqual(self.topo.active_scope["2"], "startup")
        self.assertEqual(self.topo.active_scope["5"], "startup")  # config="0"

    def test_scope_fallback_to_startup(self) -> None:
        nc = self.index.config_for("2", "alt")  # rtr1 has no blob in "alt"
        assert nc is not None
        self.assertEqual(nc.store.kind, "startup")
        nc_alt = self.index.config_for("1", "alt")
        assert nc_alt is not None
        self.assertEqual(nc_alt.store.scope, "alt")
        self.assertIsNone(self.index.config_for("5", "startup"))  # no config at all

    def test_eve_to_config_mapping(self) -> None:
        nc = self.index.config_for("1", "startup")
        assert nc is not None
        self.assertEqual(nc.iface_for("e0/0"), "et0/0")
        self.assertEqual(nc.iface_for("e1/0"), "et1/0")
        self.assertEqual(nc.eve_for("et0/1"), "e0/1")
        self.assertIsNone(nc.eve_for("et0/3"))  # configured but uncabled
        self.assertEqual(nc.svi_for(10), "vl10")

    def test_no_cloud_lab_is_none(self) -> None:
        for stem in disco.NO_CLOUD:
            d = disco.real(stem)
            if d is None:
                continue
            with self.subTest(stem):
                self.assertEqual(d.topology.status, "NONE")
                self.assertEqual(d.topology.cloud_ports(), [])
                self.assertTrue(all(not t.endpoints for t in d.traces.values()))


class TraceMinilabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.d = disco.mini("l2lab")
        cls.a = cls.d.analysis

    def eps(self, scope: str):
        return _eps(self.d.traces[scope], self.a)

    def test_routed_subif_on_attached_parent_only(self) -> None:
        eps = self.eps("startup")
        e = eps[("rtr2", "et0/1.500")]
        self.assertEqual((e.tag, e.arrives, e.direct), (500, "tagged", True))
        self.assertNotIn(("rtr2", "et0/2.500"), eps)  # same tag, other parent

    def test_trunk_without_allowed_list_carries_vlan_db(self) -> None:
        eps = self.eps("startup")
        # access VLAN 10 -> rtr1 untagged; implicit VLAN 30 (access only) -> srv1
        rtr1 = eps[("rtr1", "et0/0")]
        self.assertEqual((rtr1.tag, rtr1.arrives, rtr1.direct), (10, "untagged", False))
        self.assertIn("sw1 e0/0 vlan 10", " ".join(rtr1.path))
        self.assertEqual(eps[("srv1", "eth0")].tag, 30)
        # trunk with allowed list 20 -> only rtr2's .20 subif
        self.assertEqual(eps[("rtr2", "et0/0.20")].tag, 20)
        self.assertNotIn(("rtr2", "et0/0.99"), eps)
        # SVI on the switch itself
        self.assertEqual(eps[("sw1", "vl10")].kind, "routed")
        tr = self.d.traces["startup"]
        self.assertTrue(tr.trunk_only["1"])
        self.assertFalse(tr.trunk_only["5"])
        self.assertEqual(
            sorted(d.vlan for d in tr.domains if d.cloud_id == "1"), [10, 20, 30, 40]
        )

    def test_per_scope(self) -> None:
        eps = self.eps("alt")
        self.assertEqual(eps[("rtr1", "et0/0")].tag, 11)  # startup blob, alt switch
        self.assertEqual(eps[("rtr4", "et0/0.11")].tag, 11)
        self.assertNotIn(("rtr4", "et0/0.10"), eps)

    def test_unconfigured_and_dhcp(self) -> None:
        eps = self.eps("startup")
        fw1 = eps[("fw1", None)]
        self.assertEqual((fw1.kind, fw1.tag), ("unconfigured", "unknown"))
        rtr3 = eps[("rtr3", "et0/0")]
        self.assertEqual((rtr3.kind, rtr3.tag), ("dhcp", "untagged"))
        att = rtr3.to_attachment()
        self.assertEqual(
            (att.network_id, att.direct, att.arrives), ("8", True, "untagged")
        )

    def test_domain_facts_uncabled(self) -> None:
        nc = self.d.index.config_for("1", "startup")
        assert nc is not None
        got = {
            (f.kind, f.value, f.iface, unc) for f, unc in l2trace.domain_facts(nc, 10)
        }
        self.assertIn(("vlan_def", "10", None, False), got)
        self.assertIn(("vlan_name", "EXT-MGMT", None, False), got)
        self.assertIn(("vlan_tag", "10", "et0/1", False), got)
        self.assertIn(("vlan_tag", "10", "et0/3", True), got)
        self.assertIn(("svi_name", "Vlan10", "vl10", False), got)
        self.assertFalse(any(v == "30" for _k, v, _i, _u in got))

    def test_depth_cap(self) -> None:
        tr = l2trace.trace_scope(self.d.topology, self.d.index, "startup", max_depth=0)
        names = {self.a.nodes[e.node_id].name for e in tr.endpoints}
        self.assertNotIn("rtr1", names)
        self.assertIn("rtr4", names)
        self.assertTrue(any(f.code == "TRACE_DEPTH" for f in tr.findings))

    def test_fact_vlans(self) -> None:
        nc = self.d.index.config_for("3", "startup")
        assert nc is not None
        subif = next(f for f in nc.parsed.facts if f.kind == "subif_name")
        self.assertEqual(l2trace.fact_vlans(subif), {20})


class TraceRealLabsTest(unittest.TestCase):
    def need(self, stem: str):
        d = disco.real(stem)
        if d is None:
            self.skipTest(f"{stem} not in labs/")
        return d

    def test_sdwan_trunk_carries_all_vlans(self) -> None:
        d = self.need(disco.SDWAN)
        tr = d.traces["startup"]
        for cloud in ("132", "137", "140", "152"):
            self.assertTrue(tr.trunk_only[cloud], cloud)
            self.assertEqual(tr.wire_tags(cloud) & {2, 3}, {2, 3})
        eps = _eps(tr, d.analysis)
        self.assertEqual(eps[("dc1-spine1", "mgmt0")].tag, 2)
        self.assertFalse(eps[("dc1-spine1", "mgmt0")].direct)
        self.assertEqual(eps[("dc1-svc-fgt1", "oob-mgmt")].tag, 3)
        self.assertEqual(eps[("c8kv-75", "gi16.2")].tag, 2)
        self.assertEqual(eps[("b1-fgt1", "wan1")].tag, 201)

    def test_backbone_implicit_vlan(self) -> None:
        d = self.need(disco.BACKBONE)
        tr = d.traces["vxlan-dmvpn-backbone"]
        mgmt79 = d.index.config_for(
            next(n.id for n in d.analysis.nodes.values() if n.name == "mgmt-79"),
            "vxlan-dmvpn-backbone",
        )
        assert mgmt79 is not None
        self.assertIn(203, mgmt79.parsed.vlan_db)
        self.assertFalse(any(f.kind == "vlan_def" for f in mgmt79.parsed.facts))
        eps = _eps(tr, d.analysis)
        self.assertEqual(eps[("dc1-spine1", "mgmt0")].tag, 203)
        self.assertEqual(eps[("sw46", "gi3/3.203")].tag, 203)
        # the startup scope uses the legacy 1103 scheme
        self.assertEqual(
            _eps(d.traces["startup"], d.analysis)[("dc1-spine1", "mgmt0")].tag, 1103
        )

    def test_junos_attached_parent(self) -> None:
        d = self.need(disco.JUNOS)
        eps = _eps(d.traces["startup"], d.analysis)
        self.assertEqual(eps[("ISP-RTR9", "gi2.1240")].tag, 1240)
        self.assertNotIn(("ISP-RTR9", "gi3.1240"), eps)
        fxp = eps[("dc1-spine1", "fxp0.0")]
        self.assertEqual((fxp.tag, fxp.direct), ("untagged", True))
        self.assertEqual(eps[("dc1-fw32", None)].kind, "unconfigured")

    def test_azure_untagged(self) -> None:
        d = self.need(disco.AZURE)
        eps = _eps(d.traces["startup"], d.analysis)
        self.assertEqual(eps[("ASAv-1", "gi0/0")].tag, "untagged")
        self.assertEqual(eps[("ASAv-1", "gi0/6")].tag, "untagged")
        self.assertEqual(eps[("ASAv-1", "gi0/0")].network_id, "1")


if __name__ == "__main__":
    unittest.main()
