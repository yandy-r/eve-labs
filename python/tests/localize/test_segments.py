"""Segments, names, inventory and analyse() (design 7.3-7.6, 8.3)."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Address, IPv4Network

from evelab.localize import manifest as manifest_mod
from evelab.localize.discover import AnalyseOptions, analyse, discover, inventory, names
from evelab.localize.discover.segments import normalise_key
from evelab.localize.model import Analysis, Confidence, Fact, Segment

from . import disco
from .labfiles import TESTS_DIR, minilab, read_real, real_lab_paths

NET = IPv4Network
ADDR = IPv4Address


def seg(a: Analysis, key: str) -> Segment:
    for s in a.segments:
        if s.key == key:
            return s
    raise AssertionError(f"no segment {key!r}; have {[s.key for s in a.segments]}")


def node_id(a: Analysis, name: str) -> str:
    return next(n.id for n in a.nodes.values() if n.name == name)


def facts_of(a: Analysis, node: str, **kw: object) -> list[Fact]:
    nid = node_id(a, node)
    out = []
    for f in a.facts.values():
        if f.node_id != nid:
            continue
        if all(getattr(f, k) == v for k, v in kw.items()):
            out.append(f)
    return out


def codes(a: Analysis) -> list[str]:
    return [f.code for f in a.findings]


# ------------------------------------------------------------------ minilab


class MinilabSegmentsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.a = disco.mini("l2lab").analysis

    def test_keys_and_status(self) -> None:
        got = {s.key: s.status for s in self.a.segments}
        self.assertEqual(
            got,
            {
                "TRUNK": "CARRIER",
                "INET-500": "CONFIGURABLE",
                "EXT-LABEL": "LABEL_ONLY",
                "INTERNET": "DHCP",
                "EXT-MGMT": "CONFIGURABLE",
                "LAB-20": "LABEL_ONLY",
                "SRV-NET": "CONFIGURABLE",
                "TRUNK-20": "CONFIGURABLE",
                "TRUNK-40": "CONFIGURABLE",
            },
        )
        self.assertEqual(seg(self.a, "EXT-MGMT").site_key, "l2lab.EXT-MGMT")
        self.assertEqual(seg(self.a, "EXT-MGMT").role, "mgmt")
        self.assertEqual(seg(self.a, "INET-500").role, "inet")
        self.assertEqual(seg(self.a, "TRUNK").role, "trunk")
        self.assertEqual(seg(self.a, "INTERNET").cloud_types, {"nat0"})

    def test_carrier(self) -> None:
        trunk = seg(self.a, "TRUNK")
        self.assertEqual(trunk.network_ids, ["1"])
        self.assertEqual(
            sorted(trunk.carries), ["EXT-MGMT", "SRV-NET", "TRUNK-20", "TRUNK-40"]
        )
        self.assertEqual(trunk.schemes, [])
        self.assertIn("carried by TRUNK", seg(self.a, "EXT-MGMT").notes)
        self.assertEqual(seg(self.a, "TRUNK-20").network_ids, [])
        self.assertIn("TRUNK_ATTRS", codes(self.a))

    def test_merge_rule_b_and_schemes_per_scope(self) -> None:
        s = seg(self.a, "EXT-MGMT")
        self.assertEqual(s.network_ids, ["9"])
        self.assertEqual(len(s.schemes), 2)
        by_tag = {sch.tag: sch for sch in s.schemes}
        self.assertEqual(by_tag[10].scopes, {"startup"})
        self.assertEqual(by_tag[11].scopes, {"alt"})
        for sch in s.schemes:
            self.assertEqual(sch.subnet, NET("192.0.2.0/24"))
            self.assertEqual(sch.gateway, ADDR("192.0.2.1"))
        self.assertEqual(s.schemes[0].tag, 10)  # canonical: most nodes boot startup
        self.assertTrue(any("EVE-TRUNK:1" in n for n in s.notes), s.notes)

    def test_canonical_scope_option(self) -> None:
        a = analyse(minilab("l2lab"), None, AnalyseOptions(canonical_scope="alt"))
        self.assertEqual(seg(a, "EXT-MGMT").schemes[0].tag, 11)

    def test_merge_rule_c_vlan_name(self) -> None:
        s = seg(self.a, "SRV-NET")
        self.assertEqual(s.network_ids, ["11"])
        self.assertEqual(
            [(x.tag, x.subnet) for x in s.schemes], [(30, NET("203.0.113.0/24"))]
        )
        self.assertTrue(any("name SRV-NET" in n for n in s.notes))

    def test_hint_never_merges(self) -> None:
        lab20 = seg(self.a, "LAB-20")
        self.assertEqual(lab20.status, "LABEL_ONLY")
        self.assertTrue(any(n.startswith("hint:") for n in lab20.notes))
        hints = [f for f in self.a.findings if f.code == "MERGE_HINT"]
        self.assertTrue(any("TRUNK-20" in f.msg for f in hints))

    def test_attached_parent_scoping_and_protected_lookalike(self) -> None:
        s = seg(self.a, "INET-500")
        self.assertEqual(
            [(x.tag, x.subnet, x.gateway) for x in s.schemes],
            [(500, NET("100.64.5.0/24"), ADDR("100.64.5.1"))],
        )
        internal = facts_of(self.a, "rtr2", kind="vlan_tag", iface="et0/2.500")
        self.assertEqual([f.segment for f in internal], [None])
        external = facts_of(self.a, "rtr2", kind="vlan_tag", iface="et0/1.500")
        self.assertEqual([f.segment for f in external], ["INET-500"])
        self.assertEqual(external[0].confidence, Confidence.PROVEN)
        self.assertIn(500, self.a.protected_vlans["startup"])
        self.assertIn(99, self.a.protected_vlans["startup"])
        looks = inventory.lookalikes(self.a.facts, s)
        self.assertEqual({f.iface for f in looks}, {"et0/2.500"})
        self.assertIn(internal[0].id, inventory.protected_fact_ids(self.a.facts))

    def test_correlation_pass(self) -> None:
        peer = facts_of(self.a, "rtr2", kind="peer_ip")
        self.assertEqual(
            [(f.segment, f.confidence) for f in peer],
            [("INET-500", Confidence.CORRELATED)],
        )
        gw = facts_of(self.a, "rtr2", kind="ip_gateway")
        self.assertEqual([f.segment for f in gw], ["INET-500"])

    def test_vlan_domain_rule(self) -> None:
        defs = facts_of(self.a, "sw1", kind="vlan_name", value="EXT-MGMT")
        self.assertTrue(defs)
        for f in defs:
            self.assertEqual(
                (f.segment, f.confidence), ("EXT-MGMT", Confidence.CORRELATED)
            )
        unc = list(facts_of(self.a, "sw1", kind="vlan_tag", iface="et0/3"))
        self.assertTrue(unc)
        for f in unc:
            self.assertEqual(f.segment, "EXT-MGMT")
            self.assertIn("uncabled", f.flags)
        svi_ip = facts_of(self.a, "sw1", kind="ip_host", iface="vl10")
        self.assertEqual([f.confidence for f in svi_ip], [Confidence.PROVEN])

    def test_outlier(self) -> None:
        bad = facts_of(self.a, "rtr5", kind="ip_host")
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0].segment, "EXT-MGMT")
        self.assertIn("outlier", bad[0].flags)
        s = seg(self.a, "EXT-MGMT")
        self.assertTrue(any(bad[0].id in sch.outliers for sch in s.schemes))
        self.assertIn("OUTLIER", codes(self.a))
        incl = disco.mini("l2lab", include_outliers=True).analysis
        bad2 = facts_of(incl, "rtr5", kind="ip_host")
        self.assertNotIn("outlier", bad2[0].flags)
        self.assertNotIn("OUTLIER", codes(incl))

    def test_dhcp_and_label_only(self) -> None:
        self.assertIn("DHCP_UPLINK", codes(self.a))
        unconf = [f for f in self.a.findings if f.code == "UNCONFIGURED"]
        self.assertTrue(any("EXT-LABEL" in f.msg for f in unconf))
        self.assertEqual(seg(self.a, "EXT-LABEL").schemes, [])
        dh = seg(self.a, "INTERNET").schemes
        self.assertEqual([(x.tag, x.subnet) for x in dh], [("untagged", None)])

    def test_protected_prefixes(self) -> None:
        prefixes = set(self.a.protected_prefixes)
        self.assertIn(NET("10.5.5.0/30"), prefixes)
        self.assertIn(NET("10.99.0.0/24"), prefixes)
        self.assertNotIn(NET("192.0.2.0/24"), prefixes)
        self.assertNotIn(NET("100.64.5.0/24"), prefixes)

    def test_analysis_shape(self) -> None:
        self.assertFalse(self.a.pinned)
        self.assertEqual(self.a.active_scope[node_id(self.a, "sw1")], "alt")
        for f in self.a.facts.values():
            if f.segment is not None:
                self.assertIn(f.segment, {s.key for s in self.a.segments})
                self.assertTrue(f.evidence, f)

    def test_deterministic(self) -> None:
        a2 = analyse(minilab("l2lab"))

        def sig(a: Analysis) -> list:
            return [
                (
                    s.key,
                    s.status,
                    s.network_ids,
                    [(x.tag, str(x.subnet)) for x in s.schemes],
                )
                for s in a.segments
            ] + sorted((f.id, f.segment or "") for f in a.facts.values())

        self.assertEqual(sig(a2), sig(self.a))


class MinilabManifestTest(unittest.TestCase):
    def manifest(self, **extra: object):
        data: dict[str, object] = {
            "schema": 1,
            "lab": "l2lab.unl",
            "lab_id": "6f2b9b52-2a3e-5e64-9a8b-1a7a2d1e1c0d",
            "segment": [
                {
                    "key": "OOB",
                    "site_key": "site.oob",
                    "role": "oob",
                    "networks": ["9"],
                },
                {"key": "UPLINK", "networks": ["5"], "status": "LABEL_ONLY"},
            ],
            "merge": [{"units": ["lab-20", "EVE-TRUNK:20"]}],
            "outlier": [{"scope": "startup", "node": "7"}],
            "protect": ["198.18.0.0/15"],
        }
        data.update(extra)
        return manifest_mod.parse(data)

    def test_pins(self) -> None:
        a = analyse(minilab("l2lab"), self.manifest())
        oob = seg(a, "OOB")
        self.assertEqual((oob.site_key, oob.role), ("site.oob", "oob"))
        self.assertEqual(seg(a, "UPLINK").status, "LABEL_ONLY")  # pinned status
        merged = seg(a, "LAB-20")
        self.assertEqual(merged.network_ids, ["10"])
        self.assertEqual(
            [(x.tag, x.subnet) for x in merged.schemes], [(20, NET("198.51.100.0/24"))]
        )
        self.assertNotIn("TRUNK-20", {s.key for s in a.segments})
        rtr4 = facts_of(a, "rtr4", kind="ip_host")
        startup = [f for f in rtr4 if f.store.scope == "startup"]
        self.assertTrue(all("outlier" in f.flags for f in startup))
        self.assertIn(NET("198.18.0.0/15"), a.protected_prefixes)
        self.assertFalse(a.pinned)  # clouds 1, 7, 8, 10, 11 are not pinned
        self.assertIn("MANIFEST_STALE", codes(a))

    def test_unknown_merge_unit(self) -> None:
        m = self.manifest(merge=[{"units": ["nope", "EVE-TRUNK:20"]}])
        a = analyse(minilab("l2lab"), m)
        self.assertIn("MERGE_UNKNOWN_UNIT", codes(a))


# -------------------------------------------------------------------- names


class NamesTest(unittest.TestCase):
    def kinds(self, label: str, **kw: object) -> list[tuple[str, str]]:
        return [(t.text, t.kind) for t in names.explain(label, **kw)]  # type: ignore[arg-type]

    def test_classes(self) -> None:
        self.assertEqual(
            self.kinds("EVE-MGMT-203", tags=[2], octet3=[203]), [("203", "octet3")]
        )
        self.assertEqual(
            self.kinds("EVE-INET-201", tags=[201], octet3=[201]), [("201", "ambiguous")]
        )
        self.assertEqual(
            self.kinds("INET-1240", tags=[1240], octet3=[240]), [("1240", "tag")]
        )
        self.assertEqual(
            self.kinds("203-67", tags=[1103], octet3=[203], hosts=[67]),
            [("203", "octet3"), ("67", "host")],
        )
        self.assertEqual(self.kinds("mgmt58", netid="58"), [("58", "netid")])
        self.assertEqual(self.kinds("204-31"), [("204", "unknown"), ("31", "unknown")])
        tok = names.explain("x-0203", octet3=[203])[0]
        self.assertEqual(
            (tok.text, tok.value, tok.span.start, tok.span.end), ("0203", 203, 2, 6)
        )

    def test_templates(self) -> None:
        tpl = names.suggest_template(
            "EVE-MGMT-203", names.explain("EVE-MGMT-203", octet3=[203])
        )
        self.assertEqual(tpl, "EVE-MGMT-{octet3}")
        self.assertEqual(names.render_template(tpl, {"octet3": 51}), "EVE-MGMT-51")
        toks = names.explain("mgmt-203_111_121", octet3=[203], hosts=[111, 121])
        tpl2 = names.suggest_template("mgmt-203_111_121", toks)
        self.assertEqual(tpl2, "mgmt-{octet3}_{host1}_{host2}")
        amb = names.explain("EVE-INET-201", tags=[201], octet3=[201])
        self.assertIsNone(names.suggest_template("EVE-INET-201", amb))
        self.assertIsNone(names.suggest_template("Internet", []))
        self.assertEqual(names.render_template("{{x}}-{tag}", {"tag": 7}), "{x}-7")

    def test_octets3(self) -> None:
        self.assertEqual(names.octets3(NET("10.100.203.0/24")), {203})
        self.assertEqual(names.octets3(NET("10.100.240.0/20")), set(range(240, 256)))
        self.assertEqual(names.octets3(None), set())

    def test_normalise_key(self) -> None:
        self.assertEqual(normalise_key("EVE-MGMT-203"), "MGMT-203")
        self.assertEqual(normalise_key("Internet-105"), "INTERNET-105")
        self.assertIsNone(normalise_key("204-31"))
        self.assertEqual(normalise_key("my net/2"), "MY-NET-2")


# ---------------------------------------------------------------- real labs


class RealLabsTest(unittest.TestCase):
    def need(self, stem: str) -> Analysis:
        d = disco.real(stem)
        if d is None:
            self.skipTest(f"{stem} not in labs/")
        return d.analysis

    def scheme(self, s: Segment, i: int = 0) -> tuple:
        x = s.schemes[i]
        return (
            x.tag,
            str(x.subnet) if x.subnet else None,
            str(x.gateway) if x.gateway else None,
        )

    def test_sdwan(self) -> None:
        a = self.need(disco.SDWAN)
        self.assertEqual(
            {s.key for s in a.segments},
            {"TRUNK", "MGMT-203", "MGMT-204", "INET-201", "INET-202"},
        )
        m203 = seg(a, "MGMT-203")
        self.assertEqual(m203.network_ids, ["74", "76", "91", "54", "55", "165"])
        self.assertEqual(self.scheme(m203), (2, "10.100.203.0/24", "10.100.203.1"))
        self.assertEqual(len(m203.schemes), 1)
        self.assertEqual(self.scheme(seg(a, "MGMT-204"))[:2], (3, "10.100.204.0/24"))
        self.assertEqual(self.scheme(seg(a, "INET-201"))[:2], (201, "10.100.201.0/24"))
        self.assertEqual(self.scheme(seg(a, "INET-202"))[:2], (202, "10.100.202.0/24"))
        trunk = seg(a, "TRUNK")
        self.assertEqual(trunk.status, "CARRIER")
        self.assertEqual(sorted(trunk.network_ids), ["132", "137", "140", "152"])
        self.assertEqual(sorted(trunk.carries), ["MGMT-203", "MGMT-204"])
        for key in ("MGMT-203", "MGMT-204", "INET-201", "INET-202"):
            self.assertEqual(seg(a, key).status, "CONFIGURABLE")
        hint = seg(a, "INET-201").name_hints["25"]
        self.assertEqual([t.kind for t in hint], ["ambiguous"])
        self.assertEqual([t.kind for t in m203.name_hints["74"]], ["octet3"])
        # switch VLAN-domain rule: `vlan 3` / `name EVE-MGMT-204` on mgmt-80
        names_ = facts_of(a, "mgmt-80", kind="vlan_name", value="EVE-MGMT-204")
        self.assertTrue(names_)
        self.assertTrue(all(f.segment == "MGMT-204" for f in names_))
        # Forti remote-gw in INET-201 is a CORRELATED member
        rgw = [
            f
            for f in facts_of(a, "b1-fgt1", kind="peer_ip")
            if f.value == "10.100.201.31"
        ]
        self.assertEqual(
            [(f.segment, f.confidence) for f in rgw],
            [("INET-201", Confidence.CORRELATED)],
        )

    def test_backbone(self) -> None:
        a = self.need(disco.BACKBONE)
        mgmt = seg(a, "MGMT-203")
        self.assertEqual(len(mgmt.schemes), 3)
        s1, s2, s3 = (self.scheme(mgmt, i) for i in range(3))
        self.assertEqual(s1, (203, "172.21.203.0/24", "172.21.203.254"))
        self.assertIn("vxlan-dmvpn-backbone", mgmt.schemes[0].scopes)
        self.assertEqual(s2, (1103, "10.100.103.0/24", "10.100.103.1"))
        self.assertTrue({"startup", "vxlan-no-vpc"} <= mgmt.schemes[1].scopes)
        self.assertEqual(s3, ("untagged", "10.100.103.0/24", "10.100.103.1"))
        self.assertEqual(mgmt.schemes[2].scopes, {"vxlan-vpc"})
        for nid in ("59", "61", "74", "91", "123"):
            self.assertIn(nid, mgmt.network_ids)
        # outliers: c8kv-74 10.100.105.74 (vxlan-vpc) and bb-rr84 duplicating .83
        out_nodes = {
            a.facts[fid].node_id for sch in mgmt.schemes for fid in sch.outliers
        }
        self.assertEqual(out_nodes, {node_id(a, "c8kv-74"), node_id(a, "bb-rr84")})
        trunk = seg(a, "TRUNK")
        self.assertEqual(trunk.status, "CARRIER")
        self.assertEqual(sorted(trunk.network_ids), ["132", "137", "140", "152"])
        self.assertEqual(seg(a, "INET-201").network_ids, ["25", "78"])
        self.assertEqual(seg(a, "INET-201").status, "LABEL_ONLY")
        self.assertEqual(seg(a, "INET-202").network_ids, ["44", "117"])
        self.assertEqual(seg(a, "INET-202").status, "LABEL_ONLY")
        self.assertEqual(seg(a, "OUT-255").status, "DHCP")
        hints = " ".join(f.msg for f in a.findings if f.code == "MERGE_HINT")
        self.assertIn("204-31", hints)
        self.assertIn("out-255", hints)
        # orphan `switchport trunk allowed vlan 203` on b1-sw1 follows its SVI
        orphan = [f for f in facts_of(a, "b1-sw1", kind="vlan_list") if f.orphan]
        self.assertTrue(orphan)
        self.assertTrue(all(f.segment == "MGMT-203" for f in orphan))
        self.assertTrue(all(f.confidence == Confidence.CORRELATED for f in orphan))
        # implicit VLAN 203 on mgmt-79 (uncabled e0/3 flagged)
        e03 = [
            f
            for f in facts_of(a, "mgmt-79", kind="vlan_tag", iface="et0/3")
            if f.store.scope == "vxlan-dmvpn-backbone"
        ]
        self.assertTrue(e03)
        self.assertTrue(
            all("uncabled" in f.flags and f.segment == "MGMT-203" for f in e03)
        )
        # mirror sidecars copy the attribution of their blob
        mirrors = [
            f
            for f in a.facts.values()
            if f.store.kind == "sidecar" and f.kind == "ip_host" and f.segment
        ]
        self.assertTrue(mirrors)
        self.assertNotIn(203, a.protected_vlans["vxlan-dmvpn-backbone"])

    def test_backbone_with_manifest_fixture(self) -> None:
        path = disco.real_path(disco.BACKBONE)
        if path is None:
            self.skipTest("backbone lab absent")
        m = manifest_mod.load(
            TESTS_DIR / "fixtures" / "toml" / "manifest_backbone.toml"
        )
        d = discover(read_real(path), m)
        a = d.analysis
        mgmt = seg(a, "MGMT")
        self.assertEqual(mgmt.site_key, "site.mgmt_a")
        self.assertEqual(self.scheme(mgmt)[:2], (203, "172.21.203.0/24"))
        self.assertTrue(any("legacy scopes" in n for n in mgmt.notes))
        fw = next(s for s in a.segments if "60" in s.network_ids)
        self.assertTrue(any("[[merge]]" in n for n in fw.notes))
        self.assertEqual(seg(a, "TRUNK").carries, ["MGMT", "INET-201"])
        self.assertEqual(seg(a, "INET-201").site_key, "site.inet_a")

    def test_junos(self) -> None:
        a = self.need(disco.JUNOS)
        mgmt = seg(a, "MGMT")
        self.assertEqual(mgmt.network_ids, ["5", "13", "24", "58", "76"])
        self.assertEqual(
            self.scheme(mgmt), ("untagged", "10.100.240.0/20", "10.100.255.254")
        )
        self.assertEqual([t.kind for t in mgmt.name_hints["58"]], ["netid"])
        i1240 = seg(a, "INET-1240")
        self.assertEqual((i1240.network_ids, i1240.cloud_types), (["72"], {"pnet2"}))
        self.assertEqual(self.scheme(i1240)[:2], (1240, "172.31.240.0/24"))
        i1242 = seg(a, "INET-1242")
        self.assertEqual((i1242.network_ids, i1242.cloud_types), (["62"], {"pnet2"}))
        self.assertEqual(self.scheme(i1242)[0], 1242)
        internal = facts_of(a, "ISP-RTR9", kind="vlan_tag", iface="gi3.1240")
        self.assertEqual([f.segment for f in internal], [None])
        self.assertIn(1240, a.protected_vlans["startup"])
        self.assertIn(1241, a.protected_vlans["startup"])
        rid = [
            f
            for f in facts_of(a, "ISP-RTR9", kind="router_id")
            if f.value == "172.31.240.10"
        ]
        self.assertEqual([f.segment for f in rid], ["INET-1240"])
        unconf = " ".join(f.msg for f in a.findings if f.code == "UNCONFIGURED")
        self.assertIn("dc1-fw32 port8", unconf)

    def test_azure(self) -> None:
        a = self.need(disco.AZURE)
        inet, mgmt = seg(a, "INTERNET-105"), seg(a, "MGMT-104")
        self.assertEqual(inet.network_ids, ["1"])
        self.assertEqual(mgmt.network_ids, ["3"])
        self.assertEqual(self.scheme(inet)[:2], ("untagged", "10.100.105.0/24"))
        self.assertEqual(self.scheme(mgmt)[:2], ("untagged", "10.100.104.0/24"))
        self.assertNotEqual(inet.site_key, mgmt.site_key)

    def test_dhcp_and_label_only_labs(self) -> None:
        lab1 = self.need(disco.LAB1)
        s = seg(lab1, "INTERNET")
        self.assertEqual(
            (s.network_ids, s.status, s.cloud_types), (["58"], "DHCP", {"nat0"})
        )
        self.assertIn("DHCP_UPLINK", codes(lab1))
        nexus = self.need(disco.NEXUS_VPC)
        self.assertEqual(
            [(s.key, s.network_ids, s.status) for s in nexus.segments],
            [("INTERNET", ["6"], "DHCP")],
        )
        self.assertIn("CONFIG_NOT_PUSHED", codes(nexus))
        ei = self.need(disco.CCIE_EI)
        self.assertEqual(
            [(s.network_ids, s.status) for s in ei.segments], [(["22"], "LABEL_ONLY")]
        )

    def test_no_cloud_labs(self) -> None:
        for stem in disco.NO_CLOUD:
            d = disco.real(stem)
            if d is None:
                continue
            with self.subTest(stem):
                self.assertEqual(d.analysis.segments, [])
                self.assertIn("NO_CLOUDS", codes(d.analysis))
                self.assertTrue(
                    all(f.segment is None for f in d.analysis.facts.values())
                )

    def test_every_real_lab_is_consistent(self) -> None:
        for path in real_lab_paths():
            d = disco.real(path.stem)
            assert d is not None
            a = d.analysis
            with self.subTest(path.stem):
                keys = [s.key for s in a.segments]
                self.assertEqual(len(keys), len(set(keys)))
                nets = [n for s in a.segments for n in s.network_ids]
                self.assertEqual(len(nets), len(set(nets)))
                clouds = {n for n, net in a.networks.items() if net.is_cloud}
                self.assertEqual(set(nets), clouds)
                for s in a.segments:
                    self.assertRegex(s.key, r"^[A-Za-z][A-Za-z0-9_.-]*$")
                    for sch in s.schemes:
                        if sch.subnet and sch.gateway:
                            self.assertIn(sch.gateway, sch.subnet)


if __name__ == "__main__":
    unittest.main()
