"""Core scenarios: registry, param kinds, question relevance, labels (T16)."""

from __future__ import annotations

import unittest
from ipaddress import IPv4Address, IPv4Network

from evelab.localize import planner
from evelab.localize.model import Analysis, Segment
from evelab.localize.profile import BridgeProfile, Profile, SegmentAnswer
from evelab.localize.scenarios import (
    PARAM_KINDS,
    SCENARIOS,
    apply_answer,
    load_builtin,
    ordered,
    register_scenario,
)
from evelab.localize.scenarios.base import (
    PlanFragment,
    Question,
    Scenario,
    SubnetMap,
    ValueMaps,
    primary_label,
)
from evelab.localize.scenarios.labels import distinctive, label_renames

from . import disco

NET = IPv4Network
ADDR = IPv4Address


def seg(a: Analysis, key: str) -> Segment:
    return next(s for s in a.segments if s.key == key)


def qids(a: Analysis, prof: Profile | None = None) -> dict[str, Question]:
    return {q.id: q for q in planner.collect_questions(a, prof or Profile())}


class RegistryTest(unittest.TestCase):
    def test_core_scenarios_registered(self) -> None:
        load_builtin()
        for sid in ("bridge", "segment_l2", "segment_l3", "labels"):
            self.assertIn(sid, SCENARIOS)
            self.assertIsInstance(SCENARIOS[sid], Scenario)
        orders = [s.order for s in ordered()]
        self.assertEqual(orders, sorted(orders))

    def test_register_custom_scenario(self) -> None:
        @register_scenario
        class Dummy:
            id = "zz_dummy_test"
            order = 999

            def applies(self, a, m):
                return False

            def questions(self, a, m, prof):
                return []

            def plan(self, a, ans, maps):
                return PlanFragment()

        try:
            self.assertIn("zz_dummy_test", SCENARIOS)
            self.assertIs(ordered()[-1], SCENARIOS["zz_dummy_test"])
        finally:
            SCENARIOS.pop("zz_dummy_test", None)

    def test_param_kinds(self) -> None:
        for k in ("bridge", "vlan", "cidr", "ip", "label", "domain", "asn", "split"):
            self.assertIn(k, PARAM_KINDS)
        self.assertEqual(PARAM_KINDS["vlan"].parse("20"), 20)
        self.assertIsNotNone(PARAM_KINDS["vlan"].validate("4095", Profile()))
        self.assertIsNotNone(PARAM_KINDS["bridge"].validate("eth0", Profile()))
        prof = Profile()
        prof.bridges["br-lab"] = BridgeProfile()
        self.assertIsNone(PARAM_KINDS["bridge"].validate("br-lab", prof))
        self.assertEqual(
            PARAM_KINDS["split"].parse("10.0.1.0/24=192.168.0.0/25"),
            {NET("10.0.1.0/24"): NET("192.168.0.0/25")},
        )
        self.assertIsNotNone(PARAM_KINDS["domain"].validate("bad_domain!", prof))
        self.assertIsNotNone(PARAM_KINDS["asn"].validate("0", prof))


class ValueMapsTest(unittest.TestCase):
    def test_subnet_map(self) -> None:
        sm = SubnetMap(NET("10.100.240.0/20"), NET("192.168.48.0/24"))
        self.assertFalse(sm.fits())
        self.assertEqual(sm.map_host(ADDR("10.100.240.9")), ADDR("192.168.48.9"))
        self.assertIsNone(sm.map_host(ADDR("10.100.241.9")))
        self.assertIsNone(sm.map_host(ADDR("10.1.1.1")))
        sm2 = SubnetMap(NET("10.100.203.0/24"), NET("192.168.20.0/24"))
        self.assertEqual(
            sm2.map_net(NET("10.100.203.128/25")), NET("192.168.20.128/25")
        )

    def test_precedence_in_map_ip(self) -> None:
        m = ValueMaps()
        m.subnets["S"] = [SubnetMap(NET("10.0.0.0/24"), NET("10.9.0.0/24"))]
        m.gateways["S"] = {ADDR("10.0.0.1"): ADDR("10.9.0.254")}
        m.seg_exact["S"] = {ADDR("10.0.0.5"): ADDR("10.9.0.50")}
        m.exact_ips[ADDR("10.0.0.1")] = ADDR("10.9.0.100")
        self.assertEqual(m.map_ip("S", ADDR("10.0.0.7")), ADDR("10.9.0.7"))
        self.assertEqual(m.map_ip("S", ADDR("10.0.0.5")), ADDR("10.9.0.50"))
        self.assertEqual(m.map_ip("S", ADDR("10.0.0.1")), ADDR("10.9.0.100"))
        del m.exact_ips[ADDR("10.0.0.1")]
        self.assertEqual(m.map_ip("S", ADDR("10.0.0.1")), ADDR("10.9.0.254"))
        self.assertIsNone(m.map_ip("T", ADDR("10.0.0.7")))


class RelevanceTest(unittest.TestCase):
    """Questions follow facts (section 10.2): only feasible questions."""

    def test_l2lab_relevance(self) -> None:
        a = disco.mini("l2lab").analysis
        q = qids(a)
        sk = {s.key: s.site_key for s in a.segments}
        # LABEL_ONLY / DHCP: bridge + label only
        for key in ("EXT-LABEL", "INTERNET"):
            self.assertIn(f"{sk[key]}/bridge", q)
            self.assertIn(f"{sk[key]}/label", q)
            for kind in ("vlan", "subnet", "gateway"):
                self.assertNotIn(f"{sk[key]}/{kind}", q)
        # carrier: bridge (follows carried) but never a tag/subnet question
        self.assertIn(f"{sk['TRUNK']}/bridge", q)
        self.assertNotIn(f"{sk['TRUNK']}/vlan", q)
        self.assertNotIn(f"{sk['TRUNK']}/subnet", q)
        self.assertEqual(q[f"{sk['TRUNK']}/bridge"].default_source, "follows carried")
        # configurable tagged segment: everything
        for kind in ("bridge", "vlan", "subnet", "gateway", "label"):
            self.assertIn(f"{sk['INET-500']}/{kind}", q)
        vq = q[f"{sk['INET-500']}/vlan"]
        self.assertEqual(
            (vq.current, vq.default, vq.group), ("500", "500", "B VLAN tags")
        )
        # carried-only segments have no cloud networks: no bridge/label question
        self.assertNotIn(f"{sk['TRUNK-40']}/bridge", q)
        self.assertNotIn(f"{sk['TRUNK-40']}/label", q)
        # every question kind is registered
        self.assertTrue(all(x.kind in PARAM_KINDS for x in q.values()))
        # no split question until an answer does not fit
        self.assertFalse([x for x in q if x.endswith("/split")])

    def test_untagged_segment_has_no_tag_question(self) -> None:
        a = disco.mini("basic").analysis
        q = qids(a)
        mg = seg(a, "MGMT-203")
        self.assertEqual(mg.schemes[0].tag, "untagged")
        self.assertNotIn(f"{mg.site_key}/vlan", q)
        self.assertIn(f"{mg.site_key}/subnet", q)
        self.assertNotIn(f"{mg.site_key}/gateway", q, "no gateway discovered")

    def test_junos_internal_tags_never_asked(self) -> None:
        d = disco.real(disco.JUNOS)
        if d is None:
            self.skipTest("junos lab not present")
        a = d.analysis
        vlan_q = sorted(x for x in qids(a) if x.endswith("/vlan"))
        keys = {s.site_key: s.key for s in a.segments}
        asked = sorted(keys[x.rsplit("/", 1)[0]] for x in vlan_q)
        self.assertEqual(asked, ["INET-1240", "INET-1242"])
        for x in vlan_q:
            self.assertNotIn(qids(a)[x].current, ("1241", "1243"))

    def test_sdwan_questions(self) -> None:
        d = disco.real(disco.SDWAN)
        if d is None:
            self.skipTest("sdwan lab not present")
        a = d.analysis
        q = qids(a)
        sk = {s.key: s.site_key for s in a.segments}
        self.assertEqual(q[f"{sk['MGMT-203']}/vlan"].current, "2")
        self.assertEqual(q[f"{sk['MGMT-203']}/gateway"].current, "10.100.203.1")
        self.assertNotIn(f"{sk['TRUNK']}/vlan", q)
        self.assertGreater(q[f"{sk['MGMT-203']}/vlan"].affects, 20)

    def test_split_question_when_not_fitting(self) -> None:
        d = disco.real(disco.JUNOS)
        if d is None:
            self.skipTest("junos lab not present")
        a = d.analysis
        mg = seg(a, "MGMT")
        prof = Profile()
        prof.segments[mg.site_key] = SegmentAnswer(subnet=NET("192.168.48.0/24"))
        q = qids(a, prof)
        self.assertIn(f"{mg.site_key}/split", q)
        prof.segments[mg.site_key].subnet = NET("192.168.48.0/20")
        self.assertNotIn(f"{mg.site_key}/split", qids(a, prof))

    def test_legacy_question_only_when_asked(self) -> None:
        a = disco.mini("l2lab").analysis
        em = seg(a, "EXT-MGMT")
        self.assertGreater(len(em.schemes), 1)
        self.assertNotIn(f"{em.site_key}/legacy", qids(a))
        prof = Profile()
        prof.policy.legacy_scopes = "ask"
        q = qids(a, prof)
        self.assertIn(f"{em.site_key}/legacy", q)
        self.assertIsNone(apply_answer(prof, q[f"{em.site_key}/legacy"], "same"))
        prof.segments[em.site_key] = SegmentAnswer(vlan=70)
        maps, _ = planner.build_value_maps(a, prof)
        self.assertEqual(maps.tags[("EXT-MGMT", 10)], 70)
        self.assertEqual(maps.tags[("EXT-MGMT", 11)], 70)

    def test_no_clouds_no_questions(self) -> None:
        for stem in disco.NO_CLOUD:
            d = disco.real(stem)
            if d is not None:
                self.assertEqual(qids(d.analysis), {})


class AnswerFlowTest(unittest.TestCase):
    def test_apply_answer_and_validators(self) -> None:
        a = disco.mini("l2lab").analysis
        prof = Profile()
        q = qids(a, prof)
        sk = seg(a, "INET-500").site_key
        err = apply_answer(prof, q[f"{sk}/vlan"], "99")
        self.assertIsNotNone(err, "protected internal VLAN rejected")
        self.assertIn("protected", err or "")
        self.assertIsNone(apply_answer(prof, q[f"{sk}/vlan"], "31"))
        self.assertEqual(prof.segments[sk].vlan, 31)
        self.assertIsNotNone(apply_answer(prof, q[f"{sk}/subnet"], "10.99.0.0/24"))
        self.assertIsNone(apply_answer(prof, q[f"{sk}/subnet"], "198.18.0.0/24"))
        self.assertEqual(prof.segments[sk].subnet, NET("198.18.0.0/24"))
        q = qids(a, prof)
        self.assertEqual(q[f"{sk}/gateway"].default, "198.18.0.1")
        self.assertEqual(q[f"{sk}/gateway"].default_source, "same offset")
        self.assertIsNotNone(apply_answer(prof, q[f"{sk}/gateway"], "198.18.1.1"))
        isk = sk
        prof.bridges["pnet7"] = BridgeProfile(mode="untagged-only")
        self.assertIsNotNone(apply_answer(prof, q[f"{isk}/bridge"], "pnet7"))
        self.assertIsNotNone(apply_answer(prof, q[f"{isk}/bridge"], "eth0"))
        self.assertIsNone(apply_answer(prof, q[f"{isk}/bridge"], "pnet3"))
        self.assertEqual(prof.segments[isk].bridge, "pnet3")

    def test_bridge_default_from_role(self) -> None:
        a = disco.mini("l2lab").analysis
        prof = Profile()
        prof.roles["inet"] = "pnet3"
        q = qids(a, prof)
        bq = q[f"{seg(a, 'INET-500').site_key}/bridge"]
        self.assertEqual((bq.default, bq.default_source), ("pnet3", "role inet"))


class LabelsTest(unittest.TestCase):
    def test_distinctiveness(self) -> None:
        a = disco.mini("l2lab").analysis
        for label in ("EVE-MGMT-203", "INET-1240", "mgmt-203"):
            self.assertTrue(distinctive(label, a), label)
        for label in ("Internet", "Net", "mgmt", "trunk", "out", "EVE1", "Net-x1"):
            self.assertFalse(distinctive(label, a), label)

    def test_generic_label_not_propagated(self) -> None:
        a = disco.mini("l2lab").analysis
        inet = seg(a, "INTERNET")
        self.assertEqual(primary_label(inet), "Internet")
        prof = Profile()
        prof.segments[inet.site_key] = SegmentAnswer(label="Uplink-NAT")
        plan = planner.build_plan(a, prof)
        self.assertEqual({e.target for e in plan.edits}, {"xml_attr"})
        maps, _ = planner.build_value_maps(a, prof)
        self.assertNotIn("Internet", maps.text_labels)

    def test_template_suggestion_and_host_suffix(self) -> None:
        a = disco.mini("l2lab").analysis
        inet = seg(a, "INET-500")
        prof = Profile()
        prof.segments[inet.site_key] = SegmentAnswer(vlan=600)
        q = qids(a, prof)[f"{inet.site_key}/label"]
        self.assertEqual(q.default, "INET-600")
        self.assertTrue(q.default_source.startswith("template"))

    def test_templated_rename_keeps_shape(self) -> None:
        d = disco.real(disco.BACKBONE)
        if d is None:
            self.skipTest("backbone lab not present")
        a = d.analysis
        target = None
        for s in a.segments:
            names = set(s.labels.values())
            if len(names) > 1 and s.schemes and s.schemes[0].subnet is not None:
                target = s
                break
        if target is None:
            self.skipTest("no multi-name segment")
        sa = SegmentAnswer(label="SITE-X", subnet=NET("192.168.77.0/24"))
        old = target.schemes[0].subnet
        assert old is not None
        maps = ValueMaps()
        maps.subnets[target.key] = [SubnetMap(old, NET("192.168.77.0/24"))]
        ren = label_renames(a, target, sa, maps)
        primary = primary_label(target)
        for nid, new in ren.items():
            if target.labels[nid] == primary:
                self.assertEqual(new, "SITE-X")
            else:
                self.assertNotEqual(new, "SITE-X")
        for nid in ren:
            self.assertTrue(a.networks[nid].is_cloud)


if __name__ == "__main__":
    unittest.main()
