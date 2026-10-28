"""Planner: value maps, claims, precedence, conflicts, swaps, plan JSON (T18).

Real labs are only read; anything that writes works on temp copies.
"""

from __future__ import annotations

import atexit
import shutil
import tempfile
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from evelab.common.codec import decode_blob
from evelab.common.unl import RawLab
from evelab.localize import apply, planner
from evelab.localize.discover import analyse
from evelab.localize.model import Analysis, Confidence, Plan, Segment
from evelab.localize.profile import BridgeProfile, Profile, SegmentAnswer
from evelab.localize.scenarios.base import (
    PRIO_EXACT,
    PRIO_MEMBERSHIP,
    Claim,
    text_index,
)

from . import disco
from .labfiles import minilab_path

NET = IPv4Network
ADDR = IPv4Address


def seg(a: Analysis, key: str) -> Segment:
    return next(s for s in a.segments if s.key == key)


def answers(a: Analysis, **per_key: dict) -> Profile:
    """Profile with ``[segments."<site_key>"]`` answers keyed by segment key."""
    prof = Profile()
    for key, fields in per_key.items():
        sa = prof.segments.setdefault(seg(a, key).site_key, SegmentAnswer())
        for name, value in fields.items():
            setattr(sa, name, value)
    return prof


def codes(plan: Plan) -> set[str]:
    return {f.code for f in plan.findings}


def new_texts(plan: Plan, lab: RawLab) -> dict[tuple[str, str], str]:
    """Decoded texts after the plan: ``(scope, node id) -> text`` (+ sidecars)."""
    ch = apply.build_changes(plan, apply.ApplyOptions(), lab=lab)
    out: dict[tuple[str, str], str] = {}
    new_lab = RawLab.from_bytes(ch.unl.after, lab.path)
    for b in new_lab.config_blobs():
        dec = decode_blob(b.b64)
        if dec is not None:
            out[(b.scope, b.id)] = dec.text
    for fc in ch.files:
        if fc.kind == "sidecar":
            out[("sidecar", fc.path.name)] = fc.after.decode("utf-8")
    return out


def copy_real(stem: str) -> Path:
    src = disco.real_path(stem)
    assert src is not None
    tmp = Path(tempfile.mkdtemp(prefix="evelab-localize-t18-"))
    atexit.register(shutil.rmtree, tmp, True)  # suite-wide temp copy
    dst = tmp / src.name
    shutil.copyfile(src, dst)
    for d in src.parent.iterdir():
        if d.is_dir() and d.name.startswith(stem) and d.name.endswith("_cfgs"):
            shutil.copytree(d, tmp / d.name)
    return dst


def write_changes(plan: Plan, lab: RawLab) -> None:
    ch = apply.build_changes(plan, apply.ApplyOptions(), lab=lab)
    for fc in ch.files:
        fc.dest.write_bytes(fc.after)


class SwapTest(unittest.TestCase):
    """All edits come from the original text: A<->B never chains."""

    def test_tag_swap_l2lab(self) -> None:
        path = minilab_path("l2lab")
        lab = RawLab.read(path)
        a = analyse(lab)
        ans = answers(a, **{"EXT-MGMT": {"vlan": 30}, "SRV-NET": {"vlan": 10}})
        plan = planner.build_plan(a, ans)
        self.assertFalse(
            [f for f in plan.findings if f.severity in ("conflict", "error")],
            plan.findings,
        )
        pairs = {
            (e.text_edit.old, e.text_edit.new)
            for e in plan.edits
            if e.category == "vlan"
        }
        self.assertIn(("10", "30"), pairs)
        self.assertIn(("30", "10"), pairs)
        before = {
            (b.scope, b.id): decode_blob(b.b64).text  # type: ignore[union-attr]
            for b in lab.config_blobs()
            if decode_blob(b.b64) is not None
        }
        after = new_texts(plan, lab)
        sw = before[("startup", "1")]
        sw_after = after[("startup", "1")]
        self.assertIn("vlan 10\n", sw)
        # each definition swapped exactly once (no 10 -> 30 -> 10 chain)
        self.assertEqual(sw.count("vlan 10\n"), sw_after.count("vlan 30\n"))
        self.assertEqual(sw.count("vlan 30\n"), sw_after.count("vlan 10\n"))
        self.assertIn("interface Vlan30", sw_after)
        self.assertNotIn("interface Vlan10", sw_after)
        # legacy scheme (alt: tag 11) left alone by default
        self.assertIn("LEGACY_LEFT", codes(plan))
        self.assertEqual(
            before[("cs:alt", "1")].count("vlan 11"),
            after[("cs:alt", "1")].count("vlan 11"),
        )

    def test_tag_swap_sdwan(self) -> None:
        d = disco.real(disco.SDWAN)
        if d is None:
            self.skipTest("sdwan lab not present")
        a = d.analysis
        ans = answers(a, **{"MGMT-203": {"vlan": 3}, "MGMT-204": {"vlan": 2}})
        plan = planner.build_plan(a, ans)
        self.assertFalse(plan.blocked, list(plan.findings))
        by_fact = {}
        for e in plan.edits:
            for fid in e.provenance[1].split(","):
                by_fact.setdefault(fid, []).append(e)
        for f in a.facts.values():
            if f.kind not in ("vlan_tag", "vlan_def") or "outlier" in f.flags:
                continue
            if f.segment == "MGMT-203" and f.value == "2":
                self.assertEqual(by_fact[f.id][0].text_edit.new, "3", f)
            if f.segment == "MGMT-204" and f.value == "3":
                self.assertEqual(by_fact[f.id][0].text_edit.new, "2", f)
        lab = d.analysis.lab
        after = new_texts(plan, lab)
        # Gi16.2 sub-interfaces renamed exactly once (.2 -> .3, never .3 -> .2 again)
        for b in lab.config_blobs():
            dec = decode_blob(b.b64)
            if dec is None or "GigabitEthernet16.2\n" not in dec.text:
                continue
            new = after[(b.scope, b.id)]
            self.assertEqual(
                dec.text.count("interface GigabitEthernet16.2\n"),
                new.count("interface GigabitEthernet16.3\n"),
            )
            self.assertNotIn("interface GigabitEthernet16.2\n", new)

    def test_subnet_swap(self) -> None:
        a = disco.mini("l2lab").analysis
        ans = answers(
            a,
            **{
                "INET-500": {"subnet": NET("203.0.113.0/24")},
                "SRV-NET": {"subnet": NET("100.64.5.0/24")},
            },
        )
        plan = planner.build_plan(a, ans)
        self.assertNotIn("SUBNET_OVERLAP", codes(plan))
        ips = [e for e in plan.edits if e.category in ("ip", "gateway")]
        self.assertTrue(ips)
        for e in ips:
            old, new = ADDR(e.text_edit.old), ADDR(e.text_edit.new)
            if old in NET("100.64.5.0/24"):
                self.assertIn(new, NET("203.0.113.0/24"))
            else:
                self.assertIn(old, NET("203.0.113.0/24"))
                self.assertIn(new, NET("100.64.5.0/24"))
            self.assertEqual(int(old) & 0xFF, int(new) & 0xFF)


class BlockerTest(unittest.TestCase):
    def test_vlan_collision_with_protected_is_blocked(self) -> None:
        a = disco.mini("l2lab").analysis
        self.assertIn(99, a.protected_vlans["startup"])
        plan = planner.build_plan(a, answers(a, **{"SRV-NET": {"vlan": 99}}))
        self.assertIn("VLAN_PROTECTED", codes(plan))
        self.assertTrue(plan.blocked)

    def test_vlan_collision_sdwan_internal_3101(self) -> None:
        d = disco.real(disco.SDWAN)
        if d is None:
            self.skipTest("sdwan lab not present")
        a = d.analysis
        plan = planner.build_plan(a, answers(a, **{"INET-201": {"vlan": 3101}}))
        self.assertIn("VLAN_PROTECTED", codes(plan))
        self.assertTrue(plan.blocked)

    def test_internal_reuse_of_external_tag_untouched(self) -> None:
        a = disco.mini("l2lab").analysis
        plan = planner.build_plan(a, answers(a, **{"INET-500": {"vlan": 501}}))
        self.assertFalse(plan.blocked, plan.findings)
        internal = {
            f.id
            for f in a.facts.values()
            if f.segment is None and f.value in ("500", "Ethernet0/2.500")
        }
        self.assertTrue(internal)
        touched = {fid for e in plan.edits for fid in e.provenance[1].split(",")}
        self.assertFalse(internal & touched)
        self.assertEqual(
            sorted(e.text_edit.new for e in plan.edits if e.category == "vlan"),
            ["501", "501"],
        )

    def test_vlan_duplicate_on_bridge(self) -> None:
        d = disco.real(disco.SDWAN)
        if d is None:
            self.skipTest("sdwan lab not present")
        a = d.analysis
        plan = planner.build_plan(a, answers(a, **{"INET-201": {"vlan": 202}}))
        self.assertIn("VLAN_DUPLICATE", codes(plan))

    def test_tagged_segment_to_untagged_only_bridge(self) -> None:
        a = disco.mini("l2lab").analysis
        ans = answers(a, **{"INET-500": {"bridge": "pnet7"}})
        ans.bridges["pnet7"] = BridgeProfile(mode="untagged-only")
        plan = planner.build_plan(a, ans)
        self.assertIn("STRUCTURAL_TAGGING", codes(plan))
        self.assertFalse([e for e in plan.edits if e.category == "cloud"])

    def test_split_required(self) -> None:
        d = disco.real(disco.JUNOS)
        if d is None:
            self.skipTest("junos lab not present")
        a = d.analysis
        plan = planner.build_plan(
            a, answers(a, MGMT={"subnet": NET("192.168.48.0/24")})
        )
        self.assertIn("SPLIT_REQUIRED", codes(plan))
        self.assertTrue(plan.blocked)
        split = {
            NET("10.100.241.0/24"): NET("192.168.48.0/25"),
            NET("10.100.243.0/24"): NET("192.168.48.128/25"),
        }
        plan2 = planner.build_plan(
            a,
            answers(
                a,
                MGMT={
                    "subnet": NET("192.168.48.0/24"),
                    "split": split,
                    "gateway": ADDR("192.168.48.254"),
                },
            ),
        )
        self.assertNotIn("SPLIT_REQUIRED", codes(plan2))
        self.assertFalse(plan2.blocked, plan2.findings)
        news = {e.text_edit.old: e.text_edit.new for e in plan2.edits}
        self.assertEqual(news["10.100.241.11"], "192.168.48.11")
        self.assertEqual(news["10.100.243.12"], "192.168.48.140")
        self.assertEqual(news["10.100.255.254"], "192.168.48.254")
        masks = [e for e in plan2.edits if e.category == "mask"]
        self.assertTrue(masks, "the /20 host masks follow the answered /24")
        self.assertTrue(all(e.text_edit.new.lstrip("/") == "24" for e in masks))

    def test_subnet_overlap_with_protected(self) -> None:
        a = disco.mini("l2lab").analysis
        plan = planner.build_plan(
            a, answers(a, **{"INET-500": {"subnet": NET("10.99.0.0/24")}})
        )
        self.assertIn("SUBNET_OVERLAP", codes(plan))

    def test_gateway_outside_subnet(self) -> None:
        a = disco.mini("l2lab").analysis
        plan = planner.build_plan(
            a,
            answers(
                a,
                **{
                    "INET-500": {
                        "subnet": NET("100.64.6.0/24"),
                        "gateway": ADDR("100.64.7.1"),
                    }
                },
            ),
        )
        self.assertIn("GATEWAY_INVALID", codes(plan))


class ClaimsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.a = disco.mini("l2lab").analysis
        self.fact = next(
            f
            for f in self.a.facts.values()
            if f.segment == "INET-500" and f.kind == "ip_host"
        )

    def claim(self, new: str, prio: int = PRIO_MEMBERSHIP, **kw: object) -> Claim:
        f = self.fact
        base = {
            "store": f.store,
            "node_id": f.node_id,
            "start": f.span.start,
            "end": f.span.end,
            "old": f.value,
            "new": new,
            "category": "ip",
            "group": "INET-500/ip",
            "confidence": Confidence.PROVEN,
            "fact_ids": (f.id,),
            "priority": prio,
        }
        base.update(kw)
        return Claim(**base)  # type: ignore[arg-type]

    def test_precedence_dedupe_conflict(self) -> None:
        won, fnd = planner.resolve_claims(
            self.a, [self.claim("1.1.1.1"), self.claim("2.2.2.2", PRIO_EXACT)]
        )
        self.assertEqual([c.new for c in won], ["2.2.2.2"])
        self.assertFalse(fnd)
        won, fnd = planner.resolve_claims(
            self.a, [self.claim("1.1.1.1"), self.claim("1.1.1.1", fact_ids=("x",))]
        )
        self.assertEqual(len(won), 1)
        self.assertEqual(set(won[0].fact_ids), {self.fact.id, "x"})
        won, fnd = planner.resolve_claims(
            self.a, [self.claim("1.1.1.1"), self.claim("2.2.2.2")]
        )
        self.assertFalse(won)
        self.assertEqual([f.code for f in fnd], ["CLAIM_CONFLICT"])

    def test_overlap_and_deletion(self) -> None:
        f = self.fact
        wide = self.claim("x", start=f.span.start, end=f.span.end + 1, old=None)
        t = text_index(self.a).text(f.store, f.node_id)
        assert t is not None
        wide.old = t[f.span.start : f.span.end + 1]
        won, fnd = planner.resolve_claims(self.a, [wide, self.claim("1.1.1.1")])
        self.assertFalse(won)
        self.assertIn("CLAIM_OVERLAP", {x.code for x in fnd})
        wide.new = ""
        won, fnd = planner.resolve_claims(self.a, [wide, self.claim("1.1.1.1")])
        self.assertEqual([c.new for c in won], [""])
        self.assertFalse(fnd)

    def test_protected_fact_is_hard_error(self) -> None:
        f = next(
            x
            for x in self.a.facts.values()
            if x.segment is None and x.kind == "vlan_tag" and x.value == "99"
        )
        c = Claim(
            store=f.store,
            node_id=f.node_id,
            start=f.span.start,
            end=f.span.end,
            old=f.value,
            new="98",
            category="vlan",
            group="x/vlan",
            confidence=Confidence.PROVEN,
            fact_ids=(f.id,),
            rule=f.rule,
        )
        won, fnd = planner.resolve_claims(self.a, [c])
        self.assertFalse(won)
        self.assertEqual(fnd[0].code, "PROTECTED_EDIT")
        self.assertEqual(fnd[0].severity, "error")
        self.assertIn(f.rule, fnd[0].msg)

    def test_stale_claim(self) -> None:
        won, fnd = planner.resolve_claims(self.a, [self.claim("1.1.1.1", old="9.9")])
        self.assertFalse(won)
        self.assertEqual(fnd[0].code, "STALE_CLAIM")

    def test_host_override_beats_gateway_and_offset(self) -> None:
        a = self.a
        gw = seg(a, "INET-500").schemes[0].gateway
        assert gw is not None
        ans = answers(
            a,
            **{
                "INET-500": {
                    "subnet": NET("100.64.6.0/24"),
                    "gateway": ADDR("100.64.6.254"),
                    "hosts": {gw: ADDR("100.64.6.200")},
                }
            },
        )
        plan = planner.build_plan(a, ans)
        news = {e.text_edit.new for e in plan.edits if e.text_edit.old == str(gw)}
        self.assertEqual(news, {"100.64.6.200"})
        maps, _ = planner.build_value_maps(a, ans)
        self.assertEqual(maps.map_ip("INET-500", gw), ADDR("100.64.6.200"))
        self.assertEqual(
            maps.map_ip("INET-500", ADDR("100.64.5.7")), ADDR("100.64.6.7")
        )


class IdempotencyTest(unittest.TestCase):
    def test_minilab_rerun_zero_edits(self) -> None:
        path = minilab_path("l2lab")
        lab = RawLab.read(path)
        a = analyse(lab)
        ans = answers(
            a,
            **{
                "INET-500": {"vlan": 501, "subnet": NET("100.64.50.0/24")},
                "EXT-MGMT": {"bridge": "pnet1"},
            },
        )
        plan = planner.build_plan(a, ans)
        self.assertTrue(planner.enabled_edits(plan))
        write_changes(plan, lab)
        a2 = analyse(RawLab.read(path))
        plan2 = planner.build_plan(a2, ans)
        self.assertEqual(planner.enabled_edits(plan2), [])
        # the unanswered label follows its template with the new tag (INET-501)
        self.assertEqual(seg(a2, "INET-501").schemes[0].tag, 501)

    def test_real_lab_rerun_zero_edits(self) -> None:
        if disco.real_path(disco.SDWAN) is None:
            self.skipTest("sdwan lab not present")
        path = copy_real(disco.SDWAN)
        lab = RawLab.read(path)
        a = analyse(lab)
        ans = answers(
            a,
            **{
                "MGMT-203": {"vlan": 20, "subnet": NET("192.168.20.0/24")},
                "MGMT-204": {"vlan": 30, "subnet": NET("192.168.30.0/24")},
                "INET-202": {"bridge": "pnet3", "vlan": 302},
            },
        )
        plan = planner.build_plan(a, ans)
        self.assertFalse(plan.blocked, plan.findings)
        self.assertGreater(len(plan.edits), 100)
        write_changes(plan, lab)
        a2 = analyse(RawLab.read(path))
        self.assertEqual(planner.enabled_edits(planner.build_plan(a2, ans)), [])
        # the unanswered label follows its template (EVE-MGMT-203 -> EVE-MGMT-20)
        self.assertEqual(str(seg(a2, "MGMT-20").schemes[0].subnet), "192.168.20.0/24")


class SidecarOffsetsTest(unittest.TestCase):
    def test_crlf_sidecar_edit(self) -> None:
        path = minilab_path("crlf_sidecar")
        lab = RawLab.read(path)
        a = analyse(lab)
        plan = planner.build_plan(
            a, answers(a, **{"MGMT-203": {"subnet": NET("192.168.7.0/24")}})
        )
        side = [e for e in plan.edits if e.target == "sidecar"]
        self.assertEqual(len(side), 1)
        ch = apply.build_changes(plan, apply.ApplyOptions(), lab=lab)
        fc = next(f for f in ch.files if f.kind == "sidecar")
        self.assertIn(b"192.168.7.21", fc.after)
        self.assertEqual(fc.before.count(b"\r\n"), fc.after.count(b"\r\n"))
        self.assertEqual(fc.before.replace(b"10.100.51.21", b"192.168.7.21"), fc.after)


class PlanShapeTest(unittest.TestCase):
    def setUp(self) -> None:
        d = disco.real(disco.SDWAN)
        if d is None:
            self.skipTest("sdwan lab not present")
        self.a = d.analysis
        self.ans = answers(
            self.a,
            **{
                "INET-202": {"bridge": "pnet3", "label": "SITE-INET-302", "vlan": 302},
            },
        )

    def test_groups_cosmetic_and_heuristic(self) -> None:
        plan = planner.build_plan(self.a, self.ans)
        groups = {e.group for e in plan.edits}
        self.assertIn("INET-202/cloud", plan.enabled_groups)
        self.assertIn("cosmetic/pnet-text", groups)
        self.assertIn("cosmetic/label-text", plan.enabled_groups)
        self.ans.policy.cosmetic_text = False
        plan2 = planner.build_plan(self.a, self.ans)
        self.assertFalse({g for g in plan2.enabled_groups if g.startswith("cosmetic/")})
        self.assertLess(
            len(planner.enabled_edits(plan2)), len(planner.enabled_edits(plan))
        )
        filtered = planner.filter_enabled(plan2)
        self.assertTrue(all(e.group in plan2.enabled_groups for e in filtered.edits))
        for e in plan.edits:
            if e.confidence == Confidence.HEURISTIC:
                self.assertTrue(e.group.endswith(planner.HEURISTIC_SUFFIX))
                self.assertNotIn(e.group, plan.enabled_groups)

    def test_ambiguous_cloud_ref_skipped(self) -> None:
        plan = planner.build_plan(self.a, self.ans)
        pnet = [e for e in plan.edits if e.group == "cosmetic/pnet-text"]
        self.assertTrue(pnet)
        self.assertTrue(all(e.text_edit.new == "pnet3" for e in pnet))
        self.assertIn("AMBIGUOUS_CLOUD_REF", codes(plan))
        texts = {(ct.store, ct.node_id): ct.text for ct in self.a.texts}
        for e in pnet:
            if e.target != "blob":
                continue
            t = texts[(e.store, e.node_id)]
            line = t[t.rfind("\n", 0, e.text_edit.start) + 1 :].split("\n", 1)[0]
            self.assertIn("EVE-INET-202", line)

    def test_label_text_propagation(self) -> None:
        plan = planner.build_plan(self.a, self.ans)
        lab_edits = [e for e in plan.edits if e.text_edit.old == "EVE-INET-202"]
        targets = {e.target for e in lab_edits}
        self.assertIn("xml_attr", targets)
        self.assertTrue(targets - {"xml_attr"}, "descriptions follow the label")
        self.assertTrue(all(e.text_edit.new == "SITE-INET-302" for e in lab_edits))

    def test_json_roundtrip_and_explain(self) -> None:
        plan = planner.build_plan(self.a, self.ans)
        text = planner.dumps_plan(plan)
        back = planner.loads_plan(text)
        self.assertEqual(len(back.edits), len(plan.edits))
        self.assertEqual(back.enabled_groups, plan.enabled_groups)
        self.assertEqual(back.base_sha256, plan.base_sha256)
        self.assertEqual(apply.plan_digest(back), apply.plan_digest(plan))
        self.assertIn(self.a.lab.path.name, plan.base_sha256)
        self.assertTrue(any("/" in k for k in plan.base_sha256), "sidecars hashed")
        e = next(x for x in plan.edits if x.category == "vlan")
        lines = planner.explain(plan, e.id)
        self.assertTrue(lines[0].startswith(f"edit {e.id}"))
        self.assertTrue(any(x.startswith("question: ") for x in lines))
        self.assertTrue(any(x.startswith("rule: ") for x in lines))
        with self.assertRaises(KeyError):
            planner.explain(plan, "nope")

    def test_answers_digest_stable(self) -> None:
        p1 = planner.build_plan(self.a, self.ans)
        p2 = planner.build_plan(self.a, self.ans)
        self.assertEqual(p1.answers_digest, p2.answers_digest)
        self.assertEqual([e.id for e in p1.edits], [e.id for e in p2.edits])

    def test_empty_answers_no_edits(self) -> None:
        plan = planner.build_plan(self.a, Profile())
        self.assertEqual(plan.edits, [])
        self.assertFalse(plan.blocked)


class NoCloudTest(unittest.TestCase):
    def test_no_cloud_labs(self) -> None:
        for stem in disco.NO_CLOUD:
            d = disco.real(stem)
            if d is None:
                continue
            plan = planner.build_plan(d.analysis, Profile())
            self.assertEqual(plan.edits, [])
            self.assertEqual(planner.collect_questions(d.analysis, Profile()), [])

    def test_skip_segment(self) -> None:
        a = disco.mini("l2lab").analysis
        plan = planner.build_plan(
            a, answers(a, **{"INET-500": {"vlan": 501, "skip": True}})
        )
        self.assertEqual(plan.edits, [])


class RoleDefaultTest(unittest.TestCase):
    def test_role_default_and_carrier_follow(self) -> None:
        d = disco.real(disco.SDWAN)
        if d is None:
            self.skipTest("sdwan lab not present")
        a = d.analysis
        ans = Profile()
        ans.roles["mgmt"] = "pnet1"
        maps, _ = planner.build_value_maps(a, ans)
        self.assertEqual(maps.bridges.get("MGMT-203"), "pnet1")
        self.assertEqual(maps.bridges.get("MGMT-204"), "pnet1")
        self.assertEqual(maps.bridges.get("TRUNK"), "pnet1", "carrier follows")
        self.assertNotIn("INET-201", maps.bridges)


if __name__ == "__main__":
    unittest.main()
