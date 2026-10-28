"""Review fixes, group l3-validation (findings 2, 3, 20, 21).

* profile / TOML answers run through the prompt validators (``BAD_ANSWER``);
  a gateway equal to a mapped host address is rejected;
* overlapping subnets and partial split maps are rejected at question time, and
  a blocked interactive plan goes back to the offending segment's questions;
* the gateway default after a subnet change is always a host of the new subnet;
* an ACL wildcard next to a rewritten address follows the new prefix length.

Lab runs use temp copies (``test_cli.Tree``); nothing under ``labs/`` is written.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from evelab.common.textutil import (
    mask_form_of,
    mask_prefix_as,
    mask_render,
    prefix_to_hostmask,
)
from evelab.localize.dialects.base import PatternRule, RenderCtx, RuleDialect
from evelab.localize.model import ConfigText, Store
from evelab.localize.profile import Profile, SegmentAnswer
from evelab.localize.scenarios import apply_answer
from evelab.localize.scenarios.segment_l3 import default_gateway

from . import disco
from .test_cli import JUNOS, SDWAN, TreeCase, _real
from .test_scenarios_core import qids, seg

NET = IPv4Network
ADDR = IPv4Address


def _junos():
    d = disco.real(disco.JUNOS)
    if d is None:
        raise unittest.SkipTest("junos lab not present")
    return d.analysis


class PinnedCase(TreeCase):
    """A temp tree whose lab copies keep their ``*.localize.toml`` manifest."""

    def setUp(self) -> None:
        super().setUp()
        for frag, dest in self.t.labs.items():
            src = _real(frag).with_suffix(".localize.toml")
            if src.is_file():
                shutil.copyfile(src, dest.with_suffix(".localize.toml"))


# --------------------------------------------------------------- finding 2


class AnsweredValuesValidatedTest(PinnedCase):
    labs = (SDWAN,)

    def _plan(self, body: str) -> tuple[int, str, str]:
        answers = self.t.write("a.toml", "schema = 1\n" + body)
        return self.t.run(
            "plan", "--lab", SDWAN, "--answers", str(answers), "--non-interactive"
        )

    def test_toml_gateway_outside_subnet_is_bad_answer(self) -> None:
        code, out, err = self._plan(
            '[segments."site.mgmt_a"]\ngateway = "10.100.9.1"\n'
        )
        self.assertEqual(code, 1, out + err)
        self.assertIn("BAD_ANSWER", err)
        self.assertIn("outside 10.100.203.0/24", err)

    def test_toml_gateway_broadcast_is_bad_answer(self) -> None:
        code, out, err = self._plan(
            '[segments."site.mgmt_a"]\ngateway = "10.100.203.255"\n'
        )
        self.assertEqual(code, 1, out + err)
        self.assertIn("broadcast", err)

    def test_toml_gateway_equal_to_a_device_is_bad_answer(self) -> None:
        # 10.100.203.14 is dc1-leaf2's own management address
        code, out, err = self._plan(
            '[segments."site.mgmt_a"]\ngateway = "10.100.203.14"\n'
        )
        self.assertEqual(code, 1, out + err)
        self.assertIn("BAD_ANSWER", err)
        self.assertIn("mapped address of baseline host 10.100.203.14", err)

    def test_valid_toml_gateway_still_plans(self) -> None:
        code, out, err = self._plan(
            '[segments."site.mgmt_a"]\ngateway = "10.100.203.254"\n'
        )
        self.assertEqual(code, 0, out + err)


class GatewayHostCollisionTest(unittest.TestCase):
    def test_gateway_on_a_mapped_host_rejected_interactively_too(self) -> None:
        a = _junos()
        mg = seg(a, "MGMT")
        prof = Profile()
        prof.segments[mg.site_key] = SegmentAnswer(subnet=NET("10.200.240.0/20"))
        q = qids(a, prof)[f"{mg.site_key}/gateway"]
        # 10.100.241.11 moves to 10.200.241.11 (same offset)
        err = apply_answer(prof, q, "10.200.241.11")
        self.assertIsNotNone(err)
        self.assertIn("10.100.241.11", err or "")
        self.assertIsNone(apply_answer(prof, q, "10.200.255.253"))


# -------------------------------------------------------------- finding 20


class OverlapAndSplitAtQuestionTimeTest(unittest.TestCase):
    def test_subnet_overlapping_another_answer_rejected(self) -> None:
        a = _junos()
        i40, i42 = seg(a, "INET-1240"), seg(a, "INET-1242")
        prof = Profile()
        q = qids(a, prof)
        self.assertIsNone(
            apply_answer(prof, q[f"{i40.site_key}/subnet"], "192.168.50.0/24")
        )
        q = qids(a, prof)
        err = apply_answer(prof, q[f"{i42.site_key}/subnet"], "192.168.50.0/24")
        self.assertIsNotNone(err)
        self.assertIn("INET-1240", err or "")
        self.assertIsNone(
            apply_answer(prof, q[f"{i42.site_key}/subnet"], "192.168.51.0/24")
        )

    def test_partial_split_rejected_full_split_accepted(self) -> None:
        a = _junos()
        mg = seg(a, "MGMT")
        prof = Profile()
        prof.segments[mg.site_key] = SegmentAnswer(
            subnet=NET("192.168.10.0/24"), gateway=ADDR("192.168.10.254")
        )
        q = qids(a, prof)[f"{mg.site_key}/split"]
        # every lost /24 is listed in the note, not only the first 8 hosts
        self.assertIn("10.100.243.0/24", " ".join(q.notes))
        err = apply_answer(prof, q, "10.100.241.0/24=192.168.10.0/24")
        self.assertIsNotNone(err)
        self.assertIn("10.100.243.0/24: 8", err or "")
        self.assertIsNone(
            apply_answer(
                prof,
                q,
                "10.100.241.0/24=192.168.10.0/25,10.100.243.0/24=192.168.10.128/25",
            )
        )


class BlockedPlanRevisesInteractivelyTest(TreeCase):
    labs = (JUNOS,)

    def test_split_required_goes_back_to_the_segment(self) -> None:
        a = _junos()
        sk = seg(a, "MGMT").site_key
        answers = self.t.write(
            "a.toml",
            "schema = 1\n"
            f'[segments."{sk}"]\n'
            'subnet = "192.168.10.0/24"\n'
            'gateway = "192.168.10.254"\n'
            'split = { "10.100.241.0/24" = "192.168.10.0/24" }\n',
        )
        before = self.t.snapshot()
        argv = ("plan", "--lab", JUNOS, "--answers", str(answers))
        # pass 1: Enter everywhere; the partial split blocks the plan and the
        # user is offered to revise MGMT (EOF then quits)
        _, out, err = self.t.run(*argv, stdin="y\n" + "\n" * 60, interactive=True)
        self.assertIn("SPLIT_REQUIRED", out + err)
        self.assertIn("Revise the answers for MGMT?", out)
        # pass 2: same replies up to the revise question, accept it, Enter
        # through the MGMT bridge/subnet/gateway, answer a full split, quit
        full = "10.100.241.0/24=192.168.10.0/25,10.100.243.0/24=192.168.10.128/25"
        stdin = _until_revise(out) + "y\n\n\n\n" + full + "\nq\n"
        _, out, err = self.t.run(*argv, stdin=stdin, interactive=True)
        tail = out.split("Revise the answers for MGMT?", 1)[1]
        self.assertIn("split map", tail)
        self.assertIn("0 blockers", tail)
        self.assertNotIn("SPLIT_REQUIRED", tail)
        self.assertEqual(before, self.t.snapshot())


def _until_revise(out: str) -> str:
    """Replies (all Enter) for every prompt shown before the revise question."""
    head = out.split("Revise the answers for MGMT?", 1)[0]
    prompts = head.count("): ") + head.count("]: ")
    return "y\n" + "\n" * max(0, prompts - 1)


# -------------------------------------------------------------- finding 21


class GatewayDefaultAfterSubnetChangeTest(unittest.TestCase):
    def test_default_gateway_helper(self) -> None:
        old = NET("10.100.240.0/20")
        self.assertEqual(
            default_gateway(ADDR("10.100.255.254"), old, NET("192.168.10.0/24")),
            ("192.168.10.254", "same offset from top"),
        )
        self.assertEqual(
            default_gateway(ADDR("10.100.240.1"), old, NET("10.200.0.0/20")),
            ("10.200.0.1", "same offset"),
        )
        # far from either end: clamp by side
        self.assertEqual(
            default_gateway(ADDR("10.100.250.1"), old, NET("192.168.10.0/24")),
            ("192.168.10.254", "last host"),
        )
        self.assertEqual(
            default_gateway(ADDR("10.100.241.1"), old, NET("192.168.10.0/24")),
            ("192.168.10.1", "first host"),
        )
        self.assertEqual(
            default_gateway(ADDR("10.100.241.1"), old, NET("192.168.10.0/31")),
            (None, "required"),
        )

    def test_junos_shrunk_mgmt_gateway_default_is_valid(self) -> None:
        a = _junos()
        mg = seg(a, "MGMT")
        prof = Profile()
        prof.segments[mg.site_key] = SegmentAnswer(subnet=NET("192.168.10.0/24"))
        q = qids(a, prof)[f"{mg.site_key}/gateway"]
        self.assertEqual(q.default, "192.168.10.254")
        self.assertEqual(q.default_source, "same offset from top")
        self.assertIsNone(q.validate(q.default or "", prof))


# --------------------------------------------------------------- finding 3


class WildcardMaskTest(unittest.TestCase):
    def test_textutil_wildcard_form(self) -> None:
        self.assertEqual(mask_form_of("0.0.0.255"), "wildcard")
        self.assertEqual(mask_form_of("255.255.255.0"), "dotted")
        self.assertEqual(mask_prefix_as("0.0.1.255", "wildcard"), 23)
        self.assertEqual(mask_prefix_as("0.0.0.0", "wildcard"), 32)
        self.assertEqual(mask_render("wildcard", 23), "0.0.1.255")
        self.assertEqual(prefix_to_hostmask(32), "0.0.0.0")

    def test_rule_wildcard_rendered_with_new_prefix(self) -> None:
        class Acl(RuleDialect):
            name = "test_acl_wildcard"
            templates = ()
            rules = (
                PatternRule(
                    "t.acl",
                    r"^\s+\d+ deny ip any (?P<v>IPV4) (?P<wildcard>IPV4)\s*$",
                    "ip_host",
                ),
                PatternRule(
                    "t.acl_mask",
                    r"^\s+\d+ permit ip any (?P<v>IPV4) (?P<mask>MASK)\s*$",
                    "ip_host",
                ),
            )

        text = (
            "ip access-list extended X\n"
            " 10 deny ip any 192.168.10.0 0.0.0.255\n"
            " 20 permit ip any 192.168.20.0 0.0.0.255\n"
        )
        d = Acl()
        ct = ConfigText(
            store=Store("startup", "startup", "startup"),
            node_id="1",
            text=text,
            dialect=d.name,
            blob=None,
            path=None,
        )
        facts = {f.rule: f for f in d.parse(ct).facts}
        for rid in ("t.acl", "t.acl_mask"):
            f = facts[rid]
            self.assertEqual(f.mask_form, "wildcard", rid)
            edits = d.render(f, f.value, RenderCtx(text, new_prefix=23))
            self.assertEqual([e.new for e in edits], ["0.0.1.255"], rid)


_ACL_RULE = """
[[rule]]
id = "test.acl_any_to_net"
kind = "ip_host"
dialects = ["iosxe"]
pattern = "^\\\\s+\\\\d+ (?:deny|permit) ip any (?P<v>IPV4) (?P<wildcard>IPV4)\\\\s*$"
"""


def _inject_acl(lab: Path) -> None:
    """Add an extended ACL on the INET-201 subnet to c8kv-75 (temp copy only).

    The lab itself lost its ``permit ip any 10.100.201.0 0.0.0.255`` ACL in the
    per-provider VRF rework (32d9b62); the finding's scenario is rebuilt here.
    """
    raw = lab.read_text(encoding="utf-8")

    def add(m: re.Match[str]) -> str:
        text = base64.b64decode(m.group(2)).decode("utf-8")
        if "ip access-list standard FGT-LEGS" not in text:
            return m.group(0)
        text = text.replace(
            "ip access-list standard FGT-LEGS\n",
            "ip access-list extended INET-IN\n"
            " 10 permit ip any 10.100.201.0 0.0.0.255\n"
            "ip access-list standard FGT-LEGS\n",
        )
        enc = base64.b64encode(text.encode("utf-8")).decode("ascii")
        return m.group(1) + enc + m.group(3)

    new = re.sub(r'(<config id="75">)([A-Za-z0-9+/=]+)(</config>)', add, raw)
    assert new != raw, "c8kv-75 ACL anchor not found"
    lab.write_text(new, encoding="utf-8")
    man = lab.with_suffix(".localize.toml")
    man.write_text(man.read_text(encoding="utf-8") + _ACL_RULE, encoding="utf-8")


class SdwanAclWildcardTest(PinnedCase):
    labs = (SDWAN,)

    def test_inet_slash23_rewrites_acl_wildcard(self) -> None:
        _inject_acl(self.t.labs[SDWAN])
        answers = self.t.write(
            "a.toml",
            "schema = 1\n"
            '[segments."site.inet_a"]\n'
            'subnet = "192.168.10.0/23"\n'
            'gateway = "192.168.11.254"\n',
        )
        code, out, err = self.t.run(
            "plan",
            "--lab",
            SDWAN,
            "--answers",
            str(answers),
            "--non-interactive",
            "--json",
        )
        self.assertEqual(code, 0, out + err)
        edits = json.loads(out)["labs"][0]["plan"]["edits"]
        blob = json.dumps(edits)
        self.assertIn("0.0.1.255", blob)
        self.assertIn("255.255.254.0", blob)


if __name__ == "__main__":
    unittest.main()
