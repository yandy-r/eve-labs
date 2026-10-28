"""eve_html + generic dialects and the shared T11 helpers."""

from __future__ import annotations

import re
import unittest

from evelab.common.textutil import html_text_regions
from evelab.localize import dialects
from evelab.localize.dialects import blocks
from evelab.localize.dialects._common import LABEL_TOKEN
from evelab.localize.dialects.generic import attach_iface_blocks
from evelab.localize.model import Span

from .t11_real import textobjects
from .test_dialect_contract import DialectContractMixin, make_ct


def parse(name: str, text: str):
    return dialects.get(name).parse(make_ct(text, name))


class TestEveHtmlContract(DialectContractMixin, unittest.TestCase):
    dialect_name = "eve_html"
    require_snippets = True
    require_rule_coverage = True


class TestGenericContract(DialectContractMixin, unittest.TestCase):
    dialect_name = "generic"
    require_snippets = True
    require_rule_coverage = True


class TestEveHtmlRealTextobjects(unittest.TestCase):
    def setUp(self) -> None:
        self.objs = list(textobjects())

    def test_all_textobjects(self) -> None:
        self.assertGreater(len(self.objs), 100)
        d = dialects.get("eve_html")
        total = 0
        for rt in self.objs:
            with self.subTest(lab=rt.lab.name, textobject=rt.ident):
                self.assertEqual(dialects.pick(None, rt.text).name, "eve_html")
                pc = d.parse(rt.ct("eve_html"))
                regions = html_text_regions(rt.text)
                for f in pc.facts:
                    spans = [f.span] + ([f.mask_span] if f.mask_span else [])
                    for s in spans:
                        self.assertTrue(
                            any(r.start <= s.start and s.end <= r.end for r in regions),
                            f"{f.rule} {f.value!r} outside text nodes",
                        )
                    self.assertNotIn(f.kind, ("vlan_tag", "vlan_list", "vlan_def"))
                    self.assertEqual(f.confidence.name, "HEURISTIC")
                if "<svg" in rt.text and not regions:
                    self.assertEqual(pc.facts, [])
                total += len(pc.facts)
        self.assertGreater(total, 100)

    def test_css_and_svg_numbers_never_facts(self) -> None:
        html = (
            '<div style="left: 10.1.1.1px; width: 203px;"><svg width="1205">'
            "<text>10.9.9.9 EVE-MGMT-203</text></svg><p>10.2.2.2/24 pnet0</p></div>"
        )
        pc = parse("eve_html", html)
        self.assertEqual(
            [(f.kind, f.value) for f in pc.facts],
            [("ip_host", "10.2.2.2"), ("cloud_ref", "pnet0")],
        )

    def test_score_only_for_html(self) -> None:
        d = dialects.get("eve_html")
        self.assertEqual(d.score(None, "ip addr add 1.1.1.1/24 dev eth0\n"), 0)
        self.assertEqual(d.score(None, "<p>x</p>"), 95)


class TestGeneric(unittest.TestCase):
    def test_fallback(self) -> None:
        self.assertEqual(dialects.pick(None, "whatever 1.2.3.4\n").name, "generic")

    def test_never_tags_and_heuristic(self) -> None:
        pc = parse("generic", "vlan 203\ninterface Gi1.203\n encapsulation dot1Q 203\n")
        self.assertFalse([f for f in pc.facts if f.kind.startswith("vlan")])
        self.assertTrue(all(f.confidence.name == "HEURISTIC" for f in pc.facts))


class TestLabelToken(unittest.TestCase):
    def test_tokens(self) -> None:
        def toks(s: str) -> list[str]:
            return [m.group("v") for m in re.finditer(LABEL_TOKEN, s)]

        self.assertEqual(toks("to EVE-MGMT-203 uplink"), ["EVE-MGMT-203"])
        self.assertEqual(
            toks("INET-1240, mgmt58 and TENANT-1."), ["INET-1240", "mgmt58", "TENANT-1"]
        )
        for neg in (
            "pnet0",
            "Gi16.2",
            "plsnetlab.local",
            "Net",
            "mgmt",
            "a-b",
            "Yandy.Dev-HQ",
            "abc-",
        ):
            self.assertEqual(toks(neg), [], neg)
        self.assertEqual(toks("pnet0-trunk"), [])  # its pnet0 is a cloud_ref


class TestHelpers(unittest.TestCase):
    def test_attach_iface_blocks(self) -> None:
        text = "a dev eth0\nb\nc dev eth0\nd dev eth1\n"
        layout = blocks.split(text, "flat")

        def resolve(line_text: str, line):
            m = re.search(r"dev (\S+)", line_text)
            return (
                (m.group(1), Span(line.start + m.start(1), line.start + m.end(1)))
                if m
                else None
            )

        attach_iface_blocks(layout, resolve)
        names = [[b.name for b in ln.chain] for ln in layout.lines]
        self.assertEqual(names, [["eth0"], [], ["eth0"], ["eth1"]])
        eth0 = layout.lines[0].chain[0]
        self.assertIs(eth0, layout.lines[2].chain[0])
        self.assertEqual(text[eth0.name_span.start : eth0.name_span.end], "eth0")
        self.assertEqual(len([b for b in layout.blocks if b.kind == "interface"]), 2)


if __name__ == "__main__":
    unittest.main()
