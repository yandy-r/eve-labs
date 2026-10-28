"""Tests for evelab.common.textutil (design section 14, item 1)."""

import unittest

from evelab.common import textutil
from evelab.common.textutil import (
    LineIndex,
    VlanList,
    VlanListError,
    domain_re,
    find_ipv4,
    find_ipv6,
    hostmask_to_prefix,
    html_text_regions,
    is_netmask,
    mask_form_of,
    mask_prefix,
    mask_render,
    netmask_to_prefix,
    prefix_to_netmask,
    token_re,
)
from evelab.localize.errors import ConflictError
from evelab.localize.model import Span
from tests.localize import realtexts


def values(text: str, **kw: bool) -> list[str]:
    return [t.value for t in find_ipv4(text, **kw)]


class TestIPv4(unittest.TestCase):
    def test_span_reexport(self) -> None:
        self.assertIs(textutil.Span, Span)

    def test_boundaries_dot_one_vs_dot_ten(self) -> None:
        self.assertEqual(values("gw 172.31.240.10"), ["172.31.240.10"])
        self.assertEqual(values("gw 172.31.240.1"), ["172.31.240.1"])
        self.assertEqual(values("172.31.240.10").count("172.31.240.1"), 0)

    def test_never_inside_longer_tokens(self) -> None:
        for text in (
            "01010105",  # cert hex
            "49.0001.0000.0000.0001.00",  # ISIS NET
            "1.3.6.1.4.1.9",  # OID
            "1.2.3.4.5",
            "x10.1.1.1",
            "10.1.1.1x",
            "foo.10.1.1.1",
            "10.1.1.1.example.com",
            "1234.1.1.1",
            "10.1.1.1234",
        ):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])

    def test_invalid_quads_skipped(self) -> None:
        self.assertEqual(values("300.1.1.1 10.1.1.1 01.2.3.4"), ["10.1.1.1"])

    def test_sentence_final_period_still_matches(self) -> None:
        self.assertEqual(values("peer is 10.1.1.1."), ["10.1.1.1"])
        self.assertEqual(values("(10.1.1.1)"), ["10.1.1.1"])
        self.assertEqual(values("ip=10.1.1.1,10.1.1.2"), ["10.1.1.1", "10.1.1.2"])

    def test_spans(self) -> None:
        text = "ip address 10.1.1.1 255.255.255.0"
        (tok,) = find_ipv4(text)
        self.assertEqual(text[tok.span.start : tok.span.end], "10.1.1.1")
        assert tok.mask is not None
        self.assertEqual(text[tok.mask.span.start : tok.mask.span.end], "255.255.255.0")

    def test_mask_forms(self) -> None:
        cases = [
            ("ip address 10.1.1.1 255.255.255.0", "255.255.255.0", "dotted", 24),
            ("address 10.1.1.1/24;", "/24", "prefix", 24),
            (
                "ifconfig eth0 10.1.1.1 netmask 255.255.0.0",
                "255.255.0.0",
                "netmask",
                16,
            ),
            ("set ip 10.1.1.1 255.255.255.255", "255.255.255.255", "dotted", 32),
            ("ip route 0.0.0.0 0.0.0.0 10.1.1.1", "0.0.0.0", "dotted", 0),
        ]
        for text, mask, form, prefix in cases:
            with self.subTest(text=text):
                tok = find_ipv4(text)[0]
                assert tok.mask is not None
                self.assertEqual(tok.mask.text, mask)
                self.assertEqual(tok.mask.form, form)
                self.assertEqual(tok.mask.prefix, prefix)
                self.assertEqual(text[tok.mask.span.start : tok.mask.span.end], mask)

    def test_mask_not_reported_as_address(self) -> None:
        self.assertEqual(values("10.1.1.1 255.255.255.0"), ["10.1.1.1"])
        self.assertEqual(
            values("10.1.1.1 255.255.255.0", masks=False),
            [
                "10.1.1.1",
                "255.255.255.0",
            ],
        )
        self.assertEqual(
            values("route 0.0.0.0 0.0.0.0 10.1.1.1"), ["0.0.0.0", "10.1.1.1"]
        )

    def test_non_mask_second_address_kept(self) -> None:
        self.assertEqual(values("name-server 8.8.8.8 8.8.4.4"), ["8.8.8.8", "8.8.4.4"])

    def test_wildcard_absorbed(self) -> None:
        toks = find_ipv4("permit 10.1.1.0 0.0.0.255 any")
        self.assertEqual([t.value for t in toks], ["10.1.1.0"])
        assert toks[0].mask is not None
        self.assertTrue(toks[0].mask.wildcard)
        self.assertEqual(toks[0].mask.prefix, 24)

    def test_prefix_mask_bounds(self) -> None:
        self.assertIsNone(find_ipv4("10.1.1.0/33")[0].mask)
        self.assertIsNone(find_ipv4("10.1.1.0/245")[0].mask)
        tok = find_ipv4("10.1.1.0/8")[0]
        assert tok.mask is not None
        self.assertEqual(tok.mask.prefix, 8)

    def test_range_arguments(self) -> None:
        text = "a 10.1.1.1 b 10.1.1.2 c 10.1.1.3"
        toks = find_ipv4(text, 12, 22)
        self.assertEqual([t.value for t in toks], ["10.1.1.2"])
        self.assertEqual(find_ipv4(text, 0, 13)[0].value, "10.1.1.1")

    def test_address_property(self) -> None:
        self.assertEqual(str(find_ipv4("1.2.3.4")[0].address), "1.2.3.4")


class TestIPv6(unittest.TestCase):
    def test_detects_literals(self) -> None:
        text = "ipv6 address 2001:db8::1/64 gw fe80::1 x ::1 y ::ffff:10.1.1.1"
        toks = find_ipv6(text)
        self.assertEqual(
            [t.value for t in toks],
            ["2001:db8::1", "fe80::1", "::1", "::ffff:10.1.1.1"],
        )
        self.assertEqual(toks[0].prefix_len, 64)
        assert toks[0].prefix_span is not None
        self.assertEqual(
            text[toks[0].prefix_span.start : toks[0].prefix_span.end], "/64"
        )
        self.assertEqual(text[toks[0].span.start : toks[0].span.end], "2001:db8::1")
        self.assertIsNone(toks[1].prefix_len)

    def test_full_form(self) -> None:
        self.assertEqual(
            [t.value for t in find_ipv6("a 2001:0db8:0000:0000:0000:0000:0000:0001 b")],
            ["2001:0db8:0000:0000:0000:0000:0000:0001"],
        )

    def test_look_alikes_are_not_ipv6(self) -> None:
        for text in (
            "rd 2:2",
            "rd 203:203",
            "set community 204:204",
            "12:34:56",
            "Dec 28 18:28:00.651",
            "00:11:22:33:44:55",
            "aaaa.bbbb.cccc",
            "std::vector",
            "::",
            "http://x:80/",
            "10.1.1.1:179",
            "ratio 1:2:3",
        ):
            with self.subTest(text=text):
                self.assertEqual(find_ipv6(text), [])

    def test_trailing_period(self) -> None:
        self.assertEqual(
            [t.value for t in find_ipv6("see 2001:db8::1.")], ["2001:db8::1"]
        )

    def test_bad_prefix_length_dropped(self) -> None:
        tok = find_ipv6("2001:db8::1/200")[0]
        self.assertIsNone(tok.prefix_len)


class TestMasks(unittest.TestCase):
    def test_prefix_to_netmask(self) -> None:
        for n, mask in (
            (0, "0.0.0.0"),
            (8, "255.0.0.0"),
            (20, "255.255.240.0"),
            (24, "255.255.255.0"),
            (30, "255.255.255.252"),
            (32, "255.255.255.255"),
        ):
            with self.subTest(n=n):
                self.assertEqual(prefix_to_netmask(n), mask)
                self.assertEqual(netmask_to_prefix(mask), n)
        with self.assertRaises(ValueError):
            prefix_to_netmask(33)

    def test_netmask_validation(self) -> None:
        self.assertTrue(is_netmask("255.255.255.0"))
        self.assertFalse(is_netmask("255.0.255.0"))
        self.assertFalse(is_netmask("0.0.0.255"))
        self.assertFalse(is_netmask("garbage"))
        self.assertIsNone(netmask_to_prefix("255.255.255.1"))

    def test_hostmask(self) -> None:
        self.assertEqual(hostmask_to_prefix("0.0.0.255"), 24)
        self.assertEqual(hostmask_to_prefix("0.0.0.0"), 32)
        self.assertIsNone(hostmask_to_prefix("0.255.0.0"))

    def test_mask_prefix(self) -> None:
        self.assertEqual(mask_prefix("/24"), 24)
        self.assertEqual(mask_prefix("24"), 24)
        self.assertEqual(mask_prefix("255.255.252.0"), 22)
        self.assertIsNone(mask_prefix("/40"))
        self.assertIsNone(mask_prefix("abc"))

    def test_mask_form_of(self) -> None:
        self.assertEqual(mask_form_of("/24"), "prefix")
        self.assertEqual(mask_form_of("255.255.255.0"), "dotted")
        self.assertEqual(mask_form_of("255.255.255.0", keyword_before=True), "netmask")
        self.assertEqual(mask_form_of("nonsense"), "none")

    def test_mask_render(self) -> None:
        self.assertEqual(mask_render("prefix", 20), "/20")
        self.assertEqual(mask_render("dotted", 20), "255.255.240.0")
        self.assertEqual(mask_render("netmask", 16), "255.255.0.0")
        with self.assertRaises(ValueError):
            mask_render("none", 24)

    def test_round_trip_all_prefixes(self) -> None:
        for n in range(33):
            self.assertEqual(mask_prefix(mask_render("dotted", n)), n)
            self.assertEqual(mask_prefix(mask_render("prefix", n)), n)


class TestVlanList(unittest.TestCase):
    SAMPLE = "1,100-101,201,501-502,3101"

    def test_parse_render_identity(self) -> None:
        vl = VlanList.parse(self.SAMPLE)
        self.assertEqual(vl.render(), self.SAMPLE)
        self.assertEqual(str(vl), self.SAMPLE)
        self.assertEqual(vl.vlans(), [1, 100, 101, 201, 501, 502, 3101])
        self.assertEqual(len(vl), 7)
        self.assertIn(502, vl)
        self.assertNotIn(500, vl)

    def test_separator_preserved(self) -> None:
        for text in ("1, 100-101, 201", "10 20 30-31", "5"):
            with self.subTest(text=text):
                self.assertEqual(VlanList.parse(text).render(), text)

    def test_style_rendering(self) -> None:
        vl = VlanList.parse("1 2 10-12")
        self.assertEqual(vl.render("ios"), "1,2,10-12")
        self.assertEqual(vl.render("nxos"), "1,2,10-12")
        self.assertEqual(vl.render("space"), "1 2 10-12")
        self.assertEqual(vl.render("brace"), "1 2 10-12")
        with self.assertRaises(ValueError):
            vl.render("bogus")

    def test_braces_and_to(self) -> None:
        self.assertEqual(VlanList.parse("{ 10 20 }").vlans(), [10, 20])
        self.assertEqual(VlanList.parse("[ 10-12 30 ]").vlans(), [10, 11, 12, 30])
        self.assertEqual(VlanList.parse("100 to 102").vlans(), [100, 101, 102])

    def test_parse_errors(self) -> None:
        for bad in ("", "  ", "a", "1,,x", "5-3", "4096", "1-5000", "-1"):
            with self.subTest(bad=bad), self.assertRaises(VlanListError):
                VlanList.parse(bad)

    def test_replace_single_member_keeps_structure(self) -> None:
        vl = VlanList.parse(self.SAMPLE).replace({201: 20})
        self.assertEqual(vl.render(), "1,100-101,20,501-502,3101")
        self.assertEqual(vl.splits, ())

    def test_replace_inverse_restores_text(self) -> None:
        vl = VlanList.parse(self.SAMPLE)
        back = vl.replace({201: 20}).replace({20: 201})
        self.assertEqual(back.render(), self.SAMPLE)

    def test_replace_splits_range_only_when_needed(self) -> None:
        vl = VlanList.parse(self.SAMPLE).replace({100: 10})
        self.assertEqual(vl.render(), "1,10,101,201,501-502,3101")
        self.assertEqual(vl.splits, ("100-101",))
        mid = VlanList.parse("10-14").replace({12: 99})
        self.assertEqual(mid.render(), "10-11,99,13-14")
        self.assertEqual(mid.splits, ("10-14",))

    def test_replace_whole_range_members(self) -> None:
        vl = VlanList.parse("100-101").replace({100: 10, 101: 11})
        self.assertEqual(vl.render(), "10,11")

    def test_replace_swap_is_simultaneous(self) -> None:
        vl = VlanList.parse("2,3,4").replace({2: 3, 3: 2})
        self.assertEqual(vl.render(), "3,2,4")
        self.assertEqual(vl.vlans(), [2, 3, 4])

    def test_replace_unmapped_and_identity_are_noops(self) -> None:
        vl = VlanList.parse(self.SAMPLE)
        self.assertEqual(vl.replace({999: 5}).render(), self.SAMPLE)
        self.assertEqual(vl.replace({101: 101}).render(), self.SAMPLE)

    def test_replace_collision(self) -> None:
        vl = VlanList.parse(self.SAMPLE)
        with self.assertRaises(ConflictError) as ctx:
            vl.replace({201: 100})
        self.assertEqual(ctx.exception.code, "VLAN_COLLISION")
        self.assertEqual(ctx.exception.refs, ["100"])
        with self.assertRaises(ConflictError):
            vl.replace({201: 3101})
        with self.assertRaises(ConflictError):
            VlanList.parse("1,2").replace({1: 9, 2: 9})

    def test_replace_out_of_range(self) -> None:
        with self.assertRaises(VlanListError):
            VlanList.parse("1,2").replace({1: 5000})

    def test_preexisting_duplicates_are_not_a_collision(self) -> None:
        self.assertEqual(VlanList.parse("5,5,7").replace({7: 8}).render(), "5,5,8")

    def test_from_vlans_canonical(self) -> None:
        self.assertEqual(VlanList.from_vlans([3, 1, 2, 7, 7]).render(), "1-3,7")
        self.assertEqual(VlanList.from_vlans([1, 2], " ").render(), "1-2")

    def test_equality_ignores_splits(self) -> None:
        a = VlanList.parse("1,2")
        self.assertEqual(a, VlanList.parse("1,2").replace({}))


class TestTokens(unittest.TestCase):
    def test_domain_substrings(self) -> None:
        rx = domain_re("netlab.local")
        self.assertIsNotNone(rx.search("ip domain-name netlab.local"))
        self.assertIsNotNone(rx.search("hostname dc1-f5-1.netlab.local"))
        self.assertIsNotNone(rx.search("search netlab.local other.example"))
        self.assertIsNotNone(rx.search("see NETLAB.LOCAL."))
        self.assertIsNone(rx.search("ip domain-name plsnetlab.local"))
        self.assertIsNone(rx.search("netlab.localdomain"))
        self.assertIsNone(rx.search("netlab.local-x"))
        self.assertIsNone(rx.search("netlab.local.example.com"))
        self.assertIsNone(rx.search("netlabXlocal"))  # dot is escaped

    def test_domain_match_span(self) -> None:
        text = "name dc1-f5-1.netlab.local ok"
        m = domain_re("netlab.local").search(text)
        assert m is not None
        self.assertEqual(text[m.start() : m.end()], "netlab.local")

    def test_token_re(self) -> None:
        rx = token_re("EVE-MGMT-203")
        self.assertIsNotNone(rx.search("net EVE-MGMT-203 here"))
        self.assertIsNotNone(rx.search("(EVE-MGMT-203)"))
        self.assertIsNone(rx.search("XEVE-MGMT-203"))
        self.assertIsNone(rx.search("EVE-MGMT-2030"))
        self.assertIsNone(rx.search("EVE-MGMT-203-x"))
        self.assertIsNone(rx.search("eve-mgmt-203"))
        self.assertIsNotNone(
            token_re("eve-mgmt-203", ignore_case=True).search("EVE-MGMT-203")
        )

    def test_token_re_alias_not_inside_longer_alias(self) -> None:
        rx = token_re("pnet0")
        self.assertIsNotNone(rx.search("cloud pnet0"))
        self.assertIsNone(rx.search("alias pnet0-trunk"))
        self.assertIsNone(rx.search("pnet01"))

    def test_token_with_punctuation_edges(self) -> None:
        rx = token_re("(VLAN 3)")
        self.assertIsNotNone(rx.search("x(VLAN 3)"))

    def test_empty_rejected(self) -> None:
        with self.assertRaises(ValueError):
            token_re("")
        with self.assertRaises(ValueError):
            domain_re("")


class TestHtmlRegions(unittest.TestCase):
    @staticmethod
    def texts(html: str) -> list[str]:
        return [html[s.start : s.end] for s in html_text_regions(html)]

    def test_text_nodes_only(self) -> None:
        html = '<p style="width:203px">10.1.1.1</p><br>trail <b>x</b>'
        self.assertEqual(self.texts(html), ["10.1.1.1", "trail ", "x"])

    def test_skips_style_script_svg(self) -> None:
        html = (
            "<style>.a{width:203px}</style>"
            "<script>var x = 2;</script>"
            '<svg width="203"><g><text x="2">203</text></g><svg><g/></svg></svg>'
            "<div>after 10.1.1.1</div>"
        )
        self.assertEqual(self.texts(html), ["after 10.1.1.1"])

    def test_attribute_with_gt_inside_quotes(self) -> None:
        html = "<a title=\"a>b\" href='x>y'>real</a>"
        self.assertEqual(self.texts(html), ["real"])

    def test_comments_and_cdata(self) -> None:
        html = "<!-- 10.1.1.1 --><p>keep</p><![CDATA[ 10.1.1.2 ]]>tail"
        self.assertEqual(self.texts(html), ["keep", "tail"])

    def test_literal_lt_in_text(self) -> None:
        self.assertEqual(self.texts("<p>a < b and 3 <4</p>"), ["a < b and 3 <4"])

    def test_whitespace_only_nodes_dropped(self) -> None:
        self.assertEqual(self.texts("<div>\n  <p>x</p>\n</div>"), ["x"])

    def test_plain_text_and_empty(self) -> None:
        self.assertEqual(self.texts("just text"), ["just text"])
        self.assertEqual(html_text_regions(""), [])

    def test_unterminated_tag_stops(self) -> None:
        self.assertEqual(self.texts("<p>ok</p><div class='x"), ["ok"])

    def test_unclosed_svg_swallows_rest(self) -> None:
        self.assertEqual(self.texts("<p>a</p><svg><text>b</text>"), ["a"])

    def test_self_closing_svg_does_not_swallow(self) -> None:
        self.assertEqual(self.texts("<svg/><p>a</p>"), ["a"])

    def test_spans_are_exact_offsets(self) -> None:
        html = "<p>10.1.1.1</p>"
        (span,) = html_text_regions(html)
        self.assertEqual((span.start, span.end), (3, 11))


class TestLineIndex(unittest.TestCase):
    def test_lines(self) -> None:
        text = "ab\ncd\n\nef"
        idx = LineIndex(text)
        self.assertEqual(len(idx), 4)
        self.assertEqual(
            [idx.line(i) for i in range(len(text) + 1)], [1, 1, 1, 2, 2, 2, 3, 4, 4, 4]
        )
        self.assertEqual(idx.start(2), 3)
        with self.assertRaises(IndexError):
            idx.line(100)

    def test_empty(self) -> None:
        idx = LineIndex("")
        self.assertEqual(idx.line(0), 1)


class TestRealDumps(unittest.TestCase):
    """Sanity of the tokenizers on the real decoded configs (unl + codec)."""

    def read(self, name: str) -> str:
        return realtexts.text(name)

    def test_every_token_is_valid_and_bounded(self) -> None:
        import ipaddress

        for name in ("sdwan.txt", "junos.txt", "azure_asa_vpn.txt"):
            text = self.read(name)
            for tok in find_ipv4(text):
                ipaddress.IPv4Address(tok.value)
                self.assertEqual(text[tok.span.start : tok.span.end], tok.value)
                before = text[tok.span.start - 1 : tok.span.start]
                after = text[tok.span.end : tok.span.end + 1]
                self.assertFalse(before.isalnum() or before == ".")
                self.assertFalse(after.isalnum())
                if tok.mask:
                    self.assertGreaterEqual(tok.mask.span.start, tok.span.end)

    def test_masks_found_on_address_lines(self) -> None:
        text = self.read("azure_asa_vpn.txt")
        lines = [ln for ln in text.splitlines() if ln.startswith(" ip address ")]
        self.assertTrue(lines)
        for ln in lines:
            toks = find_ipv4(ln)
            if len(toks) == 1 and "dhcp" not in ln:
                self.assertIsNotNone(toks[0].mask, ln)

    def test_junos_slash_masks(self) -> None:
        text = self.read("junos.txt")
        found = [t for t in find_ipv4(text) if t.mask and t.mask.form == "prefix"]
        self.assertTrue(found)
        self.assertTrue(any(t.mask and t.mask.prefix == 20 for t in found))

    def test_no_look_alike_ipv6_in_ios_nxos_dumps(self) -> None:
        text = self.read("sdwan.txt")
        for tok in find_ipv6(text):
            import ipaddress

            ipaddress.IPv6Address(tok.value)

    def test_nxos_vlan_lists_parse(self) -> None:
        import re

        text = self.read("bb.txt")
        seen = 0
        for m in re.finditer(
            r"^\s*(?:vlan|switchport trunk allowed vlan(?: add)?) ([\d,\-]+)$",
            text,
            re.M,
        ):
            vl = VlanList.parse(m.group(1))
            self.assertEqual(vl.render(), m.group(1))
            seen += 1
        self.assertGreater(seen, 0)


if __name__ == "__main__":
    unittest.main()
