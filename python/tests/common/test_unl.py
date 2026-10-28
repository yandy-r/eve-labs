"""Tests for evelab.common.unl (RawLab span index, edits, splice)."""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from evelab.common.codec import decode_blob, edit_blob
from evelab.common.unl import (
    RawEdit,
    RawLab,
    check_label,
    escape_attr,
    label_warnings,
    splice,
    unescape_attr,
    verify_outside_spans,
)
from evelab.localize.errors import (
    ConflictError,
    LabParseError,
    LocalizeError,
    UnsupportedLayout,
)
from evelab.localize.model import Span, TextEdit
from tests.localize.labfiles import (
    minilab,
    minilab_names,
    minilab_path,
    read_real,
    real_lab_paths,
)

LAB_HEAD = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


def lab_bytes(body: str, attrs: str = 'name="t" id="x1"') -> bytes:
    return LAB_HEAD + f"<lab {attrs}>\n{body}</lab>\n".encode()


class RealLabTests(unittest.TestCase):
    def test_nine_real_labs(self) -> None:
        self.assertGreaterEqual(len(real_lab_paths()), 9)

    def test_index_matches_etree_on_every_real_lab(self) -> None:
        for path in real_lab_paths():
            with self.subTest(lab=path.name):
                lab = read_real(path)
                self.assertFalse(lab.read_only, lab.layout_issues)
                self.assertEqual(lab.verify_against_etree(), [])
                root = ET.parse(path).getroot()
                self.assertEqual(lab.lab_id, root.get("id"))
                self.assertEqual(lab.name, root.get("name"))
                self.assertEqual(
                    [n.id for n in lab.networks()],
                    [n.get("id") for n in root.iter("network")],
                )
                self.assertEqual(
                    [n.id for n in lab.nodes()],
                    [n.get("id") for n in root.iter("node")],
                )
                self.assertEqual(
                    sum(len(n.ifaces) for n in lab.nodes()),
                    len(list(root.iter("interface"))),
                )
                self.assertEqual(
                    len(lab.textobjects()), len(list(root.iter("textobject")))
                )
                self.assertEqual(
                    len(lab.config_blobs()), len(list(root.iter("config")))
                )

    def test_objects_count_includes_stray_empty_elements(self) -> None:
        for path in real_lab_paths():
            with self.subTest(lab=path.name):
                lab = read_real(path)
                self.assertEqual(
                    lab.objects_count(), len(re.findall(rb"<objects\b", lab.raw))
                )
        by_name = {p.name: read_real(p).objects_count() for p in real_lab_paths()}
        self.assertEqual(by_name["lab1-ei-v01.unl"], 4)
        self.assertEqual(by_name["azure_asa_vpn.unl"], 3)
        self.assertEqual(by_name["cisco_nexus_9000v_vpc_concept_lab.unl"], 2)

    def test_spans_cover_exactly_the_payload_bytes(self) -> None:
        for path in real_lab_paths():
            lab = read_real(path)
            with self.subTest(lab=path.name):
                for blob in [*lab.config_blobs(), *lab.textobjects()]:
                    self.assertEqual(lab.raw[blob.span.start : blob.span.end], blob.b64)
                    self.assertRegex(blob.b64.decode("ascii"), r"^[A-Za-z0-9+/=]*$")
                    # the payload sits directly between '>' and '<'
                    self.assertEqual(
                        lab.raw[blob.span.start - 1 : blob.span.start], b">"
                    )
                    self.assertEqual(lab.raw[blob.span.end : blob.span.end + 1], b"<")

    def test_attribute_value_spans_decode_to_etree_values(self) -> None:
        for path in real_lab_paths():
            lab = read_real(path)
            nets = {n.get("id"): n for n in ET.parse(path).getroot().iter("network")}
            with self.subTest(lab=path.name):
                for elem in lab.networks():
                    ref = nets[elem.id]
                    for name in ("type", "name"):
                        a = elem.attrs[name]
                        self.assertEqual(
                            unescape_attr(lab.raw[a.span.start : a.span.end]),
                            ref.get(name),
                        )
                        self.assertEqual(a.value, ref.get(name))
                    # start tag span starts with <network and ends with >
                    tag = lab.raw[elem.span.start : elem.span.end]
                    self.assertTrue(tag.startswith(b"<network "))
                    self.assertTrue(tag.endswith(b">"))

    def test_noop_edits_and_empty_splice_are_byte_identical(self) -> None:
        for path in real_lab_paths():
            lab = read_real(path)
            with self.subTest(lab=path.name):
                self.assertEqual(splice(lab.raw, []), lab.raw)
                edits = [
                    lab.attr_edit(n, "name", n.get("name")) for n in lab.networks()
                ]
                edits += [
                    lab.attr_edit(n, "type", n.get("type")) for n in lab.networks()
                ]
                self.assertEqual(len({(e.start, e.end) for e in edits}), len(edits))
                self.assertEqual(splice(lab.raw, edits), lab.raw)
                blob_edits = [lab.blob_edit(b, b.b64) for b in lab.config_blobs()]
                self.assertEqual(splice(lab.raw, blob_edits), lab.raw)

    def test_skip_regions_cover_tasks_description_lineobjects(self) -> None:
        lab1 = read_real(
            next(p for p in real_lab_paths() if p.name == "lab1-ei-v01.unl")
        )
        regions = dict(lab1.skip_regions())
        self.assertIn("tasks", regions)
        self.assertIn("lineobjects", regions)
        self.assertGreater(regions["tasks"].end - regions["tasks"].start, 1_000_000)
        for blob in [*lab1.config_blobs(), *lab1.textobjects()]:
            for span in regions.values():
                self.assertFalse(span.start <= blob.span.start < span.end)
        ei = read_real(
            next(p for p in real_lab_paths() if p.name.startswith("ccie_enterprise"))
        )
        self.assertIn("description", dict(ei.skip_regions()))

    def test_lab1_is_fast(self) -> None:
        path = next(p for p in real_lab_paths() if p.name == "lab1-ei-v01.unl")
        start = time.perf_counter()
        lab = RawLab.read(path)
        elapsed = time.perf_counter() - start
        self.assertGreater(len(lab.raw), 2_000_000)
        self.assertLess(elapsed, 5.0, f"RawLab.read(lab1) took {elapsed:.2f}s")

    def test_real_labs_are_not_modified_by_reading(self) -> None:
        for path in real_lab_paths():
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(RawLab.read(path).sha256, before)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_models_for_real_lab(self) -> None:
        path = next(p for p in real_lab_paths() if p.name == "azure_asa_vpn.unl")
        lab = read_real(path)
        nets = lab.network_models()
        self.assertEqual(
            {i for i, n in nets.items() if n.is_cloud},
            {
                n.get("id")
                for n in ET.parse(path).getroot().iter("network")
                if n.get("type") != "bridge"
            },
        )
        nodes = lab.node_models()
        self.assertEqual(len(nodes), len(lab.nodes()))
        for node in nodes.values():
            for i in node.ifaces:
                self.assertIn(i.network_id, nets)


class EditOnTempCopyTests(unittest.TestCase):
    """Edits against a temp copy of a real lab; labs/ is never written."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        src = next(p for p in real_lab_paths() if p.name == "azure_asa_vpn.unl")
        self.path = Path(self._tmp.name) / src.name
        shutil.copyfile(src, self.path)
        self.lab = RawLab.read(self.path)

    def test_network_rename_and_blob_edit(self) -> None:
        lab = self.lab
        cloud = next(n for n in lab.networks() if n.get("type") != "bridge")
        e1 = lab.attr_edit(cloud, "name", 'Lab & "Edge" <1>')
        blob = lab.config_blobs()[0]
        dec = decode_blob(blob.b64)
        assert dec is not None
        start = dec.text.index("\n") if "\n" in dec.text else 0
        te = TextEdit(start, start, "", "! edited\n")
        e3 = lab.blob_edit(blob, edit_blob(dec, [te]))
        edits = [e1, e3]
        new = splice(lab.raw, edits)
        self.assertTrue(verify_outside_spans(lab.raw, new, edits))
        self.assertNotEqual(new, lab.raw)

        # attribute order / spacing untouched, only the value bytes changed
        old_tag = lab.raw[cloud.span.start : cloud.span.end].decode()
        self.assertIn('name="Lab &amp; &quot;Edge&quot; &lt;1&gt;"', new.decode())
        self.assertEqual(
            old_tag.replace(f'name="{cloud.get("name")}"', "@"),
            new[cloud.span.start : cloud.span.end + len(e1.new) - len(e1.old)]
            .decode()
            .replace('name="Lab &amp; &quot;Edge&quot; &lt;1&gt;"', "@"),
        )

        again = RawLab.from_bytes(new)
        self.assertFalse(again.read_only, again.layout_issues)
        moved = {n.id: n for n in again.networks()}[cloud.id]
        self.assertEqual(moved.get("name"), 'Lab & "Edge" <1>')
        self.assertEqual(again.objects_count(), lab.objects_count())
        self.assertEqual(len(again.config_blobs()), len(lab.config_blobs()))
        new_blob = again.config_blobs()[0]
        d2 = decode_blob(new_blob.b64)
        assert d2 is not None
        self.assertEqual(d2.text, dec.text[:start] + "! edited\n" + dec.text[start:])
        # ET agrees
        root = ET.fromstring(new)
        self.assertEqual(
            next(n for n in root.iter("network") if n.get("id") == cloud.id).get(
                "name"
            ),
            'Lab & "Edge" <1>',
        )

    def test_writing_the_copy_back_keeps_stray_objects(self) -> None:
        lab = self.lab
        net = lab.networks()[0]
        new = splice(lab.raw, [lab.attr_edit(net, "name", "renamed")])
        self.path.write_bytes(new)
        again = RawLab.read(self.path)
        self.assertEqual(again.objects_count(), 3)
        self.assertEqual(new.count(b"<objects/>"), 2)


class SpliceTests(unittest.TestCase):
    RAW = b"0123456789"

    def test_sorted_application_regardless_of_input_order(self) -> None:
        edits = [RawEdit(6, 8, b"67", b"X"), RawEdit(0, 2, b"01", b"AAA")]
        self.assertEqual(splice(self.RAW, edits), b"AAA2345X89")
        self.assertEqual(splice(self.RAW, edits[::-1]), b"AAA2345X89")

    def test_adjacent_and_insert_edits(self) -> None:
        edits = [
            RawEdit(2, 2, b"", b"<"),
            RawEdit(2, 4, b"23", b"X"),
            RawEdit(4, 4, b"", b">"),
        ]
        self.assertEqual(splice(self.RAW, edits), b"01<X>456789")

    def test_overlap_raises_conflict(self) -> None:
        with self.assertRaises(ConflictError):
            splice(self.RAW, [RawEdit(0, 4, b"0123", b"x"), RawEdit(3, 5, b"34", b"y")])

    def test_duplicate_and_same_offset_inserts_conflict(self) -> None:
        with self.assertRaises(ConflictError):
            splice(self.RAW, [RawEdit(2, 4, b"23", b"x"), RawEdit(2, 4, b"23", b"x")])
        with self.assertRaises(ConflictError):
            splice(self.RAW, [RawEdit(2, 2, b"", b"x"), RawEdit(2, 2, b"", b"y")])

    def test_unexpected_old_bytes_raise_conflict(self) -> None:
        with self.assertRaises(ConflictError) as cm:
            splice(self.RAW, [RawEdit(2, 4, b"XX", b"y")])
        self.assertEqual(cm.exception.code, "STALE_EDIT")

    def test_out_of_range_raises_conflict(self) -> None:
        with self.assertRaises(ConflictError):
            splice(self.RAW, [RawEdit(8, 20, b"89", b"y")])
        with self.assertRaises(ConflictError):
            splice(self.RAW, [RawEdit(5, 3, b"", b"y")])

    def test_conflict_errors_carry_exit_code_2(self) -> None:
        try:
            splice(self.RAW, [RawEdit(2, 4, b"XX", b"y")])
        except ConflictError as exc:
            self.assertEqual(exc.exit_code, 2)

    def test_verify_outside_spans(self) -> None:
        edits = [RawEdit(2, 4, b"23", b"XYZ"), RawEdit(8, 8, b"", b"!")]
        new = splice(self.RAW, edits)
        self.assertTrue(verify_outside_spans(self.RAW, new, edits))
        self.assertFalse(verify_outside_spans(self.RAW, new[:-1] + b"?", edits))
        tampered = bytearray(new)
        tampered[0] = ord("Q")
        self.assertFalse(verify_outside_spans(self.RAW, bytes(tampered), edits))
        self.assertFalse(verify_outside_spans(self.RAW, new, edits[:1]))


class AttrEscapingTests(unittest.TestCase):
    def test_escape_and_unescape_round_trip(self) -> None:
        for value in ["a&b", 'say "hi"', "<tag>", "it's", "Café — x", "&amp;"]:
            with self.subTest(value):
                for quote in ('"', "'"):
                    esc = escape_attr(value, quote)
                    self.assertNotIn("&" + quote, esc.replace("&amp;", ""))
                    self.assertNotIn("<", esc)
                    self.assertEqual(unescape_attr(esc.encode()), value)
                    self.assertNotIn(quote, esc)

    def test_unescape_numeric_and_whitespace(self) -> None:
        self.assertEqual(unescape_attr(b"Caf&#233; &#x41;"), "Café A")
        self.assertEqual(unescape_attr(b"a\tb\r\nc\nd"), "a b c d")
        with self.assertRaises(LabParseError):
            unescape_attr(b"&bogus;")
        with self.assertRaises(LabParseError):
            unescape_attr(b"\xff\xfe")

    def test_check_label(self) -> None:
        check_label("EVE-MGMT-203")
        check_label("Café — x")
        check_label("")
        check_label("x" * 64)
        for bad in ["x" * 65, "a\nb", "a\tb", "a\x00b", "a\x1bb", "a\u2028b"]:
            with self.subTest(bad=bad), self.assertRaises(LocalizeError) as cm:
                check_label(bad)
            self.assertEqual(cm.exception.code, "BAD_LABEL")

    def test_label_warnings(self) -> None:
        self.assertEqual(label_warnings("x" * 32), [])
        self.assertEqual(len(label_warnings("x" * 33)), 1)


class MinilabTests(unittest.TestCase):
    def test_every_minilab_parses_and_is_consistent(self) -> None:
        self.assertGreaterEqual(len(minilab_names()), 12)
        for stem in minilab_names():
            with self.subTest(lab=stem):
                lab = minilab(stem)
                self.assertEqual(lab.path.name, f"{stem}.unl")
                self.assertEqual(lab.read_only, stem == "unknown_layout")
                self.assertEqual(lab.verify_against_etree() == [], not lab.read_only)

    def test_basic_index(self) -> None:
        lab = minilab("basic")
        self.assertEqual(lab.name, "basic")
        self.assertEqual(lab.objects_count(), 3)
        self.assertEqual(lab.configsets(), {"2": "alt-scheme"})
        self.assertEqual(
            [(b.scope, b.id) for b in lab.config_blobs()],
            [
                ("startup", "1"),
                ("startup", "2"),
                ("startup", "4"),
                ("cs:alt-scheme", "1"),
                ("cs:alt-scheme", "2"),
            ],
        )
        self.assertEqual(
            [(t.id, t.name, t.type) for t in lab.textobjects()],
            [("1", "txt 1", "text"), ("2", "square2", "square")],
        )
        self.assertEqual(
            {t for t, _ in lab.skip_regions()}, {"description", "tasks", "lineobjects"}
        )
        nodes = lab.node_models()
        self.assertEqual(
            {n.id: (n.name, n.template, n.config_attr) for n in nodes.values()},
            {
                "1": ("rtr1", "iol", "1"),
                "2": ("sw1", "iol", "2"),
                "3": ("fw1", "fortinet", "0"),
                "4": ("srv1", "docker", "1"),
            },
        )
        self.assertEqual(
            [(i.id, i.name, i.network_id) for i in nodes["2"].ifaces],
            [
                ("0", "e0/0", "1"),
                ("16", "e0/1", "4"),
                ("32", "e0/2", "2"),
                ("48", "e0/3", "6"),
            ],
        )
        clouds = {
            i: (n.type, n.name) for i, n in lab.network_models().items() if n.is_cloud
        }
        self.assertEqual(
            clouds,
            {
                "2": ("pnet0", "EVE-MGMT-203"),
                "3": ("pnet2", "INET-1240"),
                "5": ("pnet0", "EVE-MGMT-203"),
            },
        )

    def test_blob_edit_in_basic_configset_leaves_other_scopes_alone(self) -> None:
        lab = minilab("basic")
        startup1 = next(
            b for b in lab.config_blobs() if (b.scope, b.id) == ("startup", "1")
        )
        dec = decode_blob(startup1.b64)
        assert dec is not None
        idx = dec.text.index("1240")
        edit = lab.blob_edit(
            startup1, edit_blob(dec, [TextEdit(idx, idx + 4, "1240", "2240")])
        )
        new = splice(lab.raw, [edit])
        self.assertTrue(verify_outside_spans(lab.raw, new, [edit]))
        again = RawLab.from_bytes(new)
        got = {(b.scope, b.id): b.b64 for b in again.config_blobs()}
        want = {(b.scope, b.id): b.b64 for b in lab.config_blobs()}
        changed = {k for k in got if got[k] != want[k]}
        self.assertEqual(changed, {("startup", "1")})

    def test_no_configs(self) -> None:
        lab = minilab("no_configs")
        self.assertEqual(lab.config_blobs(), [])
        self.assertEqual(lab.configsets(), {})
        self.assertEqual(len(lab.textobjects()), 1)
        self.assertEqual(lab.verify_against_etree(), [])

    def test_config_no_blob(self) -> None:
        lab = minilab("config_no_blob")
        blobs = {b.id: b for b in lab.config_blobs()}
        self.assertNotIn("1", blobs)  # node 1 has config="1" but no element
        self.assertEqual(blobs["2"].b64, b"")
        self.assertFalse(blobs["2"].self_closing)
        self.assertTrue(blobs["3"].self_closing)
        self.assertEqual(blobs["3"].span.start, blobs["3"].span.end)
        self.assertEqual(lab.node_models()["1"].config_attr, "1")
        # an empty (not self-closing) payload can be filled in place
        edit = lab.blob_edit(blobs["2"], b"aGk=")
        self.assertIn(b'<config id="2">aGk=</config>', splice(lab.raw, [edit]))
        with self.assertRaises(UnsupportedLayout):
            lab.blob_edit(blobs["3"], b"aGk=")

    def test_garbage_and_noncanonical_labs_are_indexed_verbatim(self) -> None:
        lab = minilab("garbage_blob")
        self.assertEqual(lab.config_blobs()[0].b64, b"ff")
        nc = minilab("noncanonical_b64")
        first = nc.config_blobs()[0].b64
        self.assertTrue(first.startswith(b"\n"))
        self.assertIn(b"\n", first.strip())
        self.assertEqual(nc.config_blobs()[1].b64.endswith(b" "), True)

    def test_blob_edit_rejects_non_base64(self) -> None:
        lab = minilab("basic")
        with self.assertRaises(LocalizeError) as cm:
            lab.blob_edit(lab.config_blobs()[0], b"not base64!\n")
        self.assertEqual(cm.exception.code, "BAD_BLOB")

    def test_dup_names_are_distinct_by_id(self) -> None:
        lab = minilab("dup_names")
        nets = lab.network_models()
        self.assertEqual(len(nets), 6)
        self.assertEqual(
            [(i, n.type) for i, n in nets.items() if n.name == "Net"],
            [("3", "bridge"), ("5", "pnet0"), ("6", "bridge")],
        )
        self.assertEqual(
            [n.id for n in lab.networks() if n.get("name") == "INET-201"], ["1", "2"]
        )
        self.assertEqual([t.name for t in lab.textobjects()].count("square1"), 2)
        # renaming the cloud "Net" touches exactly one network start tag
        cloud = next(n for n in lab.networks() if n.id == "5")
        edit = lab.attr_edit(cloud, "name", "Net2")
        new = splice(lab.raw, [edit])
        self.assertEqual(new.count(b'name="Net"'), 2)
        self.assertEqual(new.count(b'name="Net2"'), 1)

    def test_amp_names(self) -> None:
        lab = minilab("amp_name")
        self.assertEqual(lab.name, 'A & B "lab"')
        names = [n.get("name") for n in lab.networks()]
        self.assertEqual(
            names, ['R&D "edge" <lab>', 'it\'s "single" quoted', "Café — AZURE"]
        )
        nets = lab.networks()
        # quoting is preserved per attribute
        self.assertEqual(nets[0].attrs["name"].quote, '"')
        self.assertEqual(nets[1].attrs["name"].quote, "'")
        edit = lab.attr_edit(nets[1], "name", 'it\'s "new" & <x>')
        self.assertEqual(edit.new, b'it&apos;s "new" &amp; &lt;x&gt;')
        edit0 = lab.attr_edit(nets[0], "name", 'x & "y"')
        self.assertEqual(edit0.new, b"x &amp; &quot;y&quot;")
        new = splice(lab.raw, [edit, edit0])
        reread = RawLab.from_bytes(new)
        self.assertEqual(
            [n.get("name") for n in reread.networks()][:2],
            ['x & "y"', 'it\'s "new" & <x>'],
        )
        self.assertEqual(reread.verify_against_etree(), [])

    def test_unchanged_value_keeps_original_escapes(self) -> None:
        lab = minilab("amp_name")
        net = lab.networks()[2]  # name has numeric character references
        edit = lab.attr_edit(net, "name", net.get("name"))
        self.assertEqual(edit.old, edit.new)
        self.assertIn(b"&#233;", edit.new)
        self.assertEqual(splice(lab.raw, [edit]), lab.raw)

    def test_attr_edit_errors(self) -> None:
        lab = minilab("basic")
        net = lab.networks()[1]
        with self.assertRaises(LocalizeError) as cm:
            lab.attr_edit(net, "nonexistent", "x")
        self.assertEqual(cm.exception.code, "NO_SUCH_ATTR")
        with self.assertRaises(LocalizeError) as cm2:
            lab.attr_edit(net, "name", "bad\nname")
        self.assertEqual(cm2.exception.code, "BAD_LABEL")

    def test_unknown_layout_is_read_only(self) -> None:
        lab = minilab("unknown_layout")
        self.assertTrue(lab.read_only)
        self.assertEqual(len(lab.layout_issues), 2)
        self.assertTrue(any("config" in i for i in lab.layout_issues))
        self.assertTrue(any("textobject" in i for i in lab.layout_issues))
        # scan-style queries still work
        self.assertEqual(len(lab.networks()), 2)
        self.assertEqual(len(lab.config_blobs()), 1)
        with self.assertRaises(UnsupportedLayout):
            lab.attr_edit(lab.networks()[0], "name", "x")
        with self.assertRaises(UnsupportedLayout):
            lab.blob_edit(lab.config_blobs()[0], b"aGk=")
        with self.assertRaises(UnsupportedLayout):
            RawLab.read(minilab_path("unknown_layout"), strict=True)

    def test_stray_empty_objects_preserved_through_edits(self) -> None:
        lab = minilab("basic")
        edit = lab.attr_edit(lab.networks()[1], "name", "EVE-MGMT-9")
        new = splice(lab.raw, [edit])
        self.assertEqual(new.count(b"<objects/>"), 2)
        self.assertEqual(RawLab.from_bytes(new).objects_count(), 3)
        self.assertEqual(lab.raw.count(b"<objects/>"), 2)


class MalformedInputTests(unittest.TestCase):
    def parse(self, raw: bytes) -> RawLab:
        return RawLab.from_bytes(raw)

    def test_valid_minimal_lab(self) -> None:
        lab = self.parse(lab_bytes(""))
        self.assertEqual((lab.lab_id, lab.name, lab.objects_count()), ("x1", "t", 0))
        self.assertEqual(lab.networks(), [])
        self.assertFalse(lab.read_only)

    def test_bom_and_missing_id(self) -> None:
        lab = self.parse(b"\xef\xbb\xbf" + lab_bytes("", attrs='name="t"'))
        self.assertEqual(lab.lab_id, "")

    def test_rejects_bad_files(self) -> None:
        cases = {
            "unclosed": LAB_HEAD + b'<lab name="t" id="1"><topology>',
            "mismatched": LAB_HEAD + b'<lab id="1"></topology></lab>',
            "not lab": LAB_HEAD + b'<other id="1"/>',
            "two roots": LAB_HEAD + b'<lab id="1"/><lab id="2"/>',
            "stray lt": LAB_HEAD + b'<lab id="1"> a < b </lab>',
            "text outside": LAB_HEAD + b'<lab id="1"/>junk',
            "doctype": LAB_HEAD + b'<!DOCTYPE lab [<!ENTITY x "y">]><lab id="1"/>',
            "dup attr": LAB_HEAD + b'<lab id="1" id="2"/>',
            "bad entity": LAB_HEAD + b'<lab id="1" name="&nope;"/>',
            "latin1 decl": b'<?xml version="1.0" encoding="ISO-8859-1"?><lab id="1"/>',
            "empty": b"",
            "unquoted attr": LAB_HEAD + b"<lab id=1/>",
        }
        for label, raw in cases.items():
            with self.subTest(label), self.assertRaises(LabParseError):
                self.parse(raw)

    def test_comments_pi_and_cdata_are_tolerated(self) -> None:
        raw = lab_bytes(
            "<!-- note <b> -->\n<?php x ?>\n<topology><networks>"
            '<network id="1" type="pnet0" name="a"/></networks></topology>\n'
        )
        lab = self.parse(raw)
        self.assertEqual([n.id for n in lab.networks()], ["1"])
        self.assertFalse(lab.read_only)

    def test_gt_inside_attribute_value(self) -> None:
        raw = lab_bytes(
            '<topology><networks><network id="1" type="pnet0" name="a>b"/>'
            "</networks></topology>\n"
        )
        lab = self.parse(raw)
        self.assertEqual(lab.networks()[0].get("name"), "a>b")
        self.assertFalse(lab.read_only)

    def test_blob_with_markup_marks_read_only(self) -> None:
        raw = lab_bytes(
            '<objects><configs><config id="1">aG<!--x-->k=</config>'
            "</configs></objects>\n"
        )
        lab = self.parse(raw)
        self.assertTrue(lab.read_only)

    def test_duplicate_configset_name_marks_read_only(self) -> None:
        raw = lab_bytes(
            '<objects><configsets><configset id="1" name="a"/>'
            '<configset id="2" name="a"/></configsets></objects>\n'
        )
        lab = self.parse(raw)
        self.assertTrue(lab.read_only)

    def test_read_missing_file_is_lab_parse_error(self) -> None:
        with self.assertRaises(LabParseError):
            RawLab.read(Path("/nonexistent-dir/does-not-exist.unl"))

    def test_read_error_mentions_the_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.unl"
            bad.write_bytes(b"<lab")
            with self.assertRaises(LabParseError) as cm:
                RawLab.read(bad)
            self.assertIn("bad.unl", str(cm.exception))

    def test_span_type(self) -> None:
        lab = minilab("basic")
        self.assertIsInstance(lab.networks()[0].span, Span)


if __name__ == "__main__":
    unittest.main()
