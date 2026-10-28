"""Tests for evelab.common.codec (blob decode/encode, text edits)."""

from __future__ import annotations

import base64
import unittest

from evelab.common.codec import (
    DecodedBlob,
    apply_text_edits,
    decode_blob,
    edit_blob,
    encode_blob,
    encode_text,
)
from evelab.localize.errors import ConflictError, LocalizeError
from evelab.localize.model import TextEdit
from tests.localize.labfiles import minilab, minilab_path, read_real, real_lab_paths


def b64(data: str | bytes) -> bytes:
    raw = data.encode() if isinstance(data, str) else data
    return base64.b64encode(raw)


def decoded(data: str | bytes) -> DecodedBlob:
    blob = decode_blob(b64(data))
    assert blob is not None
    return blob


class DecodeTests(unittest.TestCase):
    def test_utf8_text_is_canonical(self) -> None:
        d = decoded("hostname r1\n! dash —\n")
        self.assertEqual(d.text, "hostname r1\n! dash —\n")
        self.assertEqual(d.encoding, "utf-8")
        self.assertTrue(d.canonical)
        self.assertEqual(d.raw_b64, b64("hostname r1\n! dash —\n"))

    def test_latin1_fallback_round_trips_bytes(self) -> None:
        data = b"banner caf\xe9\nend\n"
        d = decoded(data)
        self.assertEqual(d.encoding, "latin-1")
        self.assertEqual(d.text, "banner caf\xe9\nend\n")
        self.assertEqual(encode_text(d.text, d.encoding), b64(data))

    def test_empty_blob_is_empty_text(self) -> None:
        d = decode_blob(b"")
        assert d is not None
        self.assertEqual((d.text, d.canonical), ("", True))

    def test_text_that_is_ff_is_text(self) -> None:
        d = decode_blob(b"ZmY=")
        assert d is not None
        self.assertEqual(d.text, "ff")

    def test_opaque_blobs(self) -> None:
        for label, payload in [
            ("literal ff", b"ff"),
            ("missing padding", b"aGVsbG8"),
            ("outside alphabet", b"aGVs bG8=\x00!"),
            ("nul bytes", b64(b"\x00\x01\x02ELF\x00")),
            ("many controls", b64(bytes(range(1, 8)) * 10 + b"text")),
        ]:
            with self.subTest(label):
                self.assertIsNone(decode_blob(payload))

    def test_cr_lf_esc_and_bell_are_text_not_binary(self) -> None:
        d = decoded("a\r\nb\x1b[0m\x07\tc\x0c")
        self.assertEqual(d.text, "a\r\nb\x1b[0m\x07\tc\x0c")

    def test_non_canonical_variants(self) -> None:
        good = b64("hostname r1\n!\nend\n")
        wrapped = good[:10] + b"\n   " + good[10:]
        for label, payload in [
            ("wrapped", wrapped),
            ("trailing space", good + b" "),
            ("leading newline", b"\n" + good),
            ("unused bits", self._unused_bits_variant()),
        ]:
            with self.subTest(label):
                d = decode_blob(payload)
                assert d is not None
                self.assertFalse(d.canonical)
                self.assertEqual(d.raw_b64, payload)
                self.assertTrue(
                    d.text.startswith("hostname r1") or label == "unused bits"
                )

    @staticmethod
    def _unused_bits_variant() -> bytes:
        enc = base64.b64encode(b"hostname rtr3\n!\nend").decode()  # ends with "=="
        assert enc.endswith("==")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        idx = alphabet.index(enc[-3])
        alt = alphabet[(idx & 0b110000) | 0b000001]
        out = (enc[:-3] + alt + "==").encode()
        assert out != enc.encode()
        assert base64.b64decode(out) == base64.b64decode(enc)
        return out


class EncodeTests(unittest.TestCase):
    def test_encode_changed_text_is_single_line_same_encoding(self) -> None:
        like = decoded("line\n" * 400)  # long enough to tempt line wrapping
        out = encode_blob("line\n" * 399 + "other\n", like)
        self.assertNotIn(b"\n", out)
        self.assertEqual(out, b64("line\n" * 399 + "other\n"))

    def test_encode_keeps_latin1(self) -> None:
        like = decoded(b"caf\xe9\n")
        out = encode_blob("caf\xe9 x\n", like)
        self.assertEqual(base64.b64decode(out), b"caf\xe9 x\n")

    def test_unrepresentable_character_is_an_error(self) -> None:
        like = decoded(b"caf\xe9\n")
        with self.assertRaises(LocalizeError) as cm:
            encode_blob("caf—\n", like)
        self.assertEqual(cm.exception.code, "BLOB_ENCODING")

    def test_unchanged_text_is_never_reencoded(self) -> None:
        raw = b"\n" + b64("x\n") + b" "
        like = decode_blob(raw)
        assert like is not None and not like.canonical
        self.assertIs(encode_blob(like.text, like), like.raw_b64)
        self.assertIs(edit_blob(like, []), like.raw_b64)

    def test_changed_text_on_non_canonical_blob_is_refused(self) -> None:
        like = decode_blob(b64("x\n") + b" ")
        assert like is not None
        with self.assertRaises(LocalizeError) as cm:
            encode_blob("y\n", like)
        self.assertEqual(cm.exception.code, "NONCANONICAL_BLOB")


class TextEditTests(unittest.TestCase):
    def test_apply_in_any_order(self) -> None:
        text = "aaa bbb ccc"
        edits = [TextEdit(8, 11, "ccc", "C"), TextEdit(0, 3, "aaa", "AAAA")]
        self.assertEqual(apply_text_edits(text, edits), "AAAA bbb C")

    def test_insertion_and_adjacent_edits(self) -> None:
        edits = [
            TextEdit(3, 3, "", "<"),
            TextEdit(3, 6, "def", "X"),
            TextEdit(6, 6, "", ">"),
        ]
        self.assertEqual(apply_text_edits("abcdef", edits), "abc<X>")

    def test_overlap_is_a_conflict(self) -> None:
        with self.assertRaises(ConflictError):
            apply_text_edits(
                "abcdef", [TextEdit(0, 3, "abc", "x"), TextEdit(2, 4, "cd", "y")]
            )
        with self.assertRaises(ConflictError):
            apply_text_edits(
                "abcdef", [TextEdit(2, 2, "", "x"), TextEdit(2, 2, "", "y")]
            )

    def test_stale_old_text_is_a_conflict(self) -> None:
        with self.assertRaises(ConflictError) as cm:
            apply_text_edits("abcdef", [TextEdit(0, 3, "xyz", "q")])
        self.assertEqual(cm.exception.code, "STALE_EDIT")

    def test_out_of_range_is_a_conflict(self) -> None:
        with self.assertRaises(ConflictError):
            apply_text_edits("abc", [TextEdit(2, 9, "c", "q")])

    def test_edit_preserves_asa_quirks(self) -> None:
        text = (
            "\n: Saved\n!\ninterface Gi0/0\n ip address 10.1.1.1 255.255.255.0 \n"
            "banner motd ^CWelcome^C\r\nend\n  \ntext after end"
        )
        like = decoded(text)
        start = text.index("10.1.1.1")
        out = edit_blob(like, [TextEdit(start, start + 8, "10.1.1.1", "10.9.9.9")])
        d = decode_blob(out)
        assert d is not None
        self.assertEqual(d.text, text.replace("10.1.1.1", "10.9.9.9"))
        self.assertTrue(d.text.startswith("\n"))
        self.assertTrue(d.canonical)

    def test_edit_preserves_missing_trailing_newline_and_crlf(self) -> None:
        text = "hostname fw1\r\nset x 1\r\nend"
        like = decoded(text)
        out = edit_blob(like, [TextEdit(9, 12, "fw1", "fw2")])
        d = decode_blob(out)
        assert d is not None
        self.assertEqual(d.text, "hostname fw2\r\nset x 1\r\nend")


class MinilabBlobTests(unittest.TestCase):
    def test_garbage_blob_lab(self) -> None:
        lab = minilab("garbage_blob")
        by_id = {b.id: decode_blob(b.b64) for b in lab.config_blobs()}
        self.assertIsNone(by_id["1"])  # literally "ff"
        self.assertIsNotNone(by_id["2"])
        self.assertIsNone(by_id["3"])  # binary
        d4 = by_id["4"]
        assert d4 is not None
        self.assertEqual(d4.text, "ff")

    def test_noncanonical_lab(self) -> None:
        lab = minilab("noncanonical_b64")
        flags = {b.id: decode_blob(b.b64) for b in lab.config_blobs()}
        for cid in ("1", "2", "3"):
            d = flags[cid]
            assert d is not None
            self.assertFalse(d.canonical, cid)
            self.assertIn("hostname rtr", d.text)
        d4 = flags["4"]
        assert d4 is not None
        self.assertTrue(d4.canonical)
        self.assertEqual(flags["1"].text, d4.text)  # type: ignore[union-attr]

    def test_basic_blobs_decode_and_mirror_sidecar(self) -> None:
        lab = minilab("basic")
        startup4 = next(
            b for b in lab.config_blobs() if (b.scope, b.id) == ("startup", "4")
        )
        d = decode_blob(startup4.b64)
        assert d is not None
        sidecar = (
            minilab_path("basic").parent / "basic_cfgs" / "4_srv1.txt"
        ).read_bytes()
        self.assertEqual(d.text.encode(), sidecar)

    def test_textobject_svg_and_html_decode(self) -> None:
        lab = minilab("basic")
        texts = {t.id: decode_blob(t.b64) for t in lab.textobjects()}
        self.assertIn("(VLAN 203)", texts["1"].text)  # type: ignore[union-attr]
        self.assertTrue(texts["2"].text.startswith("<svg"))  # type: ignore[union-attr]


class RealLabRoundTripTests(unittest.TestCase):
    """decode -> encode is byte-identical for every blob of every real lab."""

    def test_every_blob_round_trips(self) -> None:
        paths = real_lab_paths()
        self.assertGreaterEqual(len(paths), 9)
        total = 0
        for path in paths:
            lab = read_real(path)
            for blob in [*lab.config_blobs(), *lab.textobjects()]:
                with self.subTest(lab=path.name, scope=blob.scope, id=blob.id):
                    d = decode_blob(blob.b64)
                    assert d is not None, "real labs have no opaque blobs"
                    self.assertTrue(d.canonical)
                    self.assertEqual(encode_text(d.text, d.encoding), blob.b64)
                    self.assertIs(encode_blob(d.text, d), d.raw_b64)
                    total += 1
        self.assertGreater(total, 900)

    def test_real_blobs_survive_a_noop_text_edit(self) -> None:
        lab = read_real(
            next(p for p in real_lab_paths() if p.name == "azure_asa_vpn.unl")
        )
        for blob in lab.config_blobs():
            d = decode_blob(blob.b64)
            assert d is not None
            self.assertEqual(edit_blob(d, [TextEdit(0, 0, "", "")]), blob.b64)


if __name__ == "__main__":
    unittest.main()
