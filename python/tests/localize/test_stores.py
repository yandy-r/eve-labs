"""Tests for evelab.localize.stores (embedded blobs, textobjects, sidecars, mirrors)."""

from __future__ import annotations

import shutil
import unittest
from collections import Counter
from pathlib import Path

from evelab.common.codec import apply_text_edits, decode_blob
from evelab.common.unl import RawLab
from evelab.localize import dialects
from evelab.localize.errors import LocalizeError
from evelab.localize.manifest import Manifest, NodeOverride
from evelab.localize.model import ConfigText, Node, Store, TextEdit
from evelab.localize.stores import (
    active_scope,
    find_sidecar_dirs,
    is_garbage_text,
    load_texts,
    mirror_source,
    mirrors_agree,
    newline_style,
    write_sidecar,
)

from .labfiles import minilab, minilab_path, read_real, real_lab_paths

LAB_ID = "00000000-0000-4000-8000-000000000000"


def _codes(findings):
    return Counter(f.code for f in findings)


def _by(texts, kind, node_id=None):
    return [
        t
        for t in texts
        if t.store.kind == kind and (node_id is None or t.node_id == node_id)
    ]


def _manifest(lab: RawLab, **kw) -> Manifest:
    return Manifest(lab=lab.path.name, lab_id=lab.lab_id or LAB_ID, **kw)


def _sidecar_ct(text: str) -> ConfigText:
    return ConfigText(
        Store("sidecar", "x_cfgs/1_a.txt", "startup"),
        "1",
        text,
        "generic",
        None,
        Path("x_cfgs/1_a.txt"),
    )


class EmbeddedTests(unittest.TestCase):
    def test_basic_stores_and_order(self):
        lab = minilab("basic")
        texts, findings = load_texts(lab)
        kinds = [t.store.kind for t in texts]
        # embedded first (document order), then textobjects, then sidecars
        self.assertEqual(
            kinds,
            sorted(kinds, key=["startup", "configset", "textobject", "sidecar"].index),
        )
        startup = _by(texts, "startup")
        self.assertEqual([t.node_id for t in startup], ["1", "2", "4"])
        self.assertTrue(
            all(t.store == Store("startup", "startup", "startup") for t in startup)
        )
        cs = _by(texts, "configset")
        self.assertEqual([t.node_id for t in cs], ["1", "2"])
        self.assertTrue(
            all(t.store == Store("configset", "alt-scheme", "alt-scheme") for t in cs)
        )
        for t in startup + cs:
            self.assertIsNotNone(t.blob)
            self.assertIsNone(t.path)
            self.assertFalse(t.opaque)
            self.assertEqual(t.text, t.blob.text)
        self.assertIn("encapsulation dot1Q 1240", startup[0].text)
        self.assertIn("1241", cs[0].text)
        self.assertFalse(
            [f for f in findings if f.severity in ("warn", "blocker", "error")]
        )

    def test_nodes_default_and_explicit_equal(self):
        lab = minilab("basic")
        a, _ = load_texts(lab)
        b, _ = load_texts(lab, lab.node_models(), None)
        self.assertEqual(
            [(t.store, t.node_id, t.text) for t in a],
            [(t.store, t.node_id, t.text) for t in b],
        )

    def test_dialect_matches_pick(self):
        lab = minilab("basic")
        nodes = lab.node_models()
        texts, _ = load_texts(lab)
        for t in _by(texts, "startup") + _by(texts, "sidecar"):
            try:
                expected = dialects.pick(nodes[t.node_id], t.text).name
            except LocalizeError:
                expected = "generic"
            self.assertEqual(t.dialect, expected, t.store)

    def test_unknown_dialect_override(self):
        lab = minilab("basic")
        man = _manifest(lab, nodes={"1": NodeOverride(dialect="no-such-dialect")})
        texts, findings = load_texts(lab, None, man)
        errs = [f for f in findings if f.code == "UNKNOWN_DIALECT"]
        self.assertEqual(len(errs), 2)  # startup + configset blob of node 1
        self.assertTrue(all(f.severity == "error" for f in errs))
        self.assertTrue(all(t.dialect for t in texts))

    def test_textobjects(self):
        lab = minilab("basic")
        texts, _ = load_texts(lab)
        tos = _by(texts, "textobject")
        self.assertEqual(len(tos), len(lab.textobjects()))
        for t, raw in zip(tos, lab.textobjects(), strict=True):
            self.assertEqual(t.store, Store("textobject", raw.id, "-"))
            self.assertEqual(t.node_id, "")
        none, _ = load_texts(lab, textobjects=False)
        self.assertFalse(_by(none, "textobject"))

    def test_no_configs(self):
        texts, findings = load_texts(minilab("no_configs"))
        self.assertFalse(_by(texts, "startup") + _by(texts, "configset"))
        self.assertFalse(_by(texts, "sidecar"))
        self.assertFalse([f for f in findings if f.severity != "info"])


class OpaqueTests(unittest.TestCase):
    def test_garbage_blobs(self):
        texts, findings = load_texts(minilab("garbage_blob"))
        st = {t.node_id: t for t in _by(texts, "startup")}
        self.assertEqual(set(st), {"1", "2", "3", "4"})
        # literal "ff" (invalid base64) and binary payload: undecodable
        for nid in ("1", "3"):
            self.assertTrue(st[nid].opaque)
            self.assertIsNone(st[nid].blob)
            self.assertEqual(st[nid].text, "")
        # ZmY= decodes to text "ff": kept, but opaque (no facts)
        self.assertTrue(st["4"].opaque)
        self.assertIsNotNone(st["4"].blob)
        self.assertEqual(st["4"].text, "ff")
        self.assertFalse(st["2"].opaque)
        opaque = [f for f in findings if f.code == "OPAQUE_BLOB"]
        self.assertEqual(len(opaque), 3)
        self.assertTrue(all(f.severity == "info" for f in opaque))

    def test_config_without_blob(self):
        texts, findings = load_texts(minilab("config_no_blob"))
        st = {t.node_id: t for t in _by(texts, "startup")}
        self.assertNotIn("1", st)
        self.assertTrue(st["2"].opaque)
        self.assertTrue(st["3"].opaque)  # self-closing
        self.assertFalse(st["4"].opaque)
        codes = _codes(findings)
        self.assertEqual(codes["MISSING_BLOB"], 1)
        self.assertEqual(codes["OPAQUE_BLOB"], 2)
        missing = next(f for f in findings if f.code == "MISSING_BLOB")
        self.assertEqual(missing.refs, ["node:1"])

    def test_is_garbage_text(self):
        for s in ("ff", "", "  \n", "xyz\n"):
            self.assertTrue(is_garbage_text(s), s)
        for s in (
            "ip 10.0.0.1/24",
            "hostname r1\n",
            "10.1.1.1",
            "set pcname x",
            "!\nend\n",
        ):
            self.assertFalse(is_garbage_text(s), s)

    def test_noncanonical_still_read(self):
        texts, _ = load_texts(minilab("noncanonical_b64"))
        st = _by(texts, "startup")
        self.assertEqual(len(st), 4)
        self.assertEqual(sum(1 for t in st if not t.blob.canonical), 3)
        self.assertFalse(any(t.opaque for t in st))


class SidecarDirTests(unittest.TestCase):
    def test_exact(self):
        p = minilab_path("basic")
        res = find_sidecar_dirs(p, None)
        self.assertEqual(res.source, "exact")
        self.assertEqual([d.name for d in res.dirs], ["basic_cfgs"])

    def test_none(self):
        res = find_sidecar_dirs(minilab_path("missing_sidecar"), None)
        self.assertEqual((res.source, res.dirs, res.findings), ("none", [], []))

    def test_glob_non_exact_name(self):
        p = minilab_path("basic")
        (p.parent / "basic_cfgs").rename(p.parent / "basic_with_backbone_dmvpn_cfgs")
        res = find_sidecar_dirs(p, None)
        self.assertEqual(res.source, "glob")
        self.assertEqual([d.name for d in res.dirs], ["basic_with_backbone_dmvpn_cfgs"])
        texts, _ = load_texts(RawLab.read(p))
        names = [t.store.name for t in _by(texts, "sidecar")]
        self.assertEqual(
            names,
            [
                "basic_with_backbone_dmvpn_cfgs/3_fw1.txt",
                "basic_with_backbone_dmvpn_cfgs/4_srv1.txt",
            ],
        )

    def test_glob_skips_other_labs_exact_dir(self):
        p = minilab_path("basic")
        other = p.parent / "basic_two.unl"
        shutil.copyfile(p, other)
        (p.parent / "basic_cfgs").rename(p.parent / "basic_two_cfgs")
        res = find_sidecar_dirs(p, None)
        self.assertEqual(res.source, "none")
        self.assertEqual(find_sidecar_dirs(other, None).source, "exact")

    def test_ambiguous_blocker(self):
        lab = minilab("sidecar_ambiguous")
        texts, findings = load_texts(lab)
        self.assertFalse(_by(texts, "sidecar"))
        amb = [f for f in findings if f.code == "SIDECAR_AMBIGUOUS"]
        self.assertEqual(len(amb), 1)
        self.assertEqual(amb[0].severity, "blocker")
        self.assertEqual(
            amb[0].refs, ["sidecar_ambiguous_a_cfgs", "sidecar_ambiguous_b_cfgs"]
        )

    def test_manifest_sidecar_dirs_resolve_ambiguity(self):
        lab = minilab("sidecar_ambiguous")
        man = _manifest(lab, sidecar_dirs=["sidecar_ambiguous_b_cfgs"])
        texts, findings = load_texts(lab, None, man)
        self.assertNotIn("SIDECAR_AMBIGUOUS", _codes(findings))
        sc = _by(texts, "sidecar")
        self.assertEqual(
            [t.store.name for t in sc], ["sidecar_ambiguous_b_cfgs/2_fw1.txt"]
        )

    def test_manifest_missing_dir(self):
        lab = minilab("basic")
        man = _manifest(lab, sidecar_dirs=["nope_cfgs"])
        texts, findings = load_texts(lab, None, man)
        self.assertFalse(_by(texts, "sidecar"))
        self.assertEqual(_codes(findings)["SIDECAR_DIR_MISSING"], 1)


class SidecarMappingTests(unittest.TestCase):
    def test_basic_sidecars(self):
        lab = minilab("basic")
        texts, _ = load_texts(lab)
        fw = _by(texts, "sidecar", "3")[0]
        self.assertEqual(fw.store, Store("sidecar", "basic_cfgs/3_fw1.txt", "startup"))
        self.assertIsNone(fw.blob)
        self.assertEqual(fw.path, lab.path.parent / "basic_cfgs" / "3_fw1.txt")
        self.assertTrue(fw.text.startswith("# fw1 — edge firewall"))
        self.assertIsNone(fw.mirror_of)
        self.assertFalse(fw.opaque)

    def test_id_name_guard(self):
        lab = minilab("sidecar_mismatch")
        texts, findings = load_texts(lab)
        self.assertEqual(
            [t.store.name for t in _by(texts, "sidecar")],
            ["sidecar_mismatch_cfgs/2_fw1.txt"],
        )
        mism = [f for f in findings if f.code == "SIDECAR_MISMATCH"]
        self.assertEqual(
            sorted(r for f in mism for r in f.refs),
            [
                "sidecar_mismatch_cfgs/3_edge-fw.txt",
                "sidecar_mismatch_cfgs/9_ghost.txt",
            ],
        )
        self.assertTrue(all(f.severity == "warn" for f in mism))
        # notes.txt is silently ignored
        self.assertFalse(any("notes.txt" in r for f in findings for r in f.refs))

    def test_sidecar_map_forces_mapping(self):
        lab = minilab("sidecar_mismatch")
        man = _manifest(lab, sidecar_map={"3_edge-fw.txt": "3"})
        texts, findings = load_texts(lab, None, man)
        sc = {t.node_id: t for t in _by(texts, "sidecar")}
        self.assertEqual(sc["3"].store.name, "sidecar_mismatch_cfgs/3_edge-fw.txt")
        refs = [r for f in findings if f.code == "SIDECAR_MISMATCH" for r in f.refs]
        self.assertEqual(refs, ["sidecar_mismatch_cfgs/9_ghost.txt"])

    def test_sidecar_map_relpath_and_bad_node(self):
        lab = minilab("sidecar_mismatch")
        man = _manifest(
            lab,
            sidecar_map={
                "sidecar_mismatch_cfgs/notes.txt": "1",
                "9_ghost.txt": "99",
            },
        )
        texts, findings = load_texts(lab, None, man)
        sc = {t.node_id: t.store.name for t in _by(texts, "sidecar")}
        self.assertEqual(sc["1"], "sidecar_mismatch_cfgs/notes.txt")
        msgs = [f.msg for f in findings if f.code == "SIDECAR_MISMATCH"]
        self.assertTrue(any("node 99" in m for m in msgs))

    def test_missing_sidecar(self):
        texts, findings = load_texts(minilab("missing_sidecar"))
        self.assertFalse(_by(texts, "sidecar"))
        self.assertFalse([f for f in findings if f.severity != "info"])

    def test_duplicate_sidecar_for_node(self):
        lab = minilab("basic")
        man = _manifest(lab, sidecar_map={"extra_cfgs/fw1-copy.txt": "3"})
        extra = lab.path.parent / "extra_cfgs"
        extra.mkdir()
        shutil.copyfile(
            lab.path.parent / "basic_cfgs" / "3_fw1.txt", extra / "fw1-copy.txt"
        )
        man.sidecar_dirs = ["basic_cfgs"]
        texts, findings = load_texts(lab, None, man)
        self.assertEqual(len(_by(texts, "sidecar", "3")), 2)
        self.assertEqual(_codes(findings)["SIDECAR_DUPLICATE"], 1)


class MirrorTests(unittest.TestCase):
    def test_basic_mirror(self):
        lab = minilab("basic")
        texts, _ = load_texts(lab)
        srv = _by(texts, "sidecar", "4")[0]
        self.assertEqual(srv.mirror_of, ("startup", "4"))
        self.assertEqual(srv.store.scope, "startup")
        src = mirror_source(texts, srv)
        self.assertIs(src, _by(texts, "startup", "4")[0])
        self.assertEqual(src.text, srv.text)
        self.assertIsNone(mirror_source(texts, _by(texts, "sidecar", "3")[0]))

    def test_mirror_edits_agree(self):
        texts, _ = load_texts(minilab("basic"))
        srv = _by(texts, "sidecar", "4")[0]
        src = mirror_source(texts, srv)
        i = srv.text.index("10.100.51.31")
        edit = TextEdit(i, i + 12, "10.100.51.31", "10.9.9.31")
        a = apply_text_edits(srv.text, [edit])
        b = apply_text_edits(src.text, [edit])
        self.assertTrue(mirrors_agree(a, b))
        self.assertFalse(mirrors_agree(a, src.text))

    def test_diverged_sidecar_is_independent(self):
        p = minilab_path("basic")
        f = p.parent / "basic_cfgs" / "4_srv1.txt"
        f.write_bytes(f.read_bytes() + b"# local change\n")
        texts, findings = load_texts(RawLab.read(p))
        srv = _by(texts, "sidecar", "4")[0]
        self.assertIsNone(srv.mirror_of)
        indep = [x for x in findings if x.code == "SIDECAR_INDEPENDENT"]
        self.assertEqual(len(indep), 1)
        self.assertEqual(indep[0].severity, "info")

    def test_active_scope_preferred(self):
        p = minilab_path("basic")
        lab = RawLab.read(p)
        cs_blob = next(
            b
            for b in lab.config_blobs()
            if b.scope == "cs:alt-scheme" and b.node_id == "1"
        )
        side = p.parent / "basic_cfgs" / "1_rtr1.txt"
        db = decode_blob(cs_blob.b64)
        side.write_bytes(db.text.encode(db.encoding))
        texts, _ = load_texts(lab)
        rtr = _by(texts, "sidecar", "1")[0]
        self.assertEqual(rtr.mirror_of, ("alt-scheme", "1"))
        self.assertEqual(rtr.store.scope, "alt-scheme")

    def test_active_scope_helper(self):
        n = Node("1", "r", "iol", "iol", "img", "2", [])
        self.assertEqual(active_scope(n, {"2": "cs-two"}), "cs-two")
        n.config_attr = "1"
        self.assertEqual(active_scope(n, {"2": "cs-two"}), "startup")
        self.assertEqual(active_scope(None, {}), "startup")


class NewlineTests(unittest.TestCase):
    def test_style_detection(self):
        self.assertEqual(newline_style("a\nb\n"), "lf")
        self.assertEqual(newline_style("a\r\nb\r\n"), "crlf")
        self.assertEqual(newline_style("a\r\nb\n"), "mixed")
        self.assertEqual(newline_style("abc"), "none")

    def test_crlf_sidecar_roundtrip(self):
        lab = minilab("crlf_sidecar")
        texts, _ = load_texts(lab)
        fw1, fw2 = _by(texts, "sidecar", "2")[0], _by(texts, "sidecar", "3")[0]
        self.assertEqual(newline_style(fw1.text), "crlf")
        self.assertTrue(fw1.text.endswith("\r\n"))
        self.assertFalse(fw2.text.endswith("\n"))
        for ct in (fw1, fw2):
            self.assertEqual(write_sidecar(ct, ct.text), ct.path.read_bytes())

    def test_crlf_preserved_on_edit(self):
        texts, _ = load_texts(minilab("crlf_sidecar"))
        fw1 = _by(texts, "sidecar", "2")[0]
        new = fw1.text.replace("end\r\n", "end\n# added\n")
        out = write_sidecar(fw1, new)
        self.assertNotIn(b"\n", out.replace(b"\r\n", b""))
        self.assertTrue(out.endswith(b"# added\r\n"))
        # trailing newline restored when an edit drops it
        out2 = write_sidecar(fw1, fw1.text.rstrip("\r\n"))
        self.assertEqual(out2, fw1.path.read_bytes())

    def test_no_trailing_newline_kept(self):
        texts, _ = load_texts(minilab("crlf_sidecar"))
        fw2 = _by(texts, "sidecar", "3")[0]
        out = write_sidecar(fw2, fw2.text + "\n")
        self.assertEqual(out, fw2.path.read_bytes())
        self.assertEqual(
            write_sidecar(fw2, fw2.text.replace("10.100.51.2", "10.9.9.2")),
            fw2.path.read_bytes().replace(b"10.100.51.2", b"10.9.9.2"),
        )

    def test_lf_and_utf8_roundtrip(self):
        texts, _ = load_texts(minilab("basic"))
        fw = _by(texts, "sidecar", "3")[0]
        self.assertEqual(write_sidecar(fw, fw.text), fw.path.read_bytes())
        out = write_sidecar(fw, fw.text.replace("\n", "\r\n"))
        self.assertEqual(out, fw.path.read_bytes())

    def test_surrogateescape(self):
        ct = _sidecar_ct("caf\udce9\n")
        self.assertEqual(write_sidecar(ct, ct.text), b"caf\xe9\n")

    def test_not_sidecar(self):
        ct = _sidecar_ct("x\n")
        ct.store = Store("startup", "startup", "startup")
        with self.assertRaises(LocalizeError):
            write_sidecar(ct, "y\n")


class RealLabTests(unittest.TestCase):
    """Read-only checks on the committed labs (no writes)."""

    def _lab(self, stem):
        for p in real_lab_paths():
            if p.stem == stem:
                return read_real(p)
        self.skipTest(f"{stem} not present")

    def test_backbone_glob_dir_and_mirrors(self):
        lab = self._lab("vxlan_evpn_multi-site_with_backbone")
        res = find_sidecar_dirs(lab.path, None)
        self.assertEqual(res.source, "glob")
        self.assertEqual(
            [d.name for d in res.dirs],
            ["vxlan_evpn_multi-site_with_backbone_dmvpn_cfgs"],
        )
        texts, findings = load_texts(lab)
        sc = _by(texts, "sidecar")
        self.assertEqual(len(sc), 72)
        self.assertTrue(all(t.mirror_of is not None for t in sc))
        scopes = Counter(t.mirror_of[0] for t in sc)
        self.assertEqual(scopes, {"vxlan-dmvpn-backbone": 61, "startup": 11})
        for t in sc:
            self.assertEqual(t.store.scope, t.mirror_of[0])
            src = mirror_source(texts, t)
            self.assertIsNotNone(src)
            self.assertEqual(src.text, t.text)
            self.assertEqual(write_sidecar(t, t.text), t.path.read_bytes())
        self.assertFalse(
            [f for f in findings if f.severity in ("warn", "blocker", "error")]
        )

    def test_sdwan_sidecars_are_independent_stores(self):
        lab = self._lab("vxlan_evpn_multi-site_sdwan_only")
        res = find_sidecar_dirs(lab.path, None)
        self.assertEqual(res.source, "exact")
        texts, findings = load_texts(lab)
        sc = _by(texts, "sidecar")
        self.assertEqual(len(sc), 9)
        nodes = lab.node_models()
        cs = lab.configsets()
        for t in sc:
            self.assertIsNone(t.mirror_of)
            self.assertEqual(t.store.scope, active_scope(nodes[t.node_id], cs))
            self.assertEqual(write_sidecar(t, t.text), t.path.read_bytes())
        self.assertFalse(
            [f for f in findings if f.severity in ("warn", "blocker", "error")]
        )

    def test_all_real_labs_load(self):
        for p in real_lab_paths():
            with self.subTest(lab=p.name):
                lab = read_real(p)
                texts, findings = load_texts(lab)
                emb = _by(texts, "startup") + _by(texts, "configset")
                self.assertEqual(len(emb), len(lab.config_blobs()))
                self.assertEqual(len(_by(texts, "textobject")), len(lab.textobjects()))
                for t in emb:
                    if t.blob is not None and not t.opaque:
                        self.assertEqual(t.text, t.blob.text)
                self.assertFalse(
                    [f for f in findings if f.severity in ("blocker", "error")]
                )

    def test_lab1_ff_blob_is_opaque(self):
        lab = self._lab("lab1-ei-v01")
        texts, findings = load_texts(lab)
        ff = [t for t in texts if t.blob is not None and t.text.strip() == "ff"]
        self.assertTrue(ff)
        self.assertTrue(all(t.opaque for t in ff))
        self.assertIn("OPAQUE_BLOB", _codes(findings))


if __name__ == "__main__":
    unittest.main()
