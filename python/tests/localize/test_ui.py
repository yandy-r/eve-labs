"""Tests for evelab.localize.ui: prompts, non-TTY behaviour, tables, diff, redaction."""

import io
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from evelab.localize import ui
from evelab.localize.model import (
    Attachment,
    Confidence,
    Edit,
    Finding,
    Plan,
    Scheme,
    Segment,
    Store,
    TextEdit,
)


class TtyStringIO(io.StringIO):
    def isatty(self) -> bool:
        return True


class NoReadStdin(io.StringIO):
    """stdin that fails the test if anything tries to read from it."""

    def readline(self, *a: object, **k: object) -> str:
        raise AssertionError("must not read stdin when not interactive")

    read = readline


def make(inp: str = "", **kw: object) -> tuple[ui.UI, io.StringIO, io.StringIO]:
    out, err = io.StringIO(), io.StringIO()
    kw.setdefault("interactive", True)
    kw.setdefault("env", {})
    u = ui.UI(io.StringIO(inp), out, err, **kw)  # type: ignore[arg-type]
    return u, out, err


def make_edit(
    text: str,
    old: str,
    new: str,
    *,
    secret: bool = False,
    eid: str = "e1",
    after: str = "",
) -> Edit:
    start = text.index(after + old) + len(after) if after else text.index(old)
    return Edit(
        id=eid,
        file=Path("lab.unl"),
        target="blob",
        store=Store("startup", "startup", "startup"),
        node_id="1",
        text_edit=TextEdit(start, start + len(old), old, new),
        category="secret" if secret else "vlan",
        group="g",
        confidence=Confidence.PROVEN,
        secret=secret,
        provenance=[],
    )


class ColorTests(unittest.TestCase):
    def test_plain_when_not_tty(self) -> None:
        u = ui.UI(io.StringIO(), io.StringIO(), io.StringIO(), env={})
        self.assertFalse(u.color)
        self.assertEqual(u.style("x", "red"), "x")

    def test_color_on_tty(self) -> None:
        u = ui.UI(io.StringIO(), TtyStringIO(), io.StringIO(), env={"TERM": "xterm"})
        self.assertTrue(u.color)
        self.assertEqual(u.style("x", "red"), "\x1b[31mx\x1b[0m")

    def test_no_color_env(self) -> None:
        u = ui.UI(io.StringIO(), TtyStringIO(), io.StringIO(), env={"NO_COLOR": "1"})
        self.assertFalse(u.color)

    def test_empty_no_color_is_ignored(self) -> None:
        u = ui.UI(io.StringIO(), TtyStringIO(), io.StringIO(), env={"NO_COLOR": ""})
        self.assertTrue(u.color)

    def test_dumb_term_and_forced_off(self) -> None:
        u = ui.UI(io.StringIO(), TtyStringIO(), io.StringIO(), env={"TERM": "dumb"})
        self.assertFalse(u.color)
        u = ui.UI(io.StringIO(), TtyStringIO(), io.StringIO(), color=False, env={})
        self.assertFalse(u.color)

    def test_forced_on(self) -> None:
        u = ui.UI(io.StringIO(), io.StringIO(), io.StringIO(), color=True, env={})
        self.assertTrue(u.style("x", "bold").startswith("\x1b[1m"))

    def test_strip_and_visible_len(self) -> None:
        self.assertEqual(ui.strip_ansi("\x1b[31mab\x1b[0m"), "ab")
        self.assertEqual(ui.visible_len("\x1b[1mabc\x1b[0m"), 3)


class ModeTests(unittest.TestCase):
    def test_modes(self) -> None:
        self.assertEqual(make()[0].mode, "interactive")
        self.assertEqual(make(interactive=False)[0].mode, "keep")
        self.assertEqual(make(assume_yes=True)[0].mode, "yes")
        u = ui.UI(io.StringIO(), io.StringIO(), io.StringIO())
        self.assertFalse(u.interactive)  # StringIO is not a TTY

    def test_stdin_tty_detected(self) -> None:
        u = ui.UI(TtyStringIO(), io.StringIO(), io.StringIO())
        self.assertTrue(u.interactive)

    def test_quiet_suppresses_out_not_errors(self) -> None:
        u, out, err = make(verbosity=-1)
        u.out("hello")
        u.error("bad")
        self.assertEqual(out.getvalue(), "")
        self.assertIn("bad", err.getvalue())

    def test_debug_only_verbose(self) -> None:
        u, _, err = make()
        u.debug("d")
        self.assertEqual(err.getvalue(), "")
        u, _, err = make(verbosity=1)
        u.debug("d")
        self.assertIn("d", err.getvalue())

    def test_unicode_encode_fallback(self) -> None:
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding="ascii")
        u = ui.UI(io.StringIO(), out, io.StringIO(), env={})
        u.out("a · b")
        out.flush()
        self.assertEqual(raw.getvalue(), b"a ? b\n")


class PromptTests(unittest.TestCase):
    def test_enter_takes_default(self) -> None:
        u, out, _ = make("\n")
        r = u.prompt("bridge", default="pnet1", default_source="from site")
        self.assertEqual(r, ui.Reply("default", "pnet1"))
        self.assertIn("bridge [pnet1 from site]: ", out.getvalue())

    def test_typed_value(self) -> None:
        u, _, _ = make("pnet3\n")
        self.assertEqual(
            u.prompt("bridge", default="pnet1"), ui.Reply("value", "pnet3")
        )

    def test_keep_key(self) -> None:
        u, _, _ = make("k\n")
        self.assertEqual(
            u.prompt("tag", default="20", current="2"), ui.Reply("keep", "2")
        )

    def test_enter_keeps_current_without_default(self) -> None:
        u, out, _ = make("\n")
        self.assertEqual(u.prompt("tag", current="2"), ui.Reply("keep", "2"))
        self.assertIn("[Enter=keep]", out.getvalue())

    def test_skip_and_back_only_when_allowed(self) -> None:
        u, _out, _ = make("s\nb\ns\nb\n")
        r = u.prompt("x", allow_skip=True, allow_back=True)
        self.assertEqual(r.action, "skip")
        r = u.prompt("x", allow_skip=True, allow_back=True)
        self.assertEqual(r.action, "back")
        u, _, _ = make("s\n")  # 's' is a literal value when skip is off
        self.assertEqual(u.prompt("x"), ui.Reply("value", "s"))

    def test_quit_and_eof(self) -> None:
        u, _, _ = make("q\n")
        with self.assertRaises(ui.QuitRequested) as cm:
            u.prompt("x", default="d")
        self.assertEqual(cm.exception.exit_code, 0)
        u, _, _ = make("")
        with self.assertRaises(ui.QuitRequested):
            u.prompt("x", default="d")

    def test_evidence_then_default(self) -> None:
        u, out, _ = make("?\n\n")
        r = u.prompt("x", default="d", evidence=["path A", "path B"])
        self.assertEqual(r.action, "default")
        self.assertIn("(?=evidence)", out.getvalue())
        self.assertIn("path A", out.getvalue())
        self.assertIn("path B", out.getvalue())

    def test_evidence_masks_known_secret(self) -> None:
        u, out, _ = make("?\n\n")
        u.redactor.add("hunter22")
        u.prompt("x", default="d", evidence=["psk hunter22"])
        self.assertNotIn("hunter22", out.getvalue())
        self.assertIn("psk ****", out.getvalue())

    def test_validation_retries(self) -> None:
        def v(s: str) -> str | None:
            return None if s.isdigit() else "digits only"

        u, out, _ = make("abc\n42\n")
        self.assertEqual(u.prompt("tag", validate=v), ui.Reply("value", "42"))
        self.assertIn("invalid: digits only", out.getvalue())

    def test_invalid_default_not_accepted(self) -> None:
        u, out, _ = make("\n7\n")
        r = u.prompt("tag", default="x", validate=lambda s: None if s == "7" else "no")
        self.assertEqual(r, ui.Reply("value", "7"))
        self.assertIn("invalid default", out.getvalue())

    def test_required_reasks(self) -> None:
        u, out, _ = make("\nval\n")
        self.assertEqual(u.prompt("x"), ui.Reply("value", "val"))
        self.assertIn("required", out.getvalue())

    def test_optional_skip_on_enter(self) -> None:
        u, _, _ = make("\n")
        self.assertEqual(u.prompt("x", required=False, allow_skip=True).action, "skip")

    def test_choices_exact_prefix_ci(self) -> None:
        ch = ["tag", "octet", "keep"]
        for typed, want in (
            ("tag", "tag"),
            ("O", "octet"),
            ("k", "keep"),
            ("KEEP", "keep"),
        ):
            u, _, _ = make(typed + "\n")
            self.assertEqual(
                u.prompt("tpl", choices=ch), ui.Reply("value", want), typed
            )

    def test_choices_reject_and_allow_other(self) -> None:
        u, out, _ = make("zzz\ntag\n")
        self.assertEqual(u.prompt("x", choices=["tag", "octet"]).value, "tag")
        self.assertIn("choose one of: tag, octet", out.getvalue())
        u, _, _ = make("pnet9\n")
        r = u.prompt("b", choices=["pnet0", "pnet1"], allow_other=True)
        self.assertEqual(r.value, "pnet9")

    def test_ambiguous_prefix_rejected(self) -> None:
        u, out, _ = make("pnet\npnet1\n")
        r = u.prompt("b", choices=["pnet0", "pnet1"])
        self.assertEqual(r.value, "pnet1")
        self.assertIn("choose one of", out.getvalue())

    def test_choice_notes_listed(self) -> None:
        u, out, _ = make("pnet0\n")
        u.prompt("b", choices=["pnet0", "pnet1"], choice_notes={"pnet0": "up, 4 ports"})
        self.assertIn("pnet0", out.getvalue())
        self.assertIn("up, 4 ports", out.getvalue())

    def test_same_choice_listing_shown_once(self) -> None:
        u, out, _ = make("pnet0\npnet1\npnet0\n")
        notes = {"pnet0": "up, 4 ports"}
        u.prompt("a", choices=["pnet0", "pnet1"], choice_notes=notes)
        u.prompt("b", choices=["pnet0", "pnet1"], choice_notes=notes)
        self.assertEqual(out.getvalue().count("up, 4 ports"), 1)
        u.prompt("c", choices=["pnet0", "pnet1"], choice_notes={"pnet0": "down"})
        self.assertIn("down", out.getvalue())

    def test_choice_beats_reserved_key(self) -> None:
        u, _, _ = make("s\n")
        r = u.prompt("x", choices=["s", "t"], allow_skip=True)
        self.assertEqual(r, ui.Reply("value", "s"))

    def test_progress_prefix(self) -> None:
        line = ui.format_prompt("MGMT-203 bridge", progress=(1, 5), default="pnet1")
        self.assertEqual(line, " 1/5 MGMT-203 bridge [pnet1]: ")


class NonInteractiveTests(unittest.TestCase):
    def mk(self, **kw: object) -> tuple[ui.UI, io.StringIO]:
        out = io.StringIO()
        u = ui.UI(NoReadStdin(), out, io.StringIO(), env={}, **kw)  # type: ignore[arg-type]
        return u, out

    def test_non_tty_never_reads_and_keeps(self) -> None:
        u, out = self.mk()
        self.assertEqual(u.mode, "keep")
        self.assertEqual(
            u.prompt("tag", default="20", current="2"), ui.Reply("keep", "2")
        )
        self.assertEqual(u.unanswered, ["tag"])
        self.assertEqual(out.getvalue(), "")

    def test_strict_raises_exit_3(self) -> None:
        u, _ = self.mk(strict=True)
        with self.assertRaises(ui.UnansweredError) as cm:
            u.prompt("tag", current="2")
        self.assertEqual(cm.exception.exit_code, 3)

    def test_yes_takes_default(self) -> None:
        u, _ = self.mk(assume_yes=True)
        self.assertEqual(u.prompt("tag", default="20"), ui.Reply("default", "20"))
        self.assertEqual(u.unanswered, [])

    def test_yes_without_default_keeps_and_records(self) -> None:
        u, _ = self.mk(assume_yes=True)
        self.assertEqual(u.prompt("tag", current="2"), ui.Reply("keep", "2"))
        self.assertEqual(u.unanswered, ["tag"])

    def test_yes_invalid_default_raises(self) -> None:
        u, _ = self.mk(assume_yes=True)
        with self.assertRaises(ui.UnansweredError):
            u.prompt("tag", default="x", validate=lambda s: "bad")

    def test_yes_no_returns_default(self) -> None:
        u, _ = self.mk()
        self.assertTrue(u.ask_yes_no("go?", default=True))
        self.assertFalse(u.ask_yes_no("go?", default=False))
        self.assertEqual(u.unanswered, ["go?", "go?"])
        u, _ = self.mk(assume_yes=True)
        self.assertTrue(u.ask_yes_no("go?", default=True))
        self.assertEqual(u.unanswered, [])
        u, _ = self.mk(strict=True)
        with self.assertRaises(ui.UnansweredError):
            u.ask_yes_no("go?")

    def test_menu_and_picker_and_secret(self) -> None:
        u, _ = self.mk()
        self.assertEqual(u.menu({"a": "apply"}, default="a"), ("a", ""))
        with self.assertRaises(ui.UnansweredError):
            u.menu({"a": "apply"})
        with self.assertRaises(ui.UnansweredError):
            u.pick_labs([ui.PickerRow("lab")])
        self.assertIsNone(u.secret("psk"))
        self.assertIn("psk", u.unanswered)

    def test_page_prints_everything(self) -> None:
        u, out = self.mk()
        u.page("\n".join(f"l{i}" for i in range(500)))
        self.assertEqual(len(out.getvalue().splitlines()), 500)


class YesNoMenuTests(unittest.TestCase):
    def test_yes_no(self) -> None:
        u, out, _ = make("y\nno\n\nmaybe\nY\n")
        self.assertTrue(u.ask_yes_no("a"))
        self.assertFalse(u.ask_yes_no("b", default=True))
        self.assertTrue(u.ask_yes_no("c", default=True))
        self.assertIn("[Y/n]", out.getvalue())
        self.assertTrue(u.ask_yes_no("d"))
        self.assertIn("[y/N]", out.getvalue())
        self.assertIn("please answer y or n", out.getvalue())

    def test_yes_no_quit(self) -> None:
        u, _, _ = make("q\n")
        with self.assertRaises(ui.QuitRequested):
            u.ask_yes_no("x")

    def test_menu_key_and_arg(self) -> None:
        keys = {"r": "review", "d": "diff", "a": "apply", "q": "quit"}
        u, out, _ = make("D c8kv-75\nzz\na\n")
        self.assertEqual(u.menu(keys), ("d", "c8kv-75"))
        self.assertEqual(u.menu(keys), ("a", ""))
        self.assertIn("[r] review", out.getvalue())
        self.assertIn("choose one of", out.getvalue())

    def test_menu_default_on_enter(self) -> None:
        u, _, _ = make("\n")
        self.assertEqual(u.menu({"a": "apply"}, default="a"), ("a", ""))

    def test_secret_getpass(self) -> None:
        answers = iter(["one", "two", "same", "same"])
        u, out, _ = make(getpass_fn=lambda p: next(answers))
        self.assertEqual(u.secret("PSK", confirm=True), "same")
        self.assertIn("differ", out.getvalue())
        u.out(u.redactor.mask("the same value"))
        self.assertIn("the **** value", out.getvalue())


class SelectionTests(unittest.TestCase):
    def test_parse(self) -> None:
        self.assertEqual(ui.parse_selection("1 3,5-6", 6), [0, 2, 4, 5])
        self.assertEqual(ui.parse_selection("3 1 3", 6), [2, 0])
        self.assertEqual(ui.parse_selection("ALL", 3), [0, 1, 2])
        self.assertEqual(ui.parse_selection("*", 2), [0, 1])

    def test_all_skips_unselectable_explicit_rejects(self) -> None:
        sel = [True, False, True]
        self.assertEqual(ui.parse_selection("all", 3, selectable=sel), [0, 2])
        with self.assertRaisesRegex(ValueError, "not selectable"):
            ui.parse_selection("2", 3, selectable=sel)
        # a range skips non-selectable rows (review fix: the prompt's own example)
        self.assertEqual(ui.parse_selection("1-3", 3, selectable=sel), [0, 2])
        with self.assertRaisesRegex(ValueError, "nothing selectable"):
            ui.parse_selection("2-3", 3, selectable=[True, False, False])

    def test_parse_errors(self) -> None:
        for bad in ("", "0", "4", "2-1", "x", "1-9", "1.5"):
            with self.assertRaises(ValueError, msg=bad):
                ui.parse_selection(bad, 3)

    def test_single_select(self) -> None:
        self.assertEqual(ui.parse_selection("2", 3, multi=False), [1])
        with self.assertRaises(ValueError):
            ui.parse_selection("1 2", 3, multi=False)
        with self.assertRaises(ValueError):
            ui.parse_selection("all", 3, multi=False)

    def test_picker_flow(self) -> None:
        rows = [
            ui.PickerRow("labs/a.unl", "CONFIGURABLE"),
            ui.PickerRow("labs/ccie.unl", "nothing to localize", selectable=False),
            ui.PickerRow("labs/b.unl", "DHCP"),
        ]
        u, out, _ = make("2\nfoo\nall\n")
        self.assertEqual(u.pick_labs(rows), [0, 2])
        text = out.getvalue()
        self.assertIn("(nothing to localize)", text)
        self.assertIn("not selectable", text)
        self.assertIn("cannot parse", text)

    def test_picker_single_default_and_quit(self) -> None:
        u, _, _ = make("\n")
        self.assertEqual(
            u.pick_labs([ui.PickerRow("a"), ui.PickerRow("b", selectable=False)]), [0]
        )
        u, _, _ = make("q\n")
        with self.assertRaises(ui.QuitRequested):
            u.pick_labs([ui.PickerRow("a"), ui.PickerRow("b")])

    def test_picker_nothing_selectable(self) -> None:
        u, _, _ = make("1\n")
        with self.assertRaises(ui.UnansweredError):
            u.pick_labs([ui.PickerRow("a", selectable=False)])


def seg(key: str, **kw: object) -> Segment:
    base: dict[str, object] = {
        "key": key,
        "site_key": f"site.{key}",
        "role": None,
        "network_ids": ["74", "76"],
        "cloud_types": {"pnet0"},
        "labels": {},
        "attachments": [],
        "schemes": [],
        "status": "CONFIGURABLE",
    }
    base.update(kw)
    return Segment(**base)  # type: ignore[arg-type]


def scheme(tag: object, subnet: str | None, gw: str | None, scopes: set[str]) -> Scheme:
    return Scheme(
        tag=tag,  # type: ignore[arg-type]
        subnet=IPv4Network(subnet) if subnet else None,
        gateway=IPv4Address(gw) if gw else None,
        scopes=scopes,
        members=[],
        outliers=[],
    )


def att(direct: bool) -> Attachment:
    return Attachment("1", "e0", "74", "startup", [], direct, "tagged")


class TableMatrixTests(unittest.TestCase):
    def test_table_alignment_and_truncation(self) -> None:
        lines = ui.render_table(["A", "Num"], [["xx", "1"], ["y", "100"]], right=[1])
        self.assertEqual(lines[0], "A   Num")
        self.assertEqual(lines[1], "xx    1")
        self.assertEqual(lines[2], "y   100")
        long = ui.render_table(["H"], [["a" * 50]], max_width=20)
        self.assertEqual(len(long[1]), 20)
        self.assertTrue(long[1].endswith("…"))

    def test_table_ansi_padding(self) -> None:
        red = "\x1b[31mab\x1b[0m"
        lines = ui.render_table(["H1", "H2"], [[red, "z"]])
        self.assertEqual(ui.strip_ansi(lines[1]), "ab  z")

    def test_table_short_rows_padded(self) -> None:
        lines = ui.render_table(["A", "B"], [["x"]])
        self.assertEqual(lines[1], "x")

    def test_matrix_rows(self) -> None:
        segs = [
            seg(
                "MGMT-203",
                schemes=[scheme(2, "10.100.203.0/24", "10.100.203.1", {"startup"})],
                attachments=[att(True), att(True), att(False)],
            ),
            seg(
                "TRUNK",
                status="CARRIER",
                carries=["MGMT-203", "MGMT-204"],
                network_ids=["132"],
            ),
            seg(
                "DHCP-1", status="DHCP", schemes=[scheme("untagged", None, None, set())]
            ),
        ]
        lines = ui.render_matrix(segs)
        self.assertEqual(
            lines[0].split(),
            ["Segment", "Nets", "Cloud", "Tag", "Subnet", "GW", "Endpoints", "Status"],
        )
        r1 = lines[1].split()
        self.assertEqual(
            r1[:6], ["MGMT-203", "74,76", "pnet0", "2", "10.100.203.0/24", ".1"]
        )
        self.assertIn("3 (1 via L2)", lines[1])
        self.assertIn("CARRIER (MGMT-203,MGMT-204)", lines[2])
        self.assertIn(" all ", lines[2])
        self.assertIn("untagged", lines[3])
        self.assertNotIn("Scope", lines[0])

    def test_matrix_multi_scheme_has_scope_column(self) -> None:
        s = seg(
            "BB",
            schemes=[
                scheme(10, "10.1.0.0/24", "10.1.0.1", {"startup"}),
                scheme(20, "10.2.0.0/16", "10.2.0.1", {"cs:a", "cs:b"}),
            ],
        )
        lines = ui.render_matrix([s])
        self.assertIn("Scope", lines[0])
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[2].startswith(" "))
        self.assertIn("cs:a,cs:b", lines[2])
        self.assertIn("10.2.0.1", lines[2])  # /16: full gateway

    def test_matrix_outliers_and_color(self) -> None:
        sch = scheme(5, "10.0.0.0/24", "10.0.0.254", {"startup"})
        sch.outliers = ["f1", "f2"]
        colored = ui.render_matrix(
            [seg("X", schemes=[sch])], style=lambda t, c: f"<{c}>{t}"
        )
        self.assertIn("<green>CONFIGURABLE, 2 outliers", colored[1])
        self.assertIn(".254", colored[1])

    def test_findings_sorted(self) -> None:
        fs = [
            Finding("W", "warn", "w"),
            Finding("B", "blocker", "b\x1b[31m"),
            Finding("I", "info", "i"),
        ]
        lines = ui.render_findings(fs)
        self.assertTrue(lines[0].startswith("  [blocker] B"))
        self.assertIn("\\x1b", lines[0])
        self.assertTrue(lines[-1].startswith("  [info]"))

    def test_plan_summary(self) -> None:
        text = "a b c"
        lab = Path("lab.unl")
        e1 = make_edit(text, "a", "x", eid="1")
        e2 = make_edit(text, "b", "y", eid="2")
        e3 = make_edit(text, "c", "z", eid="3")
        e2.category = "cosmetic"
        e3.target = "sidecar"
        e3.file = Path("cfgs/f1.txt")
        e1.target = "xml_attr"
        e1.file = lab
        e2.file = lab
        e2.store = Store("configset", "sdwan", "sdwan")
        plan = Plan(
            1,
            lab,
            "L",
            {},
            "",
            [e1, e2, e3],
            set(),
            [Finding("W", "warn", "w"), Finding("B", "blocker", "b")],
        )
        lines = ui.render_plan_summary(plan)
        self.assertEqual(
            lines[0],
            "Plan: 2 files, 3 edits (PROVEN 2, cosmetic 1) · 0 conflicts"
            " · 1 blockers · 1 warnings",
        )
        self.assertIn("lab.unl  xml_attr 1 · cs:sdwan 1", lines[1])
        self.assertIn("sidecar 1 file 1", lines[1])

    def test_ui_table_output(self) -> None:
        u, out, _ = make(width=80)
        u.table(["A"], [["x"]])
        self.assertEqual(out.getvalue(), "A\nx\n")


class DiffTests(unittest.TestCase):
    TEXT = (
        "interface Gi1\n"
        " encapsulation dot1Q 2\n"
        " ip address 10.100.203.75 255.255.255.0\n"
        "end\n"
    )

    def test_unified_diff(self) -> None:
        after = self.TEXT.replace("dot1Q 2", "dot1Q 20")
        lines = ui.unified_diff(self.TEXT, after, "lab.unl :: startup :: node 75")
        self.assertEqual(lines[0], "--- lab.unl :: startup :: node 75")
        self.assertEqual(lines[1], "+++ lab.unl :: startup :: node 75")
        self.assertIn("- encapsulation dot1Q 2", lines)
        self.assertIn("+ encapsulation dot1Q 20", lines)
        self.assertIn(" interface Gi1", lines)

    def test_no_change_is_empty(self) -> None:
        self.assertEqual(ui.unified_diff("a\n", "a\n", "x"), [])

    def test_colors(self) -> None:
        lines = ui.unified_diff("a\n", "b\n", "x", style=lambda t, c: f"<{c}>{t}")
        self.assertIn("<red>-a", lines)
        self.assertIn("<green>+b", lines)
        self.assertTrue(any(ln.startswith("<cyan>@@") for ln in lines))

    def test_control_chars_neutralised(self) -> None:
        lines = ui.unified_diff("a\n", "b\x1b[2J\r\n", "x\x1b")
        joined = "\n".join(lines)
        self.assertNotIn("\x1b", joined)
        self.assertIn("\\x1b[2J\\r", joined)

    def test_long_line_cut(self) -> None:
        lines = ui.unified_diff("a\n", "b" * 1000 + "\n", "x", max_line=50)
        self.assertTrue(any(ln.endswith("…") and len(ln) == 50 for ln in lines))

    def test_redactor_masks_context(self) -> None:
        r = ui.Redactor(["s3cr3t-psk"])
        lines = ui.unified_diff(
            "k s3cr3t-psk\nx\n", "k s3cr3t-psk\ny\n", "x", redactor=r
        )
        self.assertNotIn("s3cr3t-psk", "\n".join(lines))
        self.assertIn(" k ****", lines)

    def test_diff_edits_masks_secret_by_span(self) -> None:
        text = "psk oldsecret\nvlan 2\n"
        edits = [
            make_edit(text, "oldsecret", "newsecret", secret=True, eid="s"),
            make_edit(text, "2", "20", eid="v", after="vlan "),
        ]
        lines = ui.diff_edits(text, edits, "lab")
        joined = "\n".join(lines)
        self.assertNotIn("oldsecret", joined)
        self.assertNotIn("newsecret", joined)
        self.assertIn("-psk ****", lines)
        self.assertIn("+psk ****", lines)
        self.assertIn("-vlan 2", lines)
        self.assertIn("+vlan 20", lines)

    def test_diff_edits_show_secrets(self) -> None:
        text = "psk oldsecret\n"
        edits = [make_edit(text, "oldsecret", "newsecret", secret=True)]
        lines = ui.diff_edits(text, edits, "lab", show_secrets=True)
        self.assertIn("-psk oldsecret", lines)
        self.assertIn("+psk newsecret", lines)

    def test_diff_edits_short_secret_does_not_mangle(self) -> None:
        text = "a 1 2 3\npw 2\n"
        edits = [make_edit(text, "2", "9", secret=True, after="pw ")]
        lines = ui.diff_edits(text, edits, "lab")
        self.assertIn("-pw ****", lines)
        self.assertIn(" a 1 2 3", lines)

    def test_diff_edits_mismatch_raises(self) -> None:
        text = "abc\n"
        e = make_edit(text, "b", "x")
        with self.assertRaises(ValueError):
            ui.diff_edits("zzz\n", [e], "lab")

    def test_apply_text_edits(self) -> None:
        te = [TextEdit(0, 1, "a", "AA"), TextEdit(2, 3, "c", "C")]
        self.assertEqual(ui.apply_text_edits("abc", te), "AAbC")
        with self.assertRaises(ValueError):
            ui.apply_text_edits(
                "abc", [TextEdit(0, 2, "ab", "x"), TextEdit(1, 3, "bc", "y")]
            )
        with self.assertRaises(ValueError):
            ui.apply_text_edits("abc", [TextEdit(0, 1, "z", "y")])
        with self.assertRaises(ValueError):
            ui.apply_text_edits("abc", [TextEdit(2, 9, "c", "y")])

    def test_ui_diff_methods(self) -> None:
        u, out, _ = make()
        self.assertTrue(u.diff("a\n", "b\n", "lbl"))
        self.assertFalse(u.diff("a\n", "a\n", "lbl"))
        self.assertIn("--- lbl", out.getvalue())
        text = "psk topsecret\n"
        u.redactor.add("topsecret")
        self.assertTrue(
            u.diff_edits(text, [make_edit(text, "topsecret", "n", secret=True)], "l")
        )
        self.assertNotIn("topsecret", out.getvalue())


class RedactTests(unittest.TestCase):
    def test_mask_longest_first(self) -> None:
        r = ui.Redactor(["abcd", "abcdef"])
        self.assertEqual(r.mask("x abcdef y abcd"), "x **** y ****")

    def test_min_len_and_show(self) -> None:
        r = ui.Redactor(["ab"])
        self.assertEqual(r.mask("ab"), "ab")
        r = ui.Redactor(["secret"], show=True)
        self.assertEqual(r.mask("secret"), "secret")
        self.assertEqual(r.display("secret"), "secret")
        self.assertEqual(ui.Redactor(["secret"]).display("secret"), "****")

    def test_digest(self) -> None:
        d = ui.sha256_digest("x")
        self.assertTrue(d.startswith("sha256:"))
        self.assertEqual(len(d), 7 + 64)
        self.assertEqual(ui.Redactor.digest("x"), d)

    def test_display_value(self) -> None:
        self.assertEqual(ui.display_value("secret", "pw"), "****")
        self.assertEqual(ui.display_value("ip_host", "1.2.3.4", {"secret"}), "****")
        self.assertEqual(ui.display_value("ip_host", "1.2.3.4"), "1.2.3.4")
        self.assertEqual(ui.display_value("secret", "pw", show=True), "pw")


class PagerTests(unittest.TestCase):
    def test_builtin_pager(self) -> None:
        text = "\n".join(f"l{i}" for i in range(7))
        u, out, _ = make("\n\n")
        u.page(text, page_size=3, force=True, external=False)
        shown = out.getvalue()
        self.assertIn("l6", shown)
        self.assertEqual(shown.count("-- more"), 2)

    def test_builtin_pager_quit(self) -> None:
        text = "\n".join(f"l{i}" for i in range(7))
        u, out, _ = make("q\n")
        u.page(text, page_size=3, force=True, external=False)
        self.assertNotIn("l3", out.getvalue())

    def test_short_text_printed(self) -> None:
        u, out, _ = make()
        u.page("a\nb\n", page_size=10, force=True)
        self.assertEqual(out.getvalue(), "a\nb\n")

    def test_external_pager_missing_falls_back(self) -> None:
        u, out, _ = make("\n", env={"PAGER": "definitely-not-a-pager-xyz"})
        text = "\n".join(f"l{i}" for i in range(5))
        u.page(text, page_size=3, force=True)
        self.assertIn("l4", out.getvalue())

    def test_external_pager_used(self) -> None:
        u, _out, _ = make(env={"PAGER": "sh -c 'cat >/dev/null'"})
        # output goes to /dev/null; only assert the call reports success
        self.assertTrue(u._external_pager("x\n"))


if __name__ == "__main__":
    unittest.main()
