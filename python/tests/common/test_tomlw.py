"""Tests for evelab.common.tomlw (deterministic TOML writer)."""

import math
import os
import stat
import tempfile
import tomllib
import unittest
from datetime import UTC, date, datetime, time
from pathlib import Path

from evelab.common import tomlw
from evelab.common.tomlw import TomlWriteError
from tests.localize.labfiles import TESTS_DIR

FIXTURES = TESTS_DIR / "fixtures" / "toml"


def roundtrip(data: dict[str, object]) -> str:
    text = tomlw.dumps(data)
    assert tomllib.loads(text) == data or "nan" in text
    return text


class ScalarTests(unittest.TestCase):
    def test_scalars(self) -> None:
        data = {"s": "x", "i": -3, "f": 1.5, "t": True, "f2": False}
        self.assertEqual(
            tomlw.dumps(data), 's = "x"\ni = -3\nf = 1.5\nt = true\nf2 = false\n'
        )

    def test_string_escapes(self) -> None:
        nasty = 'q"uote \\ back\ttab\nnl\rcr\x00nul\x7fdel é中'
        text = roundtrip({"v": nasty})
        self.assertIn("\\u0000", text)
        self.assertIn("\\u007f", text)
        self.assertEqual(tomllib.loads(text)["v"], nasty)

    def test_empty_string_and_unicode_key(self) -> None:
        roundtrip({"": "", "kéy": "v"})

    def test_floats(self) -> None:
        text = tomlw.dumps({"a": 1e-5, "b": 1e16, "c": float("inf"), "d": -math.inf})
        parsed = tomllib.loads(text)
        self.assertEqual(parsed["a"], 1e-5)
        self.assertEqual(parsed["b"], 1e16)
        self.assertEqual(parsed["c"], math.inf)
        self.assertEqual(parsed["d"], -math.inf)

    def test_nan_roundtrips(self) -> None:
        text = tomlw.dumps({"n": math.nan})
        self.assertTrue(math.isnan(tomllib.loads(text)["n"]))

    def test_bool_is_not_int(self) -> None:
        text = tomlw.dumps({"a": True, "b": 1})
        parsed = tomllib.loads(text)
        self.assertIs(parsed["a"], True)
        self.assertNotIsInstance(parsed["b"], bool)

    def test_dates(self) -> None:
        data = {
            "d": date(2026, 1, 2),
            "t": time(3, 4, 5),
            "dt": datetime(2026, 1, 2, 3, 4, 5),
            "z": datetime(2026, 1, 2, 3, 4, 5, 250000, tzinfo=UTC),
        }
        roundtrip(data)

    def test_int_range(self) -> None:
        roundtrip({"big": 2**63 - 1, "small": -(2**63)})
        with self.assertRaises(TomlWriteError):
            tomlw.dumps({"x": 2**63})


class KeyTests(unittest.TestCase):
    def test_bare_and_quoted(self) -> None:
        text = tomlw.dumps({"a-b_1": 1, "has space": 2, "dot.ted": 3, "10.0": 4})
        self.assertEqual(
            text, 'a-b_1 = 1\n"has space" = 2\n"dot.ted" = 3\n"10.0" = 4\n'
        )
        self.assertEqual(
            tomllib.loads(text),
            {"a-b_1": 1, "has space": 2, "dot.ted": 3, "10.0": 4},
        )

    def test_quoted_table_path(self) -> None:
        data = {"segments": {"site.mgmt_a": {"vlan": 20}}}
        text = tomlw.dumps(data)
        self.assertEqual(text, '[segments."site.mgmt_a"]\nvlan = 20\n')
        self.assertEqual(tomllib.loads(text), data)


class StructureTests(unittest.TestCase):
    def test_scalars_before_tables_regardless_of_input_order(self) -> None:
        data = {"t": {"x": 1}, "late": 2, "a": [{"k": 1}]}
        text = tomlw.dumps(data)
        self.assertTrue(text.startswith("late = 2\n"))
        self.assertEqual(tomllib.loads(text), data)

    def test_insertion_order_is_kept(self) -> None:
        text = tomlw.dumps({"b": 1, "a": 2, "c": 3})
        self.assertEqual(text, "b = 1\na = 2\nc = 3\n")

    def test_deterministic(self) -> None:
        data = tomllib.loads((FIXTURES / "manifest_backbone.toml").read_text())
        self.assertEqual(tomlw.dumps(data), tomlw.dumps(data))
        again = tomllib.loads(tomlw.dumps(data))
        self.assertEqual(tomlw.dumps(again), tomlw.dumps(data))

    def test_array_of_tables_with_subtables(self) -> None:
        data = {
            "segment": [
                {"key": "A", "baseline": {"vlan": 1}, "expect": {"vlan": 2}},
                {"key": "B", "baseline": {"vlan": 3}},
            ]
        }
        text = tomlw.dumps(data)
        self.assertEqual(text.count("[[segment]]"), 2)
        self.assertIn("[segment.baseline]", text)
        self.assertEqual(tomllib.loads(text), data)

    def test_nested_array_of_tables(self) -> None:
        data = {"a": [{"b": [{"x": 1}, {"x": 2}], "n": 1}, {"b": [{"x": 3}]}]}
        self.assertEqual(tomllib.loads(tomlw.dumps(data)), data)

    def test_empty_table_and_empty_list(self) -> None:
        data = {"e": {}, "l": [], "s": {"deep": {}}}
        self.assertEqual(tomllib.loads(tomlw.dumps(data)), data)

    def test_mixed_arrays_use_inline_tables(self) -> None:
        data = {"m": [{"a": 1}, 2, "x"], "nested": [[1, 2], [3]], "t": [{"a": []}]}
        text = tomlw.dumps(data)
        self.assertIn('m = [{ a = 1 }, 2, "x"]', text)
        self.assertEqual(tomllib.loads(text)["m"], data["m"])

    def test_inline_table_in_table_array_item(self) -> None:
        data = {"p": [{"baseline": {"a": {"b": 1}}, "list": [{"k": "v"}]}]}
        self.assertEqual(tomllib.loads(tomlw.dumps(data)), data)

    def test_long_list_wraps_and_roundtrips(self) -> None:
        data = {"ips": [f"10.100.{n}.0/24" for n in range(30)]}
        text = tomlw.dumps(data)
        self.assertGreater(text.count("\n"), 5)
        self.assertTrue(all(len(line) <= 88 for line in text.splitlines()))
        self.assertEqual(tomllib.loads(text), data)

    def test_tuples_and_mappings_are_accepted(self) -> None:
        text = tomlw.dumps({"t": (1, 2), "m": {"k": ("a",)}})
        self.assertEqual(tomllib.loads(text), {"t": [1, 2], "m": {"k": ["a"]}})

    def test_empty_document(self) -> None:
        self.assertEqual(tomlw.dumps({}), "")

    def test_header_comment(self) -> None:
        text = tomlw.dumps({"a": 1}, header="generated\nsecond")
        self.assertEqual(text, "# generated\n# second\n\na = 1\n")
        self.assertEqual(tomllib.loads(text), {"a": 1})
        self.assertEqual(tomlw.dumps({}, header="only"), "# only\n")

    def test_fixtures_roundtrip(self) -> None:
        for path in sorted(FIXTURES.glob("*.toml")):
            with self.subTest(path.name):
                data = tomllib.loads(path.read_text())
                self.assertEqual(tomllib.loads(tomlw.dumps(data)), data)


class ErrorTests(unittest.TestCase):
    def test_none_rejected_with_path(self) -> None:
        with self.assertRaisesRegex(TomlWriteError, r"a\.b"):
            tomlw.dumps({"a": {"b": None}})

    def test_unsupported_type(self) -> None:
        with self.assertRaises(TomlWriteError):
            tomlw.dumps({"p": Path("/x")})

    def test_non_string_key(self) -> None:
        with self.assertRaises(TomlWriteError):
            tomlw.dumps({1: "x"})  # type: ignore[dict-item]

    def test_verify_catches_mismatch(self) -> None:
        with self.assertRaises(TomlWriteError):
            tomlw.verify_roundtrip("a = 1\n", {"a": 2})
        with self.assertRaises(TomlWriteError):
            tomlw.verify_roundtrip("a = [", {"a": 2})
        with self.assertRaises(TomlWriteError):
            tomlw.verify_roundtrip("a = 1\n", {"a": True})

    def test_is_localize_error(self) -> None:
        from evelab.localize.errors import LocalizeError

        self.assertTrue(issubclass(TomlWriteError, LocalizeError))


class DumpTests(unittest.TestCase):
    def test_atomic_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.toml"
            target.write_text("old = 1\n")
            tomlw.dump(target, {"new": 2})
            self.assertEqual(tomllib.loads(target.read_text()), {"new": 2})
            self.assertEqual(os.listdir(tmp), ["out.toml"])

    def test_failed_write_keeps_old_file_and_leaves_no_temp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.toml"
            target.write_text("old = 1\n")
            with self.assertRaises(TomlWriteError):
                tomlw.dump(target, {"bad": None})
            self.assertEqual(target.read_text(), "old = 1\n")
            self.assertEqual(os.listdir(tmp), ["out.toml"])

    def test_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "secret.toml"
            tomlw.dump(target, {"a": 1}, mode=0o600)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_utf8_lf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "u.toml"
            tomlw.dump(target, {"v": "é", "t": {"x": 1}})
            raw = target.read_bytes()
            self.assertNotIn(b"\r", raw)
            self.assertIn("é".encode(), raw)


if __name__ == "__main__":
    unittest.main()
