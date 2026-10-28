"""Minimal, deterministic TOML writer (design sections 3 and 9).

``tomllib`` reads TOML; this module writes it. Output is stable: keys keep the
mapping's insertion order, except that within one table plain values come first,
then sub-tables, then arrays of tables (the order TOML syntax needs). Every write
is re-parsed with ``tomllib`` and compared with the input, so a document that
would not round-trip never reaches disk.

Supported value types: ``str``, ``bool``, ``int`` (64-bit), ``float``,
``datetime``/``date``/``time``, ``list``/``tuple`` and ``Mapping`` with ``str``
keys. ``None`` is rejected (TOML has no null): drop the key instead.
"""

from __future__ import annotations

import math
import os
import re
import tomllib
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from pathlib import Path
from typing import TypeAlias

from .errors import EveLabError

TomlValue: TypeAlias = (
    str
    | int
    | float
    | bool
    | datetime
    | date
    | time
    | list["TomlValue"]
    | dict[str, "TomlValue"]
)

_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")
_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}
_INT_MIN = -(2**63)
_INT_MAX = 2**63 - 1
_WRAP_AT = 88


class TomlWriteError(EveLabError):
    """A value cannot be written as TOML, or the output failed the re-parse check."""

    code = "TOML_WRITE"


def _quote(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _key(key: str) -> str:
    return key if _BARE_KEY.fullmatch(key) else _quote(key)


def _dotted(path: Sequence[str]) -> str:
    return ".".join(_key(part) for part in path)


def normalize(value: object, where: str = "") -> TomlValue:
    """Return a plain-types copy of ``value``; raise ``TomlWriteError`` if not."""
    if isinstance(value, bool | str | datetime | date | time):
        return value
    if isinstance(value, int):
        if not _INT_MIN <= value <= _INT_MAX:
            raise TomlWriteError(f"{where or '<root>'}: integer out of 64-bit range")
        return int(value)
    if isinstance(value, float):
        return float(value)
    if isinstance(value, Mapping):
        table: dict[str, TomlValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TomlWriteError(f"{where or '<root>'}: non-string key {key!r}")
            table[key] = normalize(item, f"{where}.{key}" if where else key)
        return table
    if isinstance(value, list | tuple):
        return [normalize(item, f"{where}[{i}]") for i, item in enumerate(value)]
    raise TomlWriteError(
        f"{where or '<root>'}: cannot write {type(value).__name__} as TOML"
    )


def _scalar(value: TomlValue) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "nan"
        if math.isinf(value):
            return "inf" if value > 0 else "-inf"
        return repr(value)
    if isinstance(value, datetime | date | time):
        return value.isoformat()
    raise AssertionError(f"not a scalar: {value!r}")  # pragma: no cover


def _inline(value: TomlValue, indent: str = "") -> str:
    """Render a value on one line, or one item per line for long arrays."""
    if isinstance(value, dict):
        if not value:
            return "{}"
        body = ", ".join(f"{_key(k)} = {_inline(v)}" for k, v in value.items())
        return "{ " + body + " }"
    if isinstance(value, list):
        if not value:
            return "[]"
        flat = "[" + ", ".join(_inline(item) for item in value) + "]"
        if len(indent) + len(flat) <= _WRAP_AT or "\n" in flat:
            return flat
        inner = indent + "    "
        lines = [f"{inner}{_inline(item, inner)}," for item in value]
        return "[\n" + "\n".join(lines) + f"\n{indent}]"
    return _scalar(value)


def _is_table_array(value: TomlValue) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, dict) for item in value)
    )


def _blocks(
    path: tuple[str, ...], table: dict[str, TomlValue], array: bool
) -> list[str]:
    """Render a table and everything under it as a list of TOML blocks."""
    lines: list[str] = []
    tables: list[tuple[str, dict[str, TomlValue]]] = []
    arrays: list[tuple[str, list[TomlValue]]] = []
    for key, value in table.items():
        if isinstance(value, dict):
            tables.append((key, value))
        elif isinstance(value, list) and _is_table_array(value):
            arrays.append((key, value))
        else:
            lines.append(f"{_key(key)} = {_inline(value)}")
    blocks: list[str] = []
    implicit = not array and not lines and bool(tables or arrays)
    if path and not implicit:
        header = f"[[{_dotted(path)}]]" if array else f"[{_dotted(path)}]"
        blocks.append("\n".join([header, *lines]))
    elif lines:
        blocks.append("\n".join(lines))
    for key, sub in tables:
        blocks.extend(_blocks((*path, key), sub, False))
    for key, items in arrays:
        for item in items:
            assert isinstance(item, dict)
            blocks.extend(_blocks((*path, key), item, True))
    return blocks


def _same(a: object, b: object) -> bool:
    if isinstance(a, float) and isinstance(b, float):
        return (math.isnan(a) and math.isnan(b)) or a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b, strict=True))
    return type(a) is type(b) and a == b


def dumps(
    data: Mapping[str, object], *, header: str | None = None, verify: bool = True
) -> str:
    """Serialise ``data`` to TOML text.

    ``header`` becomes ``#`` comment lines at the top. With ``verify`` (default) the
    text is parsed back with ``tomllib`` and must equal the input, else
    ``TomlWriteError`` is raised.
    """
    root = normalize(data)
    assert isinstance(root, dict)
    text = "\n\n".join(_blocks((), root, False))
    if text:
        text += "\n"
    if header:
        comment = "\n".join(f"# {ln}".rstrip() for ln in header.splitlines())
        text = comment + ("\n\n" + text if text else "\n")
    if verify:
        verify_roundtrip(text, root)
    return text


def verify_roundtrip(text: str, expected: Mapping[str, object]) -> None:
    """Parse ``text`` and require it to equal ``expected`` (key order is irrelevant)."""
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise TomlWriteError(f"generated TOML does not parse: {exc}") from exc
    if not _same(parsed, normalize(expected)):
        raise TomlWriteError("generated TOML does not round-trip to the input data")


def dump(
    path: Path,
    data: Mapping[str, object],
    *,
    header: str | None = None,
    mode: int | None = None,
) -> None:
    """Write ``data`` to ``path`` atomically (temp file + rename), UTF-8, LF newlines.

    ``mode`` sets the file permission bits explicitly (e.g. ``0o600`` for files that
    hold secrets); by default the usual umask-derived mode is used.
    """
    text = dumps(data, header=header)
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(
        tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666 if mode is None else mode
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            if mode is not None:
                os.fchmod(handle.fileno(), mode)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
