"""Strict, typed access to parsed TOML tables (shared by manifest.py and profile.py).

``TableReader`` hands out values one key at a time with type checks and records
which keys were read; ``done()`` then rejects every key nobody asked for, so a
typo in a manifest or profile is an error, never a silently ignored setting.
"""

from __future__ import annotations

import difflib
from collections.abc import Iterable, Sequence
from ipaddress import IPv4Address, IPv4Network

from .errors import EveLabError
from .tomlw import TomlValue

_MISSING = object()


class TableReader:
    """Read-once view of one TOML table with error messages that name the key path."""

    def __init__(
        self,
        data: object,
        path: str,
        error: type[EveLabError],
        source: str = "",
    ) -> None:
        self._error = error
        self._source = source
        self.path = path
        if not isinstance(data, dict):
            raise self._fail(f"{path or '<root>'}: expected a table")
        self._data: dict[str, TomlValue] = data
        self._seen: set[str] = set()

    # -- errors ---------------------------------------------------------------

    def _fail(self, message: str) -> EveLabError:
        prefix = f"{self._source}: " if self._source else ""
        return self._error(prefix + message)

    def fail(self, key: str, message: str) -> EveLabError:
        """Build (not raise) an error for ``key``: ``raise reader.fail(...)``."""
        return self._fail(f"{self._where(key)}: {message}")

    def _where(self, key: str) -> str:
        return f"{self.path}.{key}" if self.path else key

    def _get(self, key: str) -> object:
        self._seen.add(key)
        return self._data.get(key, _MISSING)

    # -- scalars --------------------------------------------------------------

    def has(self, key: str) -> bool:
        return key in self._data

    def keys(self) -> list[str]:
        return list(self._data)

    def req_str(self, key: str, *, choices: Iterable[str] | None = None) -> str:
        value = self.opt_str(key, choices=choices)
        if value is None:
            raise self.fail(key, "required key is missing")
        return value

    def opt_str(
        self,
        key: str,
        default: str | None = None,
        *,
        choices: Iterable[str] | None = None,
    ) -> str | None:
        value = self._get(key)
        if value is _MISSING:
            return default
        if not isinstance(value, str):
            raise self.fail(key, f"expected a string, got {_type(value)}")
        if choices is not None and value not in tuple(choices):
            raise self.fail(key, f"{value!r} is not one of {sorted(choices)}")
        return value

    def opt_int(
        self,
        key: str,
        default: int | None = None,
        *,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int | None:
        value = self._get(key)
        if value is _MISSING:
            return default
        if isinstance(value, bool) or not isinstance(value, int):
            raise self.fail(key, f"expected an integer, got {_type(value)}")
        if minimum is not None and value < minimum:
            raise self.fail(key, f"{value} is below the minimum {minimum}")
        if maximum is not None and value > maximum:
            raise self.fail(key, f"{value} is above the maximum {maximum}")
        return value

    def opt_bool(self, key: str, default: bool) -> bool:
        value = self._get(key)
        if value is _MISSING:
            return default
        if not isinstance(value, bool):
            raise self.fail(key, f"expected true/false, got {_type(value)}")
        return value

    # -- composites -----------------------------------------------------------

    def str_list(
        self, key: str, default: Sequence[str] = (), *, min_items: int = 0
    ) -> list[str]:
        value = self._get(key)
        if value is _MISSING:
            if min_items > len(default):
                raise self.fail(key, "required key is missing")
            return list(default)
        if not isinstance(value, list):
            raise self.fail(key, f"expected an array of strings, got {_type(value)}")
        out: list[str] = []
        for i, item in enumerate(value):
            if not isinstance(item, str):
                raise self.fail(f"{key}[{i}]", f"expected a string, got {_type(item)}")
            out.append(item)
        if len(out) < min_items:
            raise self.fail(key, f"needs at least {min_items} item(s)")
        return out

    def str_map(self, key: str) -> dict[str, str]:
        """A table whose values are all strings (``""`` allowed)."""
        value = self._get(key)
        if value is _MISSING:
            return {}
        if not isinstance(value, dict):
            raise self.fail(key, f"expected a table, got {_type(value)}")
        out: dict[str, str] = {}
        for k, v in value.items():
            if not isinstance(v, str):
                raise self.fail(f"{key}.{k}", f"expected a string, got {_type(v)}")
            out[k] = v
        return out

    def table(self, key: str) -> TableReader | None:
        value = self._get(key)
        if value is _MISSING:
            return None
        return TableReader(value, self._where(key), self._error, self._source)

    def subtables(self, key: str) -> dict[str, TableReader]:
        """Every sub-table of ``key`` as readers, keyed by name."""
        table = self.table(key)
        if table is None:
            return {}
        out = {
            name: table.require_table(name)
            for name in table.keys()  # noqa: SIM118 - TableReader.keys()
        }
        table.done()
        return out

    def require_table(self, key: str) -> TableReader:
        table = self.table(key)
        if table is None:
            raise self.fail(key, "required table is missing")
        return table

    def table_array(self, key: str) -> list[TableReader]:
        value = self._get(key)
        if value is _MISSING:
            return []
        if not isinstance(value, list):
            raise self.fail(key, f"expected an array of tables, got {_type(value)}")
        return [
            TableReader(item, f"{self._where(key)}[{i}]", self._error, self._source)
            for i, item in enumerate(value)
        ]

    def raw(self, key: str) -> TomlValue | None:
        """The unchecked value of ``key`` (``None`` when absent); marks it read."""
        self._seen.add(key)
        return self._data.get(key)

    def rest(self) -> dict[str, TomlValue]:
        """Every key not read so far (marked read): scenario-specific options."""
        out = {k: v for k, v in self._data.items() if k not in self._seen}
        self._seen.update(out)
        return out

    def done(self) -> None:
        """Reject keys that were never read, suggesting the closest valid one."""
        unknown = [k for k in self._data if k not in self._seen]
        if not unknown:
            return
        key = unknown[0]
        near = difflib.get_close_matches(key, sorted(self._seen), n=1)
        hint = f" (did you mean {near[0]!r}?)" if near else ""
        raise self.fail(key, f"unknown key{hint}")


def _type(value: object) -> str:
    return type(value).__name__


# -- value parsers --------------------------------------------------------------


def parse_network(reader: TableReader, key: str, text: str) -> IPv4Network:
    """IPv4 CIDR with no host bits set."""
    try:
        return IPv4Network(text, strict=True)
    except ValueError as exc:
        raise reader.fail(key, f"invalid IPv4 network {text!r}: {exc}") from exc


def parse_address(reader: TableReader, key: str, text: str) -> IPv4Address:
    try:
        return IPv4Address(text)
    except ValueError as exc:
        raise reader.fail(key, f"invalid IPv4 address {text!r}: {exc}") from exc
