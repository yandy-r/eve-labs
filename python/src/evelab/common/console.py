"""Console primitives shared by the evelab tools: prompts, tables, findings.

Rules this module enforces:

* It never blocks on input unless the console is interactive (stdin is a TTY,
  or ``interactive=True`` was forced). Otherwise prompts resolve from defaults
  (``--yes``) or keep the current value (``--non-interactive``), and with
  ``strict`` an unanswered question raises :class:`UnansweredError` (exit 3).
* Colour is used only when stdout is a TTY, ``NO_COLOR`` is unset or empty,
  ``TERM`` is not ``dumb`` and ``color`` was not forced off.
* Text taken from labs is stripped of control characters before it reaches the
  terminal, so a lab cannot inject escape sequences.

Tools subclass :class:`Console` for their own renderers (``evelab.localize.ui.UI``
adds the segment matrix, plan diffs and secret redaction).
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Literal

from .errors import EveLabError
from .findings import Finding

__all__ = [
    "Console",
    "PickerRow",
    "QuitRequested",
    "Reply",
    "StyleFn",
    "UnansweredError",
    "Validator",
    "format_prompt",
    "parse_selection",
    "render_findings",
    "render_table",
    "sanitize",
    "severity_counts",
    "strip_ansi",
    "visible_len",
]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

_STYLES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}


_SEVERITY_ORDER = {"blocker": 0, "error": 1, "conflict": 2, "warn": 3, "info": 4}
_SEVERITY_COLOR = {
    "blocker": "red",
    "error": "red",
    "conflict": "red",
    "warn": "yellow",
    "info": "dim",
}

StyleFn = Callable[[str, str], str]
Validator = Callable[[str], "str | None"]


def _plain(text: str, _style: str) -> str:
    return text


# --------------------------------------------------------------------------
# Errors and replies
# --------------------------------------------------------------------------


class QuitRequested(EveLabError):
    """The user pressed ``q``, hit EOF or interrupted: stop without writing."""

    code = "QUIT"
    exit_code = 0


class UnansweredError(EveLabError):
    """A question had no answer and the console cannot ask (design 13.1: exit 3)."""

    code = "UNANSWERED"
    exit_code = 3


@dataclass(frozen=True)
class Reply:
    """Outcome of :meth:`Console.prompt`.

    ``action`` is ``value`` (typed), ``default`` (Enter), ``keep`` (``k`` or an
    unanswered non-interactive prompt), ``skip`` (``s``) or ``back`` (``b``).
    ``value`` is the resolved text; ``None`` for ``skip``/``back`` and for a
    ``keep`` without a current value.
    """

    action: Literal["value", "default", "keep", "skip", "back"]
    value: str | None = None


@dataclass(frozen=True)
class PickerRow:
    """One line of the lab picker. ``selectable=False`` rows are never chosen."""

    label: str
    status: str = ""
    selectable: bool = True


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def strip_ansi(text: str) -> str:
    """Remove SGR colour sequences."""
    return _ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    """Length of ``text`` without colour sequences."""
    return len(strip_ansi(text))


def sanitize(text: str) -> str:
    """Replace control characters (except tab) so lab text cannot drive the TTY."""
    return _CTRL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    max_width: int | None = None,
    right: Iterable[int] = (),
    indent: str = "",
    style: StyleFn = _plain,
) -> list[str]:
    """Plain-text table with two-space gutters. Cells may contain SGR colours.

    When ``max_width`` is given the widest un-coloured column is truncated with an
    ellipsis until the table fits (or only a minimal width is left).
    """
    ncol = len(headers)
    cells = [[str(c) for c in row] + [""] * (ncol - len(row)) for row in rows]
    widths = [
        max([visible_len(headers[i])] + [visible_len(r[i]) for r in cells])
        for i in range(ncol)
    ]
    if max_width is not None:
        total = len(indent) + sum(widths) + 2 * (ncol - 1)
        while total > max_width:
            i = max(range(ncol), key=lambda k: widths[k])
            if widths[i] <= 8:
                break
            widths[i] -= 1
            total -= 1
        for r in cells:
            for i, c in enumerate(r):
                if visible_len(c) > widths[i] and c == strip_ansi(c):
                    r[i] = c[: widths[i] - 1] + "…"
    right_set = set(right)

    def fmt(row: Sequence[str], hdr: bool = False) -> str:
        parts = []
        for i, c in enumerate(row):
            pad = widths[i] - visible_len(c)
            part = " " * max(pad, 0) + c if i in right_set else c + " " * max(pad, 0)
            parts.append(part)
        line = (indent + "  ".join(parts)).rstrip()
        return style(line, "bold") if hdr else line

    return [fmt(list(headers), True)] + [fmt(r) for r in cells]


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings per severity (all severities present, zero filled)."""
    counts = dict.fromkeys(_SEVERITY_ORDER, 0)
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_findings(
    findings: Sequence[Finding], *, style: StyleFn = _plain
) -> list[str]:
    """One line per finding, most severe first (stable within a severity)."""
    ordered = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
    lines = []
    for f in ordered:
        tag = style(f"[{f.severity}]", _SEVERITY_COLOR.get(f.severity, "bold"))
        lines.append(f"  {tag} {f.code}: {sanitize(f.msg)}")
    return lines


# --------------------------------------------------------------------------
# Selection parsing
# --------------------------------------------------------------------------


def parse_selection(
    text: str,
    count: int,
    *,
    selectable: Sequence[bool] | None = None,
    multi: bool = True,
) -> list[int]:
    """Parse ``"1 3,5-7"`` / ``"all"`` into zero-based indices (input order).

    ``all`` (``a``, ``*``) selects every selectable row. Raises ``ValueError``
    with a user-facing message on bad input.
    """
    ok = list(selectable) if selectable is not None else [True] * count
    tokens = [t for t in re.split(r"[,\s]+", text.strip().lower()) if t]
    if not tokens:
        raise ValueError("nothing selected")
    picked: list[int] = []

    def take(i: int, explicit: bool) -> None:
        if not ok[i]:
            if explicit:
                raise ValueError(f"{i + 1} is not selectable")
            return
        if i not in picked:
            picked.append(i)

    for tok in tokens:
        if tok in ("all", "a", "*"):
            if not multi:
                raise ValueError("select a single entry")
            for i in range(count):
                take(i, False)
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", tok)
        if not m:
            raise ValueError(f"cannot parse {tok!r}")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if lo < 1 or hi > count or lo > hi:
            raise ValueError(f"{tok} is out of range 1-{count}")
        for n in range(lo, hi + 1):
            take(n - 1, lo == hi)  # a range skips non-selectable rows
    if not multi and len(picked) != 1:
        raise ValueError("select a single entry")
    if not picked:
        raise ValueError("nothing selectable in that choice")
    return picked


def format_prompt(
    text: str,
    *,
    progress: tuple[int, int] | None = None,
    default: str | None = None,
    default_source: str = "",
    current: str | None = None,
    choices: Sequence[str] | None = None,
    inline_choices: bool = True,
    has_evidence: bool = False,
) -> str:
    """Build the prompt line: `` 1/5 MGMT-203 bridge [pnet1 from x] (?=evidence): ``."""
    pre = f" {progress[0]}/{progress[1]} " if progress else ""
    out = f"{pre}{text}"
    if choices and inline_choices:
        out += " {" + "|".join(choices) + "}"
    if default is not None:
        out += f" [{default}{' ' + default_source if default_source else ''}]"
    elif current is not None:
        out += " [Enter=keep]"
    if has_evidence:
        out += " (?=evidence)"
    return out + ": "


# --------------------------------------------------------------------------
# Console
# --------------------------------------------------------------------------


class Console:
    """Console wrapper. All I/O of a tool goes through one instance.

    ``interactive`` forces the TTY decision (default: stdin is a TTY).
    ``assume_yes`` is ``--yes``; ``strict`` makes unanswered questions fatal.
    ``verbosity``: -1 quiet, 0 normal, 1 verbose.
    """

    def __init__(
        self,
        stdin: IO[str] | None = None,
        stdout: IO[str] | None = None,
        stderr: IO[str] | None = None,
        *,
        interactive: bool | None = None,
        assume_yes: bool = False,
        strict: bool = False,
        color: bool | None = None,
        verbosity: int = 0,
        env: Mapping[str, str] | None = None,
        width: int | None = None,
    ) -> None:
        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr
        self._interactive = interactive
        self.assume_yes = assume_yes
        self.strict = strict
        self._color = color
        self.verbosity = verbosity
        self.env: Mapping[str, str] = os.environ if env is None else env
        self._width = width
        self.unanswered: list[str] = []

    def mask(self, text: str) -> str:
        """Hook for subclasses that hide secrets in evidence lines."""
        return text

    # -- streams and capabilities ------------------------------------------

    @property
    def stdin(self) -> IO[str]:
        return self._stdin if self._stdin is not None else sys.stdin

    @property
    def stdout(self) -> IO[str]:
        return self._stdout if self._stdout is not None else sys.stdout

    @property
    def stderr(self) -> IO[str]:
        return self._stderr if self._stderr is not None else sys.stderr

    @staticmethod
    def _isatty(stream: IO[str]) -> bool:
        try:
            return bool(stream.isatty())
        except (AttributeError, ValueError, OSError):
            return False

    @property
    def interactive(self) -> bool:
        """True when questions may be asked (never on a non-TTY stdin)."""
        if self._interactive is not None:
            return self._interactive
        return self._isatty(self.stdin)

    @property
    def mode(self) -> Literal["interactive", "yes", "keep"]:
        """``yes``: take defaults; ``interactive``: ask; ``keep``: never ask."""
        if self.assume_yes:
            return "yes"
        return "interactive" if self.interactive else "keep"

    @property
    def color(self) -> bool:
        """Colour only on a TTY with ``NO_COLOR`` unset/empty and ``TERM`` not dumb."""
        if self._color is not None:
            return self._color
        if self.env.get("NO_COLOR"):
            return False
        if self.env.get("TERM") == "dumb":
            return False
        return self._isatty(self.stdout)

    @property
    def width(self) -> int:
        if self._width is not None:
            return self._width
        return shutil.get_terminal_size((100, 24)).columns

    def style(self, text: str, name: str) -> str:
        """Wrap ``text`` in the SGR sequence for ``name`` when colour is on."""
        code = _STYLES.get(name)
        if not self.color or code is None:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    # -- plain output ------------------------------------------------------

    @staticmethod
    def _write(stream: IO[str], text: str) -> None:
        try:
            stream.write(text)
        except UnicodeEncodeError:
            enc = getattr(stream, "encoding", None) or "ascii"
            stream.write(text.encode(enc, "replace").decode(enc))
        stream.flush()

    def out(self, text: str = "") -> None:
        """Print a line to stdout (unless quiet)."""
        if self.verbosity >= 0:
            self._write(self.stdout, text + "\n")

    def info(self, text: str = "") -> None:
        self.out(text)

    def lines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.out(line)

    def debug(self, text: str) -> None:
        if self.verbosity > 0:
            self._write(self.stderr, self.style(text, "dim") + "\n")

    def note(self, text: str) -> None:
        self.out(self.style("note: ", "dim") + text)

    def warn(self, text: str) -> None:
        self._write(self.stderr, self.style("warn: ", "yellow") + text + "\n")

    def error(self, text: str) -> None:
        self._write(self.stderr, self.style("error: ", "red") + text + "\n")

    def heading(self, text: str) -> None:
        self.out(self.style(text, "bold"))

    # -- tables ------------------------------------------------------------

    def table(
        self,
        headers: Sequence[str],
        rows: Sequence[Sequence[str]],
        *,
        right: Iterable[int] = (),
        indent: str = "",
    ) -> None:
        self.lines(
            render_table(
                headers,
                rows,
                max_width=self.width,
                right=right,
                indent=indent,
                style=self.style,
            )
        )

    def findings(self, findings: Sequence[Finding]) -> None:
        self.lines(render_findings(findings, style=self.style))

    def _readline(self, prompt: str) -> str:
        self._write(self.stdout, prompt)
        try:
            line = self.stdin.readline()
        except KeyboardInterrupt:
            self._write(self.stdout, "\n")
            raise QuitRequested("interrupted") from None
        if line == "":
            self._write(self.stdout, "\n")
            raise QuitRequested("end of input")
        return line.rstrip("\r\n")

    def _unanswered(self, text: str, why: str) -> None:
        self.unanswered.append(text)
        if self.strict:
            raise UnansweredError(f"unanswered question: {text} ({why})")

    def prompt(
        self,
        text: str,
        *,
        default: str | None = None,
        default_source: str = "",
        current: str | None = None,
        choices: Sequence[str] | None = None,
        choice_notes: Mapping[str, str] | None = None,
        allow_other: bool = False,
        validate: Validator | None = None,
        evidence: Sequence[str] = (),
        progress: tuple[int, int] | None = None,
        allow_skip: bool = False,
        allow_back: bool = False,
        required: bool = True,
    ) -> Reply:
        """Ask for a value (design 10.3 keys).

        Enter takes ``default`` (or keeps ``current``), ``k`` keeps ``current``,
        ``s`` skips (``allow_skip``), ``?`` prints ``evidence``, ``b`` goes back
        (``allow_back``), ``q`` raises :class:`QuitRequested`. With ``choices``
        the input must be a choice (exact, case-insensitive or unique prefix)
        unless ``allow_other``. ``validate(value)`` returns an error message or
        ``None``. A choice that equals or uniquely starts with the input wins over the
        reserved key letters.

        Non-interactive consoles never read stdin: ``--yes`` takes the default
        (an invalid default raises :class:`UnansweredError`); otherwise the
        current value is kept and the question is recorded in ``unanswered``
        (fatal when ``strict``).
        """
        if self.mode != "interactive":
            return self._auto(text, default, current, validate)
        notes = choice_notes or {}
        listing = bool(choices) and (bool(notes) or len(choices or ()) > 6)
        if listing and choices:
            rows = [f"   {c:<10} {notes.get(c, '')}".rstrip() for c in choices]
            # Consecutive questions over the same choices (one per segment)
            # show the list once.
            if rows != getattr(self, "_last_listing", None):
                for row in rows:
                    self.out(row)
                self._last_listing = rows
        line = format_prompt(
            text,
            progress=progress,
            default=default,
            default_source=default_source,
            current=current,
            choices=choices,
            inline_choices=not listing,
            has_evidence=bool(evidence),
        )
        while True:
            raw = self._readline(line).strip()
            matched = self._match_choice(raw, choices) if choices else None
            low = raw.lower()
            if matched is None:
                if low == "q":
                    raise QuitRequested("quit")
                if low == "?":
                    if evidence:
                        for ev in evidence:
                            self.out("   " + sanitize(self.mask(ev)))
                    else:
                        self.out("   (no evidence recorded)")
                    continue
                if low == "k" and current is not None:
                    return Reply("keep", current)
                if low == "s" and allow_skip:
                    return Reply("skip")
                if low == "b" and allow_back:
                    return Reply("back")
            if raw == "":
                if default is not None:
                    err = validate(default) if validate else None
                    if err:
                        self.out(f"   invalid default: {err}")
                        continue
                    return Reply("default", default)
                if current is not None:
                    return Reply("keep", current)
                if not required and allow_skip:
                    return Reply("skip")
                self.out("   a value is required")
                continue
            value = matched
            if value is None:
                if choices and not allow_other:
                    self.out("   choose one of: " + ", ".join(choices))
                    continue
                value = raw
            err = validate(value) if validate else None
            if err:
                self.out(f"   invalid: {err}")
                continue
            return Reply("value", value)

    @staticmethod
    def _match_choice(raw: str, choices: Sequence[str]) -> str | None:
        if not raw:
            return None
        if raw in choices:
            return raw
        low = raw.lower()
        ci = [c for c in choices if c.lower() == low]
        if len(ci) == 1:
            return ci[0]
        pre = [c for c in choices if c.lower().startswith(low)]
        return pre[0] if len(pre) == 1 else None

    def _auto(
        self,
        text: str,
        default: str | None,
        current: str | None,
        validate: Validator | None,
    ) -> Reply:
        if self.mode == "yes" and default is not None:
            err = validate(default) if validate else None
            if err:
                raise UnansweredError(f"default for {text!r} is invalid: {err}")
            return Reply("default", default)
        self._unanswered(
            text, "no default" if self.mode == "yes" else "not interactive"
        )
        return Reply("keep", current)

    def ask_yes_no(
        self,
        text: str,
        *,
        default: bool = False,
        evidence: Sequence[str] = (),
    ) -> bool:
        """Yes/no gate. Non-interactive consoles return ``default``."""
        if self.mode != "interactive":
            if self.mode == "keep":
                self.unanswered.append(text)
                if self.strict:
                    raise UnansweredError(f"unanswered question: {text}")
            return default
        hint = "[Y/n]" if default else "[y/N]"
        ev = " (?=evidence)" if evidence else ""
        line = f"{text} {hint}{ev}: "
        while True:
            low = self._readline(line).strip().lower()
            if low in ("y", "yes"):
                return True
            if low in ("n", "no"):
                return False
            if low == "":
                return default
            if low == "q":
                raise QuitRequested("quit")
            if low == "?" and evidence:
                for ev_line in evidence:
                    self.out("   " + sanitize(self.mask(ev_line)))
                continue
            self.out("   please answer y or n")

    def menu(
        self,
        keys: Mapping[str, str],
        *,
        title: str = "",
        default: str | None = None,
    ) -> tuple[str, str]:
        """Single-key menu; returns ``(key, rest_of_line)`` (``d c8kv-75``).

        Non-interactive consoles return ``(default, "")`` or raise
        :class:`UnansweredError` when there is no default.
        """
        if self.mode != "interactive":
            if default is not None:
                return default, ""
            raise UnansweredError(f"{title or 'menu'} needs an interactive console")
        line = "  ".join(f"[{k}] {v}" for k, v in keys.items())
        prompt = (f"{title} " if title else "") + line + ": "
        while True:
            raw = self._readline(prompt).strip()
            if not raw:
                if default is not None:
                    return default, ""
                continue
            key, _, rest = raw.partition(" ")
            key = key.lower()
            if key in keys:
                return key, rest.strip()
            self.out("   choose one of: " + ", ".join(keys))

    def pick_labs(
        self,
        rows: Sequence[PickerRow],
        *,
        title: str = "Labs",
        multi: bool = True,
    ) -> list[int]:
        """Numbered lab picker with ranges and ``all``; returns row indices.

        Rows with ``selectable=False`` (for example ``nothing to localize``) are
        listed but never chosen, not even by ``all``. A single selectable row
        is the Enter default. Raises :class:`UnansweredError` when the console
        cannot ask.
        """
        ok = [r.selectable for r in rows]
        if not any(ok):
            raise UnansweredError("no selectable labs")
        if self.mode != "interactive":
            raise UnansweredError("lab selection needs a TTY: pass LAB or --all")
        self.heading(title)
        table = [
            [str(i + 1), r.label, r.status if r.selectable else f"({r.status})"]
            for i, r in enumerate(rows)
        ]
        self.table(["#", "Lab", "Status"], table, right=[0])
        hint = "numbers, ranges (2-4), or 'all'" if multi else "a number"
        only = [i for i, s in enumerate(ok) if s]
        default = str(only[0] + 1) if len(only) == 1 else None
        while True:
            suffix = f" [{default}]" if default else ""
            raw = self._readline(f"Select {hint}{suffix} (q=quit): ").strip()
            if raw.lower() == "q":
                raise QuitRequested("quit")
            if not raw and default:
                raw = default
            try:
                return parse_selection(raw, len(rows), selectable=ok, multi=multi)
            except ValueError as exc:
                self.out(f"   {exc}")

    # -- pager -------------------------------------------------------------

    def page(
        self,
        text: str,
        *,
        page_size: int | None = None,
        force: bool = False,
        external: bool = True,
    ) -> None:
        """Show long text: external ``$PAGER`` (default ``less -FRX``), else a
        built-in Enter-for-more pager; plain print when not interactive or short.
        """
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        height = shutil.get_terminal_size((100, 24)).lines
        size = page_size if page_size is not None else max(height - 2, 5)
        paging = self.interactive and (force or self._isatty(self.stdout))
        if not paging or len(lines) <= size:
            self.lines(lines)
            return
        if external and self._external_pager(text):
            return
        i = 0
        while i < len(lines):
            self.lines(lines[i : i + size])
            i += size
            if i >= len(lines):
                break
            raw = self._readline(
                self.style(
                    f"-- more ({len(lines) - i} lines; Enter=next, q=stop) --", "dim"
                )
            )
            if raw.strip().lower() == "q":
                break

    def _external_pager(self, text: str) -> bool:
        cmd = shlex.split(self.env.get("PAGER") or "less -FRX")
        if not cmd or shutil.which(cmd[0]) is None:
            return False
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, text=True, encoding="utf-8"
            )
        except OSError:
            return False
        try:
            if proc.stdin is not None:
                proc.stdin.write(text if text.endswith("\n") else text + "\n")
                proc.stdin.close()
        except BrokenPipeError:
            pass
        proc.wait()
        return True
