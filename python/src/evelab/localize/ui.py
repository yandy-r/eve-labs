"""Interaction layer: prompts, tables, matrix, pager, decoded diff, redaction.

Design sections 10 (questions and interaction), 12.7 (secrets) and 13.1 (CLI).

Rules this module enforces:

* It never blocks on input unless the console is interactive (stdin is a TTY,
  or ``interactive=True`` was forced). Otherwise prompts resolve from defaults
  (``--yes``) or keep the current value (``--non-interactive``), and with
  ``strict`` an unanswered question raises :class:`UnansweredError` (exit 3).
* Colour is used only when stdout is a TTY, ``NO_COLOR`` is unset or empty,
  ``TERM`` is not ``dumb`` and ``color`` was not forced off.
* Secrets are shown as ``****`` unless ``show_secrets`` is set.
* Text taken from labs is stripped of control characters before it reaches the
  terminal (diff output), so a lab cannot inject escape sequences.
"""

from __future__ import annotations

import difflib
import getpass
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Literal

from .errors import LocalizeError
from .model import Edit, Finding, Plan, Segment, TextEdit

MASK = "****"
SEP = " · "

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SENTINEL_RE = re.compile(r"\x00\d+[on]\x00")

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

_STATUS_COLOR = {
    "CONFIGURABLE": "green",
    "DHCP": "cyan",
    "LABEL_ONLY": "yellow",
    "CARRIER": "blue",
    "UNKNOWN": "red",
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


class QuitRequested(LocalizeError):
    """The user pressed ``q``, hit EOF or interrupted: stop without writing."""

    code = "QUIT"
    exit_code = 0


class UnansweredError(LocalizeError):
    """A question had no answer and the console cannot ask (design 13.1: exit 3)."""

    code = "UNANSWERED"
    exit_code = 3


@dataclass(frozen=True)
class Reply:
    """Outcome of :meth:`UI.prompt`.

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


def sha256_digest(value: str) -> str:
    """``sha256:<hex>`` digest used instead of a secret in plans and JSON."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class Redactor:
    """Masks known secret values (design 12.7). ``show=True`` disables masking.

    Values shorter than ``min_len`` are not masked by value, because replacing a
    one- or two-character string everywhere would corrupt unrelated text; span
    based masking (:func:`diff_edits`) has no such limit.
    """

    def __init__(
        self, secrets: Iterable[str] = (), *, show: bool = False, min_len: int = 3
    ) -> None:
        self.show = show
        self.min_len = min_len
        self._secrets: set[str] = set()
        self.add(*secrets)

    def add(self, *values: str) -> None:
        """Register more secret values."""
        self._secrets.update(v for v in values if len(v) >= self.min_len)

    def mask(self, text: str) -> str:
        """Replace every known secret in ``text`` by ``****``."""
        if self.show or not self._secrets:
            return text
        for secret in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(secret, MASK)
        return text

    def display(self, value: str) -> str:
        """The value as it may be shown: itself with ``show``, else ``****``."""
        return value if self.show else MASK

    @staticmethod
    def digest(value: str) -> str:
        """Stable ``sha256:`` digest for storing a secret in plans/JSON."""
        return sha256_digest(value)


def display_value(
    kind: str, value: str, flags: Iterable[str] = (), *, show: bool = False
) -> str:
    """Mask a fact value when it is a secret (kind ``secret`` or flag ``secret``)."""
    if not show and (kind == "secret" or "secret" in set(flags)):
        return MASK
    return value


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


def _short_gateway(subnet: object, gateway: object) -> str:
    if gateway is None:
        return "-"
    text = str(gateway)
    prefix = getattr(subnet, "prefixlen", None)
    if subnet is not None and prefix is not None and prefix >= 24:
        net_text = str(getattr(subnet, "network_address", ""))
        if text.rsplit(".", 1)[0] == net_text.rsplit(".", 1)[0]:
            return "." + text.rsplit(".", 1)[1]
    return text


def render_matrix(
    segments: Sequence[Segment],
    *,
    style: StyleFn = _plain,
    max_width: int | None = None,
) -> list[str]:
    """Segment / scheme matrix (design 10.5, 13.1 ``scan``).

    One row per scheme; a segment with several schemes (legacy scopes) gets
    continuation rows and a ``Scope`` column appears.
    """
    multi = any(len(s.schemes) > 1 for s in segments)
    headers = ["Segment", "Nets", "Cloud", "Tag", "Subnet", "GW", "Endpoints"]
    if multi:
        headers.append("Scope")
    headers.append("Status")
    rows: list[list[str]] = []
    for seg in segments:
        total = len(seg.attachments)
        via = sum(1 for a in seg.attachments if not a.direct)
        endpoints = f"{total}" + (f" ({via} via L2)" if via else "")
        status = seg.status
        if seg.status == "CARRIER" and seg.carries:
            status += " (" + ",".join(seg.carries) + ")"
        outliers = sum(len(s.outliers) for s in seg.schemes)
        if outliers:
            status += f", {outliers} outlier" + ("s" if outliers != 1 else "")
        colored = style(status, _STATUS_COLOR.get(seg.status, "bold"))
        nets = ",".join(seg.network_ids) or "-"
        clouds = ",".join(sorted(seg.cloud_types)) or "-"
        schemes = seg.schemes or []
        if not schemes:
            tag = "all" if seg.status == "CARRIER" else "-"
            row = [seg.key, nets, clouds, tag, "-", "-", endpoints]
            if multi:
                row.append("")
            rows.append([*row, colored])
            continue
        for i, sch in enumerate(schemes):
            tag = "all" if seg.status == "CARRIER" and sch.tag == "unknown" else ""
            tag = tag or str(sch.tag)
            subnet = str(sch.subnet) if sch.subnet is not None else "-"
            first = i == 0
            row = [
                seg.key if first else "",
                nets if first else "",
                clouds if first else "",
                tag,
                subnet,
                _short_gateway(sch.subnet, sch.gateway),
                endpoints if first else "",
            ]
            if multi:
                row.append(",".join(sorted(sch.scopes)))
            rows.append([*row, colored if first else ""])
    return render_table(headers, rows, max_width=max_width, style=style)


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


def _store_label(edit: Edit) -> str:
    if edit.target == "xml_attr":
        return "xml_attr"
    if edit.target == "sidecar":
        return "sidecar"
    if edit.target == "textobject":
        return "textobject"
    if edit.store.kind == "configset":
        return f"cs:{edit.store.name}"
    return edit.store.kind


def render_plan_summary(plan: Plan, *, style: StyleFn = _plain) -> list[str]:
    """Headline and per-store lines for a plan (design 10.5 ``Plan:`` block)."""
    edits = plan.edits
    files = {e.file for e in edits}
    cosmetic = sum(1 for e in edits if e.category == "cosmetic")
    conf: dict[str, int] = {}
    for e in edits:
        if e.category != "cosmetic":
            conf[e.confidence.name] = conf.get(e.confidence.name, 0) + 1
    order = ["PROVEN", "CORRELATED", "HEURISTIC"]
    parts = [f"{k} {conf[k]}" for k in order if k in conf]
    if cosmetic:
        parts.append(f"cosmetic {cosmetic}")
    counts = severity_counts(plan.findings)
    blockers = counts["blocker"] + counts["error"]
    nfiles = len(files)
    head = (
        f"Plan: {nfiles} file{'s' if nfiles != 1 else ''}, {len(edits)} edits"
        + (f" ({', '.join(parts)})" if parts else "")
        + f"{SEP}{counts['conflict']} conflicts{SEP}{blockers} blockers"
        + f"{SEP}{counts['warn']} warnings"
    )
    bad = counts["conflict"] or blockers
    lines = [style(head, "red" if bad else "bold")]
    main: dict[str, int] = {}
    side_files: set[object] = set()
    side_edits = 0
    other: dict[str, dict[str, int]] = {}
    for e in edits:
        if e.target == "sidecar":
            side_files.add(e.file)
            side_edits += 1
        elif e.file == plan.lab:
            label = _store_label(e)
            main[label] = main.get(label, 0) + 1
        else:
            other.setdefault(e.file.name, {})
            label = _store_label(e)
            other[e.file.name][label] = other[e.file.name].get(label, 0) + 1
    segs = [f"{k} {v}" for k, v in main.items()]
    line = f"  {plan.lab.name}  " + SEP.join(segs) if segs else ""
    if side_files:
        n = len(side_files)
        line += (f"    sidecar {n} file{'s' if n != 1 else ''} {side_edits}").rstrip()
    if line.strip():
        lines.append(line)
    for name, per in other.items():
        lines.append(f"  {name}  " + SEP.join(f"{k} {v}" for k, v in per.items()))
    return lines


# --------------------------------------------------------------------------
# Diff rendering
# --------------------------------------------------------------------------


def apply_text_edits(text: str, edits: Sequence[TextEdit]) -> str:
    """Apply non-overlapping :class:`TextEdit`s to ``text``.

    Raises ``ValueError`` on overlap, out-of-range spans or ``old`` mismatch.
    """
    out: list[str] = []
    pos = 0
    for te in sorted(edits, key=lambda t: (t.start, t.end)):
        if te.start < pos or te.end < te.start or te.end > len(text):
            raise ValueError(f"bad or overlapping edit span {te.start}:{te.end}")
        if text[te.start : te.end] != te.old:
            raise ValueError(f"edit at {te.start}:{te.end} does not match old text")
        out.append(text[pos : te.start])
        out.append(te.new)
        pos = te.end
    out.append(text[pos:])
    return "".join(out)


def unified_diff(
    before: str,
    after: str,
    label: str,
    *,
    context: int = 3,
    max_line: int = 300,
    redactor: Redactor | None = None,
    style: StyleFn = _plain,
) -> list[str]:
    """Unified diff of decoded text with one ``label`` header (design 10.5).

    Lines are sanitised, long lines are cut at ``max_line`` characters, known
    secrets are masked and CR is shown as ``\\r``. Colours apply to the result.
    """
    a = before.split("\n")
    b = after.split("\n")
    raw = list(difflib.unified_diff(a, b, label, label, n=context, lineterm=""))
    if not raw:
        return []
    out: list[str] = []
    for line in raw:
        if line.startswith("---"):
            out.append(style(f"--- {sanitize(label)}", "bold"))
            continue
        if line.startswith("+++"):
            out.append(style(f"+++ {sanitize(label)}", "bold"))
            continue
        if line.startswith("@@"):
            out.append(style(line, "cyan"))
            continue
        body = _SENTINEL_RE.sub(MASK, line)
        if redactor is not None:
            body = redactor.mask(body)
        body = sanitize(body.replace("\r", "\\r"))
        if len(body) > max_line:
            body = body[: max_line - 1] + "…"
        if line.startswith("-"):
            out.append(style(body, "red"))
        elif line.startswith("+"):
            out.append(style(body, "green"))
        else:
            out.append(body)
    return out


def diff_edits(
    text: str,
    edits: Sequence[Edit],
    label: str,
    *,
    show_secrets: bool = False,
    context: int = 3,
    max_line: int = 300,
    redactor: Redactor | None = None,
    style: StyleFn = _plain,
) -> list[str]:
    """Decoded unified diff of ``edits`` (all in one store) applied to ``text``.

    ``Edit.text_edit`` offsets must index ``text``. Edits flagged ``secret`` are
    masked by span, so even a one-character secret leaves other text untouched;
    the old and new masks differ internally so the changed line still shows as
    ``-``/``+``. ``show_secrets=True`` prints the real values.
    """
    before: list[str] = []
    after: list[str] = []
    pos = 0
    for n, e in enumerate(sorted(edits, key=lambda x: x.text_edit.start)):
        te = e.text_edit
        if te.start < pos or te.end < te.start or te.end > len(text):
            raise ValueError(f"bad or overlapping edit span {te.start}:{te.end}")
        if text[te.start : te.end] != te.old:
            raise ValueError(f"edit {e.id} at {te.start}:{te.end} mismatches text")
        chunk = text[pos : te.start]
        before.append(chunk)
        after.append(chunk)
        if e.secret and not show_secrets:
            before.append(f"\x00{n}o\x00")
            after.append(f"\x00{n}n\x00")
        else:
            before.append(te.old)
            after.append(te.new)
        pos = te.end
    tail = text[pos:]
    before.append(tail)
    after.append(tail)
    red = redactor if redactor is not None else Redactor(show=show_secrets)
    return unified_diff(
        "".join(before),
        "".join(after),
        label,
        context=context,
        max_line=max_line,
        redactor=red,
        style=style,
    )


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


class UI:
    """Console wrapper. All I/O of the tool goes through one instance.

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
        show_secrets: bool = False,
        verbosity: int = 0,
        env: Mapping[str, str] | None = None,
        getpass_fn: Callable[[str], str] | None = None,
        width: int | None = None,
    ) -> None:
        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr
        self._interactive = interactive
        self.assume_yes = assume_yes
        self.strict = strict
        self._color = color
        self.show_secrets = show_secrets
        self.verbosity = verbosity
        self.env: Mapping[str, str] = os.environ if env is None else env
        self._getpass = getpass_fn
        self._width = width
        self.unanswered: list[str] = []
        self.redactor = Redactor(show=show_secrets)

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

    def matrix(self, segments: Sequence[Segment]) -> None:
        self.lines(render_matrix(segments, style=self.style, max_width=self.width))

    def findings(self, findings: Sequence[Finding]) -> None:
        self.lines(render_findings(findings, style=self.style))

    def plan_summary(self, plan: Plan) -> None:
        self.lines(render_plan_summary(plan, style=self.style))

    def diff(self, before: str, after: str, label: str, *, context: int = 3) -> bool:
        """Print a decoded unified diff; return False when there is no change."""
        lines = unified_diff(
            before,
            after,
            label,
            context=context,
            redactor=self.redactor,
            style=self.style,
        )
        self.lines(lines)
        return bool(lines)

    def diff_edits(self, text: str, edits: Sequence[Edit], label: str) -> bool:
        lines = diff_edits(
            text,
            edits,
            label,
            show_secrets=self.show_secrets,
            redactor=self.redactor,
            style=self.style,
        )
        self.lines(lines)
        return bool(lines)

    # -- input -------------------------------------------------------------

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
                            self.out("   " + sanitize(self.redactor.mask(ev)))
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
                    self.out("   " + sanitize(self.redactor.mask(ev_line)))
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

    def secret(self, text: str, *, confirm: bool = False) -> str | None:
        """Read a secret without echo (``getpass``). ``None`` when not interactive.

        Never reads from a non-interactive stdin; a missing secret is recorded
        as unanswered (fatal with ``strict``).
        """
        if self.mode != "interactive":
            self._unanswered(text, "secret needs an interactive console")
            return None
        reader = self._getpass or getpass.getpass
        while True:
            try:
                first = reader(f"{text}: ")
                if not confirm:
                    break
                if first == reader(f"{text} (again): "):
                    break
            except (KeyboardInterrupt, EOFError):
                raise QuitRequested("interrupted") from None
            self.out("   values differ, try again")
        self.redactor.add(first)
        return first

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
