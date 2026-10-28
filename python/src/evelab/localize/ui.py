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
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import IO

from evelab.common.console import (
    Console,
    PickerRow,
    QuitRequested,
    Reply,
    StyleFn,
    UnansweredError,
    Validator,
    _plain,
    format_prompt,
    parse_selection,
    render_findings,
    render_table,
    sanitize,
    severity_counts,
    strip_ansi,
    visible_len,
)

from .model import Edit, Plan, Segment, TextEdit

__all__ = [
    "UI",
    "PickerRow",
    "QuitRequested",
    "Redactor",
    "Reply",
    "StyleFn",
    "UnansweredError",
    "Validator",
    "format_prompt",
    "parse_selection",
    "render_findings",
    "render_matrix",
    "render_plan_summary",
    "render_table",
    "sanitize",
    "severity_counts",
    "strip_ansi",
    "unified_diff",
    "visible_len",
]

MASK = "****"
SEP = " · "

_SENTINEL_RE = re.compile(r"\x00\d+[on]\x00")

_STATUS_COLOR = {
    "CONFIGURABLE": "green",
    "DHCP": "cyan",
    "LABEL_ONLY": "yellow",
    "CARRIER": "blue",
    "UNKNOWN": "red",
}


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


class UI(Console):
    """eve-localize console: :class:`~evelab.common.console.Console` plus the
    segment matrix, plan summaries, decoded diffs and secret handling.

    Secrets are shown as ``****`` unless ``show_secrets`` is set.
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
        super().__init__(
            stdin,
            stdout,
            stderr,
            interactive=interactive,
            assume_yes=assume_yes,
            strict=strict,
            color=color,
            verbosity=verbosity,
            env=env,
            width=width,
        )
        self.show_secrets = show_secrets
        self._getpass = getpass_fn
        self.redactor = Redactor(show=show_secrets)

    def mask(self, text: str) -> str:
        return self.redactor.mask(text)

    def matrix(self, segments: Sequence[Segment]) -> None:
        self.lines(render_matrix(segments, style=self.style, max_width=self.width))

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
