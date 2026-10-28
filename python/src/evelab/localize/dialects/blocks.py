"""Tolerant block parsers (design section 6.2).

``split(text, style)`` turns config text into a :class:`Layout`: the list of
physical lines (each knowing the chain of blocks it sits in and whether it must
be ignored) plus the list of blocks.  Parsers never raise on malformed input;
corrupt regions are reported through ``Line.skip`` and ``Block.orphan``.

Styles
------
``indent``  ios/iosxe/nxos/asa. Blocks start at column-0 headers and end at the
            next column-0 line.  Spliced syslog lines are skipped, a truncated
            ``interface`` header opens an *orphan* block, text after ``end``
            is ignored.
``fortios`` ``config X`` / ``edit "y"`` / ``next`` / ``end`` stack.
``brace``   junos: brace depth path such as ``interfaces/fxp0/unit 0``.
``flat``    linuxsh, f5tmsh, vpcs: no blocks except shell heredocs.
``html``    only text nodes are scanned; tag interiors never are.

Block ``kind`` is what ``PatternRule.block`` matches: ``interface``, ``vlan``,
``vrf``, ``router bgp``, ``system dns`` (fortios config), ``edit:system
interface`` (fortios edit), ``interfaces/fxp0/unit 0`` (brace path) or
``heredoc:/etc/resolv.conf``.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from evelab.common.textutil import LineIndex, html_text_regions

from ..model import Span

STYLES = ("indent", "fortios", "brace", "flat", "html")

# Spliced console syslog (design 6.2): "*Dec 28 18:28:00.651: %SYS-5-..."
SYSLOG_RE = re.compile(r"^\*\w{3} +\d+ \d\d:\d\d:\d\d\.\d+: %")


@dataclass(eq=False)
class Block:
    kind: str
    name: str
    path: str  # "interface/Gi16.2", "system interface/oob-mgmt", "a/b/c"
    start: int  # offset of the header line start
    end: int  # exclusive end of the last content line (no trailing newline)
    header_line: int  # 1-based
    depth: int = 0
    name_span: Span | None = None  # the name token inside the header line
    orphan: bool = False  # corrupt / truncated header


@dataclass(frozen=True)
class Line:
    no: int  # 1-based physical line number
    start: int
    end: int  # excludes the line terminator (and a trailing CR)
    chain: tuple[Block, ...] = ()  # enclosing blocks, outermost first
    skip: str | None = None  # "syslog" | "after-end" | None


@dataclass
class Layout:
    text: str
    style: str
    lines: list[Line]
    blocks: list[Block]
    _starts: list[int] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._starts = [ln.start for ln in self.lines]

    def line_text(self, line: Line) -> str:
        return self.text[line.start : line.end]

    def line_at(self, offset: int) -> Line | None:
        """The scan unit containing ``offset`` (None for gaps, e.g. html tags)."""
        i = bisect_right(self._starts, offset) - 1
        if i >= 0 and self.lines[i].start <= offset <= self.lines[i].end:
            return self.lines[i]
        return None

    def block_lines(self, block: Block) -> Iterator[Line]:
        for ln in self.lines:
            if block in ln.chain:
                yield ln


# --------------------------------------------------------------------------- #
# line iteration
# --------------------------------------------------------------------------- #


def iter_lines(text: str) -> Iterator[tuple[int, int, int]]:
    """Yield ``(no, start, end)``; ``end`` excludes ``\\n`` and a preceding CR."""
    pos = 0
    no = 0
    n = len(text)
    while pos < n:
        nl = text.find("\n", pos)
        stop = n if nl == -1 else nl
        end = stop - 1 if stop > pos and text[stop - 1] == "\r" else stop
        no += 1
        yield no, pos, end
        pos = stop + 1


# --------------------------------------------------------------------------- #
# indent
# --------------------------------------------------------------------------- #

# (kind, regex).  A column-0 line matching one of these opens a block; an optional
# ``name`` group gives the block name.  The first match wins.
DEFAULT_INDENT_STARTS: tuple[tuple[str, str], ...] = (
    ("interface range", r"interface[ \t]+range\b.*"),
    ("interface", r"interface(?:[ \t]+(?P<name>\S+))?(?:[ \t]+.*)?$"),
    ("vlan", r"vlan[ \t]+(?P<name>[\d,\-]+)[ \t]*$"),
    ("vrf", r"(?:vrf[ \t]+(?:context|definition)|ip[ \t]+vrf)[ \t]+(?P<name>\S+)"),
    ("router bgp", r"router[ \t]+bgp\b(?:[ \t]+(?P<name>\S+))?"),
    ("router", r"router[ \t]+(?P<name>\S+)"),
    ("line", r"line[ \t]+(?P<name>.+?)[ \t]*$"),
    ("route-map", r"route-map[ \t]+(?P<name>\S+)"),
    ("ip access-list", r"ip(?:v6)?[ \t]+access-list[ \t]+(?P<name>.+?)[ \t]*$"),
    ("object", r"object(?:-group)?[ \t]+(?P<name>.+?)[ \t]*$"),
    ("crypto", r"crypto[ \t]+(?P<name>.+?)[ \t]*$"),
)

_START_CACHE: dict[tuple[tuple[str, str], ...], list[tuple[str, re.Pattern[str]]]] = {}


def compile_starts(
    starts: Sequence[tuple[str, str]],
) -> list[tuple[str, re.Pattern[str]]]:
    key = tuple(starts)
    if key not in _START_CACHE:
        _START_CACHE[key] = [(k, re.compile(rx)) for k, rx in key]
    return _START_CACHE[key]


def _iface_orphan(name: str) -> bool:
    """A truncated interface name: empty, no digit, or ending in punctuation."""
    return not name or not re.search(r"\d", name) or not name[-1].isalnum()


def _split_indent(text: str, starts: Sequence[tuple[str, str]] | None = None) -> Layout:
    compiled = compile_starts(starts or DEFAULT_INDENT_STARTS)
    lines: list[Line] = []
    blocks: list[Block] = []
    cur: Block | None = None
    ended = False
    for no, start, end in iter_lines(text):
        raw = text[start:end]
        chain = (cur,) if cur is not None else ()
        if ended:
            lines.append(Line(no, start, end, (), "after-end"))
            continue
        if SYSLOG_RE.match(raw):
            lines.append(Line(no, start, end, chain, "syslog"))
            continue
        if not raw.strip():
            lines.append(Line(no, start, end, chain))
            continue
        if raw[0] in " \t":
            if cur is not None:
                cur.end = end
            lines.append(Line(no, start, end, chain))
            continue
        # column 0
        if raw.rstrip() == "end":
            cur = None
            ended = True
            lines.append(Line(no, start, end, ()))
            continue
        blk = _match_start(raw, compiled, start, no)
        if blk is None:
            cur = None
            lines.append(Line(no, start, end, ()))
            continue
        blk.end = end
        blocks.append(blk)
        cur = blk
        lines.append(Line(no, start, end, (blk,)))
    return Layout(text, "indent", lines, blocks)


def _match_start(
    raw: str, compiled: list[tuple[str, re.Pattern[str]]], start: int, no: int
) -> Block | None:
    for kind, rx in compiled:
        m = rx.match(raw)
        if m is None:
            continue
        gd = m.groupdict()
        name = gd.get("name") or ""
        span = Span(start + m.start("name"), start + m.end("name")) if name else None
        orphan = kind == "interface" and _iface_orphan(name)
        return Block(
            kind=kind,
            name=name,
            path=f"{kind}/{name}" if name else kind,
            start=start,
            end=start,
            header_line=no,
            depth=0,
            name_span=span,
            orphan=orphan,
        )
    return None


# --------------------------------------------------------------------------- #
# fortios
# --------------------------------------------------------------------------- #

_CONFIG_RE = re.compile(r"^[ \t]*config[ \t]+(?P<name>.+?)[ \t]*$")
_EDIT_RE = re.compile(r"^[ \t]*edit[ \t]+(?P<name>\"[^\"]*\"|\S+)[ \t]*$")
_NEXT_RE = re.compile(r"^[ \t]*next[ \t]*$")
_END_RE = re.compile(r"^[ \t]*end[ \t]*$")


def _split_fortios(text: str) -> Layout:
    lines: list[Line] = []
    blocks: list[Block] = []
    stack: list[Block] = []

    def push(kind: str, name: str, start: int, no: int, span: Span | None) -> Block:
        parent_path = stack[-1].path if stack else ""
        path = f"{parent_path}/{name}" if parent_path else name
        blk = Block(kind, name, path, start, start, no, len(stack), span)
        blocks.append(blk)
        stack.append(blk)
        return blk

    def last_config() -> str:
        for b in reversed(stack):
            if not b.kind.startswith("edit:"):
                return b.kind
        return ""

    for no, start, end in iter_lines(text):
        raw = text[start:end]
        if not raw.strip():
            lines.append(Line(no, start, end, tuple(stack)))
            continue
        pop = 0
        m = _CONFIG_RE.match(raw)
        if m:
            name = m.group("name")
            push(
                name,
                name,
                start,
                no,
                Span(start + m.start("name"), start + m.end("name")),
            )
        elif (m := _EDIT_RE.match(raw)) is not None:
            while stack and stack[-1].kind.startswith("edit:"):
                stack.pop()  # tolerate a missing "next"
            name = m.group("name")
            a, b = start + m.start("name"), start + m.end("name")
            if name.startswith('"') and name.endswith('"') and len(name) >= 2:
                name, a, b = name[1:-1], a + 1, b - 1
            push(f"edit:{last_config()}", name, start, no, Span(a, b))
        elif _NEXT_RE.match(raw):
            pop = 1 if stack and stack[-1].kind.startswith("edit:") else 0
        elif _END_RE.match(raw):
            while stack and stack[-1].kind.startswith("edit:"):
                stack.pop()
            pop = 1 if stack else 0
        chain = tuple(stack)
        for b in chain:
            b.end = end
        lines.append(Line(no, start, end, chain))
        for _ in range(pop):
            stack.pop()
    return Layout(text, "fortios", lines, blocks)


# --------------------------------------------------------------------------- #
# brace (junos)
# --------------------------------------------------------------------------- #


def _brace_events(raw: str) -> list[tuple[int, str]]:
    """Positions of ``{`` and ``}`` outside quotes and comments."""
    events: list[tuple[int, str]] = []
    quote = ""
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "#" or raw.startswith("//", i):
            break
        elif raw.startswith("/*", i):
            close = raw.find("*/", i + 2)
            if close == -1:
                break
            i = close + 1
        elif c in "{}":
            events.append((i, c))
        i += 1
    return events


def _split_brace(text: str) -> Layout:
    lines: list[Line] = []
    blocks: list[Block] = []
    stack: list[Block] = []
    for no, start, end in iter_lines(text):
        raw = text[start:end]
        events = _brace_events(raw)
        chain: tuple[Block, ...] = tuple(stack)
        if not events:
            if raw.strip():
                for b in chain:
                    b.end = end
            lines.append(Line(no, start, end, chain))
            continue
        prev = 0
        for pos, ch in events:
            if ch == "{":
                seg = raw[prev:pos]
                name = seg.strip()
                lead = len(seg) - len(seg.lstrip())
                span = Span(start + prev + lead, start + prev + lead + len(name))
                parent_path = stack[-1].path if stack else ""
                path = f"{parent_path}/{name}" if parent_path else name
                blk = Block(path, name, path, start, start, no, len(stack), span)
                blocks.append(blk)
                stack.append(blk)
                chain = tuple(stack)
            else:
                chain = tuple(stack)
                if stack:
                    stack.pop()
            prev = pos + 1
        for b in chain:
            b.end = end
        lines.append(Line(no, start, end, chain))
    return Layout(text, "brace", lines, blocks)


# --------------------------------------------------------------------------- #
# flat (heredocs)
# --------------------------------------------------------------------------- #

_HEREDOC_RE = re.compile(r"<<-?[ \t]*(?P<q>['\"]?)(?P<tag>\w+)(?P=q)")
_REDIRECT_RE = re.compile(r"(?<![<>])>{1,2}[ \t]*(?P<p>[^\s<>|;&]+)")
_TEE_RE = re.compile(r"\btee\b(?:[ \t]+-\w+)*[ \t]+(?P<p>[^\s<>|;&]+)")


def _split_flat(text: str) -> Layout:
    lines: list[Line] = []
    blocks: list[Block] = []
    cur: Block | None = None
    tag = ""
    for no, start, end in iter_lines(text):
        raw = text[start:end]
        if cur is not None:
            cur.end = end
            lines.append(Line(no, start, end, (cur,)))
            if raw.strip() == tag:
                cur = None
            continue
        m = _HEREDOC_RE.search(raw)
        if m is None:
            lines.append(Line(no, start, end, ()))
            continue
        rest = raw[: m.start()] + " " + raw[m.end() :]
        pm = _REDIRECT_RE.search(rest) or _TEE_RE.search(rest)
        path = pm.group("p").strip("'\"") if pm else ""
        kind = f"heredoc:{path}" if path else "heredoc"
        cur = Block(kind, path or m.group("tag"), kind, start, end, no)
        tag = m.group("tag")
        blocks.append(cur)
        lines.append(Line(no, start, end, (cur,)))
    return Layout(text, "flat", lines, blocks)


# --------------------------------------------------------------------------- #
# html
# --------------------------------------------------------------------------- #


def _split_html(text: str) -> Layout:
    idx = LineIndex(text)
    lines: list[Line] = []
    for region in html_text_regions(text):
        pos = region.start
        while pos < region.end:
            nl = text.find("\n", pos, region.end)
            stop = region.end if nl == -1 else nl
            end = stop - 1 if stop > pos and text[stop - 1] == "\r" else stop
            if text[pos:end].strip():
                lines.append(Line(idx.line(pos), pos, end, ()))
            pos = stop + 1
    return Layout(text, "html", lines, [])


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #


def split(
    text: str, style: str, starts: Sequence[tuple[str, str]] | None = None
) -> Layout:
    """Parse ``text`` with the block parser for ``style``.

    ``starts`` overrides the ``indent`` header table (``DEFAULT_INDENT_STARTS``).
    """
    if style == "indent":
        return _split_indent(text, starts)
    if style == "fortios":
        return _split_fortios(text)
    if style == "brace":
        return _split_brace(text)
    if style == "flat":
        return _split_flat(text)
    if style == "html":
        return _split_html(text)
    raise ValueError(f"unknown block style {style!r}; expected one of {STYLES}")
