"""Raw, span-indexed view of an EVE-NG ``.unl`` lab (design section 5.1).

``RawLab`` keeps the exact file bytes and a span index built by a small
markup tokenizer.  The file is **never re-serialised**: every change is a
``RawEdit`` (byte span, expected old bytes, new bytes) applied by ``splice``.
``xml.etree.ElementTree`` is used only as a read-only cross-check of the span
index (``RawLab.verify_against_etree``); if the two disagree the lab is marked
``read_only`` and every edit constructor refuses.

All offsets are **byte offsets** into ``RawLab.raw``.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .errors import ConflictError, EveLabError, LabParseError, UnsupportedLayout
from .labmodel import Interface, Network, Node
from .spans import Span

__all__ = [
    "RawAttr",
    "RawBlob",
    "RawEdit",
    "RawElem",
    "RawIface",
    "RawLab",
    "check_label",
    "escape_attr",
    "label_warnings",
    "splice",
    "unescape_attr",
    "verify_outside_spans",
]

LABEL_MAX = 64
LABEL_WARN = 32

# ---------------------------------------------------------------- tokenizer

_NAME = rb"[A-Za-z_:][\w:.\-]*"
_TOKEN = re.compile(
    rb"<!--(?P<comment>.*?)-->"
    rb"|<!\[CDATA\[(?P<cdata>.*?)\]\]>"
    rb"|<\?(?P<pi>.*?)\?>"
    rb"|(?P<doctype><!DOCTYPE)"
    rb"|</(?P<end>" + _NAME + rb")\s*>"
    rb"|<(?P<start>" + _NAME + rb")"
    rb"(?P<attrs>(?:\s+" + _NAME + rb"\s*=\s*(?:\"[^\"<]*\"|'[^'<]*'))*)"
    rb"\s*(?P<selfclose>/?)>",
    re.DOTALL,
)
_ATTR = re.compile(rb"(" + _NAME + rb")\s*=\s*(?:\"([^\"<]*)\"|'([^'<]*)')")
_XML_ENCODING = re.compile(rb"encoding\s*=\s*[\"']([^\"']+)[\"']")
_ENTITY = re.compile(r"&(#x[0-9A-Fa-f]+|#[0-9]+|amp|lt|gt|quot|apos);")
_BAD_AMP = re.compile(r"&(?!(?:#x[0-9A-Fa-f]+|#[0-9]+|amp|lt|gt|quot|apos);)")
_NAMED = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
_B64_BYTES = re.compile(rb"[A-Za-z0-9+/=]*")
_BOM = b"\xef\xbb\xbf"


@dataclass
class _El:
    """Internal tree node of the tokenizer (offsets into the raw bytes)."""

    tag: str
    span: Span  # start tag, '<' .. '>' inclusive
    attrs: dict[str, RawAttr]
    self_closing: bool
    parent: _El | None = None
    children: list[_El] = field(default_factory=list)
    content_start: int = 0  # first byte after the start tag
    content_end: int = 0  # first byte of the end tag (== content_start if empty)
    end: int = 0  # first byte after the end tag

    def child(self, tag: str) -> _El | None:
        for ch in self.children:
            if ch.tag == tag:
                return ch
        return None

    def kids(self, tag: str) -> list[_El]:
        return [ch for ch in self.children if ch.tag == tag]


def unescape_attr(raw_value: bytes) -> str:
    """Decode a raw attribute value like an XML parser (entities, whitespace)."""
    try:
        text = raw_value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LabParseError(f"attribute value is not valid UTF-8: {exc}") from exc
    if _BAD_AMP.search(text):
        raise LabParseError(f"unknown entity or bare '&' in attribute {text!r}")
    text = text.replace("\r\n", " ")
    text = text.replace("\t", " ").replace("\n", " ").replace("\r", " ")

    def sub(m: re.Match[str]) -> str:
        ent = m.group(1)
        if ent in _NAMED:
            return _NAMED[ent]
        try:
            code = int(ent[2:], 16) if ent[1] == "x" else int(ent[1:])
            return chr(code)
        except (ValueError, OverflowError) as exc:
            raise LabParseError(f"bad character reference &{ent};") from exc

    return _ENTITY.sub(sub, text)


def escape_attr(value: str, quote: str = '"') -> str:
    """Escape ``value`` for use inside an attribute quoted with ``quote``."""
    out = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if quote == "'":
        return out.replace("'", "&apos;")
    return out.replace('"', "&quot;")


def check_label(value: str) -> None:
    """Raise ``EveLabError(code="BAD_LABEL")`` unless ``value`` is a legal label.

    Legal: printable characters only (no control characters, no newlines), at
    most ``LABEL_MAX`` characters.  Use ``label_warnings`` for soft limits.
    """
    if len(value) > LABEL_MAX:
        raise EveLabError(
            f"label {value!r} is longer than {LABEL_MAX} characters", code="BAD_LABEL"
        )
    for ch in value:
        if not ch.isprintable():
            raise EveLabError(
                f"label {value!r} contains a non-printable character {ch!r}",
                code="BAD_LABEL",
            )


def label_warnings(value: str) -> list[str]:
    """Soft problems with a label (currently: longer than ``LABEL_WARN``)."""
    if len(value) > LABEL_WARN:
        return [f"label {value!r} is longer than {LABEL_WARN} characters"]
    return []


_TOKEN_CACHE: dict[bytes, _El] = {}
_TOKEN_CACHE_SIZE = 32


def _tokenize(raw: bytes) -> _El:
    """``_tokenize_uncached`` memoised per raw bytes.  The tree is never
    mutated after tokenizing, and a lab is read several times per run (load,
    apply staging/validation, rescan, revert), so identical bytes are
    tokenized once (performance, review #38).  Errors are not cached."""
    hit = _TOKEN_CACHE.get(raw)
    if hit is None:
        hit = _tokenize_uncached(raw)
        _TOKEN_CACHE[raw] = hit
        while len(_TOKEN_CACHE) > _TOKEN_CACHE_SIZE:
            _TOKEN_CACHE.pop(next(iter(_TOKEN_CACHE)))
    return hit


def _tokenize_uncached(raw: bytes) -> _El:
    """Build the element tree of ``raw`` or raise ``LabParseError``."""
    pos = 3 if raw.startswith(_BOM) else 0
    stack: list[_El] = []
    root: _El | None = None

    def gap(start: int, stop: int) -> None:
        if raw.find(b"<", start, stop) != -1:
            at = raw.find(b"<", start, stop)
            raise LabParseError(f"malformed markup at byte {at}")
        if not stack and raw[start:stop].strip(b" \t\r\n"):
            raise LabParseError(f"text outside the root element at byte {start}")

    for m in _TOKEN.finditer(raw, pos):
        gap(pos, m.start())
        pos = m.end()
        if m.group("pi") is not None:
            if m.start() == (3 if raw.startswith(_BOM) else 0):
                enc = _XML_ENCODING.search(m.group("pi"))
                if enc and enc.group(1).lower() not in (b"utf-8", b"utf8"):
                    raise LabParseError(
                        f"unsupported XML encoding {enc.group(1).decode('ascii')!r}"
                    )
            continue
        if m.group("doctype") is not None:
            raise LabParseError("DOCTYPE declarations are not supported")
        if m.group("comment") is not None or m.group("cdata") is not None:
            continue
        if (end := m.group("end")) is not None:
            if not stack or stack[-1].tag != end.decode():
                raise LabParseError(f"unexpected </{end.decode()}> at byte {m.start()}")
            el = stack.pop()
            el.content_end = m.start()
            el.end = m.end()
            continue
        tag = m.group("start").decode()
        attrs: dict[str, RawAttr] = {}
        for am in _ATTR.finditer(raw, m.start("attrs"), m.end("attrs")):
            name = am.group(1).decode()
            if name in attrs:
                raise LabParseError(f"duplicate attribute {name!r} on <{tag}>")
            grp = 2 if am.group(2) is not None else 3
            value = am.group(grp)
            attrs[name] = RawAttr(
                name=name,
                value=unescape_attr(value),
                span=Span(am.start(grp), am.end(grp)),
                quote='"' if grp == 2 else "'",
            )
        self_closing = bool(m.group("selfclose"))
        el = _El(
            tag=tag,
            span=Span(m.start(), m.end()),
            attrs=attrs,
            self_closing=self_closing,
            parent=stack[-1] if stack else None,
            content_start=m.end(),
        )
        if stack:
            stack[-1].children.append(el)
        elif root is not None:
            raise LabParseError("more than one root element")
        else:
            root = el
        if self_closing:
            el.content_end = el.end = m.end()
        else:
            stack.append(el)
    gap(pos, len(raw))
    if stack:
        raise LabParseError(f"unclosed element <{stack[-1].tag}>")
    if root is None:
        raise LabParseError("no root element")
    return root


# -------------------------------------------------------------- public shapes


@dataclass(frozen=True)
class RawAttr:
    """One attribute: decoded ``value`` and the raw byte ``span`` of its value."""

    name: str
    value: str
    span: Span  # the bytes between the quotes
    quote: str  # '"' or "'"


@dataclass(frozen=True)
class RawElem:
    """An element start tag: ``span`` covers ``<`` .. ``>``; ``attrs`` in file order."""

    tag: str
    span: Span
    attrs: Mapping[str, RawAttr] = field(compare=False)

    @property
    def id(self) -> str:
        return self.get("id")

    def get(self, name: str, default: str = "") -> str:
        """Decoded value of attribute ``name`` or ``default``."""
        attr = self.attrs.get(name)
        return attr.value if attr is not None else default

    def values(self) -> dict[str, str]:
        """All attributes as decoded ``name -> value``."""
        return {k: a.value for k, a in self.attrs.items()}


@dataclass(frozen=True)
class RawIface:
    """A ``<interface>`` child of a node."""

    elem: RawElem

    @property
    def id(self) -> str:
        return self.elem.get("id")

    @property
    def name(self) -> str:
        return self.elem.get("name")

    @property
    def network_id(self) -> str | None:
        attr = self.elem.attrs.get("network_id")
        return attr.value if attr is not None else None

    @property
    def vid(self) -> str:
        return self.elem.get("vid")

    def to_model(self) -> Interface:
        return Interface(self.id, self.name, self.network_id, self.vid)


@dataclass(frozen=True)
class RawNode:
    """A ``<node>`` element with its interfaces (document order)."""

    elem: RawElem
    ifaces: tuple[RawIface, ...]

    @property
    def id(self) -> str:
        return self.elem.get("id")

    @property
    def name(self) -> str:
        return self.elem.get("name")

    def to_model(self) -> Node:
        e = self.elem
        return Node(
            id=self.id,
            name=self.name,
            type=e.get("type"),
            template=e.get("template"),
            image=e.get("image"),
            config_attr=e.get("config", "0"),
            ifaces=[i.to_model() for i in self.ifaces],
        )


@dataclass(frozen=True)
class RawBlob:
    """A base64 payload inside ``<config>`` or ``<textobject><data>``.

    ``kind`` is ``"config"`` or ``"textobject"``.  For configs ``scope`` is
    ``"startup"`` or ``"cs:<configset name>"`` and ``node_id`` is the config id
    (== node id); for textobjects ``scope`` is ``"-"`` and ``node_id`` is None.
    ``span`` covers the bytes between the start and end tags; ``b64`` is that
    slice.  A self-closing ``<config id="N"/>`` has an empty span and
    ``self_closing=True`` and cannot be edited in place.
    """

    kind: Literal["config", "textobject"]
    scope: str
    id: str
    node_id: str | None
    name: str
    type: str
    configset_id: str | None
    span: Span
    b64: bytes = field(compare=False, repr=False)
    elem: RawElem = field(compare=False, repr=False)
    self_closing: bool = False


@dataclass(frozen=True)
class RawEdit:
    """Replace ``raw[start:end]`` (which must equal ``old``) with ``new``."""

    start: int
    end: int
    old: bytes
    new: bytes


# ------------------------------------------------------------------- splice


def _check_spans(ordered: Sequence[RawEdit], size: int) -> None:
    prev: RawEdit | None = None
    for e in ordered:
        if not 0 <= e.start <= e.end <= size:
            raise ConflictError(
                f"edit span {e.start}:{e.end} is out of range (size {size})",
                code="BAD_SPAN",
            )
        if prev is not None and (
            e.start < prev.end or (e.start == prev.start == prev.end == e.end)
        ):
            raise ConflictError(
                f"edits overlap: {prev.start}:{prev.end} and {e.start}:{e.end}"
            )
        prev = e


def splice(raw: bytes, edits: Sequence[RawEdit]) -> bytes:
    """Apply ``edits`` to ``raw`` and return the new bytes.

    Edits are sorted by start offset.  Overlapping edits (or two insertions at
    one offset) raise ``ConflictError``; so does any edit whose ``old`` differs
    from the bytes found at its span (``code="STALE_EDIT"``).  Bytes outside the
    spans are copied verbatim.
    """
    ordered = sorted(edits, key=lambda e: (e.start, e.end))
    _check_spans(ordered, len(raw))
    view = memoryview(raw)
    pieces: list[bytes | memoryview] = []
    pos = 0
    for e in ordered:
        if raw[e.start : e.end] != e.old:
            raise ConflictError(
                f"bytes at {e.start}:{e.end} changed since the edit was planned "
                f"(found {raw[e.start : e.end][:40]!r}, expected {e.old[:40]!r})",
                code="STALE_EDIT",
            )
        pieces.append(view[pos : e.start])
        pieces.append(e.new)
        pos = e.end
    pieces.append(view[pos:])
    return b"".join(pieces)


def verify_outside_spans(before: bytes, after: bytes, edits: Sequence[RawEdit]) -> bool:
    """True when ``after`` equals ``before`` with exactly ``edits`` applied.

    Compares the untouched gaps between the sorted spans and the new bytes with
    slice comparisons (no difflib), so it stays fast on multi-megabyte labs.
    """
    ordered = sorted(edits, key=lambda e: (e.start, e.end))
    try:
        _check_spans(ordered, len(before))
    except ConflictError:
        return False
    bv, av = memoryview(before), memoryview(after)
    bpos = apos = 0
    for e in ordered:
        gap = e.start - bpos
        if av[apos : apos + gap] != bv[bpos : e.start]:
            return False
        apos += gap
        if av[apos : apos + len(e.new)] != e.new:
            return False
        apos += len(e.new)
        bpos = e.end
    return av[apos:] == bv[bpos:]


# -------------------------------------------------------------------- RawLab


def _hash_compact(data: bytes) -> str:
    return hashlib.sha1(b"".join(data.split())).hexdigest()


class RawLab:
    """Exact bytes of a ``.unl`` plus a span index of what the tool may touch.

    Attributes: ``path``, ``raw``, ``sha256``, ``lab_id``, ``name``,
    ``read_only`` (ET cross-check failed: scan only) and ``layout_issues``
    (human-readable reasons).
    """

    path: Path
    raw: bytes
    sha256: str
    lab_id: str
    name: str
    read_only: bool
    layout_issues: list[str]

    def __init__(self, path: Path, raw: bytes) -> None:
        self.path = path
        self.raw = raw
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.layout_issues = []
        self._networks: list[RawElem] = []
        self._nodes: list[RawNode] = []
        self._blobs: list[RawBlob] = []
        self._textobjects: list[RawBlob] = []
        self._configsets: dict[str, str] = {}
        self._objects_count = 0
        self._skips: list[tuple[str, Span]] = []
        root = _tokenize(raw)
        if root.tag != "lab":
            raise LabParseError(f"root element is <{root.tag}>, expected <lab>")
        self._root = self._elem(root)
        self.lab_id = self._root.get("id").strip()
        self.name = self._root.get("name")
        self._index(root)
        self.layout_issues.extend(self.verify_against_etree())
        self.read_only = bool(self.layout_issues)

    # ------------------------------------------------------------ construction

    @classmethod
    def read(cls, path: Path, *, strict: bool = False) -> RawLab:
        """Read ``path``.

        Raises ``LabParseError`` when the file is not well-formed XML or not a
        ``<lab>``.  When the span index disagrees with ElementTree the lab is
        returned with ``read_only=True`` (so scans still work); pass
        ``strict=True`` to raise ``UnsupportedLayout`` instead.
        """
        path = Path(path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise LabParseError(f"{path}: cannot read: {exc}") from exc
        try:
            lab = cls(path, raw)
        except LabParseError as exc:
            raise LabParseError(f"{path}: {exc}") from exc
        if strict and lab.read_only:
            raise UnsupportedLayout(
                f"{path}: " + "; ".join(lab.layout_issues), refs=lab.layout_issues
            )
        return lab

    @classmethod
    def from_bytes(cls, raw: bytes, path: Path | None = None) -> RawLab:
        """Index in-memory bytes (used to re-read a freshly written lab)."""
        return cls(path if path is not None else Path("<memory>"), raw)

    # ------------------------------------------------------------------ index

    def _elem(self, el: _El) -> RawElem:
        return RawElem(tag=el.tag, span=el.span, attrs=el.attrs)

    def _index(self, root: _El) -> None:
        topo = root.child("topology")
        if topo is not None:
            nodes_el = topo.child("nodes")
            if nodes_el is not None:
                for n in nodes_el.kids("node"):
                    ifaces = tuple(RawIface(self._elem(i)) for i in n.kids("interface"))
                    self._nodes.append(RawNode(self._elem(n), ifaces))
            nets_el = topo.child("networks")
            if nets_el is not None:
                self._networks = [self._elem(n) for n in nets_el.kids("network")]
        desc = root.child("description")
        if desc is not None:
            self._skips.append(("description", Span(desc.span.start, desc.end)))
        objects = root.kids("objects")
        self._objects_count = len(objects)
        main = next((o for o in objects if o.children), None)
        if main is None:
            return
        for tag in ("tasks", "lineobjects"):
            for el in main.kids(tag):
                self._skips.append((tag, Span(el.span.start, el.end)))
        configs = main.child("configs")
        if configs is not None:
            self._index_configs(configs, "startup", None)
        sets = main.child("configsets")
        if sets is not None:
            for cs in sets.kids("configset"):
                cs_id, cs_name = cs.attrs.get("id"), cs.attrs.get("name")
                if cs_id is None or cs_name is None:
                    self.layout_issues.append("configset without id or name")
                    continue
                if cs_id.value in self._configsets:
                    self.layout_issues.append(f"duplicate configset id {cs_id.value}")
                if cs_name.value in self._configsets.values():
                    self.layout_issues.append(
                        f"duplicate configset name {cs_name.value!r}"
                    )
                self._configsets[cs_id.value] = cs_name.value
                self._index_configs(cs, f"cs:{cs_name.value}", cs_id.value)
        tobjs = main.child("textobjects")
        if tobjs is not None:
            for to in tobjs.kids("textobject"):
                data = to.child("data")
                if data is None or len(to.kids("data")) != 1:
                    continue
                blob = self._make_blob(
                    "textobject", to, data, "-", to.attrs.get("id"), None
                )
                if blob is not None:
                    self._textobjects.append(blob)

    def _index_configs(self, container: _El, scope: str, cs_id: str | None) -> None:
        seen: set[str] = set()
        for cfg in container.kids("config"):
            cid = cfg.attrs.get("id")
            blob = self._make_blob("config", cfg, cfg, scope, cid, cs_id)
            if blob is None:
                continue
            if blob.id in seen:
                self.layout_issues.append(f"duplicate config id {blob.id} in {scope}")
            seen.add(blob.id)
            self._blobs.append(blob)

    def _make_blob(
        self,
        kind: Literal["config", "textobject"],
        owner: _El,
        holder: _El,
        scope: str,
        id_attr: RawAttr | None,
        cs_id: str | None,
    ) -> RawBlob | None:
        if id_attr is None:
            self.layout_issues.append(f"<{owner.tag}> without id in {scope}")
            return None
        start, stop = holder.content_start, holder.content_end
        if holder.children or self.raw.find(b"<", start, stop) != -1:
            self.layout_issues.append(
                f"<{holder.tag} id={id_attr.value}> contains markup"
            )
            return None
        elem = self._elem(owner)
        return RawBlob(
            kind=kind,
            scope=scope,
            id=id_attr.value,
            node_id=id_attr.value if kind == "config" else None,
            name=elem.get("name"),
            type=elem.get("type"),
            configset_id=cs_id,
            span=Span(start, stop),
            b64=self.raw[start:stop],
            elem=elem,
            self_closing=holder.self_closing,
        )

    # ---------------------------------------------------------------- queries

    def networks(self) -> list[RawElem]:
        """``<network>`` start tags (id, attrs, spans) in document order."""
        return list(self._networks)

    def nodes(self) -> list[RawNode]:
        """``<node>`` elements with their interfaces in document order."""
        return list(self._nodes)

    def config_blobs(self) -> list[RawBlob]:
        """Startup (``scope="startup"``) and configset (``"cs:<name>"``) configs."""
        return list(self._blobs)

    def configsets(self) -> dict[str, str]:
        """Configset id -> name."""
        return dict(self._configsets)

    def textobjects(self) -> list[RawBlob]:
        """``<textobject>`` ``<data>`` payloads (id, name, type, span)."""
        return list(self._textobjects)

    def objects_count(self) -> int:
        """Number of ``<objects>`` children of ``<lab>``, stray empty ones included."""
        return self._objects_count

    def skip_regions(self) -> list[tuple[str, Span]]:
        """Regions never decoded: ``description``, ``tasks``, ``lineobjects``."""
        return list(self._skips)

    def network_models(self) -> dict[str, Network]:
        """Networks as the shared model, keyed by id (first wins on duplicates)."""
        out: dict[str, Network] = {}
        for e in self._networks:
            out.setdefault(
                e.id, Network(e.id, e.get("type"), e.get("name"), e.values())
            )
        return out

    def node_models(self) -> dict[str, Node]:
        """Nodes as the shared model, keyed by id (first wins on duplicates)."""
        out: dict[str, Node] = {}
        for n in self._nodes:
            out.setdefault(n.id, n.to_model())
        return out

    # ------------------------------------------------------------ cross-check

    def _raw_signature(self) -> dict[str, list[tuple[str, ...]]]:
        sig: dict[str, list[tuple[str, ...]]] = {
            "networks": [(e.id, e.get("type"), e.get("name")) for e in self._networks],
            "nodes": [(n.id, n.name, n.elem.get("type")) for n in self._nodes],
            "interfaces": [
                (n.id, i.id, i.name, i.network_id or "")
                for n in self._nodes
                for i in n.ifaces
            ],
            "configsets": [(i, n) for i, n in self._configsets.items()],
            "configs": [
                (
                    "startup" if b.configset_id is None else f"cs:{b.configset_id}",
                    b.id,
                    _hash_compact(b.b64),
                )
                for b in self._blobs
            ],
            "textobjects": [
                (b.id, b.name, b.type, _hash_compact(b.b64)) for b in self._textobjects
            ],
        }
        return {k: sorted(v) for k, v in sig.items()}

    def _etree_signature(self, root: ET.Element) -> dict[str, list[tuple[str, ...]]]:
        parents = {c: p for p in root.iter() for c in p}

        def where(cfg: ET.Element) -> str:
            par = parents.get(cfg)
            if par is None:
                return "?"
            grand = parents.get(par)
            if par.tag == "configs" and grand is not None and grand.tag == "objects":
                return "startup" if parents.get(grand) is root else "?"
            if par.tag == "configset":
                sets = parents.get(par)
                obj = parents.get(sets) if sets is not None else None
                if (
                    sets is not None
                    and sets.tag == "configsets"
                    and obj is not None
                    and obj.tag == "objects"
                    and parents.get(obj) is root
                ):
                    return f"cs:{par.get('id', '')}"
            return "?" + par.tag

        def data_hash(text: str | None) -> str:
            return _hash_compact((text or "").encode("utf-8"))

        sig: dict[str, list[tuple[str, ...]]] = {
            "networks": [
                (n.get("id", ""), n.get("type", ""), n.get("name", ""))
                for n in root.iter("network")
            ],
            "nodes": [
                (n.get("id", ""), n.get("name", ""), n.get("type", ""))
                for n in root.iter("node")
            ],
            "interfaces": [
                (
                    n.get("id", ""),
                    i.get("id", ""),
                    i.get("name", ""),
                    i.get("network_id", ""),
                )
                for n in root.iter("node")
                for i in n.iter("interface")
            ],
            "configsets": [
                (c.get("id", ""), c.get("name", "")) for c in root.iter("configset")
            ],
            "configs": [
                (where(c), c.get("id", ""), data_hash(c.text))
                for c in root.iter("config")
            ],
            "textobjects": [
                (
                    t.get("id", ""),
                    t.get("name", ""),
                    t.get("type", ""),
                    data_hash(d.text if (d := t.find("data")) is not None else None),
                )
                for t in root.iter("textobject")
            ],
        }
        return {k: sorted(v) for k, v in sig.items()}

    def verify_against_etree(self) -> list[str]:
        """Compare the span index with an independent ElementTree parse.

        Returns a list of problems (empty = the index sees everything ET sees):
        ids and counts of networks, nodes, interfaces, configs per container,
        configsets, textobjects and ``<objects>`` elements, and a digest of every
        blob's text.  ElementTree is only read, never used to write.
        """
        try:
            root = ET.fromstring(self.raw)
        except ET.ParseError as exc:
            raise LabParseError(f"not well-formed XML: {exc}") from exc
        issues: list[str] = []
        if (
            root.get("id", "").strip() != self.lab_id
            or root.get("name", "") != self.name
        ):
            issues.append("lab id/name differ between span index and ElementTree")
        if len(root.findall("objects")) != self._objects_count:
            issues.append(
                f"<objects> count: index {self._objects_count}, "
                f"ElementTree {len(root.findall('objects'))}"
            )
        raw_sig = self._raw_signature()
        et_sig = self._etree_signature(root)
        for key, mine in raw_sig.items():
            theirs = et_sig[key]
            if mine == theirs:
                continue
            extra = [x[:2] for x in theirs if x not in mine][:5]
            missing = [x[:2] for x in mine if x not in theirs][:5]
            issues.append(
                f"{key}: index has {len(mine)}, ElementTree has {len(theirs)}; "
                f"only in ElementTree {extra}; only in index {missing}"
            )
        return issues

    # ------------------------------------------------------------------ edits

    def _require_writable(self) -> None:
        if self.read_only:
            raise UnsupportedLayout(
                f"{self.path}: lab is read-only (unsupported layout): "
                + "; ".join(self.layout_issues),
                refs=self.layout_issues,
            )

    def attr_edit(self, elem: RawElem, attr: str, new: str) -> RawEdit:
        """Edit that replaces only the value bytes of ``elem``'s ``attr``.

        ``new`` is the *decoded* value; it is checked with ``check_label`` and
        escaped (``& < > "``, or ``'`` when the attribute is single-quoted).  If
        ``new`` equals the current decoded value the edit is a no-op that keeps
        the original bytes (so non-canonical escapes survive idempotent runs).
        """
        self._require_writable()
        a = elem.attrs.get(attr)
        if a is None:
            raise EveLabError(
                f"<{elem.tag}> has no attribute {attr!r} to edit", code="NO_SUCH_ATTR"
            )
        check_label(new)
        old = self.raw[a.span.start : a.span.end]
        if new == a.value:
            return RawEdit(a.span.start, a.span.end, old, old)
        return RawEdit(
            a.span.start,
            a.span.end,
            old,
            escape_attr(new, a.quote).encode("utf-8"),
        )

    def blob_edit(self, blob: RawBlob, new_b64: bytes) -> RawEdit:
        """Edit that replaces the payload bytes of ``blob`` with ``new_b64``."""
        self._require_writable()
        if blob.self_closing:
            raise UnsupportedLayout(
                f"<{blob.elem.tag} id={blob.id}/> is self-closing and cannot be "
                "edited in place"
            )
        if _B64_BYTES.fullmatch(new_b64) is None:
            raise EveLabError(
                "new blob payload contains non-base64 bytes", code="BAD_BLOB"
            )
        return RawEdit(blob.span.start, blob.span.end, blob.b64, new_b64)
