"""Text utilities shared by dialects, discovery, scenarios and the planner.

Everything here works on ``str`` and reports offsets as indices into that same
string (never bytes), so spans can be used to splice decoded config text.

Contents (design sections 6.5 and 14.1):

* IPv4 tokenizer with adjacent mask capture (``find_ipv4``)
* IPv6 literal detector (``find_ipv6``)
* mask helpers (``prefix_to_netmask``, ``netmask_to_prefix``, ``mask_render`` ...)
* ``VlanList``: style-preserving VLAN list parse / replace / render
* ``token_re`` / ``domain_re``: whole-token matchers for labels and domains
* ``html_text_regions``: text-node spans of an HTML fragment
* ``LineIndex``: offset to line number
"""

from __future__ import annotations

import ipaddress
import re
from bisect import bisect_right
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import Literal

from .errors import ConflictError
from .spans import Span

__all__ = [
    "IPV4_RE",
    "IPV4_SRC",
    "MASK_SRC",
    "Ipv4Token",
    "Ipv6Token",
    "LineIndex",
    "MaskToken",
    "Span",
    "VlanList",
    "VlanListError",
    "domain_re",
    "find_ipv4",
    "find_ipv6",
    "hostmask_to_prefix",
    "html_text_regions",
    "is_netmask",
    "mask_form_of",
    "mask_prefix",
    "mask_prefix_as",
    "mask_render",
    "netmask_to_prefix",
    "prefix_to_hostmask",
    "prefix_to_netmask",
    "token_re",
]

# --------------------------------------------------------------------------- #
# IPv4
# --------------------------------------------------------------------------- #

# Section 6.5.  The trailing guard is ``(?!\w|\.\w)`` instead of the document's
# ``(?![\w.]|\.\d)`` so that a sentence-final period ("to 10.1.1.1.") still
# matches, while ``1.2.3.4.5`` (OID), ``10.1.1.1.example.com`` and
# ``172.31.240.10`` (vs ``.1``) do not.
IPV4_SRC = r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\w)"
IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\w)")
# Pattern fragment for "a mask in any common form" (used by PatternRule MASK).
MASK_SRC = r"(?:/\d{1,2}(?!\d)|\d{1,3}(?:\.\d{1,3}){3})"

_QUAD = r"\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\w)"
_MASK_PREFIX_RE = re.compile(r"/(\d{1,2})(?!\d)")
_MASK_KEYWORD_RE = re.compile(r"[ \t]+netmask[ \t]+(" + _QUAD + ")")
_MASK_DOTTED_RE = re.compile(r"[ \t]+(" + _QUAD + ")")


@dataclass(frozen=True)
class MaskToken:
    """A mask found next to an address."""

    text: str  # "255.255.255.0" or "/24" (as written, without the keyword)
    span: Span
    form: Literal["dotted", "prefix", "netmask"]
    prefix: int  # prefix length; for a wildcard, the equivalent prefix
    wildcard: bool = False  # ``0.0.0.255`` style (ACL); never rewritten blindly


@dataclass(frozen=True)
class Ipv4Token:
    """One validated dotted quad, with its adjacent mask when present."""

    value: str
    span: Span
    mask: MaskToken | None = None

    @property
    def address(self) -> IPv4Address:
        return IPv4Address(self.value)


def prefix_to_netmask(prefix: int) -> str:
    """``24`` -> ``"255.255.255.0"``."""
    if not 0 <= prefix <= 32:
        raise ValueError(f"prefix length out of range: {prefix}")
    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return str(IPv4Address(bits))


def netmask_to_prefix(mask: str) -> int | None:
    """``"255.255.255.0"`` -> ``24``; ``None`` if not a contiguous netmask."""
    try:
        value = int(IPv4Address(mask))
    except ValueError:
        return None
    inverted = value ^ 0xFFFFFFFF
    if inverted & (inverted + 1):
        return None
    return 32 - inverted.bit_length()


def is_netmask(mask: str) -> bool:
    return netmask_to_prefix(mask) is not None


def hostmask_to_prefix(mask: str) -> int | None:
    """``"0.0.0.255"`` -> ``24``; ``None`` if not a contiguous wildcard."""
    try:
        value = int(IPv4Address(mask))
    except ValueError:
        return None
    if value & (value + 1):
        return None
    return 32 - value.bit_length()


def mask_prefix(text: str) -> int | None:
    """Prefix length of ``"/24"``, ``"24"`` or ``"255.255.255.0"``; else None."""
    text = text.strip()
    if text.startswith("/"):
        text = text[1:]
    if text.isdigit():
        n = int(text)
        return n if 0 <= n <= 32 else None
    return netmask_to_prefix(text)


def mask_form_of(text: str, *, keyword_before: bool = False) -> str:
    """Classify a mask token: ``dotted`` | ``prefix`` | ``netmask`` |
    ``wildcard`` | ``none``.

    ``keyword_before`` is true when the token follows the word ``netmask``.
    """
    text = text.strip()
    if mask_prefix(text) is None:
        # ``0.0.0.255`` (ACL / OSPF wildcard): a contiguous host mask that is
        # not also a netmask.  ``0.0.0.0`` / ``255.255.255.255`` stay dotted.
        return "wildcard" if hostmask_to_prefix(text) is not None else "none"
    if text.startswith("/") or text.isdigit():
        return "prefix"
    return "netmask" if keyword_before else "dotted"


def mask_render(form: str, prefix: int) -> str:
    """Render ``prefix`` in ``form``: ``/24`` for prefix, dotted otherwise."""
    if form == "prefix":
        if not 0 <= prefix <= 32:
            raise ValueError(f"prefix length out of range: {prefix}")
        return f"/{prefix}"
    if form in ("dotted", "netmask"):
        return prefix_to_netmask(prefix)
    if form == "wildcard":
        return prefix_to_hostmask(prefix)
    raise ValueError(f"cannot render mask form {form!r}")


def prefix_to_hostmask(prefix: int) -> str:
    """``24`` -> ``"0.0.0.255"`` (the ACL wildcard of a prefix length)."""
    if not 0 <= prefix <= 32:
        raise ValueError(f"prefix length out of range: {prefix}")
    return str(IPv4Address((1 << (32 - prefix)) - 1))


def mask_prefix_as(text: str, form: str) -> int | None:
    """Prefix length of a mask token read in its recorded ``form``.

    A ``wildcard`` token is read as a host mask (``0.0.0.255`` -> 24); every
    other form goes through :func:`mask_prefix`.
    """
    if form == "wildcard":
        return hostmask_to_prefix(text.strip())
    return mask_prefix(text)


def _mask_after(text: str, pos: int, end: int, *, masks: bool) -> MaskToken | None:
    if not masks or pos >= end:
        return None
    m = _MASK_PREFIX_RE.match(text, pos, end)
    if m:
        n = int(m.group(1))
        if n <= 32:
            return MaskToken(m.group(0), Span(m.start(), m.end()), "prefix", n)
    m = _MASK_KEYWORD_RE.match(text, pos, end)
    if m:
        prefix = netmask_to_prefix(m.group(1))
        if prefix is not None:
            return MaskToken(m.group(1), Span(m.start(1), m.end(1)), "netmask", prefix)
    m = _MASK_DOTTED_RE.match(text, pos, end)
    if m:
        quad = m.group(1)
        prefix = netmask_to_prefix(quad)
        if prefix is not None:
            return MaskToken(quad, Span(m.start(1), m.end(1)), "dotted", prefix)
        prefix = hostmask_to_prefix(quad)
        if prefix is not None:
            return MaskToken(
                quad, Span(m.start(1), m.end(1)), "dotted", prefix, wildcard=True
            )
    return None


def find_ipv4(
    text: str, start: int = 0, end: int | None = None, *, masks: bool = True
) -> list[Ipv4Token]:
    """All valid dotted quads in ``text[start:end]`` with adjacent masks.

    A mask directly after an address (``/24``, `` 255.255.255.0``,
    `` netmask 255.255.255.0``) is attached to it and is not reported as an
    address of its own.  Invalid quads (``300.1.1.1``, leading zeros) are
    skipped.
    """
    stop = len(text) if end is None else end
    out: list[Ipv4Token] = []
    pos = start
    while pos < stop:
        m = IPV4_RE.search(text, pos, stop)
        if m is None:
            break
        pos = m.end()
        try:
            ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue
        mask = _mask_after(text, m.end(), stop, masks=masks)
        out.append(Ipv4Token(m.group(1), Span(m.start(1), m.end(1)), mask))
        if mask is not None:
            pos = mask.span.end
    return out


# --------------------------------------------------------------------------- #
# IPv6
# --------------------------------------------------------------------------- #

_IPV6_CAND = re.compile(
    r"(?<![\w:.])(?=[0-9A-Fa-f:]*:)(?P<addr>[0-9A-Fa-f:]+(?:\.\d{1,3}){0,3})"
    r"(?P<plen>/\d{1,3})?(?![\w:])"
)


@dataclass(frozen=True)
class Ipv6Token:
    value: str  # the address, without any prefix length
    span: Span  # span of the address only
    prefix_len: int | None = None
    prefix_span: Span | None = None  # span of "/64" including the slash


def find_ipv6(text: str, start: int = 0, end: int | None = None) -> list[Ipv6Token]:
    """IPv6 literals (``2001:db8::1``, ``fe80::1/64``, ``::ffff:10.1.1.1``).

    Candidates are validated with :mod:`ipaddress`, so times (``12:34:56``),
    MACs (``00:11:22:33:44:55``), ``rd 2:2`` and ``community 204:204`` never
    match.  Detection only: IPv6 is reported, not rewritten (design 15 #69).
    """
    stop = len(text) if end is None else end
    out: list[Ipv6Token] = []
    for m in _IPV6_CAND.finditer(text, start, stop):
        addr = m.group("addr")
        if addr.count(":") < 2 or not any(c in "0123456789abcdefABCDEF" for c in addr):
            continue
        try:
            ipaddress.IPv6Address(addr)
        except ValueError:
            continue
        plen = m.group("plen")
        prefix_len: int | None = None
        prefix_span: Span | None = None
        if plen is not None:
            n = int(plen[1:])
            if n <= 128:
                prefix_len = n
                prefix_span = Span(m.start("plen"), m.end("plen"))
        out.append(
            Ipv6Token(
                addr, Span(m.start("addr"), m.end("addr")), prefix_len, prefix_span
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Whole-token matchers
# --------------------------------------------------------------------------- #


def _bounded(token: str, flags: int) -> re.Pattern[str]:
    if not token:
        raise ValueError("empty token")
    before = r"(?<![\w-])" if re.match(r"\w", token[0]) else ""
    after = r"(?![\w-])" if re.match(r"\w", token[-1]) else ""
    return re.compile(before + re.escape(token) + after, flags)


def token_re(token: str, *, ignore_case: bool = False) -> re.Pattern[str]:
    """Whole-token matcher for a label such as ``EVE-MGMT-203``.

    ``pnet0`` does not match inside ``pnet0-trunk`` or ``xpnet0``.  The guards
    only apply on a side where the token itself starts/ends with a word char.
    """
    return _bounded(token, re.IGNORECASE if ignore_case else 0)


def domain_re(domain: str) -> re.Pattern[str]:
    """Matcher for a domain name, case-insensitive.

    ``(?<![\\w-])`` + escaped domain + ``(?![\\w-]|\\.[\\w-])``.  A preceding
    ``.`` is allowed so FQDN suffixes match: ``netlab.local`` matches in
    ``dc1-f5-1.netlab.local`` but never in ``plsnetlab.local``, and a longer
    domain (``netlab.local.example``) is not a match.  A final period
    ("see netlab.local.") is fine.
    """
    if not domain:
        raise ValueError("empty domain")
    before = r"(?<![\w-])" if re.match(r"\w", domain[0]) else ""
    after = r"(?![\w-]|\.[\w-])" if re.match(r"\w", domain[-1]) else ""
    return re.compile(before + re.escape(domain) + after, re.IGNORECASE)


# --------------------------------------------------------------------------- #
# VLAN lists
# --------------------------------------------------------------------------- #

VLAN_MAX = 4095
_RANGE_JOIN_RE = re.compile(r"(\d+)\s*(?:-|\bto\b)\s*(\d+)")
_LIST_TOKEN_RE = re.compile(r"^(\d+)(?:-(\d+))?$")
_LIST_SEP_RE = re.compile(r"[,\s]+")
_STYLE_SEP = {"ios": ",", "nxos": ",", "space": " ", "brace": " "}


class VlanListError(ValueError):
    """Unparseable VLAN list."""


@dataclass(frozen=True)
class VlanList:
    """An ordered VLAN list that remembers how it was written.

    ``items`` keeps the original order and range structure, ``sep`` the
    separator style (``","``, ``", "``, ``" "``).  ``replace`` changes members
    in place, splitting a range only where a member inside it is remapped
    (recorded in ``splits``), and refuses to create duplicates.
    """

    items: tuple[tuple[int, int], ...]
    sep: str = ","
    splits: tuple[str, ...] = field(default=(), compare=False)

    @classmethod
    def parse(cls, text: str) -> VlanList:
        """Parse ``"1,100-101,201"`` / ``"1 100-101"`` / ``"{ 10 20 }"``."""
        body = text.strip()
        if body[:1] in "{[(" and body[-1:] in "}])":
            body = body[1:-1].strip()
        if not body:
            raise VlanListError(f"empty VLAN list: {text!r}")
        norm = _RANGE_JOIN_RE.sub(r"\1-\2", body)
        parts = [p for p in _LIST_SEP_RE.split(norm) if p]
        items: list[tuple[int, int]] = []
        for part in parts:
            m = _LIST_TOKEN_RE.match(part)
            if m is None:
                raise VlanListError(f"bad VLAN list element {part!r} in {text!r}")
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) is not None else lo
            if lo > hi or hi > VLAN_MAX:
                raise VlanListError(f"bad VLAN range {part!r} in {text!r}")
            items.append((lo, hi))
        return cls(tuple(items), _detect_sep(body))

    @classmethod
    def from_vlans(cls, vlans: Iterable[int], sep: str = ",") -> VlanList:
        """Canonical list: sorted, unique, consecutive runs as ranges."""
        values = sorted(set(vlans))
        for v in values:
            if not 0 <= v <= VLAN_MAX:
                raise VlanListError(f"VLAN out of range: {v}")
        items: list[tuple[int, int]] = []
        for v in values:
            if items and items[-1][1] == v - 1:
                items[-1] = (items[-1][0], v)
            else:
                items.append((v, v))
        return cls(tuple(items), sep)

    def __iter__(self) -> Iterator[int]:
        for lo, hi in self.items:
            yield from range(lo, hi + 1)

    def __len__(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.items)

    def __contains__(self, vlan: object) -> bool:
        return isinstance(vlan, int) and any(lo <= vlan <= hi for lo, hi in self.items)

    def vlans(self) -> list[int]:
        """Sorted unique members."""
        return sorted(set(self))

    def replace(self, mapping: Mapping[int, int]) -> VlanList:
        """Remap members; all replacements apply simultaneously (swaps work).

        Raises ``ConflictError(code="VLAN_COLLISION")`` if the result would hold
        a VLAN twice that was not duplicated before.
        """
        for new in mapping.values():
            if not 0 <= new <= VLAN_MAX:
                raise VlanListError(f"VLAN out of range: {new}")
        active = {k: v for k, v in mapping.items() if k != v}
        new_items: list[tuple[int, int]] = []
        splits: list[str] = list(self.splits)
        for lo, hi in self.items:
            if not any(lo <= k <= hi for k in active):
                new_items.append((lo, hi))
                continue
            parts: list[tuple[int, int]] = []
            run: tuple[int, int] | None = None
            for v in range(lo, hi + 1):
                nv = active.get(v)
                if nv is None:
                    run = (v, v) if run is None else (run[0], v)
                    continue
                if run is not None:
                    parts.append(run)
                    run = None
                parts.append((nv, nv))
            if run is not None:
                parts.append(run)
            if hi > lo and len(parts) > 1:
                splits.append(f"{lo}-{hi}")
            new_items.extend(parts)
        result = VlanList(tuple(new_items), self.sep, tuple(splits))
        before = _duplicates(self)
        clash = sorted(_duplicates(result) - before)
        if clash:
            raise ConflictError(
                "VLAN list collision on " + ", ".join(map(str, clash)),
                code="VLAN_COLLISION",
                refs=[str(v) for v in clash],
            )
        return result

    def render(self, style: str | None = None) -> str:
        """Text form.  ``style`` None keeps the parsed separator.

        ``ios``/``nxos`` join with ``,``; ``space``/``brace`` join with a
        space (any enclosing braces belong to the surrounding config text).
        """
        if style is None:
            sep = self.sep
        elif style in _STYLE_SEP:
            sep = _STYLE_SEP[style]
        else:
            raise ValueError(f"unknown list style {style!r}")
        return sep.join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in self.items)

    def __str__(self) -> str:
        return self.render()


def _detect_sep(body: str) -> str:
    comma = re.search(r",[ \t]*", body)
    if comma:
        return comma.group(0)
    if re.search(r"\s", body):
        return " "
    return ","


def _duplicates(vl: VlanList) -> set[int]:
    seen: set[int] = set()
    dup: set[int] = set()
    for v in vl:
        if v in seen:
            dup.add(v)
        seen.add(v)
    return dup


# --------------------------------------------------------------------------- #
# HTML text nodes
# --------------------------------------------------------------------------- #

_TAG_RE = re.compile(r"<[^>\"']*(?:(?:\"[^\"]*\"|'[^']*')[^>\"']*)*>")
_TAG_NAME_RE = re.compile(r"<(/?)([A-Za-z][\w:-]*)")
_SVG_TAG_RE = re.compile(r"<(/?)svg\b[^>]*>", re.IGNORECASE)
_RAW_ELEMENTS = frozenset({"style", "script"})


def html_text_regions(html: str) -> list[Span]:
    """Spans of the text nodes of an HTML fragment.

    Only text between ``>`` and ``<`` is returned.  Tag interiors (attributes,
    inline ``style``), comments, ``<style>`` / ``<script>`` contents and whole
    ``<svg>`` subtrees are never included; whitespace-only nodes are dropped.
    """
    out: list[Span] = []
    n = len(html)
    text_start = 0
    i = 0

    def emit(a: int, b: int) -> None:
        if b > a and html[a:b].strip():
            out.append(Span(a, b))

    while i < n:
        lt = html.find("<", i)
        if lt == -1:
            emit(text_start, n)
            return out
        nxt = html[lt + 1 : lt + 2]
        if not (nxt.isalpha() or (nxt and nxt in "/!?")):
            i = lt + 1  # a literal "<" in text
            continue
        emit(text_start, lt)
        if html.startswith("<!--", lt):
            close = html.find("-->", lt + 4)
            j = n if close == -1 else close + 3
        elif html.startswith("<![CDATA[", lt):
            close = html.find("]]>", lt + 9)
            j = n if close == -1 else close + 3
        else:
            tm = _TAG_RE.match(html, lt)
            if tm is None:
                return out  # unterminated tag: nothing reliable after it
            j = tm.end()
            nm = _TAG_NAME_RE.match(html, lt)
            if nm and not nm.group(1) and not html[lt:j].endswith("/>"):
                name = nm.group(2).lower()
                if name in _RAW_ELEMENTS:
                    cm = re.compile(rf"</{name}\s*>", re.IGNORECASE).search(html, j)
                    j = n if cm is None else cm.end()
                elif name == "svg":
                    j = _skip_svg(html, j)
        text_start = i = j
    return out


def _skip_svg(html: str, pos: int) -> int:
    depth = 1
    for m in _SVG_TAG_RE.finditer(html, pos):
        if m.group(1):
            depth -= 1
            if depth == 0:
                return m.end()
        elif not m.group(0).endswith("/>"):
            depth += 1
    return len(html)


# --------------------------------------------------------------------------- #
# Lines
# --------------------------------------------------------------------------- #


class LineIndex:
    """Offset -> 1-based line number for one text."""

    def __init__(self, text: str) -> None:
        starts = [0]
        pos = text.find("\n")
        while pos != -1:
            starts.append(pos + 1)
            pos = text.find("\n", pos + 1)
        self._starts = starts
        self._len = len(text)

    def __len__(self) -> int:
        return len(self._starts)

    def line(self, offset: int) -> int:
        """1-based line number containing ``offset``."""
        if offset < 0 or offset > self._len:
            raise IndexError(offset)
        return bisect_right(self._starts, offset)

    def start(self, line: int) -> int:
        """Offset of the first character of 1-based ``line``."""
        return self._starts[line - 1]
