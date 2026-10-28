"""Base64 config-blob codec (design section 5.2).

A blob is the single-line base64 text EVE stores inside ``<config>`` and
``<textobject><data>``.  This module turns it into text and back so that an edit
is a plain span splice inside the decoded text.  Nothing here touches the lab
file; ``unl.py`` owns the byte offsets.

Rules:

* decode as UTF-8, fall back to latin-1 for the whole blob so the bytes always
  round-trip exactly;
* ``canonical`` means ``b64encode(decoded) == raw_b64`` (single line, no
  whitespace, standard padding).  A non-canonical blob is readable but any edit
  to it is refused (``NONCANONICAL_BLOB``);
* an undecodable or binary blob decodes to ``None`` ("opaque");
* a blob whose text did not change is never re-encoded.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .errors import ConflictError, EveLabError
from .spans import TextEdit

Encoding = Literal["utf-8", "latin-1"]

# Control characters that legitimately occur in device configs (BEL, BS, HT, LF,
# VT, FF, CR, ESC).  Any other C0 control byte counts towards the binary heuristic.
_TEXT_CONTROLS = frozenset(b"\a\b\t\n\v\f\r\x1b")
_BINARY_CONTROL_RATIO = 0.05


@dataclass
class DecodedBlob:
    """A decoded blob plus what is needed to write it back unchanged."""

    raw_b64: bytes
    text: str
    encoding: Encoding
    canonical: bool


def _looks_binary(data: bytes) -> bool:
    """True when ``data`` is not plausibly text (NUL bytes or many controls)."""
    if not data:
        return False
    if b"\x00" in data:
        return True
    bad = sum(1 for b in data if b < 0x20 and b not in _TEXT_CONTROLS)
    return bad / len(data) > _BINARY_CONTROL_RATIO


def decode_blob(b64: bytes) -> DecodedBlob | None:
    """Decode ``b64``; ``None`` means opaque (invalid base64 or binary payload).

    ASCII whitespace inside the blob is tolerated on read but makes the result
    non-canonical.  Missing padding or characters outside the base64 alphabet
    make the blob opaque (for example the VPCS config that is literally ``ff``).
    """
    compact = b"".join(b64.split())
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    if _looks_binary(data):
        return None
    encoding: Encoding = "utf-8"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
        encoding = "latin-1"
    canonical = base64.b64encode(data) == b64
    return DecodedBlob(raw_b64=b64, text=text, encoding=encoding, canonical=canonical)


def encode_text(text: str, encoding: Encoding) -> bytes:
    """Canonical single-line base64 of ``text``; no shortcuts (used by tests)."""
    try:
        data = text.encode(encoding)
    except UnicodeEncodeError as exc:
        raise EveLabError(
            f"text is not representable as {encoding}: {exc}", code="BLOB_ENCODING"
        ) from exc
    return base64.b64encode(data)


def encode_blob(text: str, like: DecodedBlob) -> bytes:
    """Encode ``text`` the way ``like`` was stored (single line, same encoding).

    Unchanged text returns ``like.raw_b64`` untouched, so a blob with no edits is
    never re-encoded.  Changed text on a non-canonical blob is refused.
    """
    if text == like.text:
        return like.raw_b64
    if not like.canonical:
        raise EveLabError(
            "refusing to rewrite a non-canonical base64 blob", code="NONCANONICAL_BLOB"
        )
    return encode_text(text, like.encoding)


def apply_text_edits(text: str, edits: Sequence[TextEdit]) -> str:
    """Apply ``TextEdit`` spans (character offsets) to ``text``.

    Edits are sorted by start; overlapping edits and edits whose ``old`` does not
    match the text at the span raise ``ConflictError``.
    """
    pieces: list[str] = []
    pos = 0
    prev: TextEdit | None = None
    for edit in sorted(edits, key=lambda e: (e.start, e.end)):
        if not 0 <= edit.start <= edit.end <= len(text):
            raise ConflictError(
                f"text edit span {edit.start}:{edit.end} is out of range",
                code="BAD_SPAN",
            )
        if prev is not None and (
            edit.start < prev.end or (edit.start == prev.start == prev.end == edit.end)
        ):
            raise ConflictError(
                f"text edits overlap at {prev.start}:{prev.end} and "
                f"{edit.start}:{edit.end}"
            )
        found = text[edit.start : edit.end]
        if found != edit.old:
            raise ConflictError(
                f"text at {edit.start}:{edit.end} is {found!r}, expected {edit.old!r}",
                code="STALE_EDIT",
            )
        pieces.append(text[pos : edit.start])
        pieces.append(edit.new)
        pos = edit.end
        prev = edit
    pieces.append(text[pos:])
    return "".join(pieces)


def edit_blob(like: DecodedBlob, edits: Sequence[TextEdit]) -> bytes:
    """Apply ``edits`` to ``like.text`` and return the new base64 bytes.

    With no edits the original ``raw_b64`` is returned byte for byte.
    """
    if not edits:
        return like.raw_b64
    return encode_blob(apply_text_edits(like.text, edits), like)
