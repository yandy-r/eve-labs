"""Config stores: embedded startup/configset blobs, textobjects and sidecars (5.3).

``load_texts`` turns everything a lab carries as text into ``ConfigText`` objects:

* ``<configs>`` blobs -> ``Store("startup", "startup", "startup")``;
* ``<configset name=X>`` blobs -> ``Store("configset", X, X)``;
* ``<textobject id=N>`` data -> ``Store("textobject", N, "-")`` (``node_id=""``);
* sidecar files ``<dir>/NN_<node name>.txt`` -> ``Store("sidecar", <relpath>, scope)``
  where ``relpath`` is relative to the lab's directory (POSIX form) and ``scope`` is
  the scope of the blob it mirrors, else the node's active scope.

Sidecar directories are resolved in order: manifest ``sidecar_dirs``;
``<stem>_cfgs``; ``<stem>*_cfgs`` (directories that are the exact ``_cfgs`` of
another lab next to this one are excluded).  More than one ``<stem>*_cfgs`` match
without a manifest entry is ``blocker SIDECAR_AMBIGUOUS`` and no sidecar is loaded.
A file is accepted only when ``NN`` is a node id **and** the name equals that
node's name (``warn SIDECAR_MISMATCH`` otherwise); the manifest ``[sidecar_map]``
(``"file" = "node id"``, key = file name or lab-relative path) forces a mapping.

Sidecars are read as bytes and decoded as UTF-8 with ``surrogateescape``; the
text is **not** newline-normalised, so spans are exact and ``write_sidecar``
reproduces the original newline style and trailing-newline state.

Mirror detection: a sidecar that is byte-identical to one of its node's decoded
blobs gets ``mirror_of = (store scope, node_id)`` (scope = ``"startup"`` or the
configset name).  When several scopes match, the node's active scope wins, then
the manifest ``canonical_scope``, then ``startup``, then document order.

Opaque texts (``ConfigText.opaque``) produce no facts: undecodable/binary blobs
(``text=""``, ``blob=None``) and decodable garbage such as the VPCS config ``ZmY=``
(``"ff"``; ``blob`` kept, ``text`` kept).  Empty blobs are opaque too.  Each gets an
``info`` finding.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal

from evelab.common.codec import DecodedBlob, decode_blob

from .errors import LocalizeError
from .model import ConfigText, Finding, Node, Store

if TYPE_CHECKING:
    from evelab.common.unl import RawBlob, RawLab

    from .manifest import Manifest

__all__ = [
    "SIDECAR_RE",
    "SidecarDirs",
    "active_scope",
    "blob_store",
    "find_sidecar_dirs",
    "is_garbage_text",
    "load_texts",
    "mirror_source",
    "mirrors_agree",
    "newline_style",
    "write_sidecar",
]

SIDECAR_RE = re.compile(r"^(\d+)_(.+)\.txt$")
SIDECAR_SUFFIX = "_cfgs"
TEXTOBJECT_DIALECT = "eve_html"
FALLBACK_DIALECT = "generic"
SIDECAR_ENCODING = "utf-8"
SIDECAR_ERRORS = "surrogateescape"

NewlineStyle = Literal["lf", "crlf", "mixed", "none"]

# A decodable blob whose stripped text is one short token with no dots (the VPCS
# config "ff") carries no configuration: it is treated as opaque.
_GARBAGE_MAX = 16


# ------------------------------------------------------------------ helpers


def active_scope(node: Node | None, configsets: Mapping[str, str]) -> str:
    """Scope a node boots from: its configset name, else ``"startup"``."""
    if node is not None and node.config_attr in configsets:
        return configsets[node.config_attr]
    return "startup"


def blob_store(blob: RawBlob) -> Store:
    """``Store`` of an embedded config or textobject blob."""
    if blob.kind == "textobject":
        return Store("textobject", blob.id, "-")
    if blob.scope == "startup":
        return Store("startup", "startup", "startup")
    name = blob.scope[3:] if blob.scope.startswith("cs:") else blob.scope
    return Store("configset", name, name)


def is_garbage_text(text: str) -> bool:
    """True for decodable text that cannot hold configuration (e.g. ``"ff"``)."""
    s = text.strip()
    if not s:
        return True
    return (
        len(s) <= _GARBAGE_MAX
        and not any(c.isspace() for c in s)
        and "." not in s
        and ":" not in s
    )


def newline_style(text: str) -> NewlineStyle:
    """Line-ending style of ``text``."""
    lf = text.count("\n")
    crlf = text.count("\r\n")
    if lf == 0:
        return "none"
    if crlf == 0:
        return "lf"
    if crlf == lf:
        return "crlf"
    return "mixed"


def _ends_with_newline(text: str) -> bool:
    return text.endswith("\n")


def write_sidecar(ct: ConfigText, new_text: str) -> bytes:
    """Bytes of a sidecar after editing, in ``ct``'s newline style and trailing-nl.

    ``ct.text`` is the original (un-normalised) text.  CRLF files get bare LFs
    in ``new_text`` converted to CRLF; LF files get CRLFs converted to LF; mixed
    or single-line files keep ``new_text`` as is.  The trailing-newline state of
    the original is restored (one newline added or removed).
    """
    if ct.store.kind != "sidecar":
        raise LocalizeError(
            f"write_sidecar called for a {ct.store.kind} store", code="NOT_SIDECAR"
        )
    style = newline_style(ct.text)
    out = new_text
    if style == "crlf":
        out = re.sub(r"(?<!\r)\n", "\r\n", out)
    elif style == "lf":
        out = out.replace("\r\n", "\n")
    eol = "\r\n" if style == "crlf" else "\n"
    if _ends_with_newline(ct.text):
        if not _ends_with_newline(out):
            out += eol
    elif out.endswith("\r\n"):
        out = out[:-2]
    elif out.endswith("\n"):
        out = out[:-1]
    return out.encode(SIDECAR_ENCODING, SIDECAR_ERRORS)


def _text_bytes(blob: DecodedBlob) -> bytes:
    return blob.text.encode(blob.encoding)


def mirror_source(texts: Iterable[ConfigText], ct: ConfigText) -> ConfigText | None:
    """The embedded ``ConfigText`` a sidecar ``ct`` mirrors (``None`` if none)."""
    if ct.mirror_of is None:
        return None
    scope, node_id = ct.mirror_of
    for other in texts:
        if (
            other.store.kind in ("startup", "configset")
            and other.store.scope == scope
            and other.node_id == node_id
        ):
            return other
    return None


def mirrors_agree(sidecar_text: str, blob_text: str) -> bool:
    """Post-edit equality check of a mirror pair (lab aborts when False)."""
    return sidecar_text == blob_text


# ------------------------------------------------------------- dialect pick


def _dialect_name(
    node: Node | None,
    text: str,
    override: str | None,
    findings: list[Finding],
    ref: str,
) -> str:
    from . import dialects

    try:
        return dialects.pick(node, text, override).name
    except LocalizeError as exc:
        if override:
            findings.append(
                Finding(
                    "UNKNOWN_DIALECT",
                    "error",
                    f"{ref}: dialect override {override!r} is not registered "
                    f"({exc}); using content detection",
                    [ref],
                )
            )
            try:
                return dialects.pick(node, text).name
            except LocalizeError:
                pass
        return FALLBACK_DIALECT


def _textobject_dialect() -> str:
    from . import dialects

    try:
        return dialects.get(TEXTOBJECT_DIALECT).name
    except LocalizeError:
        return FALLBACK_DIALECT


def _override(manifest: Manifest | None, node_id: str) -> str | None:
    if manifest is None:
        return None
    ov = manifest.nodes.get(node_id)
    return ov.dialect if ov is not None and ov.dialect else None


# ------------------------------------------------------------ embedded blobs


def _embedded(
    lab: RawLab,
    nodes: Mapping[str, Node],
    manifest: Manifest | None,
    findings: list[Finding],
) -> list[ConfigText]:
    out: list[ConfigText] = []
    for blob in lab.config_blobs():
        store = blob_store(blob)
        node_id = blob.node_id or blob.id
        node = nodes.get(node_id)
        ref = f"{store.scope}:{node_id}"
        if node is None:
            findings.append(
                Finding(
                    "ORPHAN_CONFIG",
                    "info",
                    f"config {node_id} in {store.scope} has no matching node",
                    [ref],
                )
            )
        decoded = None if blob.self_closing else decode_blob(blob.b64)
        if decoded is None:
            why = "self-closing" if blob.self_closing else "undecodable or binary"
            if blob.self_closing or not blob.b64.strip():
                why = "empty"
            findings.append(
                Finding(
                    "OPAQUE_BLOB",
                    "info",
                    f"{ref}: config is {why}; no facts are read from it",
                    [ref],
                )
            )
            out.append(
                ConfigText(
                    store, node_id, "", FALLBACK_DIALECT, None, None, opaque=True
                )
            )
            continue
        if is_garbage_text(decoded.text):
            what = "empty" if not decoded.text.strip() else f"{decoded.text.strip()!r}"
            findings.append(
                Finding(
                    "OPAQUE_BLOB",
                    "info",
                    f"{ref}: config is {what}; no facts are read from it",
                    [ref],
                )
            )
            out.append(
                ConfigText(
                    store,
                    node_id,
                    decoded.text,
                    FALLBACK_DIALECT,
                    decoded,
                    None,
                    opaque=True,
                )
            )
            continue
        dialect = _dialect_name(
            node, decoded.text, _override(manifest, node_id), findings, ref
        )
        out.append(ConfigText(store, node_id, decoded.text, dialect, decoded, None))
    for node in nodes.values():
        if node.config_attr == "1" and not any(
            ct.node_id == node.id and ct.store.kind == "startup" for ct in out
        ):
            findings.append(
                Finding(
                    "MISSING_BLOB",
                    "info",
                    f'node {node.id} ({node.name}) has config="1" but no startup '
                    "config",
                    [f"node:{node.id}"],
                )
            )
    return out


def _textobjects(lab: RawLab, findings: list[Finding]) -> list[ConfigText]:
    out: list[ConfigText] = []
    for blob in lab.textobjects():
        store = blob_store(blob)
        ref = f"textobject:{blob.id}"
        decoded = None if blob.self_closing else decode_blob(blob.b64)
        if decoded is None or not decoded.text.strip():
            if blob.b64.strip():
                findings.append(
                    Finding(
                        "OPAQUE_BLOB",
                        "info",
                        f"{ref}: data is undecodable or binary; skipped",
                        [ref],
                    )
                )
            text = decoded.text if decoded is not None else ""
            out.append(
                ConfigText(
                    store, "", text, FALLBACK_DIALECT, decoded, None, opaque=True
                )
            )
            continue
        out.append(
            ConfigText(store, "", decoded.text, _textobject_dialect(), decoded, None)
        )
    return out


# ------------------------------------------------------------------ sidecars


@dataclass
class SidecarDirs:
    """Resolved sidecar directories (``source``: manifest | exact | glob | none)."""

    dirs: list[Path]
    source: Literal["manifest", "exact", "glob", "none", "ambiguous"]
    findings: list[Finding]


def find_sidecar_dirs(lab_path: Path, manifest: Manifest | None) -> SidecarDirs:
    """Resolve the sidecar directories of ``lab_path`` (design 5.3)."""
    lab_path = Path(lab_path)
    parent = lab_path.parent
    stem = lab_path.stem
    findings: list[Finding] = []
    if manifest is not None and manifest.sidecar_dirs:
        dirs: list[Path] = []
        for entry in manifest.sidecar_dirs:
            d = parent / PurePosixPath(entry)
            if d.is_dir():
                dirs.append(d)
            else:
                findings.append(
                    Finding(
                        "SIDECAR_DIR_MISSING",
                        "warn",
                        f"manifest sidecar_dirs entry {entry!r} is not a directory",
                        [entry],
                    )
                )
        return SidecarDirs(dirs, "manifest", findings)
    exact = parent / f"{stem}{SIDECAR_SUFFIX}"
    if exact.is_dir():
        return SidecarDirs([exact], "exact", findings)
    candidates = []
    if parent.is_dir():
        for d in sorted(parent.iterdir()):
            name = d.name
            if not (
                d.is_dir() and name.startswith(stem) and name.endswith(SIDECAR_SUFFIX)
            ):
                continue
            owner = name[: -len(SIDECAR_SUFFIX)]
            if owner != stem and (parent / f"{owner}.unl").is_file():
                continue  # the exact sidecar dir of another lab
            candidates.append(d)
    if not candidates:
        return SidecarDirs([], "none", findings)
    if len(candidates) == 1:
        return SidecarDirs(candidates, "glob", findings)
    names = [d.name for d in candidates]
    findings.append(
        Finding(
            "SIDECAR_AMBIGUOUS",
            "blocker",
            f"{len(names)} sidecar directories match {stem}*{SIDECAR_SUFFIX} "
            f"({', '.join(names)}); set sidecar_dirs in the manifest",
            names,
        )
    )
    return SidecarDirs([], "ambiguous", findings)


def _relpath(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def _map_lookup(sidecar_map: Mapping[str, str], rel: str, name: str) -> str | None:
    if rel in sidecar_map:
        return sidecar_map[rel]
    return sidecar_map.get(name)


def _candidate_files(
    dirs: list[Path], parent: Path, sidecar_map: Mapping[str, str]
) -> list[Path]:
    files: dict[Path, None] = {}
    for d in dirs:
        for f in sorted(d.iterdir()):
            if f.is_file():
                files[f] = None
    for key in sidecar_map:
        if "/" in key:
            f = parent / PurePosixPath(key)
            if f.is_file():
                files.setdefault(f, None)
    return list(files)


def _pick_mirror(
    raw: bytes,
    node: Node | None,
    embedded: list[ConfigText],
    configsets: Mapping[str, str],
    canonical: str | None,
) -> tuple[str | None, bool]:
    """(mirrored scope, node has decodable blobs)."""
    same = [ct for ct in embedded if ct.blob is not None and not ct.opaque]
    if not same:
        return None, False
    hits = [ct.store.scope for ct in same if _text_bytes(ct.blob) == raw]
    if not hits:
        return None, True
    order = [active_scope(node, configsets), canonical, "startup"]
    for pref in order:
        if pref in hits:
            return pref, True
    return hits[0], True


def _sidecars(
    lab: RawLab,
    nodes: Mapping[str, Node],
    manifest: Manifest | None,
    embedded: list[ConfigText],
    findings: list[Finding],
) -> list[ConfigText]:
    lab_path = Path(lab.path)
    parent = lab_path.parent
    resolved = find_sidecar_dirs(lab_path, manifest)
    findings.extend(resolved.findings)
    sidecar_map = dict(manifest.sidecar_map) if manifest is not None else {}
    configsets = lab.configsets()
    canonical = manifest.canonical_scope if manifest is not None else None
    by_node: dict[str, list[ConfigText]] = {}
    for ct in embedded:
        by_node.setdefault(ct.node_id, []).append(ct)

    out: list[ConfigText] = []
    seen_nodes: dict[str, str] = {}
    for f in _candidate_files(resolved.dirs, parent, sidecar_map):
        rel = _relpath(f, parent)
        forced = _map_lookup(sidecar_map, rel, f.name)
        m = SIDECAR_RE.match(f.name)
        if forced is not None:
            node_id = forced
            node = nodes.get(node_id)
            if node is None:
                findings.append(
                    Finding(
                        "SIDECAR_MISMATCH",
                        "warn",
                        f"{rel}: sidecar_map names node {node_id}, which does not "
                        "exist; skipped",
                        [rel],
                    )
                )
                continue
        elif m is None:
            continue  # not NN_name.txt: ignored silently
        else:
            node_id, name = m.group(1), m.group(2)
            node = nodes.get(node_id)
            if node is None or node.name != name:
                actual = "no such node" if node is None else f"node is {node.name!r}"
                findings.append(
                    Finding(
                        "SIDECAR_MISMATCH",
                        "warn",
                        f"{rel}: id {node_id} / name {name!r} does not match the lab "
                        f"({actual}); skipped",
                        [rel],
                    )
                )
                continue
        raw = f.read_bytes()
        text = raw.decode(SIDECAR_ENCODING, SIDECAR_ERRORS)
        if node_id in seen_nodes:
            findings.append(
                Finding(
                    "SIDECAR_DUPLICATE",
                    "warn",
                    f"node {node_id} has more than one sidecar "
                    f"({seen_nodes[node_id]}, {rel}); both are kept",
                    [seen_nodes[node_id], rel],
                )
            )
        else:
            seen_nodes[node_id] = rel
        mirror, has_blobs = _pick_mirror(
            raw, node, by_node.get(node_id, []), configsets, canonical
        )
        scope = mirror if mirror is not None else active_scope(node, configsets)
        store = Store("sidecar", rel, scope)
        if b"\x00" in raw or is_garbage_text(text):
            findings.append(
                Finding(
                    "OPAQUE_BLOB",
                    "info",
                    f"{rel}: sidecar is empty or binary; no facts are read from it",
                    [rel],
                )
            )
            out.append(
                ConfigText(store, node_id, text, FALLBACK_DIALECT, None, f, opaque=True)
            )
            continue
        if mirror is None and has_blobs:
            findings.append(
                Finding(
                    "SIDECAR_INDEPENDENT",
                    "info",
                    f"{rel}: differs from every embedded config of node {node_id}; "
                    "edited as an independent store",
                    [rel],
                )
            )
        dialect = _dialect_name(node, text, _override(manifest, node_id), findings, rel)
        mirror_of = (mirror, node_id) if mirror is not None else None
        out.append(ConfigText(store, node_id, text, dialect, None, f, mirror_of))
    return out


# --------------------------------------------------------------------- entry


def load_texts(
    lab: RawLab,
    nodes: Mapping[str, Node] | None = None,
    manifest: Manifest | None = None,
    *,
    textobjects: bool = True,
) -> tuple[list[ConfigText], list[Finding]]:
    """All config texts of ``lab`` (embedded, textobjects, sidecars) + findings.

    Order: embedded blobs in document order, textobjects, sidecars sorted by path.
    ``nodes`` defaults to ``lab.node_models()``.
    """
    if nodes is None:
        nodes = lab.node_models()
    findings: list[Finding] = []
    embedded = _embedded(lab, nodes, manifest, findings)
    texts = list(embedded)
    if textobjects:
        texts.extend(_textobjects(lab, findings))
    texts.extend(_sidecars(lab, nodes, manifest, embedded, findings))
    return texts, findings
