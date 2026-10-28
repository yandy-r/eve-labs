"""Apply engine (design section 12): preflight, transaction, validation, undo.

Nothing in this module decides *what* to change; it turns a :class:`Plan` into
bytes, proves that only the planned bytes changed, and writes them safely:

* :func:`preflight` - plan freshness (sha256), running nodes,
  the ``.localize/lock``, git cleanliness, ownership/writability.
* :func:`apply_plans` / :func:`apply_plan` - one transaction per lab: backup,
  build new bytes, stage a full copy (lab + sidecar dirs) in a temp dir,
  validate it (:func:`validate_written`, mirrors, ``check-labs``, the injected
  re-scan hook), write temps next to the originals preserving mode/owner,
  ``os.replace`` them, verify, and roll back on any failure.  Successful labs
  are journaled in ``.localize/journal.json`` and recorded in
  ``.localize/state.json``.
* :func:`undo` - restore a journaled run's backups, refusing when a file no
  longer has the sha the run wrote (EVE re-saved it).
* ``ApplyOptions.out_dir`` - copy mode: write localized copies with a new lab
  uuid and never touch the originals.

How :class:`~evelab.localize.model.Edit` offsets are interpreted (contract for the
planner, see the design doc "Resolutions applied when apply.py was written"):

* ``xml_attr``: ``text_edit.start/end`` are **byte offsets** of an attribute
  *value* span in the ``.unl`` (``RawAttr.span``); ``old``/``new`` are decoded
  values (``RawLab.attr_edit`` escapes ``new``).
* ``blob`` (``store.kind`` ``startup``/``configset``) and ``textobject``:
  offsets index the decoded blob text (``DecodedBlob.text``); the blob is
  located by ``store`` (scope / configset name / textobject id) + ``node_id``.
* ``sidecar``: offsets index the decoded sidecar text, see
  :func:`sidecar_decode` (UTF-8 + surrogateescape; a file whose every LF is a
  CRLF is presented with LF and written back with CRLF).
* Only edits whose ``group`` is in ``plan.enabled_groups`` are applied.
* ``Edit.file`` and ``plan.base_sha256`` keys may be absolute or relative to
  the lab's directory (then to ``ApplyOptions.repo_root``).
"""

from __future__ import annotations

import base64
import contextlib
import getpass
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from evelab.common import hostenv
from evelab.common.checklabs import CHECK_LABS, run_check_labs
from evelab.common.codec import apply_text_edits, decode_blob, edit_blob
from evelab.common.unl import (
    RawBlob,
    RawEdit,
    RawElem,
    RawLab,
    label_warnings,
    splice,
    verify_outside_spans,
)

from .errors import (
    BlockedError,
    ConflictError,
    LabParseError,
    LocalizeError,
    PreconditionError,
    UnsupportedLayout,
    ValidationError,
)
from .model import Edit, Finding, Plan, TextEdit

__all__ = [
    "ApplyOptions",
    "Changes",
    "FileChange",
    "LabResult",
    "RunRecord",
    "apply_plan",
    "apply_plans",
    "build_changes",
    "list_runs",
    "load_journal",
    "load_state",
    "plan_digest",
    "preflight",
    "run_check_labs",
    "sidecar_decode",
    "sidecar_encode",
    "undo",
    "validate_written",
]

JOURNAL_SCHEMA = 1
BLOCKING = ("conflict", "blocker", "error")
_SIDECAR_RE = re.compile(r"^(\d+)_(.+)\.txt$")
_LAB_TAG = re.compile(rb"<lab(?=[\s/>])[^>]*>")
_ID_ATTR = re.compile(rb"(?<=\s)id\s*=\s*(?:\"([^\"<]*)\"|'([^'<]*)')")

RescanHook = Callable[[Path, Plan], "Sequence[Edit] | int"]
LabStatus = Literal["localized", "unchanged", "skipped", "failed", "untouched"]


# --------------------------------------------------------------------------
# Options and results
# --------------------------------------------------------------------------


@dataclass
class ApplyOptions:
    """Everything the engine needs besides the plan (CLI flags map 1:1).

    Host probe roots (``proc``, ``tmp_root``, ``docker_names``) exist so tests
    can inject fakes; ``rescan`` is the re-scan idempotency hook (design 12.3
    step 7): called with the staged lab path and the plan, it must return the
    residual edits (or their count) of analyse + build_plan with the same
    answers; anything but zero rolls the lab back.  It may also raise
    :class:`ValidationError` (e.g. schemes differ from the targets).
    """

    state_dir: Path | None = None  # default <repo root or cwd>/.localize
    backup_dir: Path | None = None  # default <state_dir>/backups
    repo_root: Path | None = None  # default: git rev-parse from the lab dir
    no_backup: bool = False
    require_clean: bool = False
    force_running: bool = False
    out_dir: Path | None = None
    new_lab_id: str | None = None  # copy mode; default reuse dest id or uuid4
    continue_on_error: bool = False
    rescan: RescanHook | None = None
    check_labs: bool = True
    check_labs_script: Path = CHECK_LABS
    check_labs_peers: Sequence[Path] | None = None  # None = git-tracked labs
    mark_localized: bool = True  # False for `revert`: clears the state entry
    state_extra: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    proc: Path = hostenv.PROC
    tmp_root: Path = hostenv.UNETLAB_TMP
    docker_names: Callable[[], Iterable[str]] = hostenv.docker_container_names
    use_fcntl: bool | None = None
    run_id: str | None = None
    clock: Callable[[], datetime] | None = None
    user: str | None = None
    host: str | None = None


@dataclass
class FileChange:
    """New bytes for one file (``dest`` differs from ``path`` in copy mode)."""

    path: Path  # source file the plan was computed against
    dest: Path  # file that will be written
    kind: Literal["unl", "sidecar"]
    before: bytes
    after: bytes
    raw_edits: list[RawEdit] = field(default_factory=list)  # unl only
    created: bool = False  # dest did not exist (copy mode)
    dest_before: bytes | None = None  # existing dest bytes (copy mode)

    @property
    def changed(self) -> bool:
        current = self.before if self.dest_before is None else self.dest_before
        return self.created or self.after != current


@dataclass
class Changes:
    lab: RawLab
    files: list[FileChange]
    edited_blobs: list[tuple[str, str]]  # (scope, id); textobjects use scope "-"
    findings: list[Finding] = field(default_factory=list)
    lab_id: str = ""  # lab id after the change (new uuid in copy mode)

    @property
    def unl(self) -> FileChange:
        return next(f for f in self.files if f.kind == "unl")


@dataclass
class LabResult:
    lab: Path
    lab_id: str
    status: LabStatus
    findings: list[Finding] = field(default_factory=list)
    files: dict[str, dict[str, Any]] = field(default_factory=dict)
    error: str | None = None
    exit_code: int = 0


@dataclass
class RunRecord:
    run_id: str
    ts: str
    labs: list[LabResult]
    journaled: bool = False
    mode: Literal["in-place", "out"] = "in-place"

    def by_status(self, status: LabStatus) -> list[LabResult]:
        return [r for r in self.labs if r.status == status]

    @property
    def ok(self) -> bool:
        return all(r.status in ("localized", "unchanged") for r in self.labs)

    @property
    def exit_code(self) -> int:
        codes = [r.exit_code for r in self.labs if r.exit_code]
        for code in (5, 4, 2, 1):
            if code in codes:
                return code
        return 0

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.labs for f in r.findings]


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str | None:
    try:
        return _sha(path.read_bytes())
    except OSError:
        return None


def _now(opts: ApplyOptions) -> datetime:
    return opts.clock() if opts.clock else datetime.now(UTC)


def _err(code: str, msg: str, refs: Iterable[str] = ()) -> Finding:
    return Finding(code, "error", msg, list(refs))


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str] | None:
    exe = shutil.which("git")
    if exe is None:
        return None
    try:
        return subprocess.run(
            [exe, "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _git_root(start: Path) -> Path | None:
    res = _git(
        start if start.is_dir() else start.parent, "rev-parse", "--show-toplevel"
    )
    if res is None or res.returncode != 0 or not res.stdout.strip():
        return None
    return Path(res.stdout.strip()).resolve()


def _repo_root(opts: ApplyOptions, near: Path | None = None) -> Path | None:
    if opts.repo_root is not None:
        return Path(opts.repo_root).resolve()
    return _git_root(near or Path.cwd())


def _state_dir(opts: ApplyOptions, near: Path | None = None) -> Path:
    # Absolute: journal paths must not depend on the cwd of a later `undo`.
    if opts.state_dir is not None:
        return Path(opts.state_dir).resolve()
    return ((_repo_root(opts, near) or Path.cwd()) / ".localize").resolve()


def _backup_root(opts: ApplyOptions, near: Path | None = None) -> Path:
    if opts.backup_dir is not None:
        return Path(opts.backup_dir).resolve()
    return _state_dir(opts, near) / "backups"


def _git_file_status(root: Path, path: Path) -> Literal["clean", "dirty", "untracked"]:
    """Git view of one file; ``untracked`` also covers "not in this repo"."""
    try:
        rel = path.resolve().relative_to(root)
    except ValueError:
        return "untracked"
    tracked = _git(root, "ls-files", "--error-unmatch", "--", str(rel))
    if tracked is None or tracked.returncode != 0:
        return "untracked"
    st = _git(root, "status", "--porcelain", "--", str(rel))
    if st is None or st.returncode != 0:
        return "untracked"
    return "dirty" if st.stdout.strip() else "clean"


def resolve_path(plan: Plan, name: str | Path, repo_root: Path | None = None) -> Path:
    """Resolve an ``Edit.file`` / ``base_sha256`` key (see module docstring)."""
    p = Path(name)
    if p.is_absolute():
        return p
    lab_dir = Path(plan.lab).parent
    if p == Path(Path(plan.lab).name):
        return Path(plan.lab)
    cand = lab_dir / p
    if cand.exists() or repo_root is None:
        return cand
    alt = repo_root / p
    return alt if alt.exists() else cand


def _same(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return a == b


def _key(path: Path) -> str:
    return str(Path(path).resolve())


def plan_digest(plan: Plan) -> str:
    """sha256 over the enabled edits (secret values only enter as a hash)."""
    rows = sorted(
        (
            str(e.file),
            e.target,
            tuple(e.store),
            e.node_id or "",
            e.text_edit.start,
            e.text_edit.end,
            e.text_edit.old,
            e.text_edit.new,
        )
        for e in _enabled(plan)
    )
    blob = json.dumps([plan.lab_id, plan.answers_digest, rows], ensure_ascii=False)
    return _sha(blob.encode("utf-8", "surrogateescape"))


def _enabled(plan: Plan) -> list[Edit]:
    return [e for e in plan.edits if e.group in plan.enabled_groups]


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as exc:
        raise LocalizeError(f"{path}: unreadable: {exc}", code="STATE_CORRUPT") from exc


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def load_journal(opts: ApplyOptions) -> dict[str, Any]:
    """``{"schema": 1, "runs": [...]}`` from ``<state_dir>/journal.json``."""
    data = _read_json(_state_dir(opts) / "journal.json", None)
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        return {"schema": JOURNAL_SCHEMA, "runs": []}
    return data


def load_state(opts: ApplyOptions) -> dict[str, Any]:
    """``{lab_id: {localized, site_keys, values, after_sha, files, ...}}``."""
    data = _read_json(_state_dir(opts) / "state.json", {})
    return data if isinstance(data, dict) else {}


def list_runs(opts: ApplyOptions) -> list[dict[str, Any]]:
    """Journal entries, oldest first (for ``eve-localize runs``)."""
    return list(load_journal(opts)["runs"])


# --------------------------------------------------------------------------
# Sidecar text
# --------------------------------------------------------------------------


def sidecar_decode(raw: bytes) -> tuple[str, str]:
    """Decoded text and newline (``"\\r\\n"`` when every LF is a CRLF)."""
    text = raw.decode("utf-8", "surrogateescape")
    lf = text.count("\n")
    if lf and text.count("\r\n") == lf:
        return text.replace("\r\n", "\n"), "\r\n"
    return text, "\n"


def sidecar_encode(text: str, newline: str) -> bytes:
    if newline == "\r\n":
        text = text.replace("\n", "\r\n")
    return text.encode("utf-8", "surrogateescape")


def _sidecar_dirs(lab_path: Path) -> list[Path]:
    """``<stem>_cfgs``, else the single ``<stem>*_cfgs`` (design 5.3)."""
    parent, stem = lab_path.parent, lab_path.stem
    exact = parent / f"{stem}_cfgs"
    if exact.is_dir():
        return [exact]
    hits = sorted(
        p
        for p in parent.glob(f"{glob_escape(stem)}*_cfgs")
        if p.is_dir() and p.name.startswith(stem)
    )
    return hits if len(hits) == 1 else []


def glob_escape(text: str) -> str:
    return re.sub(r"([*?\[])", r"[\1]", text)


# --------------------------------------------------------------------------
# Plan -> bytes
# --------------------------------------------------------------------------


def _attr_index(lab: RawLab) -> dict[tuple[int, int], tuple[RawElem, str]]:
    elems: list[RawElem] = list(lab.networks())
    for n in lab.nodes():
        elems.append(n.elem)
        elems.extend(i.elem for i in n.ifaces)
    elems.extend(b.elem for b in lab.textobjects())
    elems.extend(b.elem for b in lab.config_blobs())
    out: dict[tuple[int, int], tuple[RawElem, str]] = {}
    for el in elems:
        for name, a in el.attrs.items():
            out.setdefault((a.span.start, a.span.end), (el, name))
    return out


def _find_blob(lab: RawLab, e: Edit) -> RawBlob:
    kind = e.store.kind
    if e.target == "textobject" or kind == "textobject":
        hits = [b for b in lab.textobjects() if b.id == e.store.name]
    elif kind == "startup":
        hits = [
            b for b in lab.config_blobs() if b.scope == "startup" and b.id == e.node_id
        ]
    elif kind == "configset":
        scope = f"cs:{e.store.name}"
        hits = [b for b in lab.config_blobs() if b.scope == scope and b.id == e.node_id]
    else:
        raise LocalizeError(
            f"edit {e.id}: store kind {kind!r} is not a blob store", code="BAD_EDIT"
        )
    if len(hits) != 1:
        raise LocalizeError(
            f"edit {e.id}: no unique blob for {tuple(e.store)} node {e.node_id}",
            code="BAD_EDIT",
            refs=[e.id],
        )
    return hits[0]


def _root_id_edit(raw: bytes, current: str, new_id: str) -> RawEdit:
    m = _LAB_TAG.search(raw)
    a = _ID_ATTR.search(m.group(0)) if m else None
    if m is None or a is None:
        raise LocalizeError("cannot locate <lab id> to rewrite", code="BAD_LAYOUT")
    grp = 1 if a.group(1) is not None else 2
    start, end = m.start() + a.start(grp), m.start() + a.end(grp)
    if raw[start:end].decode("utf-8").strip() != current:
        raise LocalizeError(
            "<lab id> span does not match the lab id", code="BAD_LAYOUT"
        )
    return RawEdit(start, end, raw[start:end], new_id.encode("ascii"))


def _copy_dest(path: Path, lab_path: Path, out_dir: Path) -> Path:
    try:
        return out_dir / path.relative_to(lab_path.parent)
    except ValueError:
        return out_dir / path.parent.name / path.name


def _lab_id_of(path: Path) -> str | None:
    """``<lab id>`` read from the head of a ``.unl`` (None when unreadable)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(1 << 16)
    except OSError:
        return None
    m = _LAB_TAG.search(head)
    a = _ID_ATTR.search(m.group(0)) if m else None
    if a is None:
        return None
    val = a.group(1) if a.group(1) is not None else a.group(2)
    return val.decode("utf-8", "replace").strip() or None


def _copy_id(
    plan: Plan,
    opts: ApplyOptions,
    lab: RawLab,
    dest_lab: Path,
    avoid_ids: Iterable[str],
    findings: list[Finding],
) -> str:
    """Lab id of a copy: reuse the dest's id on a re-run, else a new uuid4.

    The dest's id is only reused when it is not the source's id, not the id of
    another tracked lab (a plain copy of a peer) and not an id this run already
    gave another copy (review fixes, apply-safety).
    """
    if opts.new_lab_id:
        return opts.new_lab_id
    dest_id = None
    if dest_lab.is_file():
        with contextlib.suppress(LabParseError):
            dest_id = RawLab.read(dest_lab).lab_id or None
    if dest_id is None:
        return str(uuid.uuid4())
    taken = {lab.lab_id, *avoid_ids}
    if dest_id not in taken:
        taken.update(filter(None, map(_lab_id_of, _peers(plan, opts, dest_lab))))
    if dest_id in taken:
        findings.append(
            Finding(
                "DEST_ID_DUPLICATE",
                "warn",
                f"{dest_lab} has lab id {dest_id}, which another lab already uses "
                "(a plain copy?); the copy gets a new lab id",
                [str(dest_lab)],
            )
        )
        return str(uuid.uuid4())
    return dest_id


def build_changes(
    plan: Plan,
    opts: ApplyOptions | None = None,
    *,
    lab: RawLab | None = None,
    new_lab_id: str | None = None,
    avoid_ids: Iterable[str] = (),
) -> Changes:
    """Compute the new bytes of every file the plan touches (nothing is written).

    Raises :class:`ConflictError` (stale/overlapping edits),
    :class:`UnsupportedLayout` (read-only lab, self-closing config) or
    :class:`LocalizeError` (``NONCANONICAL_BLOB``, ``BAD_EDIT``...).
    In copy mode (``opts.out_dir``) every file gets a ``dest`` under it, the
    lab's sidecar dirs are copied whole and the lab id is replaced (see
    :func:`_copy_id`; ``avoid_ids`` are ids the copy must not reuse).
    """
    opts = opts or ApplyOptions()
    lab_path = Path(plan.lab)
    lab = lab if lab is not None else RawLab.read(lab_path)
    root = opts.repo_root
    findings: list[Finding] = []
    unl_edits: list[RawEdit] = []
    by_blob: dict[tuple[str, str], tuple[RawBlob, list[TextEdit]]] = {}
    by_sidecar: dict[str, tuple[Path, list[TextEdit]]] = {}
    attrs: dict[tuple[int, int], tuple[RawElem, str]] | None = None

    for e in _enabled(plan):
        f = resolve_path(plan, e.file, root)
        if e.target == "sidecar":
            by_sidecar.setdefault(_key(f), (f, []))[1].append(e.text_edit)
            continue
        if not _same(f, lab_path):
            raise LocalizeError(
                f"edit {e.id}: {e.target} edit points at {f}, not the lab file",
                code="BAD_EDIT",
                refs=[e.id],
            )
        if e.target == "xml_attr":
            attrs = attrs if attrs is not None else _attr_index(lab)
            hit = attrs.get((e.text_edit.start, e.text_edit.end))
            if hit is None:
                raise ConflictError(
                    f"edit {e.id}: no attribute value at bytes "
                    f"{e.text_edit.start}:{e.text_edit.end}",
                    code="BAD_SPAN",
                    refs=[e.id],
                )
            el, name = hit
            if e.text_edit.old != el.attrs[name].value:
                raise ConflictError(
                    f"edit {e.id}: <{el.tag} id={el.id}> {name}="
                    f"{el.attrs[name].value!r}, expected {e.text_edit.old!r}",
                    code="STALE_EDIT",
                    refs=[e.id],
                )
            unl_edits.append(lab.attr_edit(el, name, e.text_edit.new))
            for w in label_warnings(e.text_edit.new):
                findings.append(Finding("LABEL_LONG", "warn", w, [e.id]))
        elif e.target in ("blob", "textobject"):
            blob = _find_blob(lab, e)
            by_blob.setdefault((blob.scope, blob.id), (blob, []))[1].append(e.text_edit)
        else:
            raise LocalizeError(
                f"edit {e.id}: unknown target {e.target!r}", code="BAD_EDIT"
            )

    edited: list[tuple[str, str]] = []
    for (scope, bid), (blob, tedits) in by_blob.items():
        dec = decode_blob(blob.b64)
        if dec is None:
            raise LocalizeError(
                f"blob {scope}/{bid} is opaque and cannot be edited",
                code="OPAQUE_BLOB",
            )
        new_b64 = edit_blob(dec, tedits)
        if new_b64 != blob.b64:
            unl_edits.append(lab.blob_edit(blob, new_b64))
            edited.append((scope, bid))

    lab_id = plan.lab_id or lab.lab_id
    out_dir = Path(opts.out_dir) if opts.out_dir is not None else None
    if out_dir is not None and new_lab_id is None:
        dest_lab = out_dir / lab_path.name
        new_lab_id = _copy_id(plan, opts, lab, dest_lab, avoid_ids, findings)
    if new_lab_id is not None and new_lab_id != lab.lab_id:
        unl_edits.append(_root_id_edit(lab.raw, lab.lab_id, new_lab_id))
        lab_id = new_lab_id

    after = splice(lab.raw, unl_edits)
    files = [FileChange(lab_path, lab_path, "unl", lab.raw, after, unl_edits)]
    for f, tedits in by_sidecar.values():
        try:
            raw = f.read_bytes()
        except OSError as exc:
            raise LocalizeError(f"{f}: cannot read: {exc}", code="BAD_EDIT") from exc
        text, nl = sidecar_decode(raw)
        new = sidecar_encode(apply_text_edits(text, tedits), nl)
        files.append(FileChange(f, f, "sidecar", raw, new))

    if out_dir is not None:
        seen = {_key(fc.path) for fc in files}
        dirs = _sidecar_dirs(lab_path)
        for fc in files:
            if fc.kind == "sidecar" and fc.path.parent not in dirs:
                dirs.append(fc.path.parent)
        for d in dirs:
            for p in sorted(d.iterdir()):
                if p.is_file() and _key(p) not in seen:
                    raw = p.read_bytes()
                    files.append(FileChange(p, p, "sidecar", raw, raw))
                    seen.add(_key(p))
        for fc in files:
            fc.dest = _copy_dest(fc.path, lab_path, out_dir)
            if fc.dest.is_file():
                fc.dest_before = fc.dest.read_bytes()
            else:
                fc.created = True
    return Changes(lab, files, edited, findings, lab_id)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def _shape(lab: RawLab) -> dict[str, Any]:
    return {
        "networks": [e.id for e in lab.networks()],
        "nodes": [n.id for n in lab.nodes()],
        "interfaces": [(n.id, i.id) for n in lab.nodes() for i in n.ifaces],
        "configsets": lab.configsets(),
        "configs": sorted((b.scope, b.id) for b in lab.config_blobs()),
        "textobjects": [b.id for b in lab.textobjects()],
        "objects": lab.objects_count(),
    }


def validate_written(
    path: Path,
    plan: Plan,
    before: RawLab,
    *,
    changes: Changes | None = None,
    expect_lab_id: str | None = None,
    peers: Sequence[Path] = (),
    check_labs_script: Path | None = CHECK_LABS,
) -> list[Finding]:
    """Validate a written ``.unl`` against ``before`` + ``plan`` (design 12.3).

    Covers steps 1-4 and 6: well-formed ``<lab>`` with the expected id, ids and
    counts unchanged, bytes outside the planned spans identical (and the planned
    spans hold exactly the planned bytes), edited blobs canonical with the same
    encoding and trailing newline, and ``check-labs`` on the file plus ``peers``
    (``check_labs_script=None`` skips it).  Mirrors (5) and re-scan (7) need the
    sidecars and the analysis and are run by :func:`apply_plans`.  Returns error
    findings (empty = valid).
    """
    path = Path(path)
    expect = expect_lab_id or before.lab_id
    if changes is None:
        changes = build_changes(
            plan, lab=before, new_lab_id=expect if expect != before.lab_id else None
        )
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [_err("VALIDATION_IO", f"{path}: cannot read: {exc}")]
    out: list[Finding] = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        return [_err("VALIDATION_XML", f"{path}: not well-formed XML: {exc}")]
    if root.tag != "lab":
        return [_err("VALIDATION_XML", f"{path}: root is <{root.tag}>, not <lab>")]
    if (root.get("id") or "").strip() != expect:
        out.append(
            _err("VALIDATION_ID", f"{path}: lab id {root.get('id')!r} != {expect!r}")
        )
    try:
        after = RawLab.from_bytes(data, path)
    except LocalizeError as exc:
        return [*out, _err("VALIDATION_XML", f"{path}: {exc}")]
    if after.read_only:
        out.append(
            _err(
                "VALIDATION_LAYOUT",
                f"{path}: span index and ElementTree disagree after write",
                after.layout_issues,
            )
        )
    b_shape, a_shape = _shape(before), _shape(after)
    for k, v in b_shape.items():
        if a_shape[k] != v:
            out.append(_err("VALIDATION_COUNTS", f"{path}: {k} changed by the write"))
    unl = changes.unl
    if not verify_outside_spans(before.raw, data, unl.raw_edits):
        out.append(
            _err(
                "VALIDATION_SPANS",
                f"{path}: bytes differ from the original plus the planned edits",
            )
        )
    a_blobs = {(b.scope, b.id): b for b in after.config_blobs()}
    a_blobs.update({("-", b.id): b for b in after.textobjects()})
    b_blobs = {(b.scope, b.id): b for b in before.config_blobs()}
    b_blobs.update({("-", b.id): b for b in before.textobjects()})
    for key in changes.edited_blobs:
        nb, ob = a_blobs.get(key), b_blobs.get(key)
        nd = decode_blob(nb.b64) if nb is not None else None
        od = decode_blob(ob.b64) if ob is not None else None
        where = f"{path}: blob {key[0]}/{key[1]}"
        if nd is None or od is None:
            out.append(_err("VALIDATION_BLOB", f"{where} does not decode"))
        elif not nd.canonical:
            out.append(_err("VALIDATION_BLOB", f"{where} is not canonical base64"))
        elif nd.encoding != od.encoding:
            out.append(_err("VALIDATION_BLOB", f"{where} changed encoding"))
        elif nd.text.endswith("\n") != od.text.endswith("\n"):
            out.append(_err("VALIDATION_BLOB", f"{where} changed trailing newline"))
    if check_labs_script is not None:
        out.extend(_check_labs_findings(path, peers, check_labs_script))
    return out


def _check_labs_findings(
    path: Path, peers: Sequence[Path], script: Path
) -> list[Finding]:
    with tempfile.TemporaryDirectory(prefix="evelab-localize-check-") as tmp:
        target = path
        if path.suffix != ".unl":
            target = Path(tmp) / "candidate.unl"
            shutil.copyfile(path, target)
        others = [p for p in peers if not _same(p, path)]
        try:
            rc, text = run_check_labs([*others, target], script)
        except Exception as exc:  # noqa: BLE001 - report, never crash validation
            return [_err("VALIDATION_CHECK_LABS", f"check-labs crashed: {exc}")]
    if rc == 0:
        return []
    lines = [ln for ln in text.splitlines() if ln.startswith("ERROR")]
    return [_err("VALIDATION_CHECK_LABS", f"check-labs failed for {path}", lines)]


def _mirror_findings(changes: Changes) -> list[Finding]:
    """Sidecar/blob pairs byte-identical before must stay identical (12.3.5)."""
    lab = changes.lab
    names = {n.id: n.name for n in lab.nodes()}
    try:
        after_lab = RawLab.from_bytes(changes.unl.after, lab.path)
    except LocalizeError:
        return []  # reported by validate_written
    touched = {_key(f.path): f for f in changes.files if f.kind == "sidecar"}
    dirs = {d.resolve() for d in _sidecar_dirs(Path(lab.path))}
    dirs.update(f.path.parent.resolve() for f in touched.values())

    def payloads(rl: RawLab) -> dict[str, list[tuple[str, bytes]]]:
        out: dict[str, list[tuple[str, bytes]]] = {}
        for b in rl.config_blobs():
            with contextlib.suppress(ValueError):
                out.setdefault(b.id, []).append(
                    (b.scope, base64.b64decode(b"".join(b.b64.split())))
                )
        return out

    before_p, after_p = payloads(lab), payloads(after_lab)
    found: list[Finding] = []
    for d in sorted(dirs):
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            m = _SIDECAR_RE.match(p.name)
            if not p.is_file() or m is None or names.get(m.group(1)) != m.group(2):
                continue
            fc = touched.get(_key(p))
            sb = fc.before if fc else p.read_bytes()
            sa = fc.after if fc else sb
            a_map = dict(after_p.get(m.group(1), []))
            for scope, data in before_p.get(m.group(1), []):
                if data == sb and a_map.get(scope) != sa:
                    found.append(
                        _err(
                            "VALIDATION_MIRROR",
                            f"{p.name} mirrored {scope} config of node "
                            f"{m.group(1)} but the edits made them differ",
                            [str(p)],
                        )
                    )
    return found


def _sidecar_findings(changes: Changes) -> list[Finding]:
    out: list[Finding] = []
    for fc in changes.files:
        if fc.kind != "sidecar" or fc.after == fc.before:
            continue
        _, nl_b = sidecar_decode(fc.before)
        text, nl_a = sidecar_decode(fc.after)
        if nl_a != nl_b and text.count("\n"):
            out.append(_err("VALIDATION_SIDECAR", f"{fc.path}: newline style changed"))
        if fc.after.endswith(b"\n") != fc.before.endswith(b"\n"):
            out.append(
                _err("VALIDATION_SIDECAR", f"{fc.path}: trailing newline changed")
            )
    return out


def _peers(plan: Plan, opts: ApplyOptions, dest: Path) -> list[Path]:
    if opts.check_labs_peers is not None:
        peers = [Path(p) for p in opts.check_labs_peers]
    else:
        root = _repo_root(opts, Path(plan.lab).parent)
        res = _git(root, "ls-files", "-z", "--", "*.unl") if root else None
        if root is None or res is None or res.returncode != 0:
            peers = []
        else:
            peers = [root / p for p in res.stdout.split("\0") if p]
    drop = [dest] if opts.out_dir is not None else [Path(plan.lab), dest]
    return [p for p in peers if p.is_file() and not any(_same(p, d) for d in drop)]


def _stage(changes: Changes, tmp: Path, lab_path: Path) -> Path:
    """Write the new lab plus its sidecar dirs into ``tmp``; return the lab path."""
    staged_lab = tmp / lab_path.name
    staged_lab.write_bytes(changes.unl.after)
    dirs = set(_sidecar_dirs(lab_path))
    dirs.update(f.path.parent for f in changes.files if f.kind == "sidecar")
    for d in dirs:
        target = _copy_dest(d, lab_path, tmp)
        if d.is_dir():
            shutil.copytree(d, target, dirs_exist_ok=True)
    for fc in changes.files:
        if fc.kind == "sidecar":
            dest = _copy_dest(fc.path, lab_path, tmp)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(fc.after)
    return staged_lab


def _validate_all(
    plan: Plan, changes: Changes, opts: ApplyOptions, lab_path: Path
) -> list[Finding]:
    found = _mirror_findings(changes) + _sidecar_findings(changes)
    dest = changes.unl.dest
    with tempfile.TemporaryDirectory(prefix="evelab-localize-stage-") as tmp:
        staged = _stage(changes, Path(tmp), lab_path)
        found += validate_written(
            staged,
            plan,
            changes.lab,
            changes=changes,
            expect_lab_id=changes.lab_id,
            peers=_peers(plan, opts, dest) if opts.check_labs else (),
            check_labs_script=opts.check_labs_script if opts.check_labs else None,
        )
        if opts.rescan is not None and not any(f.severity in BLOCKING for f in found):
            try:
                residual = opts.rescan(staged, plan)
            except ValidationError as exc:
                found.append(_err("VALIDATION_RESCAN", str(exc), exc.refs))
            else:
                n = residual if isinstance(residual, int) else len(residual)
                if n:
                    refs = (
                        []
                        if isinstance(residual, int)
                        else [getattr(e, "id", str(e)) for e in residual][:20]
                    )
                    found.append(
                        _err(
                            "VALIDATION_RESCAN",
                            f"re-scan of the written lab still plans {n} edit(s)",
                            refs,
                        )
                    )
    return found


# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------


def _lock(opts: ApplyOptions, near: Path | None = None) -> hostenv.Lock:
    return hostenv.Lock(_state_dir(opts, near) / "lock", use_fcntl=opts.use_fcntl)


def _lock_finding(opts: ApplyOptions, near: Path | None) -> Finding | None:
    lock = _lock(opts, near)
    try:
        lock.acquire()
    except PreconditionError as exc:
        return Finding("LOCK_HELD", "blocker", str(exc), [str(lock.path)])
    except OSError as exc:
        return Finding("LOCK_HELD", "blocker", f"cannot take lock: {exc}")
    lock.release()
    return None


def _plan_files(plan: Plan, repo_root: Path | None) -> dict[str, Path]:
    return {k: resolve_path(plan, k, repo_root) for k in plan.base_sha256}


def _preflight_one(
    plan: Plan, opts: ApplyOptions, state: Mapping[str, Any]
) -> list[Finding]:
    lab_path = Path(plan.lab)
    root = _repo_root(opts, lab_path.parent)
    out: list[Finding] = []
    ref = [str(lab_path)]
    if plan.blocked:
        out.append(
            Finding("PLAN_BLOCKED", "blocker", f"{lab_path}: plan has blockers", ref)
        )
    files = _plan_files(plan, root)
    for k, p in files.items():
        cur = _sha_file(p)
        if cur is None:
            out.append(Finding("FILE_MISSING", "blocker", f"{p}: missing", [k]))
        elif cur != plan.base_sha256[k]:
            out.append(
                Finding(
                    "SHA_DRIFT",
                    "blocker",
                    f"{p} changed since the plan was made; re-run plan",
                    [k],
                )
            )
    covered = {_key(p) for p in files.values()}
    edit_files = {_key(resolve_path(plan, e.file, root)) for e in _enabled(plan)}
    if _enabled(plan):
        edit_files.add(_key(lab_path))
    for f in sorted(edit_files - covered):
        out.append(
            Finding("MISSING_BASE_SHA", "blocker", f"{f}: not in plan.base_sha256")
        )
    try:
        lab = RawLab.read(lab_path)
    except LabParseError as exc:
        return [*out, Finding("LAB_PARSE", "blocker", str(exc), ref)]
    if lab.read_only and (_enabled(plan) or opts.out_dir is not None):
        out.append(
            Finding(
                "UNSUPPORTED_LAYOUT",
                "blocker",
                f"{lab_path}: read-only (unsupported layout)",
                lab.layout_issues,
            )
        )
    if plan.lab_id and lab.lab_id != plan.lab_id:
        out.append(
            Finding("LAB_ID_CHANGED", "blocker", f"{lab_path}: lab id changed", ref)
        )
    targets = [Path(p) for p in sorted(edit_files)]
    if opts.out_dir is not None:
        out_dir = Path(opts.out_dir)
        probe = out_dir if out_dir.exists() else out_dir.parent
        if not os.access(probe, os.W_OK):
            out.append(
                Finding("NOT_WRITABLE", "blocker", f"{out_dir}: not writable", ref)
            )
        return out + _copy_findings(lab_path, out_dir, opts)
    out.extend(
        hostenv.runtime_findings(
            lab.lab_id,
            force_running=opts.force_running,
            proc=opts.proc,
            tmp_root=opts.tmp_root,
            docker_names=opts.docker_names,
        )
    )
    if targets:
        out.append(
            Finding(
                "EVE_SAVE_RACE",
                "warn",
                "close the lab in the EVE web UI first: an open editor may save "
                "over the localized file (use --out to avoid the race)",
                ref,
            )
        )
    recorded = (state.get(lab.lab_id) or {}).get("files", {})
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    for p in targets:
        if root is not None:
            status = _git_file_status(root, p)
            if status == "dirty" and recorded.get(_key(p)) == _sha_file(p):
                status = "clean"  # dirty only because of our own localization
            if status == "dirty":
                sev: Literal["warn", "blocker"] = (
                    "blocker" if opts.require_clean else "warn"
                )
                out.append(Finding("DIRTY", sev, f"{p}: uncommitted changes", [str(p)]))
            if opts.no_backup and status != "clean":
                out.append(
                    Finding(
                        "NO_BACKUP_UNSAFE",
                        "blocker",
                        f"{p}: --no-backup needs a clean, tracked file",
                        [str(p)],
                    )
                )
        elif opts.no_backup:
            out.append(
                Finding(
                    "NO_BACKUP_UNSAFE",
                    "blocker",
                    f"{p}: --no-backup needs a git checkout",
                    [str(p)],
                )
            )
        if not os.access(p.parent, os.W_OK):
            out.append(
                Finding(
                    "NOT_WRITABLE", "blocker", f"{p.parent}: not writable", [str(p)]
                )
            )
        if euid not in (None, 0):
            with contextlib.suppress(OSError):
                if p.stat().st_uid != euid:
                    out.append(
                        Finding(
                            "OWNER_DIFFERS",
                            "warn",
                            f"{p}: owned by uid {p.stat().st_uid}; not root, so the "
                            "rewritten file will be owned by you - run "
                            "`make fix-perms` (or --fix-perms) afterwards",
                            [str(p)],
                        )
                    )
    return out


def _copy_targets(lab_path: Path, out_dir: Path) -> list[tuple[Path, Path]]:
    """``(source, dest)`` of the lab and its sidecar files in copy mode."""
    pairs = [(lab_path, out_dir / lab_path.name)]
    for d in _sidecar_dirs(lab_path):
        pairs.append((d, _copy_dest(d, lab_path, out_dir)))
        with contextlib.suppress(OSError):
            for p in sorted(d.iterdir()):
                if p.is_file():
                    pairs.append((p, _copy_dest(p, lab_path, out_dir)))
    return pairs


def _copy_findings(lab_path: Path, out_dir: Path, opts: ApplyOptions) -> list[Finding]:
    """Copy-mode guards: never write over the source; a lab already at the
    destination gets the same running-node checks as an in-place apply."""
    ref = [str(lab_path)]
    out: list[Finding] = []
    if _same(out_dir, lab_path.parent) or any(
        _same(src, dest) for src, dest in _copy_targets(lab_path, out_dir)
    ):
        out.append(
            Finding(
                "OUT_IS_SOURCE",
                "blocker",
                f"--out {out_dir} would overwrite {lab_path} itself; pick another "
                "directory (or drop --out to localize in place)",
                ref,
            )
        )
        return out
    dest_lab = out_dir / lab_path.name
    dest_id = _lab_id_of(dest_lab) if dest_lab.is_file() else None
    if dest_id is not None:
        out.extend(
            hostenv.runtime_findings(
                dest_id,
                force_running=opts.force_running,
                proc=opts.proc,
                tmp_root=opts.tmp_root,
                docker_names=opts.docker_names,
            )
        )
        out.append(
            Finding(
                "EVE_SAVE_RACE",
                "warn",
                f"{dest_lab} already exists and will be overwritten: close it in "
                "the EVE web UI first",
                [str(dest_lab)],
            )
        )
    return out


def _dest_collisions(plans: Sequence[Plan], opts: ApplyOptions) -> list[Finding]:
    """Copy mode: two labs of one run must not share a destination file."""
    if opts.out_dir is None:
        return []
    out_dir = Path(opts.out_dir)
    owner: dict[str, Path] = {}
    out: list[Finding] = []
    for plan in plans:
        lab_path = Path(plan.lab)
        for _src, dest in _copy_targets(lab_path, out_dir):
            k = _key(dest)
            other = owner.setdefault(k, lab_path)
            if not _same(other, lab_path):
                out.append(
                    Finding(
                        "DEST_COLLISION",
                        "blocker",
                        f"{other} and {lab_path} would both be copied to {dest}; "
                        "apply them with different --out directories",
                        [str(other), str(lab_path)],
                    )
                )
                break
    return out


def preflight(plans: Sequence[Plan], opts: ApplyOptions) -> list[Finding]:
    """All preconditions for applying ``plans`` (design 12.1).

    Severity ``blocker`` stops the affected lab (exit 4 when applied); ``warn``
    and ``info`` are reported only.  Never writes anything (the lock is taken
    and released immediately).
    """
    out: list[Finding] = []
    # Python >= 3.11 is enforced by scripts/eve-localize before any import.
    near = Path(plans[0].lab).parent if plans else None
    lf = _lock_finding(opts, near)
    if lf is not None:
        out.append(lf)
    state = load_state(replace(opts, state_dir=_state_dir(opts, near)))
    out.extend(_dest_collisions(plans, opts))
    for plan in plans:
        out.extend(_preflight_one(plan, opts, state))
    return out


# --------------------------------------------------------------------------
# Transaction
# --------------------------------------------------------------------------


def _stat_of(path: Path) -> tuple[int, int, int]:
    st = path.stat()
    return st.st_mode & 0o7777, st.st_uid, st.st_gid


def _write_temp(
    dest: Path,
    data: bytes,
    mode: int | None,
    owner: tuple[int, int] | None,
    run_id: str,
) -> Path:
    """Temp file next to ``dest`` with ``data`` fsynced, mode and owner applied.

    Directories created for ``dest`` (copy mode) get ``owner`` too when running
    as root, so EVE (``www-data``) can save into a fresh ``--out`` tree.
    """
    missing = [p for p in (dest.parent, *dest.parent.parents) if not p.exists()]
    dest.parent.mkdir(parents=True, exist_ok=True)
    if missing and owner is not None and _is_root() and hasattr(os, "chown"):
        for d in missing:
            os.chown(d, *owner)
    tmp = dest.with_name(f".{dest.name}.{run_id}.localize-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644 if mode is None else mode)
        if owner is not None and _is_root() and hasattr(os, "chown"):
            os.chown(tmp, *owner)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    return tmp


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _fsync_dir(path: Path) -> None:
    if os.name != "posix":
        return
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _backup_rel(path: Path, root: Path | None) -> Path:
    rp = path.resolve()
    if root is not None:
        with contextlib.suppress(ValueError):
            return rp.relative_to(root)
    return Path(*rp.parts[1:])


def _new_run_id(opts: ApplyOptions, now: datetime, journal: dict[str, Any]) -> str:
    if opts.run_id:
        return opts.run_id
    base = now.strftime("%Y%m%dT%H%M%SZ")
    used = {r.get("run_id") for r in journal["runs"]}
    backups = _backup_root(opts)
    rid, n = base, 1
    while rid in used or (backups / rid).exists():
        n += 1
        rid = f"{base}-{n}"
    return rid


def _apply_one(
    plan: Plan,
    opts: ApplyOptions,
    run_id: str,
    state: dict[str, Any],
    entries: dict[str, Any],
) -> LabResult:
    lab_path = Path(plan.lab)
    res = LabResult(lab_path, plan.lab_id, "failed")
    root = _repo_root(opts, lab_path.parent)
    res.findings = _preflight_one(plan, opts, state)
    if any(f.severity in BLOCKING for f in res.findings):
        res.status, res.exit_code = "skipped", 4
        if any(f.code == "PLAN_BLOCKED" for f in res.findings):
            res.exit_code = 2
        res.error = "preflight failed"
        return res
    try:
        changes = build_changes(plan, opts, avoid_ids=entries.keys())
    except (ConflictError, BlockedError) as exc:
        res.findings.append(Finding(exc.code, "conflict", str(exc), exc.refs))
        res.error, res.exit_code = str(exc), 2
        return res
    except UnsupportedLayout as exc:
        res.findings.append(Finding(exc.code, "blocker", str(exc), exc.refs))
        res.error, res.exit_code = str(exc), 2
        return res
    except LocalizeError as exc:
        sev: Literal["blocker", "error"] = (
            "blocker" if exc.code in ("NONCANONICAL_BLOB", "OPAQUE_BLOB") else "error"
        )
        res.findings.append(Finding(exc.code, sev, str(exc), exc.refs))
        res.error, res.exit_code = str(exc), 2 if sev == "blocker" else 1
        return res
    res.lab_id = changes.lab_id
    res.findings.extend(changes.findings)
    todo = [fc for fc in changes.files if fc.changed]
    if not todo:
        res.status = "unchanged"
        res.findings.append(Finding("NOTHING_TO_DO", "info", f"{lab_path}: 0 edits"))
        return res

    problems = _validate_all(plan, changes, opts, lab_path)
    if opts.rescan is None:
        res.findings.append(
            Finding("RESCAN_SKIPPED", "info", "no re-scan hook: idempotency unchecked")
        )
    if problems:
        res.findings.extend(problems)
        res.error, res.exit_code = "validation failed (nothing written)", 5
        return res

    # 0. the files must still hold the bytes the changes were built from:
    # validation takes seconds and EVE may have saved the lab meanwhile.
    current: dict[str, bytes] = {}
    for fc in todo:
        drift = _drift(fc)
        if drift is not None:
            res.findings.append(Finding("SHA_DRIFT", "blocker", drift, [str(fc.dest)]))
            res.status, res.exit_code = "skipped", 4
            res.error = "changed during validation (nothing written)"
            return res
        if not fc.created:
            current[_key(fc.dest)] = _prior(fc)

    # 1. backups (from the verified bytes, so they always match before_sha)
    backup_dir = _backup_root(opts, lab_path.parent) / run_id
    metas: dict[str, tuple[int, int, int] | None] = {}
    backups: dict[str, str | None] = {}
    for fc in todo:
        k = _key(fc.dest)
        if fc.created:
            metas[k], backups[k] = None, None
            continue
        meta = _stat_of(fc.dest)
        metas[k] = meta
        if opts.no_backup:
            backups[k] = None
            continue
        bpath = backup_dir / _backup_rel(fc.dest, root)
        bpath.parent.mkdir(parents=True, exist_ok=True)
        bpath.write_bytes(current[k])
        with contextlib.suppress(OSError):
            shutil.copystat(fc.dest, bpath)
        backups[k] = str(bpath.resolve())
    # 2. temps (validated content), 4. replace
    temps: list[tuple[FileChange, Path]] = []
    replaced: list[FileChange] = []
    try:
        for fc in todo:
            meta = metas[_key(fc.dest)]
            if meta is not None:
                mode, owner = meta[0], (meta[1], meta[2])
            else:  # copy mode, new file: the source's mode and owner (root only)
                st = fc.path.stat()
                mode, owner = st.st_mode & 0o7777, (st.st_uid, st.st_gid)
            tmp = _write_temp(fc.dest, fc.after, mode, owner, run_id)
            temps.append((fc, tmp))
            if tmp.read_bytes() != fc.after:
                raise ValidationError(f"{tmp}: temp file read-back differs")
        for fc, tmp in temps:
            drift = _drift(fc)  # last check, right before the replace
            if drift is not None:
                raise PreconditionError(drift, code="SHA_DRIFT", refs=[str(fc.dest)])
            os.replace(tmp, fc.dest)
            replaced.append(fc)
        for d in {fc.dest.parent for fc in todo}:
            _fsync_dir(d)
        for fc in todo:
            if _sha_file(fc.dest) != _sha(fc.after):
                raise ValidationError(f"{fc.dest}: content differs after replace")
    except (OSError, LocalizeError) as exc:
        for _fc, tmp in temps:
            with contextlib.suppress(OSError):
                tmp.unlink()
        res.findings.extend(_rollback(replaced, metas, run_id, backups))
        if isinstance(exc, PreconditionError):
            res.findings.append(Finding(exc.code, "blocker", str(exc), exc.refs))
            res.status, res.exit_code = "skipped", 4
            res.error = "changed during the write (rolled back)"
            return res
        res.findings.append(_err("WRITE_FAILED", f"write failed, rolled back: {exc}"))
        res.error, res.exit_code = str(exc), 5
        return res
    except BaseException:  # Ctrl-C mid-write: put the lab back, then stop
        for _fc, tmp in temps:
            with contextlib.suppress(OSError):
                tmp.unlink()
        _rollback(replaced, metas, run_id, backups)
        raise

    # 5. journal entry (written by the caller) + state
    files: dict[str, dict[str, Any]] = {}
    for fc in todo:
        k = _key(fc.dest)
        meta = metas[k]
        prior = fc.dest_before if opts.out_dir is not None else fc.before
        files[k] = {
            "before_sha": None if fc.created or prior is None else _sha(prior),
            "after_sha": _sha(fc.after),
            "mode": None if meta is None else meta[0],
            "uid": None if meta is None else meta[1],
            "gid": None if meta is None else meta[2],
            "backup": backups.get(k),
            "created": fc.created,
        }
    res.files = files
    mode = "out" if opts.out_dir is not None else "in-place"
    entry: dict[str, Any] = {
        "lab": _key(changes.unl.dest),
        "source": _key(lab_path),
        "mode": mode,
        "files": files,
        "answers_digest": plan.answers_digest,
        "plan_digest": plan_digest(plan),
        "edits": len(_enabled(plan)),
    }
    if mode == "in-place":
        entry["prev_state"] = state.get(plan.lab_id)
        if opts.mark_localized:
            extra = dict(opts.state_extra.get(plan.lab_id, {}))
            prev = state.get(plan.lab_id) or {}
            prev_files = dict(prev.get("files", {}))
            prev_files.update({k: v["after_sha"] for k, v in files.items()})
            # Start from the previous entry so fields the caller did not
            # recompute (baseline, baseline_maps, baseline_split) survive.
            new = dict(prev)
            new.update(
                localized=True,
                lab=_key(lab_path),
                site_keys=extra.pop("site_keys", prev.get("site_keys", {})),
                values=extra.pop("values", prev.get("values", {})),
                after_sha=(
                    files[_key(lab_path)]["after_sha"]
                    if _key(lab_path) in files
                    else prev.get("after_sha")
                ),
                files=prev_files,
                run_id=run_id,
            )
            new.update(extra)
            state[plan.lab_id] = new
        else:
            state.pop(plan.lab_id, None)
    entries[changes.lab_id] = entry
    res.status = "localized"
    return res


def _restore(dest: Path, data: bytes, meta: Sequence[int] | None, run_id: str) -> None:
    mode, owner = (None, None) if meta is None else (meta[0], (meta[1], meta[2]))
    tmp = _write_temp(dest, data, mode, owner, run_id + "-restore")
    os.replace(tmp, dest)
    _fsync_dir(dest.parent)


def _prior(fc: FileChange) -> bytes:
    """Bytes ``fc.dest`` held when the changes were built."""
    return fc.dest_before if fc.dest_before is not None else fc.before


def _drift(fc: FileChange) -> str | None:
    """Why ``fc.dest`` no longer holds :func:`_prior` (None = unchanged)."""
    if fc.created:
        if fc.dest.exists():
            return f"{fc.dest} appeared since the plan was built; re-run"
        return None
    if _sha_file(fc.dest) != _sha(_prior(fc)):
        return f"{fc.dest} changed while it was being localized (EVE save?); re-run"
    return None


def _rollback(
    replaced: Sequence[FileChange],
    metas: Mapping[str, tuple[int, int, int] | None],
    run_id: str,
    backups: Mapping[str, str | None] | None = None,
) -> list[Finding]:
    """Put back what this lab replaced, but only files still holding our bytes."""
    out: list[Finding] = []
    for fc in reversed(replaced):
        k = _key(fc.dest)
        try:
            if _sha_file(fc.dest) != _sha(fc.after):
                raise OSError("it changed after the write")
            if fc.created:
                fc.dest.unlink()
            else:
                _restore(fc.dest, _prior(fc), metas.get(k), run_id)
        except OSError as exc:
            where = (backups or {}).get(k) or "git"
            out.append(
                _err(
                    "ROLLBACK_FAILED",
                    f"{fc.dest}: rollback failed ({exc}); restore it from {where}",
                    [str(fc.dest)],
                )
            )
    return out


def apply_plans(plans: Sequence[Plan], opts: ApplyOptions) -> RunRecord:
    """Apply ``plans`` as one run; each lab is its own transaction (12.2).

    Holds ``<state_dir>/lock`` for the whole run (``PreconditionError`` if
    held).  A lab that fails preflight is ``skipped``; one that fails building
    or validation is ``failed`` (nothing replaced, or rolled back).  Without
    ``continue_on_error`` the remaining labs are left ``untouched``.  The
    journal entry lists only the labs actually written; it and ``state.json``
    are rewritten as each lab commits, so an interrupted run stays undoable.
    In copy mode, labs whose copies would share a destination refuse the
    whole run (``DEST_COLLISION``, nothing written).
    """
    near = Path(plans[0].lab).parent if plans else None
    opts = replace(opts, state_dir=_state_dir(opts, near))
    now = _now(opts)
    mode: Literal["in-place", "out"] = "out" if opts.out_dir is not None else "in-place"
    with _lock(opts, near):
        journal = load_journal(opts)
        state = load_state(opts)
        run_id = _new_run_id(opts, now, journal)
        record = RunRecord(run_id, now.isoformat(timespec="seconds"), [], mode=mode)
        entries: dict[str, Any] = {}
        collisions = _dest_collisions(plans, opts)
        if collisions:
            for plan in plans:
                res = LabResult(Path(plan.lab), plan.lab_id, "skipped")
                res.findings = [f for f in collisions if str(plan.lab) in f.refs]
                res.error, res.exit_code = "copy destinations collide", 4
                record.labs.append(res)
            return record
        run_entry: dict[str, Any] | None = None
        stop = False
        for plan in plans:
            if stop:
                record.labs.append(LabResult(Path(plan.lab), plan.lab_id, "untouched"))
                continue
            written = len(entries)
            res = _apply_one(plan, opts, run_id, state, entries)
            record.labs.append(res)
            if len(entries) != written:  # the lab committed: persist it now
                if run_entry is None:
                    run_entry = {
                        "run_id": run_id,
                        "ts": record.ts,
                        "user": opts.user or _user(),
                        "host": opts.host or socket.gethostname(),
                        "mode": mode,
                        "labs": entries,
                    }
                    journal["runs"].append(run_entry)
                _write_json(_state_dir(opts) / "journal.json", journal)
                if mode == "in-place":
                    _write_json(_state_dir(opts) / "state.json", state)
                record.journaled = True
            if res.status in ("failed", "skipped") and not opts.continue_on_error:
                stop = True
    return record


def apply_plan(plan: Plan, opts: ApplyOptions) -> RunRecord:
    """Apply one plan (see :func:`apply_plans`)."""
    return apply_plans([plan], opts)


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no passwd entry / env
        return "unknown"


# --------------------------------------------------------------------------
# Undo
# --------------------------------------------------------------------------


def undo(run_id: str | None, opts: ApplyOptions) -> list[Path]:
    """Restore the backups of a journaled run (latest not-undone run if None).

    Refuses (``PreconditionError``, nothing restored) when any file's current
    sha differs from the journal's ``after_sha`` - EVE (or someone) changed it
    since - or a needed backup is missing; suggests ``git restore`` or
    ``revert``.  Live nodes block unless ``force_running``.  Restores mode and
    owner, deletes files created by copy mode, puts back the previous
    ``state.json`` entries and marks the run ``undone``.
    """
    opts = replace(opts, state_dir=_state_dir(opts))
    with _lock(opts):
        journal = load_journal(opts)
        runs = [r for r in journal["runs"] if not r.get("undone")]
        if run_id is not None:
            runs = [r for r in journal["runs"] if r.get("run_id") == run_id]
            if not runs:
                raise PreconditionError(
                    f"no run {run_id!r} in the journal", code="NO_RUN"
                )
            if runs[-1].get("undone"):
                raise PreconditionError(
                    f"run {run_id} was already undone", code="ALREADY_UNDONE"
                )
        if not runs:
            raise PreconditionError("nothing to undo", code="NO_RUN")
        run = runs[-1]
        problems: list[str] = []
        for lab_id, entry in run["labs"].items():
            if entry.get("mode") == "in-place" and not opts.force_running:
                for f in hostenv.runtime_findings(
                    lab_id,
                    proc=opts.proc,
                    tmp_root=opts.tmp_root,
                    docker_names=opts.docker_names,
                ):
                    if f.severity == "blocker":
                        problems.append(f.msg)
            for path, info in entry["files"].items():
                cur = _sha_file(Path(path))
                if cur != info["after_sha"]:
                    problems.append(
                        f"{path} changed since run {run['run_id']} "
                        "(EVE re-saved it?); use `git restore` or `revert`"
                    )
                elif not info.get("created") and not (
                    info.get("backup") and Path(info["backup"]).is_file()
                ):
                    problems.append(
                        f"{path}: no backup for run {run['run_id']}; use `git restore`"
                    )
                elif (
                    not info.get("created")
                    and info.get("before_sha")
                    and _sha_file(Path(info["backup"])) != info["before_sha"]
                ):
                    problems.append(
                        f"{path}: backup {info['backup']} does not match the "
                        "journal's before_sha; use `git restore` or `revert`"
                    )
        if problems:
            raise PreconditionError(
                "undo refused: " + "; ".join(problems),
                code="UNDO_REFUSED",
                refs=problems,
            )
        restored: list[Path] = []
        state = load_state(opts)
        for lab_id, entry in run["labs"].items():
            for path, info in entry["files"].items():
                p = Path(path)
                if info.get("created"):
                    p.unlink()
                else:
                    data = Path(info["backup"]).read_bytes()
                    meta = (
                        None
                        if info.get("mode") is None
                        else (info["mode"], info["uid"], info["gid"])
                    )
                    _restore(p, data, meta, f"undo-{run['run_id']}")
                    if info.get("before_sha") and _sha_file(p) != info["before_sha"]:
                        raise ValidationError(
                            f"{p}: restored content has the wrong sha"
                        )
                restored.append(p)
            if entry.get("mode") == "in-place":
                prev = entry.get("prev_state")
                if prev:
                    state[lab_id] = prev
                else:
                    state.pop(lab_id, None)
        run["undone"] = _now(opts).isoformat(timespec="seconds")
        _write_json(_state_dir(opts) / "journal.json", journal)
        _write_json(_state_dir(opts) / "state.json", state)
    return restored
