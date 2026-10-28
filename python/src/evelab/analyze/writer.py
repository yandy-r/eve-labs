"""Turn answered questions into node attribute edits and write them safely.

Only attribute *values* change (``image="..."``, ``qemu_version``, ``cpu``,
``ram``): every edit is a byte splice on :class:`~evelab.common.unl.RawLab`, the
result is re-parsed, compared with the original outside the edited spans, run
through ``check-labs`` and written atomically with the file's mode and owner. A
byte copy of the original goes to the backup directory first.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from evelab.common.checklabs import run_check_labs
from evelab.common.errors import (
    ConflictError,
    PreconditionError,
    UnsupportedLayout,
    ValidationError,
)
from evelab.common.fsutil import atomic_write
from evelab.common.unl import (
    RawEdit,
    RawLab,
    escape_attr,
    splice,
    verify_outside_spans,
)

from .checks import KEEP, LabReport

__all__ = [
    "Change",
    "apply_changes",
    "plan_changes",
    "render",
    "validate",
    "write_lab",
]


@dataclass(frozen=True)
class Change:
    node_id: str
    node_name: str
    attr: str
    old: str
    new: str
    question: str


def plan_changes(rep: LabReport, answers: Mapping[str, str]) -> list[Change]:
    """Changes for every question of ``rep`` answered with a new value."""
    out: list[Change] = []
    for q in rep.questions:
        new = answers.get(q.id)
        if new is None or new in (KEEP, q.current):
            continue
        for node_id, name in q.nodes:
            out.append(Change(node_id, name, q.attr, q.current, new, q.id))
    return out


def _edits(lab: RawLab, changes: Sequence[Change]) -> list[RawEdit]:
    if lab.read_only:
        raise UnsupportedLayout(
            f"{lab.path}: lab is read-only (unsupported layout): "
            + "; ".join(lab.layout_issues)
        )
    nodes = {n.id: n for n in lab.nodes()}
    edits: list[RawEdit] = []
    for c in changes:
        node = nodes.get(c.node_id)
        attr = node.elem.attrs.get(c.attr) if node is not None else None
        if attr is None or attr.value != c.old:
            raise ConflictError(
                f"{lab.path}: node {c.node_id} {c.attr} is no longer {c.old!r}",
                code="STALE",
            )
        if any(not ch.isprintable() for ch in c.new):
            raise ConflictError(f"{c.new!r} is not printable", code="BAD_VALUE")
        old = lab.raw[attr.span.start : attr.span.end]
        new = escape_attr(c.new, attr.quote).encode("utf-8")
        edits.append(RawEdit(attr.span.start, attr.span.end, old, new))
    return edits


def apply_changes(raw: bytes, changes: Sequence[Change], path: Path) -> bytes:
    """``raw`` with ``changes`` applied (raises ``STALE`` on a mismatch)."""
    lab = RawLab.from_bytes(raw, path)
    return splice(raw, _edits(lab, changes))


def render(lab: RawLab, changes: Sequence[Change]) -> tuple[bytes, list[RawEdit]]:
    edits = _edits(lab, changes)
    return splice(lab.raw, edits), edits


def _shape(lab: RawLab) -> tuple[object, ...]:
    return (
        [e.id for e in lab.networks()],
        [(n.id, [i.id for i in n.ifaces]) for n in lab.nodes()],
        sorted((b.scope, b.id) for b in lab.config_blobs()),
        [b.id for b in lab.textobjects()],
        lab.lab_id,
    )


def validate(
    lab: RawLab,
    data: bytes,
    edits: Sequence[RawEdit],
    changes: Sequence[Change],
    *,
    peers: Sequence[Path] = (),
) -> list[str]:
    """Problems with ``data`` as the new content of ``lab`` (empty = valid)."""
    errs: list[str] = []
    try:
        after = RawLab.from_bytes(data, lab.path)
    except Exception as exc:  # noqa: BLE001 - any parse failure is a validation error
        return [f"does not parse: {exc}"]
    if after.read_only:
        errs.append("span index and ElementTree disagree after the edit")
    if _shape(after) != _shape(lab):
        errs.append("ids or counts changed")
    if not verify_outside_spans(lab.raw, data, edits):
        errs.append("bytes outside the edited attributes changed")
    nodes = {n.id: n for n in after.nodes()}
    for c in changes:
        node = nodes.get(c.node_id)
        if node is None or node.elem.get(c.attr) != c.new:
            errs.append(f"node {c.node_id} {c.attr} is not {c.new!r} after the edit")
    with tempfile.TemporaryDirectory(prefix="eve-analyze-") as tmp:
        cand = Path(tmp) / "candidate.unl"
        cand.write_bytes(data)
        others = [p for p in peers if p.resolve() != Path(lab.path).resolve()]
        rc, text = run_check_labs([*others, cand])
    if rc != 0:
        errs += [ln for ln in text.splitlines() if ln.startswith("ERROR")] or [
            "check-labs failed"
        ]
    return errs


def write_lab(
    lab: RawLab,
    changes: Sequence[Change],
    *,
    backup: Path | None,
    peers: Sequence[Path] = (),
) -> bytes:
    """Write ``changes`` to ``lab.path``; returns the new bytes.

    ``SHA_DRIFT`` (exit 4) when the file changed since it was read (EVE saved
    it), ``VALIDATION`` (exit 5) when the result fails :func:`validate`.
    ``backup`` receives a byte copy of the original first.
    """
    path = Path(lab.path)
    data, edits = render(lab, changes)
    errs = validate(lab, data, edits, changes, peers=peers)
    if errs:
        raise ValidationError(f"{path}: " + "; ".join(errs), refs=errs)
    if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(lab.raw).digest():
        raise PreconditionError(
            f"{path} changed since it was analysed (saved in EVE?); re-run",
            code="SHA_DRIFT",
        )
    if backup is not None:
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
    atomic_write(path, data, tag="analyze")
    if path.read_bytes() != data:
        if backup is not None:
            atomic_write(path, backup.read_bytes(), tag="analyze")
        raise ValidationError(f"{path}: content differs after write (restored)")
    return data
