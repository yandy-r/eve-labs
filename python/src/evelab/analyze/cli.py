"""Command line interface of eve-analyze.

``scripts/eve-analyze`` is a thin shim around :func:`main`. Commands (default
``run``)::

    run | analyze    interactive: scan -> pick labs -> questions -> review -> apply
    scan | list      host summary, per-lab findings and questions (--json)
    plan             answer and show the changes; never writes
    apply            answer (from --answers / -y) and write without confirming
    inventory        print this host's inventory as JSON (for --inventory)

Exit codes (same as eve-localize): 0 ok / nothing to do / quit, 1 error,
2 problems found (scan --strict), 3 unanswered under --strict, 4 precondition
failed, 5 validation failed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from evelab.common import hostenv, labfiles
from evelab.common.console import (
    Console,
    PickerRow,
    QuitRequested,
    UnansweredError,
    sanitize,
)
from evelab.common.errors import EveLabError, PreconditionError
from evelab.common.findings import Finding
from evelab.common.unl import RawLab

from . import __version__, gitops
from .answers import load_answers, save_answers
from .checks import KEEP, LabReport, Question, analyse_lab
from .host import HostInventory, HostRoots, probe
from .writer import Change, plan_changes, write_lab

__all__ = ["COMMANDS", "Runtime", "build_parser", "main"]

COMMANDS = ("run", "analyze", "scan", "list", "plan", "apply", "inventory")
ALIASES = {"analyze": "run", "list": "scan"}
EXIT_PRIORITY = (5, 4, 3, 2, 1)
STATE_DIR = ".analyze"
_PICKABLE_KINDS = ("image", "qemu_version")


@dataclass
class Runtime:
    """Streams and host probe roots; tests inject fakes."""

    stdin: IO[str] | None = None
    stdout: IO[str] | None = None
    stderr: IO[str] | None = None
    env: Mapping[str, str] | None = None
    interactive: bool | None = None
    roots: HostRoots = field(default_factory=HostRoots)
    proc: Path = hostenv.PROC
    tmp_root: Path = hostenv.UNETLAB_TMP
    docker_names: Callable[[], Iterable[str]] = hostenv.docker_container_names
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


_EPILOG = """commands (default: run):
  run|analyze   scan, pick labs, answer the questions, review, apply (+ git commit)
  scan|list     host summary, findings and questions per lab (--json)
  plan          answer and show the changes; never writes
  apply         answer from --answers / --yes and write without confirming
  inventory     print this host's inventory as JSON (use it with --inventory)

git: a clone of upstream gets a local branch (analyze/<host>); a fork commits on
the current branch; --no-commit only writes the files.

exit codes: 0 ok/nothing to do, 1 error, 2 problems (scan --strict), 3 unanswered
(--strict), 4 precondition failed, 5 validation failed"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eve-analyze",
        usage="%(prog)s [COMMAND] [LAB ...] [options]",
        description="Check labs against this EVE host (images, QEMU builds, "
        "CPU/RAM, templates, bridges) and switch them to what the host has.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("labs", nargs="*", metavar="LAB", help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    g = p.add_argument_group("selection")
    g.add_argument(
        "--lab",
        action="append",
        default=[],
        metavar="PATH|SUBSTRING",
        help="lab file or unique substring of its path (repeatable)",
    )
    g.add_argument("--all", action="store_true", help="every tracked lab")
    g.add_argument("--root", type=Path, help="repository root (default: git top)")
    g = p.add_argument_group("inputs")
    g.add_argument(
        "--inventory",
        type=Path,
        metavar="FILE",
        help="host inventory JSON from `eve-analyze inventory` (default: probe here)",
    )
    g.add_argument(
        "--answers",
        action="append",
        default=[],
        type=Path,
        metavar="FILE",
        help="answers TOML, JSON {id: value} or filled scan --json (repeatable)",
    )
    g.add_argument("--save-answers", type=Path, metavar="FILE")
    g = p.add_argument_group("behaviour")
    g.add_argument(
        "--latest",
        action="store_true",
        help="recommend the newest image even when the lab's image is present",
    )
    g.add_argument("--dry-run", action="store_true", help="never write")
    g.add_argument(
        "-y", "--yes", action="store_true", help="accept recommendations, no prompts"
    )
    g.add_argument("--non-interactive", action="store_true", help="never prompt")
    g.add_argument(
        "--strict",
        action="store_true",
        help="unanswered required questions fail (scan: any problem fails)",
    )
    g.add_argument("--force-running", action="store_true")
    g.add_argument("--no-backup", action="store_true")
    g = p.add_argument_group("git")
    g.add_argument("--no-commit", action="store_true", help="write files only")
    g.add_argument("--branch", metavar="NAME", help="commit on this branch")
    g.add_argument(
        "--upstream",
        metavar="OWNER/REPO",
        help=f"upstream repository (default ${gitops.UPSTREAM_ENV} or "
        f"{gitops.UPSTREAM})",
    )
    g = p.add_argument_group("output")
    g.add_argument("--json", action="store_true")
    g.add_argument("--no-color", action="store_true")
    g.add_argument("-v", "--verbose", action="count", default=0)
    g.add_argument("-q", "--quiet", action="store_true")
    return p


def _split_command(argv: list[str]) -> tuple[str, list[str]]:
    for i, tok in enumerate(argv):
        if tok.startswith("-"):
            continue
        if tok in COMMANDS:
            return ALIASES.get(tok, tok), argv[:i] + argv[i + 1 :]
        break
    return "run", argv


# --------------------------------------------------------------------------- #
# Session
# --------------------------------------------------------------------------- #


@dataclass
class Session:
    cmd: str
    args: argparse.Namespace
    ui: Console
    rt: Runtime
    root: Path
    inv: HostInventory = field(default_factory=HostInventory)
    answers: dict[str, str] = field(default_factory=dict)
    codes: list[int] = field(default_factory=list)

    def code(self, value: int) -> None:
        if value:
            self.codes.append(value)

    @property
    def exit_code(self) -> int:
        cs = set(self.codes)
        return next((c for c in EXIT_PRIORITY if c in cs), 0)


@dataclass
class LabResult:
    rel: str
    report: LabReport | None = None
    error: str | None = None
    changes: list[Change] = field(default_factory=list)
    written: bool = False


def _inventory(sess: Session) -> HostInventory:
    if sess.args.inventory is not None:
        return HostInventory.load(sess.args.inventory)
    return probe(sess.rt.roots)


def _require_eve(sess: Session) -> None:
    if not sess.inv.eve:
        raise PreconditionError(
            "no /opt/unetlab/addons here: run this on the EVE host, or take an "
            "inventory there (eve-analyze inventory > host.json) and pass "
            "--inventory host.json",
            code="NOT_EVE_HOST",
        )


def _lab_paths(sess: Session) -> list[Path]:
    names = list(sess.args.labs) + list(sess.args.lab)
    if names and not sess.args.all:
        return labfiles.resolve_lab_names(sess.root, names)
    labs = [p.resolve() for p in labfiles.all_labs(sess.root)]
    if not labs:
        raise EveLabError(f"no labs under {sess.root}", code="NO_LAB")
    return labs


def _analyse(sess: Session, paths: Sequence[Path]) -> list[LabResult]:
    out: list[LabResult] = []
    for path in paths:
        rel = labfiles.rel_path(sess.root, path)
        try:
            lab = RawLab.read(path)
        except EveLabError as exc:
            out.append(LabResult(rel, error=f"{rel}: {exc}"))
            sess.code(exc.exit_code)
            continue
        rep = analyse_lab(lab, rel, sess.inv, latest=sess.args.latest, root=sess.root)
        out.append(LabResult(rel, report=rep))
    return out


def _status(r: LabResult) -> str:
    if r.report is None:
        return "unreadable"
    req = sum(1 for q in r.report.questions if q.required)
    opt = len(r.report.questions) - req
    warn = sum(1 for f in r.report.findings if f.severity != "info")
    parts = []
    if req:
        parts.append(f"{req} to fix")
    if opt:
        parts.append(f"{opt} upgrade{'s' if opt != 1 else ''}")
    if warn:
        parts.append(f"{warn} warning{'s' if warn != 1 else ''}")
    return ", ".join(parts) or "ok"


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def _host_lines(inv: HostInventory) -> list[str]:
    def n(xs: Sequence[str] | None) -> str:
        return "?" if xs is None else str(len(xs))

    mem = f"{inv.mem_mb} MB" if inv.mem_mb else "?"
    kvm = {True: "yes", False: "NO", None: "?"}[inv.kvm]
    bridges = ", ".join(f"{k} {v}" for k, v in inv.bridges.items()) or "none"
    return [
        f"host {inv.hostname or '?'}: {inv.cpus or '?'} CPUs, {mem} RAM, kvm {kvm}",
        f"  images: qemu {n(inv.qemu_images)}, iol {n(inv.iol_images)}, "
        f"dynamips {n(inv.dynamips_images)}, docker {n(inv.docker_images)}; "
        f"templates {n(inv.templates)}; qemu builds "
        + (", ".join(inv.qemu_versions) if inv.qemu_versions else "?"),
        f"  bridges: {bridges}",
    ]


def _question_rows(q: Question) -> list[str]:
    names = ", ".join(n for _, n in q.nodes[:6])
    more = f" +{len(q.nodes) - 6}" if len(q.nodes) > 6 else ""
    tag = "fix" if q.required else "upgrade"
    rec = q.recommended or KEEP
    return [
        f"  [{tag}] {q.id}",
        f"      {q.reason} ({names}{more})",
        f"      recommended: {rec}",
    ]


def _show_report(sess: Session, r: LabResult) -> None:
    ui = sess.ui
    if r.report is None:
        ui.error(r.error or f"{r.rel}: unreadable")
        return
    nodes = len(r.report.lab.nodes())
    ui.heading(f"{r.rel} ({nodes} node{'s' if nodes != 1 else ''}): {_status(r)}")
    ui.findings(r.report.findings)
    for q in r.report.questions:
        ui.lines(sanitize(line) for line in _question_rows(q))


def _finding_json(f: Finding) -> dict[str, Any]:
    return {"code": f.code, "severity": f.severity, "msg": f.msg, "refs": f.refs}


def _emit_json(sess: Session, data: object) -> None:
    out = sess.rt.stdout if sess.rt.stdout is not None else sys.stdout
    out.write(json.dumps(data, indent=2, sort_keys=False) + "\n")
    out.flush()


def change_lines(changes: Sequence[Change]) -> list[str]:
    """One line per (attribute, old, new) with the nodes it applies to."""
    groups: dict[tuple[str, str, str], list[str]] = {}
    for c in changes:
        groups.setdefault((c.attr, c.old, c.new), []).append(c.node_name)
    return [
        sanitize(f"  {attr}: {old or '(none)'} -> {new}  ({', '.join(nodes)})")
        for (attr, old, new), nodes in groups.items()
    ]


# --------------------------------------------------------------------------- #
# Questions
# --------------------------------------------------------------------------- #


def _resolve_index(q: Question, raw: str) -> str:
    if q.kind in _PICKABLE_KINDS and raw.isdigit():
        i = int(raw)
        if 1 <= i <= len(q.choices):
            return q.choices[i - 1].value
    return raw


def _ask(sess: Session, q: Question, pos: tuple[int, int]) -> str:
    """Answer for ``q``: a carried/file answer, the prompt, or the defaults."""
    ui = sess.ui
    given = sess.answers.get(q.id)
    if given is not None:
        err = q.validate(given)
        if err is None:
            return given
        if ui.mode != "interactive":
            raise EveLabError(f"answer for {q.id}: {given!r}: {err}", code="BAD_ANSWER")
        ui.warn(f"answer for {q.id} ignored: {given!r}: {err}")
    if ui.mode == "yes":
        return q.recommended or KEEP
    if ui.mode == "keep":
        if q.required:
            ui.unanswered.append(q.id)
            if ui.strict:
                raise UnansweredError(f"unanswered question: {q.id} ({q.reason})")
        return KEEP
    names = ", ".join(n for _, n in q.nodes)
    ui.out(f" {pos[0]}/{pos[1]} {sanitize(q.reason)}")
    ui.out(f"      nodes: {sanitize(names)}")
    pickable = q.kind in _PICKABLE_KINDS
    for i, c in enumerate(q.choices, 1):
        label = f"{i}) {c.value}" if pickable else c.value
        ui.out(f"      {sanitize(label):<48} {c.note}".rstrip())
    hint = "number or value" if pickable else "value"
    reply = ui.prompt(
        f"   {q.attr} ({hint}, k=keep)",
        default=q.recommended,
        current=q.current or KEEP,
        allow_other=True,
        validate=lambda raw: q.validate(_resolve_index(q, raw)),
        evidence=[q.reason, f"nodes: {names}", f"current: {q.current or '(none)'}"],
        allow_skip=True,
    )
    if reply.action in ("skip", "back") or reply.value is None:
        return KEEP
    return _resolve_index(q, reply.value)


def answer_lab(sess: Session, r: LabResult) -> None:
    assert r.report is not None
    qs = r.report.questions
    for i, q in enumerate(qs, 1):
        value = _ask(sess, q, (i, len(qs)))
        if value in (q.current, ""):
            value = KEEP
        sess.answers[q.id] = value
    r.changes = plan_changes(r.report, sess.answers)


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #


@dataclass
class WriteCtx:
    run_id: str
    git: gitops.GitState | None
    branch_done: bool = False


def _git_ctx(sess: Session) -> gitops.GitState | None:
    if sess.args.no_commit:
        return None
    state = gitops.detect(sess.root, sess.args.upstream)
    return None if state.mode == "none" else state


def _ensure_branch(sess: Session, ctx: WriteCtx) -> None:
    """Switch to the target branch once, right before the first write."""
    if ctx.branch_done or ctx.git is None:
        return
    ctx.branch_done = True
    name = gitops.branch_name(ctx.git, sess.inv.hostname, sess.args.branch)
    if name is not None:
        gitops.switch_branch(ctx.git, name)
        sess.ui.note(f"on branch {name} ({ctx.git.reason})")


def _preflight(sess: Session, r: LabResult) -> bool:
    assert r.report is not None
    fs = hostenv.runtime_findings(
        r.report.lab.lab_id,
        force_running=sess.args.force_running,
        proc=sess.rt.proc,
        tmp_root=sess.rt.tmp_root,
        docker_names=sess.rt.docker_names,
    )
    sess.ui.findings([f for f in fs if f.severity != "info" or sess.ui.verbosity > 0])
    if any(f.severity == "blocker" for f in fs):
        sess.code(4)
        sess.ui.error(f"{r.rel}: not written (stop and wipe its nodes first)")
        return False
    return True


def _write(sess: Session, r: LabResult, ctx: WriteCtx) -> None:
    assert r.report is not None
    if not _preflight(sess, r):
        return
    _ensure_branch(sess, ctx)
    backup = None
    if not sess.args.no_backup:
        backup = sess.root / STATE_DIR / "backups" / ctx.run_id / r.rel
    peers = labfiles.all_labs(sess.root)
    try:
        write_lab(r.report.lab, r.changes, backup=backup, peers=peers)
    except EveLabError as exc:
        sess.code(exc.exit_code)
        sess.ui.error(f"{r.rel}: {exc.code}: {exc}")
        return
    r.written = True
    sess.ui.out(f"  wrote {r.rel} ({len(r.changes)} change(s))")


def _commit(sess: Session, results: Sequence[LabResult], ctx: WriteCtx) -> None:
    written = [r for r in results if r.written and r.report is not None]
    if not written:
        return
    if ctx.git is None:
        if not sess.args.no_commit:
            sess.ui.note("not a git checkout: files written, nothing committed")
        return
    host = sess.inv.hostname or "this host"
    body = "\n".join(
        f"- {r.rel}: "
        + ", ".join(sorted({f"{c.attr} {c.old} -> {c.new}" for c in r.changes}))
        for r in written
    )
    msg = (
        f"chore(labs): Use images and settings available on {host}\n\n"
        f"Generated by eve-analyze {__version__}.\n\n{body}\n"
    )
    labs = [(Path(r.report.lab.path), r.changes) for r in written if r.report]
    try:
        res = gitops.commit_changes(ctx.git, labs, msg)
    except EveLabError as exc:
        sess.code(1)
        sess.ui.error(f"commit failed ({exc}); the changes are in the working tree")
        return
    for rel, why in res.skipped.items():
        sess.ui.warn(f"{rel}: not committed: {why}")
    if res.sha:
        where = ctx.git.branch or "HEAD"
        sess.ui.out(
            f"committed {res.sha[:12]} on {where} ({len(res.committed)} lab(s))"
        )


def _run_id(sess: Session) -> str:
    return sess.rt.clock().strftime("%Y%m%dT%H%M%SZ")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def cmd_inventory(sess: Session) -> None:
    _emit_json(sess, sess.inv.to_json())


def cmd_scan(sess: Session) -> None:
    _require_eve(sess)
    results = _analyse(sess, _lab_paths(sess))
    problems = any(
        r.report is None
        or any(q.required for q in r.report.questions)
        or any(f.severity != "info" for f in r.report.findings)
        for r in results
    )
    if sess.args.json:
        _emit_json(
            sess,
            {
                "schema": 1,
                "host": sess.inv.to_json(),
                "labs": [
                    {
                        "lab": r.rel,
                        "lab_id": r.report.lab.lab_id if r.report else None,
                        "error": r.error,
                        "findings": [
                            _finding_json(f)
                            for f in (r.report.findings if r.report else [])
                        ],
                        "questions": [
                            q.to_json()
                            for q in (r.report.questions if r.report else [])
                        ],
                    }
                    for r in results
                ],
            },
        )
    else:
        sess.ui.lines(_host_lines(sess.inv))
        sess.ui.out()
        for r in results:
            _show_report(sess, r)
    if problems and sess.args.strict:
        sess.code(2)


def _pick(sess: Session, results: list[LabResult]) -> list[LabResult]:
    explicit = bool(sess.args.labs or sess.args.lab or sess.args.all)
    todo = [r for r in results if r.report is not None and r.report.questions]
    if explicit or sess.ui.mode != "interactive" or not todo:
        return todo
    rows = [PickerRow(r.rel, _status(r), r in todo) for r in results]
    picked = sess.ui.pick_labs(rows, title="Labs")
    return [results[i] for i in picked]


def cmd_run(sess: Session) -> None:
    _require_eve(sess)
    ui = sess.ui
    for f in sess.args.answers:
        sess.answers.update(load_answers(f))
    results = _analyse(sess, _lab_paths(sess))
    if not sess.args.json:
        ui.lines(_host_lines(sess.inv))
        ui.out()
        for r in results:
            if r.error:
                ui.error(r.error)
            elif r.report is not None and r.report.findings:
                ui.heading(f"{r.rel}: {_status(r)}")
                ui.findings(r.report.findings)
    chosen = _pick(sess, results)
    if not chosen:
        ui.out("Nothing to change on this host.")
    for r in chosen:
        assert r.report is not None
        ui.heading(f"== {r.rel}")
        answer_lab(sess, r)
        if not r.changes:
            ui.out("  no changes")
            continue
        ui.lines(change_lines(r.changes))
    if sess.args.save_answers is not None:
        save_answers(sess.args.save_answers, sess.answers, sess.inv.hostname)
        ui.note(f"answers saved to {sess.args.save_answers}")
    pending = [r for r in chosen if r.changes]
    if sess.args.json:
        _emit_json(
            sess,
            {
                "schema": 1,
                "labs": [
                    {
                        "lab": r.rel,
                        "changes": [c.__dict__ for c in r.changes],
                    }
                    for r in pending
                ],
            },
        )
    if not pending or sess.args.dry_run:
        if pending:
            ui.out("Dry run: nothing written.")
        return
    if sess.cmd == "run" and ui.mode == "keep":
        ui.note("not interactive: nothing written (use apply, or --yes)")
        return
    if sess.cmd == "run" and ui.mode == "interactive":
        total = sum(len(r.changes) for r in pending)
        if not ui.ask_yes_no(
            f"Write {total} change(s) to {len(pending)} lab(s)?", default=True
        ):
            ui.out("Nothing written.")
            return
    ctx = WriteCtx(run_id=_run_id(sess), git=_git_ctx(sess))
    lock = hostenv.exclusive_lock(sess.root / STATE_DIR / "lock")
    with lock:
        for r in pending:
            _write(sess, r, ctx)
        _commit(sess, pending, ctx)
    if any(r.written for r in pending) and not sess.args.no_backup:
        ui.note(f"backups: {STATE_DIR}/backups/{ctx.run_id}/")


HANDLERS: dict[str, Callable[[Session], None]] = {
    "run": cmd_run,
    "plan": cmd_run,
    "apply": cmd_run,
    "scan": cmd_scan,
    "inventory": cmd_inventory,
}


def main(argv: Sequence[str] | None = None, runtime: Runtime | None = None) -> int:
    rt = runtime or Runtime()
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd, rest = _split_command(argv)
    parser = build_parser()
    try:
        args = parser.parse_args(rest)
    except SystemExit as exc:  # --help / --version / usage errors
        return int(exc.code or 0) if isinstance(exc.code, int) else 1
    if cmd == "plan":
        args.dry_run = True
    interactive = rt.interactive
    if args.non_interactive or args.json or cmd == "apply":
        interactive = False
    verbosity = -1 if args.quiet or args.json else min(args.verbose, 1)
    ui = Console(
        rt.stdin,
        rt.stdout,
        rt.stderr,
        interactive=interactive,
        assume_yes=args.yes,
        strict=args.strict,
        color=False if args.no_color else None,
        verbosity=verbosity,
        env=rt.env,
    )
    try:
        root = labfiles.find_root(args.root)
        sess = Session(cmd, args, ui, rt, root)
        sess.inv = _inventory(sess)
        HANDLERS[cmd](sess)
        if ui.unanswered and cmd != "scan":
            ui.warn(
                f"{len(ui.unanswered)} required question(s) unanswered: "
                + ", ".join(ui.unanswered)
            )
        return sess.exit_code
    except QuitRequested:
        ui.out("Quit: nothing written.")
        return 0
    except UnansweredError as exc:
        ui.error(str(exc))
        return 3
    except EveLabError as exc:
        ui.error(f"{exc.code}: {exc}")
        return exc.exit_code
    except KeyboardInterrupt:
        ui.error("interrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
