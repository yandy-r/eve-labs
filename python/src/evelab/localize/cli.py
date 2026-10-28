"""Command line interface (design sections 10, 12 and 13).

``scripts/eve-localize`` is a thin shim around :func:`main`. Everything here is
orchestration: lab selection, profile/answers loading, the question loop, review,
and handing plans to :mod:`evelab.localize.apply`. No module below the CLI prints.

Commands (default ``run``)::

    run | localize       interactive flow: picker -> questions -> review -> apply
    scan | list          analysis only (matrix, findings); --json = question schema
    plan                 build plans and show the diff; never writes
    apply                build (or --plan FILE) and apply
    revert               apply the baselines (state.json / manifest) as targets
    undo [RUN]           restore a journaled run's backups (sha guarded)
    runs                 list journal entries
    check | localize-check   CI: manifests vs discovery, leaks, "reverted by EVE?"
    discover LAB         draft manifest (stdout); --write / --update
    explain LAB          fact dump; --edit ID explains one planned edit
    profile              --example | --wizard

Exit codes: 0 ok / nothing to do / quit, 1 error, 2 conflicts or blockers,
3 unanswered under --strict, 4 precondition failed, 5 validation failed.
"""

from __future__ import annotations

import argparse
import copy
import difflib
import json
import os
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import IO, Any

from evelab.common import hostenv
from evelab.common.paths import REPO_ROOT, SCRIPTS_DIR
from evelab.common.unl import RawLab

from . import SCHEMA, __version__, apply, manifest, planner, profile
from .discover import AnalyseOptions, analyse
from .errors import LocalizeError
from .manifest import Baseline, Manifest
from .model import Analysis, Edit, Finding, Plan, Segment
from .profile import Answers, LabOverride, Profile, SegmentAnswer
from .scenarios import PARAM_KINDS, Question, apply_answer, load_builtin
from .scenarios.base import (
    ValueMaps,
    canonical_scheme,
    current_bridge,
    primary_label,
)
from .ui import UI, PickerRow, QuitRequested, UnansweredError, sanitize

__all__ = ["COMMANDS", "Runtime", "build_parser", "main"]

COMMANDS = (
    "run",
    "localize",
    "scan",
    "list",
    "plan",
    "apply",
    "revert",
    "undo",
    "runs",
    "check",
    "localize-check",
    "discover",
    "explain",
    "profile",
)
ALIASES = {"localize": "run", "list": "scan", "localize-check": "check"}
WRITING = ("run", "apply", "revert")
EXIT_PRIORITY = (5, 4, 3, 2, 1)
BLOCKING = ("conflict", "blocker", "error")
_ANSWER_SOURCES = ("from ", "map.", "scenarios.", "site_routes.")
_SEV_RANK = {"info": 0, "warn": 1, "conflict": 2, "blocker": 3, "error": 4}
EXAMPLE_PROFILE = Path("localize") / "site.example.toml"
DEFAULT_PROFILE = Path(".localize") / "site.toml"
PLUGINS_ENV = "EVE_LOCALIZE_PLUGINS"
FIX_PERMS = SCRIPTS_DIR / "fix-lab-permissions.sh"
# manifest param key/kind -> services [map.<kind>]
_PARAM_MAP_KIND = {"dns": "dns", "ntp": "ntp", "domain": "domain", "sla": "probe"}


# --------------------------------------------------------------------------- #
# Runtime (injectable I/O and host probes, for tests)
# --------------------------------------------------------------------------- #


@dataclass
class Runtime:
    """Streams and host probe roots; tests inject fakes (never the real /proc)."""

    stdin: IO[str] | None = None
    stdout: IO[str] | None = None
    stderr: IO[str] | None = None
    env: Mapping[str, str] | None = None
    interactive: bool | None = None
    getpass_fn: Callable[[str], str] | None = None
    proc: Path = hostenv.PROC
    tmp_root: Path = hostenv.UNETLAB_TMP
    docker_names: Callable[[], Iterable[str]] = hostenv.docker_container_names
    sys_net: Path = hostenv.SYS_NET
    check_labs_peers: Sequence[Path] | None = None
    use_fcntl: bool | None = None


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

_EPILOG = """commands (default: run):
  run|localize     interactive flow: lab picker -> questions -> review -> apply
  scan|list        analysis only: segment/scheme matrix, findings (--json: questions)
  plan             build plan + diff; never writes (same as run --dry-run)
  apply            build (or --plan FILE) and apply
  revert           apply the recorded/manifest baselines as targets
  undo [RUN]       restore a journaled run's backups (sha-guarded)
  runs             list journal entries
  check            CI: manifests vs discovery, leaks, unpinned, "reverted by EVE?"
  discover LAB     print draft manifest; --write -> .draft; --update refreshes
  explain LAB      fact dump with confidence/evidence; --edit ID explains an edit
  profile          --example (regenerate localize/site.example.toml) | --wizard

exit codes: 0 ok/nothing to do, 1 error, 2 conflicts/blockers, 3 unanswered
(--strict), 4 precondition failed, 5 validation failed (rolled back)"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eve-localize",
        usage="%(prog)s [COMMAND] [LAB ...] [options]",
        description="Relocate EVE-NG labs to your site: cloud bridges, VLAN tags, "
        "subnets, gateways, labels and services.",
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
        "--profile",
        action="append",
        default=[],
        type=Path,
        metavar="FILE",
        help="site profile TOML (repeatable; default .localize/site.toml)",
    )
    g.add_argument(
        "--answers",
        action="append",
        default=[],
        type=Path,
        metavar="FILE",
        help="answers TOML, or JSON {question id: value} / filled scan --json",
    )
    g.add_argument("--save-answers", type=Path, metavar="FILE")
    g.add_argument(
        "--save-secrets", action="store_true", help="write secrets into answers"
    )
    g.add_argument("--plan", type=Path, metavar="FILE", help="apply a saved plan")
    g.add_argument("--save-plan", type=Path, metavar="FILE")
    g.add_argument(
        "--plugins",
        action="append",
        default=[],
        type=Path,
        metavar="DIR",
        help="extra dialects/scenarios/packs (repeatable; also "
        f"${PLUGINS_ENV}, {os.pathsep!r}-separated)",
    )
    g = p.add_argument_group("behaviour")
    g.add_argument("--dry-run", action="store_true", help="never write")
    g.add_argument(
        "-y", "--yes", action="store_true", help="accept defaults, no confirmation"
    )
    g.add_argument("--non-interactive", action="store_true", help="never prompt")
    g.add_argument(
        "--strict",
        action="store_true",
        help="unanswered questions / unpinned labs / warnings fail",
    )
    g.add_argument("--allow-unpinned", action="store_true")
    g.add_argument("--scope", metavar="NAME[,..]", help="restrict edited scopes")
    g.add_argument("--legacy", choices=("leave", "ask", "same"))
    g.add_argument("--include-heuristic", action="store_true")
    g.add_argument("--include-outliers", action="store_true")
    g.add_argument("--no-cosmetic", action="store_true")
    g.add_argument("--out", type=Path, metavar="DIR", help="copy mode (new lab id)")
    g.add_argument("--continue-on-error", action="store_true")
    g.add_argument("--list", action="store_true", help="summary table (scan)")
    g.add_argument("--check", action="store_true", help="alias of the check command")
    g.add_argument("--write", action="store_true", help="discover: write .draft")
    g.add_argument("--update", action="store_true", help="discover: refresh manifest")
    g.add_argument("--edit", metavar="ID", help="explain: one planned edit")
    g.add_argument("--example", action="store_true", help="profile: example file")
    g.add_argument("--wizard", action="store_true", help="profile: bridge wizard")
    g = p.add_argument_group("safety")
    g.add_argument("--require-clean", action="store_true")
    g.add_argument("--force-running", action="store_true")
    g.add_argument("--backup-dir", type=Path, metavar="DIR")
    g.add_argument("--no-backup", action="store_true")
    g.add_argument("--state-dir", type=Path, metavar="DIR", help=argparse.SUPPRESS)
    g.add_argument("--fix-perms", action="store_true")
    g.add_argument("--show-secrets", action="store_true")
    g = p.add_argument_group("output")
    g.add_argument(
        "--diff", choices=("none", "summary", "decoded", "raw"), default=None
    )
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
# Session and lab context
# --------------------------------------------------------------------------- #


@dataclass
class LabCtx:
    path: Path
    rel: str
    lab: RawLab | None = None
    manifest: Manifest | None = None
    analysis: Analysis | None = None
    error: str | None = None
    exit_code: int = 0

    @property
    def clouds(self) -> int:
        if self.analysis is None:
            return 0
        return sum(1 for n in self.analysis.networks.values() if n.is_cloud)


@dataclass
class Session:
    cmd: str
    args: argparse.Namespace
    ui: UI
    rt: Runtime
    root: Path
    state_dir: Path
    ans: Answers = field(default_factory=Profile)
    json_answers: dict[str, str] = field(default_factory=dict)
    codes: list[int] = field(default_factory=list)
    current: Analysis | None = None  # lab being asked (evidence rendering)

    def code(self, value: int) -> None:
        if value:
            self.codes.append(value)

    @property
    def exit_code(self) -> int:
        return worst(self.codes)


def worst(codes: Iterable[int]) -> int:
    cs = set(codes)
    return next((c for c in EXIT_PRIORITY if c in cs), 0)


def _git_top(start: Path) -> Path | None:
    try:
        res = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = res.stdout.strip()
    return Path(out).resolve() if res.returncode == 0 and out else None


def find_root(arg: Path | None) -> Path:
    if arg is not None:
        return arg.resolve()
    return _git_top(Path.cwd()) or REPO_ROOT


def all_labs(root: Path) -> list[Path]:
    """``git ls-files '*.unl'`` under ``root``; fallback: rglob (no dot dirs)."""
    paths: list[Path] = []
    if _git_top(root) == root:
        try:
            out = subprocess.run(
                ["git", "-C", str(root), "ls-files", "-z", "--", "*.unl"],
                capture_output=True,
                timeout=30,
                check=False,
            ).stdout
            paths = [root / p for p in out.decode().split("\0") if p]
        except (OSError, subprocess.SubprocessError):
            paths = []
    if not paths:
        for p in root.rglob("*.unl"):
            rel = p.relative_to(root).parts
            if any(part.startswith(".") for part in rel[:-1]):
                continue
            paths.append(p)
    return sorted(p for p in paths if p.is_file())


def _rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return str(path)


def resolve_labs(sess: Session, names: Sequence[str]) -> list[Path]:
    """Paths for LAB arguments: existing files, else unique path substrings."""
    out: list[Path] = []
    labs: list[Path] | None = None
    root = sess.root.resolve()
    for name in names:
        # A relative path is resolved against --root first; a CWD-relative or
        # absolute path is accepted only if it lies under --root, so the lab
        # written and its state/journal belong to the same tree (review #37).
        cand = [Path(name)] if Path(name).is_absolute() else [root / name, Path(name)]
        hit = next((c for c in cand if c.is_file()), None)
        if hit is not None:
            if not hit.resolve().is_relative_to(root):
                raise LocalizeError(
                    f"{name!r} resolves to {hit.resolve()}, outside --root {root}",
                    code="LAB_OUTSIDE_ROOT",
                )
            out.append(hit.resolve())
            continue
        if labs is None:
            labs = all_labs(sess.root)
        low = name.lower()
        matches = [p for p in labs if low in _rel(sess.root, p).lower()]
        if len(matches) > 1:
            exact = [p for p in matches if p.stem.lower() == low]
            matches = exact or matches
        if not matches:
            raise LocalizeError(f"no lab matches {name!r}", code="NO_LAB")
        if len(matches) > 1:
            listing = ", ".join(_rel(sess.root, p) for p in matches)
            raise LocalizeError(
                f"{name!r} matches several labs: {listing}", code="AMBIGUOUS_LAB"
            )
        out.append(matches[0].resolve())
    seen: list[Path] = []
    for p in out:
        if p not in seen:
            seen.append(p)
    return seen


def _cloud_count(path: Path) -> int | None:
    try:
        lab = RawLab.read(path)
    except LocalizeError:
        return None
    return sum(1 for n in lab.networks() if n.get("type", "bridge") != "bridge")


def select_labs(sess: Session, *, default_all: bool = False) -> list[Path]:
    a = sess.args
    names = list(a.labs) + list(a.lab)
    if a.all or (default_all and not names):
        return [p.resolve() for p in all_labs(sess.root)]
    if names:
        return resolve_labs(sess, names)
    labs = all_labs(sess.root)
    if not labs:
        raise LocalizeError(f"no labs under {sess.root}", code="NO_LAB")
    state = _load_state(sess)
    rows: list[PickerRow] = []
    for p in labs:
        n = _cloud_count(p)
        lab_id = manifest.read_lab_id(p) or ""
        if n is None:
            rows.append(PickerRow(_rel(sess.root, p), "unreadable", False))
        elif n == 0:
            rows.append(PickerRow(_rel(sess.root, p), "nothing to localize", False))
        else:
            st = f"{n} cloud network{'s' if n != 1 else ''}"
            if manifest.manifest_path_for(p).is_file():
                st += ", manifest"
            if state.get(lab_id, {}).get("localized"):
                st += ", localized"
            rows.append(PickerRow(_rel(sess.root, p), st))
    picked = sess.ui.pick_labs(rows)
    return [labs[i].resolve() for i in picked]


def _load_state(sess: Session) -> dict[str, Any]:
    try:
        return apply.load_state(apply.ApplyOptions(state_dir=sess.state_dir))
    except LocalizeError as exc:
        sess.ui.warn(str(exc))
        return {}


def plugin_dirs(sess: Session) -> list[Path]:
    """``--plugins DIR`` arguments, then ``$EVE_LOCALIZE_PLUGINS`` entries."""
    env = sess.rt.env if sess.rt.env is not None else os.environ
    dirs = [Path(p) for p in sess.args.plugins]
    dirs += [Path(p) for p in env.get(PLUGINS_ENV, "").split(os.pathsep) if p]
    out: list[Path] = []
    for d in dirs:
        if d.resolve() not in [o.resolve() for o in out]:
            out.append(d)
    return out


def load_plugins(sess: Session) -> None:
    """Built-in dialects and scenarios first, then the plugin dirs, so a
    plugin clashing with a built-in is reported (``DIALECT_DUPLICATE`` /
    ``SCENARIO_DUPLICATE``) against the plugin file, deterministically."""
    from . import dialects

    dialects.load_builtin()
    load_builtin()
    dirs = plugin_dirs(sess)
    if dirs:
        dialects.load_packs(dirs)


def used_plugin_dialects(a: Analysis) -> dict[str, str]:
    """``{dialect: plugin source file}`` for the plugin dialects ``a`` parsed
    texts with (recorded in ``state.json`` by apply; review fix #27)."""
    from . import dialects

    return {
        ct.dialect: dialects.PLUGIN_SOURCES[ct.dialect]
        for ct in a.texts
        if ct.dialect in dialects.PLUGIN_SOURCES
    }


def check_recorded_dialects(rel: str, entry: Mapping[str, Any] | None) -> None:
    """Refuse (UNKNOWN_DIALECT) to work on a lab localized with plugin
    dialects that are not loaded now: re-planning without them would leave
    their values localized while revert reports success and check says ok."""
    from . import dialects

    recorded = (entry or {}).get("plugin_dialects") or {}
    if not isinstance(recorded, Mapping):
        return
    missing = {n: src for n, src in recorded.items() if n not in dialects.REGISTRY}
    if not missing:
        return
    dirs = sorted({str(Path(str(src)).parent) for src in missing.values()})
    raise LocalizeError(
        f"{rel}: localized with plugin dialect(s) "
        f"{', '.join(sorted(missing))} that are not loaded; pass "
        + " ".join(f"--plugins {d}" for d in dirs)
        + f" (or set {PLUGINS_ENV})",
        code="UNKNOWN_DIALECT",
    )


def load_lab(sess: Session, path: Path) -> LabCtx:
    lc = LabCtx(path=path, rel=_rel(sess.root, path))
    try:
        lc.lab = RawLab.read(path)
    except LocalizeError as exc:
        lc.error, lc.exit_code = f"{lc.rel}: {exc}", exc.exit_code
        return lc
    try:
        lc.manifest = manifest.find_for(path)
    except LocalizeError as exc:
        lc.error, lc.exit_code = f"{lc.rel}: {exc}", exc.exit_code
        return lc
    aopts = AnalyseOptions(include_outliers=sess.args.include_outliers)
    try:
        check_recorded_dialects(lc.rel, _load_state(sess).get(lc.lab.lab_id))
        lc.analysis = analyse(lc.lab, lc.manifest, aopts)
    except LocalizeError as exc:
        lc.error, lc.exit_code = f"{lc.rel}: {exc}", exc.exit_code
        if exc.code == "UNKNOWN_DIALECT":
            lc.error = f"{exc.code}: {exc}"
    return lc


# --------------------------------------------------------------------------- #
# Profile and answers
# --------------------------------------------------------------------------- #


def _stringify(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list | tuple):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def parse_json_answers(data: object, source: str) -> dict[str, str]:
    """``{"answers": {id: value}}``, a plain ``{id: value}`` or a filled scan --json."""
    out: dict[str, str] = {}
    if not isinstance(data, dict):
        raise LocalizeError(f"{source}: expected a JSON object", code="ANSWERS")
    if isinstance(data.get("labs"), list):
        for lab in data["labs"]:
            for q in lab.get("questions", []) if isinstance(lab, dict) else []:
                if not isinstance(q, dict) or "id" not in q:
                    continue
                for key in ("answer", "value"):
                    val = _stringify(q.get(key))
                    if val is not None:
                        out[str(q["id"])] = val
                        break
        return out
    table = data.get("answers", data)
    if not isinstance(table, dict):
        raise LocalizeError(f"{source}: 'answers' must be an object", code="ANSWERS")
    for k, v in table.items():
        if k == "schema":
            continue
        val = _stringify(v)
        if val is not None:
            out[str(k)] = val
    return out


def _repo_answer_prefixes(sess: Session) -> set[str]:
    """Question-id prefixes valid somewhere in the repo: every committed
    manifest segment ``site_key`` and every registered scenario id."""
    from .scenarios import SCENARIOS

    out = set(SCENARIOS)
    for path in all_labs(sess.root):
        mpath = manifest.manifest_path_for(path)
        if not mpath.is_file():
            continue
        try:
            m = manifest.find_for(path)
        except LocalizeError:
            continue
        if m is not None:
            out.update(ms.site_key for ms in m.segments if ms.site_key)
    return out


def check_unused_answers(
    sess: Session, seen: set[str], site_keys: Iterable[str] = ()
) -> bool:
    """Warn about ``--answers`` JSON ids that matched no question (review #36).

    ``seen``: the question ids of the labs processed; ``site_keys``: their
    segment site keys (for TOML profile ``[segments.KEY]`` tables).  An unused id whose
    prefix (``<site_key>/`` or ``<scenario>/``) belongs to a processed lab is
    "not a question of this lab" (typo, stale id, e.g. ``vlan`` of an untagged
    segment); with ``--all`` every unused id is unknown; on a subset run an id
    whose prefix is valid elsewhere in the repo belongs to another lab and is
    ignored (answers files are site-wide).  Under ``--strict`` an unknown id
    is an error (returns False, exit 1); otherwise a warning.
    """
    a = sess.args
    seen_prefixes = {q.split("/", 1)[0] for q in seen}
    repo: set[str] | None = None
    # TOML profile segment keys are site-wide: warn (never fail) only for a
    # key no processed lab and no committed manifest knows.
    known = set(site_keys) | seen_prefixes
    stray = [k for k in sess.ans.segments if k not in known]
    if stray and known:
        repo = _repo_answer_prefixes(sess)
        for key in sorted(k for k in stray if k not in repo):
            close = difflib.get_close_matches(key, sorted(repo), n=3, cutoff=0.6)
            hint = f" (did you mean {', '.join(close)}?)" if close else ""
            sess.ui.warn(
                f"profile [segments.{key!r}] matches no segment of any lab{hint}"
            )
    unused = sorted(set(sess.json_answers) - seen)
    if not unused:
        return True
    bad: list[str] = []
    for key in unused:
        prefix, _, rest = key.partition("/")
        if a.all or (prefix in seen_prefixes and ":" not in rest):
            bad.append(key)
            continue
        if prefix in seen_prefixes:
            continue  # per-value id (services/dns:X) of another lab
        if repo is None:
            repo = _repo_answer_prefixes(sess)
        if prefix not in repo:
            bad.append(key)
    if not bad:
        return True
    for key in bad:
        close = difflib.get_close_matches(key, sorted(seen), n=3, cutoff=0.6)
        hint = f" (did you mean {', '.join(close)}?)" if close else ""
        msg = f"answer {key!r} matches no question of the selected labs{hint}"
        if a.strict:
            sess.ui.error(f"BAD_ANSWER: {msg}")
        else:
            sess.ui.warn(f"{msg}: ignored")
    if a.strict:
        sess.code(1)
        return False
    return True


def load_inputs(sess: Session) -> None:
    a = sess.args
    toml_paths: list[Path] = []
    for p in list(a.profile) + list(a.answers):
        if p.suffix.lower() == ".json":
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise LocalizeError(f"{p}: cannot read answers: {exc}") from exc
            sess.json_answers.update(parse_json_answers(data, str(p)))
        else:
            toml_paths.append(p)
    if not a.profile and not a.answers:
        default = sess.root / DEFAULT_PROFILE
        if default.is_file():
            toml_paths.append(default)
    sess.ans = profile.load_profile(toml_paths)
    if a.legacy == "ask":
        sess.ans.policy.legacy_scopes = "ask"
    if toml_paths and sess.ui.verbosity >= 0 and not a.json:
        names = ", ".join(_rel(sess.root, p) for p in toml_paths)
        nseg = len(sess.ans.segments)
        nmap = sum(len(v) for v in sess.ans.maps.values())
        host = hostenv.bridges_summary(hostenv.list_bridges(sys_net=sess.rt.sys_net))
        sess.ui.out(
            f"Profile: {names} ({nseg} segment answers, {nmap} value maps)"
            f" · host: {host}"
        )


def _written_labels(sess: Session, lc: LabCtx) -> tuple[str, ...]:
    """Labels an earlier apply propagated into device text (state.json)."""
    if lc.lab is None:
        return ()
    entry = _load_state(sess).get(lc.lab.lab_id) or {}
    table = entry.get("baseline_text_labels") if isinstance(entry, dict) else None
    return tuple(sorted(table)) if isinstance(table, dict) else ()


def plan_options(sess: Session, lc: LabCtx) -> planner.PlanOptions:
    a = sess.args
    return planner.PlanOptions(
        written_labels=_written_labels(sess, lc),
        manifest=lc.manifest,
        lab_id=lc.lab.lab_id if lc.lab is not None else None,
        include_heuristic=True if a.include_heuristic else None,
        cosmetic_text=False if a.no_cosmetic else None,
        include_outliers=a.include_outliers,
        legacy_scopes=a.legacy if a.legacy in ("leave", "same") else None,
    )


# --------------------------------------------------------------------------- #
# Display helpers
# --------------------------------------------------------------------------- #


def _store_line(a: Analysis) -> str:
    startup = sum(1 for t in a.texts if t.store.kind == "startup")
    cs: Counter[str] = Counter(
        t.store.name for t in a.texts if t.store.kind == "configset"
    )
    side: Counter[str] = Counter(
        Path(t.store.name).parent.as_posix() or "."
        for t in a.texts
        if t.store.kind == "sidecar"
    )
    tob = sum(1 for t in a.texts if t.store.kind == "textobject")
    parts = [f"startup ({startup} blobs)"]
    parts += [f"configset {n} ({c})" for n, c in cs.items()]
    parts += [f"sidecar {d} ({c} files)" for d, c in side.items()]
    if tob:
        parts.append(f"textobjects ({tob})")
    return "Stores: " + " · ".join(parts)


def _show_findings(ui: UI, findings: Sequence[Finding], verbose: int) -> None:
    floor = 0 if verbose > 0 else 1
    shown = [f for f in findings if _SEV_RANK.get(f.severity, 0) >= floor]
    hidden = len(findings) - len(shown)
    if verbose <= 0:
        per: Counter[tuple[str, str]] = Counter((f.severity, f.code) for f in shown)
        seen: Counter[tuple[str, str]] = Counter()
        folded: list[Finding] = []
        for f in shown:
            k = (f.severity, f.code)
            seen[k] += 1
            if per[k] <= 3 or seen[k] <= 2:
                folded.append(f)
            elif seen[k] == 3:
                folded.append(
                    Finding(f.code, f.severity, f"... and {per[k] - 2} more (-v)")
                )
        shown = folded
    if shown:
        ui.findings(shown)
    if hidden:
        ui.out(f"  ({hidden} info finding{'s' if hidden != 1 else ''}; -v shows them)")


def lab_header(sess: Session, lc: LabCtx) -> None:
    ui, a = sess.ui, lc.analysis
    assert a is not None
    if lc.manifest is not None:
        pin = "pinned: manifest OK" if a.pinned else "manifest: drift (see findings)"
    else:
        pin = "unpinned: no manifest"
    ui.heading(f"Lab: {lc.rel}  [{pin}]")
    ui.out(_store_line(a))
    if a.segments:
        ui.matrix(a.segments)
    _show_findings(ui, a.findings, ui.verbosity)


def _nothing(sess: Session, lc: LabCtx) -> bool:
    a = lc.analysis
    if a is None or lc.clouds:
        return False
    if not sess.args.json:
        sess.ui.out(f"Lab: {lc.rel}")
        sess.ui.out(
            f"Nothing to localize: all {len(a.networks)} networks are internal "
            "bridges (no pnet/nat/cloud). No changes."
        )
    return True


def _fact_line(a: Analysis, fid: str) -> str:
    f = a.facts.get(fid)
    if f is None:
        if fid.startswith("network:"):
            n = a.networks.get(fid.split(":", 1)[1])
            if n is not None:
                return f"{fid}: {n.type} {n.name!r}"
        return fid
    node = a.nodes.get(f.node_id or "")
    where = f"{f.store.kind}:{f.store.name}"
    who = f" node {f.node_id} {node.name}" if node is not None else ""
    ev = f" — {f.evidence}" if f.evidence else ""
    return (
        f"{fid}: {f.kind} {f.value!r} {f.confidence.name} [{where}{who} line "
        f"{f.line} {f.rule}]{ev}"
    )


def question_dict(q: Question, ans: Answers, lab_id: str) -> dict[str, Any]:
    return {
        "id": q.id,
        "group": q.group,
        "kind": q.kind,
        "prompt": q.prompt,
        "current": q.current,
        "default": q.default,
        "default_source": q.default_source,
        "choices": q.choices,
        "depends_on": list(q.depends_on),
        "affects": q.affects,
        "segment": q.segment,
        "scenario": q.scenario,
        "notes": list(q.notes),
        "answered": is_answered(q, ans, lab_id),
        "answer": None,
    }


def segment_dict(a: Analysis, seg: Segment) -> dict[str, Any]:
    return {
        "key": seg.key,
        "site_key": seg.site_key,
        "role": seg.role,
        "status": seg.status,
        "networks": list(seg.network_ids),
        "bridge": current_bridge(a, seg),
        "labels": dict(seg.labels),
        "carries": list(seg.carries),
        "schemes": [
            {
                "tag": s.tag,
                "subnet": str(s.subnet) if s.subnet is not None else None,
                "gateway": str(s.gateway) if s.gateway is not None else None,
                "scopes": sorted(s.scopes),
                "members": len(s.members),
                "outliers": len(s.outliers),
            }
            for s in seg.schemes
        ],
    }


def finding_dict(f: Finding) -> dict[str, Any]:
    return {"code": f.code, "severity": f.severity, "msg": f.msg, "refs": f.refs}


def _emit_json(sess: Session, data: object) -> None:
    out = sess.rt.stdout or sys.stdout
    out.write(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n")
    out.flush()


# --------------------------------------------------------------------------- #
# Questions
# --------------------------------------------------------------------------- #


def is_answered(q: Question, ans: Answers, lab_id: str) -> bool:
    """The profile/answers already decide this question (no prompt needed)."""
    if q.id.endswith("/enabled") and q.kind == "bool":
        sid = q.scenario or q.id.split("/", 1)[0]
        return ans.scenario_enabled(sid, lab_id) is not None
    return q.default_source.startswith(_ANSWER_SOURCES)


def _site_key(q: Question) -> str:
    return q.id.rsplit("/", 1)[0]


def _skipped(q: Question, ans: Answers) -> bool:
    if not q.segment:
        return False
    sa = ans.segments.get(_site_key(q))
    return bool(sa is not None and sa.skip)


def _gated_off(q: Question, ans: Answers, lab_id: str) -> bool:
    for dep in q.depends_on:
        if dep.endswith("/enabled"):
            sid = dep.split("/", 1)[0]
            if ans.scenario_enabled(sid, lab_id) is not True:
                return True
    return False


def _store(sess: Session, q: Question, raw: str, origin: str) -> None:
    err = apply_answer(sess.ans, q, raw)
    if err:
        raise LocalizeError(f"{origin}: {q.id}: {err}", code="BAD_ANSWER")


def _check_answered(sess: Session, q: Question) -> None:
    """Run the prompt validators on a value the profile / TOML answers decided.

    Without a prompt nothing else would check it: a profile gateway outside the
    answered subnet, a broadcast address or an overlapping subnet must fail the
    same way a typed or JSON answer does (``BAD_ANSWER``).  The answered value
    is the question's default (``default_source`` "from ...", "map.", ...).
    """
    if q.kind in ("bool", "secret") or q.default is None:
        return
    kind = PARAM_KINDS.get(q.kind)
    if kind is None:
        err: str | None = f"unknown parameter kind {q.kind!r}"
    else:
        err = kind.validate(q.default, sess.ans) or q.validate(q.default, sess.ans)
    if err:
        raise LocalizeError(
            f"profile/answers ({q.default_source}): {q.id}: {err}", code="BAD_ANSWER"
        )


def _bridge_choices(sess: Session, q: Question) -> list[str]:
    """The question's choices plus the cloud bridges present on this host."""
    choices = list(q.choices or [])
    for name in hostenv.list_bridges(sys_net=sess.rt.sys_net):
        if name not in choices:
            choices.append(name)
    return choices


def _bridge_notes(sess: Session, choices: list[str]) -> dict[str, str]:
    notes = hostenv.bridge_notes(choices, sys_net=sess.rt.sys_net)
    for name in choices:
        bp = sess.ans.bridges.get(name)
        roles = [r for r, b in sess.ans.roles.items() if b == name]
        if bp is not None:
            roles = sorted(set(roles) | set(bp.roles))
        extra = []
        if roles:
            extra.append("roles " + ",".join(roles))
        if bp is not None and bp.mode != "trunk":
            extra.append(bp.mode)
        if extra:
            notes[name] = (notes.get(name, "") + "; " + "; ".join(extra)).strip("; ")
    return notes


def ask_questions(
    sess: Session,
    lc: LabCtx,
    popts: planner.PlanOptions,
    only: frozenset[str] | None = None,
) -> None:
    """Question loop: re-collects after every answer (defaults follow answers).

    ``only`` limits the loop to the questions of these segment keys (the
    revise pass after a blocked plan).
    """
    ui, a = sess.ui, lc.analysis
    assert a is not None and lc.lab is not None
    lab_id = lc.lab.lab_id
    asked: set[str] = set()
    history: list[tuple[str, Profile, set[str]]] = []
    group = ""
    for _guard in range(10_000):
        qs = planner.collect_questions(a, sess.ans, popts)
        live = [
            q
            for q in qs
            if not _gated_off(q, sess.ans, lab_id) and not _skipped(q, sess.ans)
        ]
        pending = [
            q for q in live if q.id not in asked and (only is None or q.segment in only)
        ]
        if not pending:
            return
        q = pending[0]
        asked.add(q.id)
        if q.id in sess.json_answers:
            _store(sess, q, sess.json_answers[q.id], "answers")
            continue
        answered = is_answered(q, sess.ans, lab_id)
        if answered and ui.mode != "interactive":
            _check_answered(sess, q)
            continue
        if q.group != group and ui.mode == "interactive":
            group = q.group
            ui.heading(f"[{group}]")
        same = [x for x in live if x.group == q.group]
        progress = (same.index(q) + 1, len(same)) if len(same) > 1 else None
        snapshot = (q.id, copy.deepcopy(sess.ans), set(asked) - {q.id})
        for note in q.notes if ui.mode == "interactive" else ():
            ui.note(note)
        action = _ask_one(sess, q, lab_id, answered, progress)
        if action == "back":
            asked.discard(q.id)
            if history:
                _qid, prev, prev_asked = history.pop()
                sess.ans, asked = prev, prev_asked
            continue
        history.append(snapshot)
    raise LocalizeError("question loop did not converge", code="QUESTION_LOOP")


def _ask_one(
    sess: Session,
    q: Question,
    lab_id: str,
    answered: bool,
    progress: tuple[int, int] | None,
) -> str:
    ui = sess.ui
    kind = PARAM_KINDS.get(q.kind)
    if q.kind == "bool":
        cur = sess.ans.scenario_enabled(q.scenario, lab_id) if answered else None
        default = cur if cur is not None else (q.default or "no").startswith("y")
        val = ui.ask_yes_no(q.prompt, default=bool(default), evidence=q.evidence)
        if ui.mode == "interactive" or (ui.mode == "yes" and not answered and val):
            _store(sess, q, "yes" if val else "no", "answer")
        return "value"
    if q.kind == "secret":
        val = ui.secret(q.prompt)
        if val:
            _store(sess, q, val, "answer")
        return "value"

    def validate(value: str) -> str | None:
        if kind is None:
            return f"unknown parameter kind {q.kind!r}"
        return kind.validate(value, sess.ans) or q.validate(value, sess.ans)

    evidence = []
    if ui.mode == "interactive" and q.evidence and sess.current is not None:
        evidence = [_fact_line(sess.current, fid) for fid in q.evidence]
    choices = _bridge_choices(sess, q) if q.kind == "bridge" else q.choices
    reply = ui.prompt(
        q.prompt,
        default=q.default,
        default_source=q.default_source if q.default_source != "keep" else "",
        current=q.current,
        choices=choices if q.kind != "site_routes" else None,
        choice_notes=_bridge_notes(sess, choices or []) if q.kind == "bridge" else None,
        allow_other=True,
        validate=validate,
        evidence=evidence,
        progress=progress,
        allow_skip=bool(q.segment),
        allow_back=True,
        required=q.current is not None or q.default is not None,
    )
    if reply.action == "back":
        return "back"
    if reply.action == "skip":
        sa = sess.ans.segments.setdefault(_site_key(q), SegmentAnswer())
        sa.skip = True
        return "skip"
    if reply.action == "keep":
        if answered and q.current is not None and ui.mode == "interactive":
            _store(sess, q, "keep" if q.kind == "site_routes" else q.current, "keep")
        return "keep"
    value = reply.value
    if value is None:
        return "keep"
    if reply.action == "default" and (answered or value == q.current):
        return "value"
    _store(sess, q, value, "answer")
    return "value"


def run_questions(
    sess: Session,
    lc: LabCtx,
    popts: planner.PlanOptions,
    only: frozenset[str] | None = None,
) -> None:
    sess.current = lc.analysis
    try:
        ask_questions(sess, lc, popts, only)
    finally:
        sess.current = None


# Answer fields a blocking finding invalidates (cleared before re-asking, so the
# segment's questions come back with the baseline as default; a split map is
# only asked while none is answered).
_REVISE_FIELDS: dict[str, tuple[str, ...]] = {
    "SUBNET_OVERLAP": ("subnet", "gateway", "split", "hosts"),
    "SPLIT_REQUIRED": ("split", "hosts"),
    "GATEWAY_INVALID": ("gateway",),
    "VLAN_DUPLICATE": ("vlan",),
}


def _show_plan(sess: Session, lc: LabCtx, plan: Plan) -> None:
    ui = sess.ui
    ui.plan_summary(planner.filter_enabled(plan))
    _show_findings(ui, plan.findings, ui.verbosity)
    mode = sess.args.diff or "summary"
    if mode in ("decoded", "raw"):
        show_diff(sess, lc, plan, mode)


def _revise_blocked(
    sess: Session, lc: LabCtx, popts: planner.PlanOptions, plan: Plan
) -> bool:
    """Offer to re-ask the segments named by the plan's blocking findings.

    Returns False (nothing changed) when no finding names a segment or the
    user declines; the caller then reports the blocked plan as before.
    """
    an = lc.analysis
    assert an is not None and lc.lab is not None
    fields: dict[str, set[str]] = {}
    for f in plan.findings:
        if f.severity not in BLOCKING:
            continue
        for ref in f.refs:
            if ref.startswith("segment:"):
                fields.setdefault(ref.split(":", 1)[1], set()).update(
                    _REVISE_FIELDS.get(f.code, ())
                )
    known = {s.key: s for s in an.segments}
    keys = sorted(k for k in fields if k in known)
    if not keys:
        return False
    if not sess.ui.ask_yes_no(
        f"Revise the answers for {', '.join(keys)}?", default=True
    ):
        return False
    lab = sess.ans.labs.get(lc.lab.lab_id)
    for key in keys:
        holders = [sess.ans.segments.get(known[key].site_key)]
        if lab is not None:
            holders.append(lab.segments.get(key))
        for sa in holders:
            for name in fields[key] if sa is not None else ():
                setattr(sa, name, None)
    run_questions(sess, lc, popts, frozenset(keys))
    return True


# --------------------------------------------------------------------------- #
# Plans: scope filter, diff, review
# --------------------------------------------------------------------------- #


def _scopes(sess: Session) -> set[str] | None:
    if not sess.args.scope:
        return None
    return {s.strip() for s in sess.args.scope.split(",") if s.strip()}


def edit_in_scope(e: Edit, scopes: set[str] | None) -> bool:
    if scopes is None:
        return True
    if e.target == "sidecar":
        return "sidecar" in scopes
    if e.target == "xml_attr":
        return "xml" in scopes or "startup" in scopes
    return e.store.scope in scopes or e.store.name in scopes


def restrict_plan(plan: Plan, scopes: set[str] | None) -> Plan:
    if scopes is None:
        return plan
    edits = [e for e in plan.edits if edit_in_scope(e, scopes)]
    groups = {e.group for e in edits}
    return replace(plan, edits=edits, enabled_groups=plan.enabled_groups & groups)


def build_lab_plan(
    sess: Session, lc: LabCtx, ans: Answers, popts: planner.PlanOptions
) -> Plan:
    assert lc.analysis is not None
    plan = planner.build_plan(lc.analysis, ans, popts)
    targets = {
        e.text_edit.new
        for e in plan.edits
        if e.target == "xml_attr" and e.category == "cloud"
    }
    plan.findings.extend(hostenv.bridge_findings(targets, sys_net=sess.rt.sys_net))
    return restrict_plan(plan, _scopes(sess))


def _edit_text(lc: LabCtx, e: Edit) -> str | None:
    a = lc.analysis
    assert a is not None
    if e.target == "sidecar":
        path = Path(e.file)
        if not path.is_absolute():
            path = lc.path.parent / path
        try:
            return apply.sidecar_decode(path.read_bytes())[0]
        except OSError:
            return None
    for ct in a.texts:
        if ct.store == e.store and (ct.node_id or None) == (e.node_id or None):
            return ct.blob.text if ct.blob is not None else ct.text
    return None


def _edit_label(lc: LabCtx, e: Edit) -> str:
    a = lc.analysis
    assert a is not None
    if e.target == "sidecar":
        store = f"sidecar {e.store.name}"
    elif e.store.kind == "configset":
        store = f"cs:{e.store.name}"
    else:
        store = (
            e.store.kind if e.target != "textobject" else f"textobject {e.store.name}"
        )
    node = a.nodes.get(e.node_id or "")
    who = f" :: node {e.node_id} {node.name}" if node is not None else ""
    return f"{lc.path.name} :: {store}{who}"


def _xml_attr_context(lc: LabCtx, e: Edit) -> str:
    """``network 3 'MGMT' type:`` for an xml_attr edit (review fix #25)."""
    if lc.lab is not None:
        pos = e.text_edit.start
        for el in lc.lab.networks():
            for attr in el.attrs.values():
                if attr.span.start <= pos <= attr.span.end:
                    return f"network {el.id} {el.get('name')!r} {attr.name}:"
        for node in lc.lab.nodes():
            for attr in node.elem.attrs.values():
                if attr.span.start <= pos <= attr.span.end:
                    return f"node {node.id} {node.name!r} {attr.name}:"
    return f"offset {e.text_edit.start}:"


def _find_edit(plan: Plan, ref: str) -> str | None:
    """The edit id for ``ref``: an exact id or a unique id prefix."""
    ids = [e.id for e in plan.edits]
    if ref in ids:
        return ref
    hits = [i for i in ids if i.startswith(ref)]
    return hits[0] if len(hits) == 1 else None


def show_diff(sess: Session, lc: LabCtx, plan: Plan, mode: str, filt: str = "") -> None:
    ui = sess.ui
    edits = planner.enabled_edits(plan)
    if filt:
        low = filt.lower()
        a = lc.analysis
        assert a is not None

        def hit(e: Edit) -> bool:
            node = a.nodes.get(e.node_id or "")
            hay = [e.node_id or "", e.store.name, e.group, e.id]
            if node is not None:
                hay.append(node.name)
            return any(low in h.lower() for h in hay)

        edits = [e for e in edits if hit(e)]
    if mode == "raw":
        for e in edits:
            old, new = e.text_edit.old, e.text_edit.new
            if e.secret and not ui.show_secrets:
                old = new = "****"
            ui.out(
                f"{e.id} {e.target} {_edit_label(lc, e)} "
                f"{e.text_edit.start}:{e.text_edit.end} {sanitize(repr(old))} -> "
                f"{sanitize(repr(new))} [{e.group}]"
            )
        return
    buckets: dict[tuple[Any, ...], list[Edit]] = {}
    for e in edits:
        buckets.setdefault(
            (str(e.file), e.target, tuple(e.store), e.node_id), []
        ).append(e)
    for (_f, target, _s, _n), group in buckets.items():
        label = _edit_label(lc, group[0])
        if target == "xml_attr":
            ui.out(ui.style(f"--- {label} :: xml attributes", "bold"))
            for e in group:
                ui.out(f"[{e.id}] {_xml_attr_context(lc, e)}")
                ui.out(ui.style(f"-{sanitize(e.text_edit.old)}", "red"))
                ui.out(ui.style(f"+{sanitize(e.text_edit.new)}", "green"))
            continue
        text = _edit_text(lc, group[0])
        if text is None:
            ui.warn(f"{label}: text not available for diff")
            continue
        try:
            ui.diff_edits(text, group, label)
        except ValueError as exc:
            ui.warn(f"{label}: {exc}")


def review(sess: Session, lc: LabCtx, plan: Plan, *, can_apply: bool) -> bool:
    """Interactive review menu. Returns True to apply (queue) this lab's plan."""
    ui = sess.ui
    keys = {
        "r": "review groups",
        "d": "diff",
        "i": "edit ids",
        "x": "explain ID",
        "s": "save plan",
    }
    if can_apply:
        keys["a"] = "apply"
        keys["n"] = "skip lab"
    else:
        keys["c"] = "continue"
    keys["q"] = "quit"
    while True:
        key, rest = ui.menu(keys, default="c" if not can_apply else None)
        if key == "q":
            raise QuitRequested("quit")
        if key == "c":
            return False
        if key == "n":
            return False
        if key == "a":
            if plan.blocked:
                ui.error("the plan has conflicts/blockers: fix the answers first")
                continue
            ui.out(
                "   queued: written after the last lab (q before then writes nothing)"
            )
            return True
        if key == "d":
            show_diff(sess, lc, plan, "decoded", rest)
        elif key == "i":
            show_diff(sess, lc, plan, "raw", rest)
        elif key == "x":
            if not rest:
                ui.out("   usage: x EDIT_ID (or a unique prefix; 'i' lists the ids)")
                continue
            eid = _find_edit(plan, rest)
            if eid is None:
                ui.out(f"   no edit {rest!r} ('i' lists the edit ids)")
                continue
            ui.lines("   " + line for line in planner.explain(plan, eid))
        elif key == "s":
            target = Path(rest) if rest else sess.args.save_plan
            if target is None:
                ui.out("   usage: s FILE")
                continue
            target.write_text(planner.dumps_plan(plan) + "\n", encoding="utf-8")
            ui.out(f"   plan saved to {target}")
        elif key == "r":
            _review_groups(sess, plan)
            ui.plan_summary(planner.filter_enabled(plan))


def _review_groups(sess: Session, plan: Plan) -> None:
    ui = sess.ui
    counts = planner.group_counts(plan)
    groups = sorted(counts)
    rows = [
        [str(i + 1), g, str(counts[g]), "on" if g in plan.enabled_groups else "off"]
        for i, g in enumerate(groups)
    ]
    ui.table(["#", "Group", "Edits", "State"], rows, right=[0, 2])
    reply = ui.prompt("Toggle groups (numbers, ranges; Enter=done)", current="")
    raw = (reply.value or "").strip()
    if not raw:
        return
    from .ui import parse_selection

    try:
        picked = parse_selection(raw, len(groups))
    except ValueError as exc:
        ui.out(f"   {exc}")
        return
    for i in picked:
        g = groups[i]
        if g in plan.enabled_groups:
            plan.enabled_groups.discard(g)
        else:
            plan.enabled_groups.add(g)


# --------------------------------------------------------------------------- #
# State values (for revert and check)
# --------------------------------------------------------------------------- #


def _scheme_values(a: Analysis, seg: Segment) -> dict[str, Any]:
    sch = canonical_scheme(seg)
    return {
        "networks": list(seg.network_ids),
        "bridge": current_bridge(a, seg) or None,
        "vlan": sch.tag if sch is not None and isinstance(sch.tag, int) else None,
        "subnet": str(sch.subnet) if sch is not None and sch.subnet else None,
        "gateway": str(sch.gateway) if sch is not None and sch.gateway else None,
        "label": primary_label(seg) if seg.labels else None,
    }


def _service_maps(
    a: Analysis, ans: Answers, popts: planner.PlanOptions
) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for q in planner.collect_questions(a, ans, popts):
        if q.scenario != "services" or q.current is None:
            continue
        kind = q.id.split("/", 1)[1].split(":", 1)[0]
        new = ans.map_value(kind, q.current)
        if new is not None and new != q.current:
            out.setdefault(kind, {})[q.current] = new
    return out


def state_extra(
    lc: LabCtx,
    ans: Answers,
    popts: planner.PlanOptions,
    prev: Mapping[str, Any] | None,
    plan: Plan | None = None,
) -> dict[str, Any]:
    """``state.json`` entry fields: target values, original baseline, value maps."""
    a = lc.analysis
    assert a is not None
    prev = prev or {}
    vmaps, _ = planner.build_value_maps(a, ans, popts)
    values: dict[str, Any] = {}
    current: dict[str, Any] = {}
    for seg in a.segments:
        cur = _scheme_values(a, seg)
        current[seg.key] = cur
        sa = ans.segment_answer(seg.site_key, a.lab.lab_id, seg.key)
        tgt = dict(cur)
        if not sa.skip:
            for k in ("bridge", "vlan", "subnet", "gateway", "label"):
                v = getattr(sa, k)
                if v is not None and not (k == "vlan" and cur["vlan"] is None):
                    tgt[k] = v if isinstance(v, int | str) else str(v)
            if sa.label is None and seg.labels:
                # template-derived rename (label left unanswered)
                pl = primary_label(seg)
                pn = next((n for n in seg.network_ids if seg.labels.get(n) == pl), "")
                tgt["label"] = vmaps.labels.get(pn, tgt["label"])
        values[seg.key] = tgt
    maps = _service_maps(a, ans, popts)
    base_maps: dict[str, dict[str, str]] = {
        k: dict(v) for k, v in prev.get("baseline_maps", {}).items()
    }
    composed: dict[str, dict[str, str]] = {}
    for kind in set(base_maps) | set(maps):
        old = base_maps.get(kind, {})
        new = maps.get(kind, {})
        res = {o: new.get(c, c) for o, c in old.items()}
        for o, n in new.items():
            if o not in old.values():
                res.setdefault(o, n)
        res = {o: n for o, n in res.items() if o != n}
        if res:
            composed[kind] = res
    return {
        "site_keys": {s.key: s.site_key for s in a.segments},
        "values": values,
        "baseline": _baseline_of(prev, current),
        "baseline_maps": composed,
        "baseline_split": _baseline_split(a, ans, prev),
        "baseline_text_labels": _baseline_text_labels(vmaps, prev, plan),
        "plugin_dialects": {
            **(prev.get("plugin_dialects") or {}),
            **used_plugin_dialects(a),
        },
    }


def _baseline_text_labels(
    vmaps: ValueMaps, prev: Mapping[str, Any], plan: Plan | None
) -> dict[str, str]:
    """``{label now written in device text: original label}``, composed over runs.

    ``revert`` (and any later apply) feeds the keys back as
    ``PlanOptions.written_labels``, so the references follow the label back
    even when the current label is not distinctive (``MGMTX``)."""
    old: dict[str, str] = {
        str(k): str(v)
        for k, v in (prev.get("baseline_text_labels") or {}).items()
        if isinstance(v, str)
    }
    written: list[str] | None = None
    if plan is not None:
        written = [
            e.text_edit.new
            for e in planner.enabled_edits(plan)
            if e.target != "xml_attr" and e.category in ("label", "cosmetic")
        ]
    res: dict[str, str] = {}
    for cur, orig in old.items():
        res[vmaps.text_labels.get(cur, cur)] = orig
    for o, n in vmaps.text_labels.items():
        if o in old:
            continue
        if written is not None and not any(n in w for w in written):
            continue
        res.setdefault(n, o)
    return {k: v for k, v in sorted(res.items()) if k != v}


def _baseline_of(prev: Mapping[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """The recorded original baseline; ``current`` only for a lab not yet
    localized - a localized lab without one (old state) stays unknown rather
    than recording localized values as the baseline (review fixes)."""
    if prev.get("baseline"):
        return dict(prev["baseline"])
    return {} if prev.get("localized") else current


def saved_plan_state(
    sess: Session,
    plan: Plan,
    opts: apply.ApplyOptions,
    prev: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """``state.json`` fields for ``apply --plan`` (a saved plan has no answers):
    the baseline from the file as it is now, the values from the bytes the plan
    writes.  None when the lab cannot be analysed (apply reports why)."""
    lc = load_lab(sess, Path(plan.lab))
    if lc.analysis is None or lc.lab is None:
        return None
    try:
        changes = apply.build_changes(plan, replace(opts, out_dir=None), lab=lc.lab)
        after = RawLab.from_bytes(changes.unl.after, Path(plan.lab))
        aopts = AnalyseOptions(include_outliers=sess.args.include_outliers)
        post = analyse(after, lc.manifest, aopts)
    except LocalizeError:
        return None
    a = lc.analysis
    current = {seg.key: _scheme_values(a, seg) for seg in a.segments}
    return {
        "site_keys": {s.key: s.site_key for s in post.segments},
        "values": {seg.key: _scheme_values(post, seg) for seg in post.segments},
        "baseline": _baseline_of(prev or {}, current),
        "plugin_dialects": {
            **((prev or {}).get("plugin_dialects") or {}),
            **used_plugin_dialects(a),
        },
    }


def _baseline_split(
    a: Analysis, ans: Answers, prev: Mapping[str, Any]
) -> dict[str, dict[str, str]]:
    """Per segment ``{current subnet: original subnet}`` for split maps, so
    ``revert`` can undo a split exactly (T21 fix)."""
    out: dict[str, dict[str, str]] = {
        k: dict(v) for k, v in (prev.get("baseline_split") or {}).items()
    }
    for seg in a.segments:
        sa = ans.segment_answer(seg.site_key, a.lab.lab_id, seg.key)
        if sa.skip or not sa.split:
            continue
        nets = [sch.subnet for sch in seg.schemes if sch.subnet is not None]
        old = out.get(seg.key, {})
        res: dict[str, str] = {}
        for src, dst in sa.split.items():
            if src == dst or not any(src.overlaps(n) for n in nets):
                continue
            res[str(dst)] = old.get(str(src), str(src))
        if res:
            out[seg.key] = res
    return out


def localized_from_state(
    entry: Mapping[str, Any], m: Manifest | None
) -> tuple[dict[str, Baseline], dict[str, list[str]]]:
    seg_vals: dict[str, Baseline] = {}
    for key, v in (entry.get("values") or {}).items():
        try:
            seg_vals[key] = Baseline(
                bridge=v.get("bridge"),
                label=v.get("label"),
                vlan=v.get("vlan"),
                subnet=IPv4Network(v["subnet"]) if v.get("subnet") else None,
                gateway=IPv4Address(v["gateway"]) if v.get("gateway") else None,
            )
        except (ValueError, AttributeError, TypeError):
            continue
    params: dict[str, list[str]] = {}
    maps = entry.get("baseline_maps") or {}
    if m is not None and maps:
        flat: dict[str, str] = {}
        for table in maps.values():
            flat.update(table)
        for p in m.params:
            # The param's own map kind wins: dns 1.1.1.1 and probe 1.1.1.1 may go
            # to different values (T21 fix).
            mk = _param_map_kind(p.key, p.kind)
            table = maps.get(mk, {}) if mk is not None else flat
            vals = [table.get(v, v) for v in p.baseline]
            if vals != p.baseline:
                params[p.key] = [v for v in vals if v != ""]
    return seg_vals, params


def revert_answers(lc: LabCtx, entry: Mapping[str, Any] | None) -> Answers | None:
    """Answers whose targets are the recorded / manifest baselines."""
    a = lc.analysis
    assert a is not None and lc.lab is not None
    ans = Profile()
    lab = ans.labs.setdefault(lc.lab.lab_id, LabOverride())
    known = False
    base = (entry or {}).get("baseline") or {}
    for seg in a.segments:
        rec = next(
            (
                v
                for v in base.values()
                if set(v.get("networks") or []) & set(seg.network_ids)
            ),
            None,
        )
        sa = SegmentAnswer()
        if rec is not None:
            known = True
            sa.bridge = rec.get("bridge")
            sa.vlan = rec.get("vlan")
            sa.subnet = IPv4Network(rec["subnet"]) if rec.get("subnet") else None
            sa.gateway = IPv4Address(rec["gateway"]) if rec.get("gateway") else None
            sa.label = rec.get("label")
        split = ((entry or {}).get("baseline_split") or {}).get(seg.key)
        if split:
            try:
                sa.split = {IPv4Network(k): IPv4Network(v) for k, v in split.items()}
                known = True
            except ValueError:
                pass
        ms = lc.manifest.segment(seg.key) if lc.manifest is not None else None
        if ms is not None:
            b = ms.baseline
            for k in ("bridge", "label", "vlan", "subnet", "gateway"):
                if getattr(b, k) is not None:
                    setattr(sa, k, getattr(b, k))
                    known = True
        lab.segments[seg.key] = sa
    for kind, table in ((entry or {}).get("baseline_maps") or {}).items():
        for orig, cur in table.items():
            if cur:
                ans.maps.setdefault(kind, {})[cur] = orig
                known = True
    return ans if known else None


# --------------------------------------------------------------------------- #
# Apply options and the rescan hook
# --------------------------------------------------------------------------- #


def apply_options(sess: Session, **extra: Any) -> apply.ApplyOptions:
    a, rt = sess.args, sess.rt
    return apply.ApplyOptions(
        state_dir=sess.state_dir,
        backup_dir=a.backup_dir,
        repo_root=sess.root,
        no_backup=a.no_backup,
        require_clean=a.require_clean,
        force_running=a.force_running,
        out_dir=a.out,
        continue_on_error=a.continue_on_error,
        check_labs_peers=rt.check_labs_peers,
        proc=rt.proc,
        tmp_root=rt.tmp_root,
        docker_names=rt.docker_names,
        use_fcntl=rt.use_fcntl,
        **extra,
    )


def rescan_answers(ans: Answers) -> Answers:
    """``ans`` as seen by the post-write re-scan.

    ``[map.<kind>]`` entries are keyed by the *old* value. After a swap
    (``a = b``, ``b = a``) or a chain (``a = b``, ``c = a``) the written lab holds
    the targets, so re-planning with the same map would rewrite them again and
    fail ``VALIDATION_RESCAN``. Entries whose key is also a target of the same map
    are dropped; the others still catch a value the write left behind.
    """
    pruned = {
        kind: {o: n for o, n in table.items() if o not in set(table.values())}
        for kind, table in ans.maps.items()
    }
    if pruned == ans.maps:
        return ans
    out = copy.deepcopy(ans)
    out.maps = {kind: table for kind, table in pruned.items() if table}
    return out


def make_rescan(
    sess: Session, plans: Mapping[str, tuple[LabCtx, Answers, planner.PlanOptions]]
) -> apply.RescanHook:
    scopes = _scopes(sess)

    def hook(staged: Path, plan: Plan) -> list[Edit]:
        lc, ans, popts = plans[plan.lab_id]
        lab = RawLab.read(staged)
        use = rescan_answers(ans)
        if lab.lab_id != plan.lab_id and plan.lab_id in ans.labs:
            use = copy.deepcopy(use)
            use.labs[lab.lab_id] = use.labs[plan.lab_id]
        aopts = AnalyseOptions(include_outliers=sess.args.include_outliers)
        a = analyse(lab, lc.manifest, aopts)
        p = planner.build_plan(a, use, replace(popts, lab_id=lab.lab_id))
        return planner.enabled_edits(restrict_plan(p, scopes))

    return hook


def _report_run(sess: Session, rec: apply.RunRecord) -> None:
    ui = sess.ui
    for r in rec.labs:
        rel = _rel(sess.root, r.lab)
        status = r.status
        if status == "localized" and sess.cmd == "revert":
            status = "reverted"
        line = f"  {status:<10} {rel}"
        if r.error:
            line += f" ({r.error})"
        ui.out(line)
        _show_findings(ui, r.findings, ui.verbosity)
    if rec.journaled:
        ui.out(f"Run {rec.run_id} journaled.")


def _next_steps(sess: Session, rec: apply.RunRecord, plans: Sequence[Plan]) -> None:
    ui = sess.ui
    done = {r.lab_id for r in rec.labs if r.status == "localized"}
    if not done:
        return
    sidecars = any(
        e.target == "sidecar"
        for p in plans
        for e in planner.enabled_edits(p)
        if p.lab_id in done or sess.args.out
    )
    steps = ["wipe affected nodes in EVE"]
    if sidecars:
        steps.append("re-paste sidecar configs to devices (Forti/F5)")
    if sess.args.out is None:
        steps.append(
            "close and reopen the lab in the UI only after this run "
            "(EVE overwrites the file on save)"
        )
    ui.out("Next: " + "; ".join(steps) + ".")
    if sess.args.out is None and sess.cmd != "revert":
        site = sess.ans.site or "my site"
        ui.out(
            f"Suggested commit (if you keep it local): chore(labs): localize for {site}"
        )


def _fix_perms(sess: Session, target: Path | None = None) -> None:
    """Run fix-lab-permissions.sh (on ``target`` only when given: copy mode)."""
    if not FIX_PERMS.is_file():
        sess.ui.warn(f"{FIX_PERMS} not found")
        return
    argv = ["bash", str(FIX_PERMS)] + ([str(target)] if target is not None else [])
    res = subprocess.run(argv, check=False, capture_output=True, text=True)
    if res.returncode != 0:
        sess.ui.warn(f"fix-perms failed: {res.stderr.strip()}")


def do_apply(
    sess: Session,
    queued: Sequence[tuple[LabCtx, Plan, Answers, planner.PlanOptions]],
    *,
    mark_localized: bool = True,
) -> None:
    ui = sess.ui
    if not queued:
        return
    plans = [p for _lc, p, _a, _o in queued]
    ctx = {p.lab_id: (lc, ans, popts) for lc, p, ans, popts in queued}
    state = _load_state(sess)
    extra = {}
    if mark_localized:
        extra = {
            p.lab_id: state_extra(lc, ans, popts, state.get(p.lab_id), p)
            for lc, p, ans, popts in queued
        }
    opts = apply_options(
        sess,
        rescan=make_rescan(sess, ctx),
        state_extra=extra,
        mark_localized=mark_localized,
    )
    pf = apply.preflight(plans, opts)
    if pf:
        ui.heading("Preflight:")
        _show_findings(ui, pf, ui.verbosity)
    rec = apply.apply_plans(plans, opts)
    ui.heading("Result:")
    _report_run(sess, rec)
    sess.code(rec.exit_code)
    _next_steps(sess, rec, plans)
    if sess.args.fix_perms and rec.journaled:
        # Copy mode: only the --out tree (never the whole labs repo).
        out = Path(sess.args.out).resolve() if sess.args.out is not None else None
        _fix_perms(sess, out)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def _labs_ctx(sess: Session, *, default_all: bool = False) -> list[LabCtx]:
    out: list[LabCtx] = []
    for path in select_labs(sess, default_all=default_all):
        lc = load_lab(sess, path)
        if lc.error:
            sess.ui.error(lc.error)
            sess.code(lc.exit_code or 1)
            continue
        out.append(lc)
    return out


def cmd_scan(sess: Session) -> None:
    ui, a = sess.ui, sess.args
    if a.list and not a.json:
        rows = []
        state = _load_state(sess)
        for lc in _labs_ctx(sess, default_all=True):
            an = lc.analysis
            assert an is not None and lc.lab is not None
            keys = ", ".join(f"{s.key}({s.status[:4]})" for s in an.segments) or "-"
            pin = "manifest" if lc.manifest is not None else "-"
            loc = "yes" if state.get(lc.lab.lab_id, {}).get("localized") else "-"
            status = "nothing to localize" if not lc.clouds else f"{lc.clouds} clouds"
            rows.append([lc.rel, status, pin, loc, keys])
        ui.table(["Lab", "Status", "Manifest", "Localized", "Segments"], rows)
        return
    labs = _labs_ctx(sess, default_all=a.json or a.list)
    doc: dict[str, Any] = {"schema": SCHEMA, "tool": "eve-localize", "labs": []}
    for lc in labs:
        an = lc.analysis
        assert an is not None and lc.lab is not None
        popts = plan_options(sess, lc)
        if a.json:
            qs = planner.collect_questions(an, sess.ans, popts) if lc.clouds else []
            doc["labs"].append(
                {
                    "lab": lc.rel,
                    "lab_id": lc.lab.lab_id,
                    "pinned": an.pinned,
                    "manifest": lc.manifest is not None,
                    "nothing_to_localize": not lc.clouds,
                    "segments": [segment_dict(an, s) for s in an.segments],
                    "questions": [
                        question_dict(q, sess.ans, lc.lab.lab_id) for q in qs
                    ],
                    "findings": [finding_dict(f) for f in an.findings],
                }
            )
            continue
        if _nothing(sess, lc):
            continue
        lab_header(sess, lc)
        if a.strict and lc.manifest is None:
            ui.error(f"{lc.rel}: unpinned (no manifest) under --strict")
            sess.code(1)
        ui.out("")
    if a.json:
        _emit_json(sess, doc)


def _will_write(sess: Session) -> bool:
    a = sess.args
    if sess.cmd not in WRITING or a.dry_run or a.plan_only:
        return False
    return not (sess.cmd == "run" and not (sess.ui.interactive or a.yes))


def cmd_run(sess: Session) -> None:
    """run / plan / apply: questions per lab (answers carried forward), then apply."""
    ui, a = sess.ui, sess.args
    if sess.cmd == "apply" and a.plan is not None:
        return cmd_apply_saved(sess)
    write = _will_write(sess)
    labs = _labs_ctx(sess)
    queued: list[tuple[LabCtx, Plan, Answers, planner.PlanOptions]] = []
    json_out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_keys: set[str] = set()
    for lc in labs:
        if _nothing(sess, lc):
            continue
        an = lc.analysis
        assert an is not None and lc.lab is not None
        popts = plan_options(sess, lc)
        if not a.json:
            lab_header(sess, lc)
        if lc.manifest is None:
            if a.strict and not a.allow_unpinned:
                ui.error(f"{lc.rel}: unpinned (no manifest) under --strict")
                sess.code(1)
                continue
            if write and ui.mode != "interactive" and not a.allow_unpinned:
                ui.error(
                    f"{lc.rel}: unpinned lab (no manifest): non-interactive apply "
                    "needs --allow-unpinned"
                )
                sess.code(4)
                continue
            if ui.mode == "interactive" and not ui.ask_yes_no(
                "Unpinned lab (no manifest): is the segment matrix right?",
                default=True,
            ):
                ui.out(f"Skipped {lc.rel}.")
                continue
        run_questions(sess, lc, popts)
        seen_keys.update(seg.site_key for seg in an.segments)
        if sess.json_answers:
            seen_ids.update(
                q.id for q in planner.collect_questions(an, sess.ans, popts)
            )
        plan = build_lab_plan(sess, lc, sess.ans, popts)
        if a.json:
            json_out.append({"lab": lc.rel, "plan": planner.plan_to_dict(plan)})
        else:
            _show_plan(sess, lc, plan)
            # interactive: a conflict/blocker sends the user back to the
            # offending segment's questions instead of discarding every answer
            while (
                plan.blocked
                and ui.mode == "interactive"
                and _revise_blocked(sess, lc, popts, plan)
            ):
                plan = build_lab_plan(sess, lc, sess.ans, popts)
                _show_plan(sess, lc, plan)
        if plan.blocked:
            sess.code(2)
        if a.save_plan is not None and len(labs) == 1:
            a.save_plan.write_text(planner.dumps_plan(plan) + "\n", encoding="utf-8")
            if not a.json:
                ui.out(f"Plan saved to {a.save_plan}")
        if not write:
            if ui.mode == "interactive" and not a.json:
                review(sess, lc, plan, can_apply=False)
            continue
        if not planner.enabled_edits(plan):
            ui.out(f"{lc.rel}: 0 edits, nothing to apply.")
            continue
        if plan.blocked:
            ui.error(f"{lc.rel}: conflicts/blockers: not applied")
            continue
        if ui.mode == "interactive" and not review(sess, lc, plan, can_apply=True):
            continue
        queued.append((lc, plan, sess.ans, popts))
    if not check_unused_answers(sess, seen_ids, seen_keys):
        queued = []  # --strict: an unknown answer id is an error, nothing written
    if a.save_answers is not None:
        profile.save_answers(a.save_answers, sess.ans, include_secrets=a.save_secrets)
        if a.save_secrets:
            ui.warn(f"{a.save_answers} contains secrets (mode 0600): never commit it")
        if not a.json:
            ui.out(f"Answers saved to {a.save_answers}")
    if a.json:
        _emit_json(sess, {"schema": SCHEMA, "labs": json_out})
    if write:
        do_apply(sess, queued)


def cmd_apply_saved(sess: Session) -> None:
    ui, a = sess.ui, sess.args
    try:
        plan = planner.loads_plan(a.plan.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError) as exc:
        raise LocalizeError(f"{a.plan}: cannot load plan: {exc}") from exc
    plan = restrict_plan(plan, _scopes(sess))
    ui.plan_summary(planner.filter_enabled(plan))
    _show_findings(ui, plan.findings, ui.verbosity)
    if a.dry_run:
        return
    if ui.mode == "interactive" and not ui.ask_yes_no("Apply this plan?"):
        return
    opts = apply_options(sess)
    if a.out is None:  # in place: record the baseline revert needs
        prev = _load_state(sess).get(plan.lab_id)
        extra = saved_plan_state(sess, plan, opts, prev)
        if extra is not None:
            opts = replace(opts, state_extra={plan.lab_id: extra})
    pf = apply.preflight([plan], opts)
    if pf:
        ui.heading("Preflight:")
        _show_findings(ui, pf, ui.verbosity)
    rec = apply.apply_plans([plan], opts)
    ui.heading("Result:")
    _report_run(sess, rec)
    sess.code(rec.exit_code)


def cmd_revert(sess: Session) -> None:
    ui, a = sess.ui, sess.args
    write = _will_write(sess)
    state = _load_state(sess)
    queued: list[tuple[LabCtx, Plan, Answers, planner.PlanOptions]] = []
    for lc in _labs_ctx(sess):
        if _nothing(sess, lc):
            continue
        assert lc.lab is not None
        entry = state.get(lc.lab.lab_id)
        if entry and entry.get("localized") and not entry.get("baseline"):
            ui.warn(
                f"{lc.rel}: state.json has no recorded baseline for this lab; "
                "bridges and other values outside the manifest cannot be "
                "restored - check `git diff` and use `git restore` if needed"
            )
        ans = revert_answers(lc, entry)
        if ans is None:
            ui.out(
                f"{lc.rel}: no baseline known (no state entry, no manifest): skipped"
            )
            continue
        popts = replace(plan_options(sess, lc), include_outliers=a.include_outliers)
        plan = build_lab_plan(sess, lc, ans, popts)
        ui.heading(f"Revert: {lc.rel}")
        ui.plan_summary(planner.filter_enabled(plan))
        _show_findings(ui, plan.findings, ui.verbosity)
        if a.diff in ("decoded", "raw"):
            show_diff(sess, lc, plan, a.diff)
        if plan.blocked:
            sess.code(2)
            continue
        if not planner.enabled_edits(plan):
            if entry and entry.get("localized") and not entry.get("baseline"):
                ui.out(f"{lc.rel}: nothing to revert from the known baselines.")
                sess.code(1)
            else:
                ui.out(f"{lc.rel}: already at baseline.")
            continue
        if (
            write
            and ui.mode == "interactive"
            and not a.yes
            and not review(sess, lc, plan, can_apply=True)
        ):
            continue
        queued.append((lc, plan, ans, popts))
    if write:
        do_apply(sess, queued, mark_localized=False)


def cmd_undo(sess: Session) -> None:
    run_id = sess.args.labs[0] if sess.args.labs else None
    restored = apply.undo(run_id, apply_options(sess))
    for p in restored:
        sess.ui.out(f"  restored {_rel(sess.root, p)}")
    sess.ui.out(f"Undo done: {len(restored)} file(s).")


def cmd_runs(sess: Session) -> None:
    runs = apply.list_runs(apply.ApplyOptions(state_dir=sess.state_dir))
    if sess.args.json:
        _emit_json(sess, runs)
        return
    if not runs:
        sess.ui.out("No runs journaled.")
        return
    rows = []
    for r in runs:
        labs = r.get("labs", {})
        names = ", ".join(Path(v.get("lab", k)).name for k, v in labs.items())
        rows.append(
            [
                r.get("run_id", "?"),
                r.get("ts", ""),
                r.get("mode", ""),
                "undone" if r.get("undone") else "",
                names,
            ]
        )
    sess.ui.table(["Run", "Time", "Mode", "Undone", "Labs"], rows)


def cmd_check(sess: Session) -> None:
    ui, a = sess.ui, sess.args
    state = _load_state(sess)
    all_findings: list[dict[str, Any]] = []
    failed = False
    checked = _labs_ctx(sess, default_all=True)
    for lc in checked:
        an = lc.analysis
        assert an is not None and lc.lab is not None
        entry = state.get(lc.lab.lab_id) or {}
        findings = check_lab(lc, entry)
        bad = [
            f
            for f in findings
            if f.severity in BLOCKING or (a.strict and f.severity == "warn")
        ]
        failed = failed or bool(bad)
        if a.json:
            all_findings.append(
                {"lab": lc.rel, "findings": [finding_dict(f) for f in findings]}
            )
            continue
        status = "FAIL" if bad else "ok"
        ui.out(f"{status:<4} {lc.rel}" + ("" if lc.clouds else " (no clouds)"))
        _show_findings(ui, findings, ui.verbosity)
    if a.all or not (a.labs or a.lab):
        ex = check_example(sess, checked)
        if ex is not None:
            failed = failed or ex.severity in BLOCKING or a.strict
            if a.json:
                all_findings.append({"lab": None, "findings": [finding_dict(ex)]})
            else:
                ui.findings([ex])
    if a.json:
        _emit_json(sess, {"schema": SCHEMA, "results": all_findings, "ok": not failed})
    if failed:
        sess.code(1)


def check_lab(lc: LabCtx, entry: Mapping[str, Any]) -> list[Finding]:
    an = lc.analysis
    assert an is not None
    if not lc.clouds:
        return []
    localized = bool(entry.get("localized"))
    seg_vals, params = (
        localized_from_state(entry, lc.manifest) if localized else ({}, {})
    )
    findings = manifest.check(
        an, lc.manifest, localized=seg_vals, localized_params=params
    )
    if not localized:
        return findings
    if lc.manifest is not None:
        if any(f.code == "NOT_AT_BASELINE" for f in findings):
            plain = manifest.check(an, lc.manifest, leaks=False)
            if not any(f.code == "NOT_AT_BASELINE" for f in plain):
                findings.append(_reverted(lc))
        return findings
    base = entry.get("baseline") or {}
    values = entry.get("values") or {}
    for seg in an.segments:
        cur = _scheme_values(an, seg)
        b, v = base.get(seg.key), values.get(seg.key)
        if not b or not v:
            continue
        keys = ("vlan", "subnet", "gateway", "label")
        if any(b.get(k) != v.get(k) for k in keys) and all(
            cur.get(k) == b.get(k) for k in keys
        ):
            findings.append(_reverted(lc))
            break
    return findings


def _reverted(lc: LabCtx) -> Finding:
    return Finding(
        "REVERTED_BY_EVE",
        "warn",
        f"{lc.rel}: state.json says localized but the lab holds baseline values "
        "(reverted by EVE? the UI saves its own copy): re-run apply",
    )


def check_example(sess: Session, loaded: Sequence[LabCtx] = ()) -> Finding | None:
    path = sess.root / EXAMPLE_PROFILE
    if not path.is_file():
        return None
    try:
        want = example_profile_text(sess, loaded)
    except LocalizeError as exc:
        return Finding("EXAMPLE_PROFILE", "error", f"{path}: {exc}")
    if path.read_text(encoding="utf-8") != want:
        return Finding(
            "STALE_EXAMPLE",
            "error",
            f"{_rel(sess.root, path)} is stale: run "
            "'eve-localize profile --example'",
        )
    return None


def _param_map_kind(key: str, kind: str) -> str | None:
    for prefix, mk in _PARAM_MAP_KIND.items():
        if key.startswith(prefix):
            return mk
    return "domain" if kind == "domain" else None


def _baseline_bridge(
    a: Analysis, seg: Segment, entry: Mapping[str, Any] | None
) -> str | None:
    """The segment's pre-localization bridge: the ``state.json`` baseline when
    the lab is localized (matched by segment key, else by network ids), else
    the lab's current bridge (review fix #35: a localized bridge must not
    leak into the committed example profile)."""
    base = (entry or {}).get("baseline") or {}
    if entry and entry.get("localized") and isinstance(base, Mapping):
        hit = base.get(seg.key)
        if not isinstance(hit, Mapping):
            nets = set(seg.network_ids)
            hit = next(
                (
                    v
                    for v in base.values()
                    if isinstance(v, Mapping) and nets & set(v.get("networks") or ())
                ),
                None,
            )
        if isinstance(hit, Mapping) and "bridge" in hit:
            return hit.get("bridge") or None
    return current_bridge(a, seg) or None


def example_profile_text(sess: Session, loaded: Sequence[LabCtx] = ()) -> str:
    """``localize/site.example.toml``: author baselines from every manifest.

    ``loaded`` are labs already analysed by the caller (``check --all``);
    their analysis is reused instead of analysing the lab a second time
    (review fix #38).
    """
    prof = Profile(site="example")
    state = _load_state(sess)
    # an analysis made with --include-outliers may differ: analyse again then
    same_opts = not getattr(sess.args, "include_outliers", False)
    reuse = {
        lc.path.resolve(): lc
        for lc in loaded
        if same_opts and lc.analysis is not None and lc.manifest is not None
    }
    for path in all_labs(sess.root):
        lc = reuse.get(path.resolve())
        if lc is not None:
            m, a = lc.manifest, lc.analysis
            assert m is not None and a is not None
        else:
            try:
                m = manifest.find_for(path)
            except LocalizeError as exc:
                raise LocalizeError(f"{_rel(sess.root, path)}: {exc}") from exc
            if m is None:
                continue
            a = analyse(RawLab.read(path), m)
        entry = state.get(a.lab.lab_id)
        segs = {s.key: s for s in a.segments}
        for ms in m.segments:
            seg = segs.get(ms.key)
            key = ms.site_key or (seg.site_key if seg is not None else None)
            if not key or key in prof.segments:
                continue
            b = ms.baseline
            # committed manifest baseline bridge first, then the state.json
            # baseline, then the lab (never a localized bridge; review #35)
            bridge = getattr(b, "bridge", None)
            if bridge is None and seg is not None:
                bridge = _baseline_bridge(a, seg, entry)
            prof.segments[key] = SegmentAnswer(
                bridge=bridge,
                vlan=b.vlan,
                subnet=b.subnet,
                gateway=b.gateway,
                label=b.label,
            )
        for p in m.params:
            mk = _param_map_kind(p.key, p.kind)
            if mk is None:
                continue
            for v in p.baseline:
                prof.maps.setdefault(mk, {}).setdefault(v, v)
    return profile.dumps(prof)


def cmd_discover(sess: Session) -> None:
    ui, a = sess.ui, sess.args
    names = list(a.labs) + list(a.lab)
    if not names and not a.all:
        raise LocalizeError("discover needs LAB (or --all)", code="NO_LAB")
    state = _load_state(sess)
    for path in select_labs(sess):
        rel = _rel(sess.root, path)
        lab = RawLab.read(path)
        mpath = manifest.manifest_path_for(path)
        previous: Manifest | None = None
        if a.update:
            if not mpath.is_file():
                raise LocalizeError(f"{rel}: no manifest to --update (use --write)")
            if state.get(lab.lab_id, {}).get("localized"):
                raise LocalizeError(
                    f"{rel}: lab is localized: revert it before discover --update "
                    "(it would record local values)",
                    code="LOCALIZED",
                )
            previous = manifest.load(mpath)
        if not any(n.get("type", "bridge") != "bridge" for n in lab.networks()):
            ui.out(f"{rel}: no cloud networks, no manifest needed")
            continue
        an = analyse(lab, previous)
        text = manifest.generate(an, previous)
        if a.update:
            _write_text(mpath, text)
            ui.out(f"Updated {_rel(sess.root, mpath)}: review the diff and commit")
        elif a.write:
            dpath = manifest.draft_path_for(path)
            _write_text(dpath, text)
            ui.out(
                f"Wrote {_rel(sess.root, dpath)}: review it, then rename to "
                f"{mpath.name}"
            )
        else:
            (sess.rt.stdout or sys.stdout).write(text)


def _write_text(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    if path.exists():
        st = path.stat()
        os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, path)


def cmd_explain(sess: Session) -> None:
    ui, a = sess.ui, sess.args
    from .discover.inventory import protected_fact_ids

    for lc in _labs_ctx(sess):
        an = lc.analysis
        assert an is not None
        if a.edit:
            plan = build_lab_plan(sess, lc, sess.ans, plan_options(sess, lc))
            try:
                ui.lines(planner.explain(plan, a.edit))
            except KeyError:
                ui.error(f"no edit {a.edit!r} in the plan of {lc.rel}")
                sess.code(1)
            continue
        protected = protected_fact_ids(an.facts)
        facts = sorted(
            an.facts.values(),
            key=lambda f: (tuple(f.store), f.node_id or "", f.line, f.span.start),
        )
        if a.json:
            _emit_json(
                sess,
                {
                    "lab": lc.rel,
                    "facts": [
                        {
                            "id": f.id,
                            "kind": f.kind,
                            "value": "****" if "secret" in f.flags else f.value,
                            "store": list(f.store),
                            "node_id": f.node_id,
                            "line": f.line,
                            "rule": f.rule,
                            "iface": f.iface,
                            "segment": f.segment,
                            "confidence": f.confidence.name,
                            "evidence": f.evidence,
                            "flags": sorted(f.flags),
                            "protected": f.id in protected,
                        }
                        for f in facts
                    ],
                },
            )
            continue
        ui.heading(f"Lab: {lc.rel} ({len(facts)} facts, {len(protected)} protected)")
        rows = []
        for f in facts:
            node = an.nodes.get(f.node_id or "")
            value = "****" if "secret" in f.flags and not ui.show_secrets else f.value
            rows.append(
                [
                    f.id,
                    f.kind,
                    sanitize(value),
                    f.confidence.name[:4],
                    f.segment or ("PROTECTED" if f.id in protected else "-"),
                    f"{f.store.kind}:{f.store.name}",
                    node.name if node is not None else "-",
                    str(f.line),
                    f.rule,
                    ",".join(sorted(f.flags)),
                ]
            )
        ui.table(
            [
                "Fact",
                "Kind",
                "Value",
                "Conf",
                "Segment",
                "Store",
                "Node",
                "Line",
                "Rule",
                "Flags",
            ],
            rows,
        )
        if ui.verbosity > 0:
            for f in facts:
                if f.evidence:
                    ui.out(f"  {f.id}: {sanitize(f.evidence)}")


def cmd_profile(sess: Session) -> None:
    ui, a = sess.ui, sess.args
    if a.example:
        text = example_profile_text(sess)
        target = sess.root / EXAMPLE_PROFILE
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_text(target, text)
        ui.out(f"Wrote {_rel(sess.root, target)}")
        return
    if a.wizard:
        return profile_wizard(sess)
    raise LocalizeError("profile needs --example or --wizard", code="USAGE")


def profile_wizard(sess: Session) -> None:
    from .profile import BridgeProfile

    ui = sess.ui
    bridges = hostenv.list_bridges(sys_net=sess.rt.sys_net)
    ui.out(hostenv.bridges_summary(bridges))
    prof = sess.ans
    for name, info in bridges.items():
        cur = prof.bridges.get(name)
        reply = ui.prompt(
            f"{name} ({info.state}) roles (comma list: mgmt,inet,oob,trunk,nat; "
            "Enter=none)",
            current=",".join(cur.roles) if cur else "",
        )
        roles = [r.strip() for r in (reply.value or "").split(",") if r.strip()]
        if not roles:
            continue
        mode = ui.prompt(
            f"{name} mode",
            default=cur.mode if cur else "trunk",
            choices=["trunk", "untagged-only"],
        )
        prof.bridges[name] = BridgeProfile(roles=roles, mode=mode.value or "trunk")
        for r in roles:
            prof.roles.setdefault(r, name)
    target = sess.args.save_answers or (sess.root / DEFAULT_PROFILE)
    target.parent.mkdir(parents=True, exist_ok=True)
    profile.save_answers(target, prof, include_secrets=sess.args.save_secrets)
    ui.out(f"Profile saved to {_rel(sess.root, target)}")


HANDLERS: dict[str, Callable[[Session], None]] = {
    "run": cmd_run,
    "plan": cmd_run,
    "apply": cmd_run,
    "scan": cmd_scan,
    "revert": cmd_revert,
    "undo": cmd_undo,
    "runs": cmd_runs,
    "check": cmd_check,
    "discover": cmd_discover,
    "explain": cmd_explain,
    "profile": cmd_profile,
}


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main(argv: Sequence[str] | None = None, runtime: Runtime | None = None) -> int:
    rt = runtime or Runtime()
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd, rest = _split_command(argv)
    parser = build_parser()
    try:
        args = parser.parse_args(rest)
    except SystemExit as exc:  # --help / --version / usage errors
        return int(exc.code or 0) if isinstance(exc.code, int) else 1
    if args.check:
        cmd = "check"
    elif args.list and cmd == "run":
        cmd = "scan"
    args.plan_only = cmd == "plan"
    if cmd == "plan":
        args.dry_run = True
    interactive = rt.interactive
    if args.non_interactive or args.json:
        interactive = False
    verbosity = -1 if args.quiet else min(args.verbose, 1)
    if args.json and cmd not in ("discover",):
        verbosity = -1
    ui = UI(
        rt.stdin,
        rt.stdout,
        rt.stderr,
        interactive=interactive,
        assume_yes=args.yes,
        strict=args.strict,
        color=False if args.no_color else None,
        show_secrets=args.show_secrets,
        verbosity=verbosity,
        env=rt.env,
        getpass_fn=rt.getpass_fn,
    )
    try:
        root = find_root(args.root)
        state_dir = args.state_dir.resolve() if args.state_dir else root / ".localize"
        sess = Session(cmd, args, ui, rt, root, state_dir)
        load_plugins(sess)
        if cmd not in ("undo", "runs"):
            load_inputs(sess)
        HANDLERS[cmd](sess)
        return sess.exit_code
    except QuitRequested:
        ui.out("Quit: nothing written.")
        return 0
    except UnansweredError as exc:
        ui.error(str(exc))
        return 3
    except LocalizeError as exc:
        ui.error(f"{exc.code}: {exc}")
        return exc.exit_code
    except KeyboardInterrupt:
        ui.error("interrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
