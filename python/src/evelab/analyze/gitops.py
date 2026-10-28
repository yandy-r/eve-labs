"""Where analyze commits its changes.

* **clone** - ``origin`` is the upstream repository (``yandy-r/eve-labs``, or
  ``$EVE_LABS_UPSTREAM`` / ``--upstream``): the user cloned upstream directly, so
  the changes go on a local branch (``analyze/<host>``) and ``main`` stays a
  clean mirror of upstream. A run that starts on a non-default branch commits
  there (the user already keeps a local branch).
* **fork** - ``origin`` is another repository (a fork, or the user's own
  remote): commit on the current branch, normally ``main``.
* **none** - not a git checkout (downloaded archive): files are written with
  backups and nothing is committed.

The commit holds only analyze's edits. They are applied to the ``HEAD`` version
of each lab through a temporary index (``git commit-tree``), so uncommitted
work in the same file (for example labs localized by eve-localize, which must
not be committed) stays uncommitted in the working tree. Git hooks do not run
for this commit.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from evelab.common.errors import EveLabError

from .writer import Change, apply_changes

__all__ = [
    "UPSTREAM",
    "UPSTREAM_ENV",
    "CommitResult",
    "GitState",
    "branch_name",
    "commit_changes",
    "detect",
    "remote_slug",
    "switch_branch",
]

UPSTREAM = "yandy-r/eve-labs"
UPSTREAM_ENV = "EVE_LABS_UPSTREAM"
GitMode = Literal["none", "clone", "fork"]

_SLUG = re.compile(r"[:/]([^/:]+)/([^/]+?)(?:\.git)?/?$")


class GitError(EveLabError):
    code = "GIT"


def _git(
    top: Path,
    *args: str,
    stdin: bytes | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        res = subprocess.run(
            ["git", "-C", str(top), *args],
            input=stdin,
            capture_output=True,
            timeout=60,
            check=False,
            env={**os.environ, **env} if env else None,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitError(f"git {args[0]}: {exc}") from exc
    if check and res.returncode != 0:
        msg = res.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {' '.join(args[:2])} failed: {msg}")
    return res


def _out(top: Path, *args: str) -> str | None:
    res = _git(top, *args, check=False)
    text = res.stdout.decode("utf-8", "replace").strip()
    return text if res.returncode == 0 and text else None


def remote_slug(url: str) -> str | None:
    """``owner/repo`` of a GitHub-style remote URL (https, ssh or scp form)."""
    m = _SLUG.search(url.strip())
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


@dataclass
class GitState:
    top: Path | None
    mode: GitMode
    branch: str | None = None  # None: detached HEAD or not git
    default_branch: str = "main"
    origin: str | None = None
    has_head: bool = False
    reason: str = ""


def detect(root: Path, upstream: str | None = None) -> GitState:
    """Classify the checkout at ``root`` (see the module docstring)."""
    up = (upstream or os.environ.get(UPSTREAM_ENV) or UPSTREAM).lower()
    top_s = _out(root, "rev-parse", "--show-toplevel")
    if top_s is None:
        return GitState(None, "none", reason="not a git checkout")
    top = Path(top_s).resolve()
    branch = _out(top, "symbolic-ref", "--quiet", "--short", "HEAD")
    has_head = _out(top, "rev-parse", "--verify", "--quiet", "HEAD") is not None
    head_ref = _out(
        top, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"
    )
    default = head_ref.split("/", 1)[1] if head_ref and "/" in head_ref else "main"
    url = _out(top, "remote", "get-url", "origin")
    origin = remote_slug(url) if url else None
    if origin == up:
        mode: GitMode = "clone"
        reason = f"origin is upstream {up}: changes go on a local branch"
    else:
        mode = "fork"
        reason = (
            f"origin is {origin}: committing on the current branch"
            if origin
            else "no origin remote: committing on the current branch"
        )
    return GitState(top, mode, branch, default, origin, has_head, reason)


def _sanitize(text: str) -> str:
    name = re.sub(r"[^a-z0-9._-]+", "-", text.lower()).strip("-.")
    return name or "host"


def _branch_exists(top: Path, name: str) -> bool:
    return (
        _out(top, "rev-parse", "--verify", "--quiet", f"refs/heads/{name}") is not None
    )


def branch_name(
    state: GitState, hostname: str, requested: str | None = None
) -> str | None:
    """Branch to commit on; ``None`` means stay on the current branch.

    clone mode on the default branch (or detached): ``requested`` or a new
    ``analyze/<host>`` (``-2``, ``-3`` ... when taken). Elsewhere: ``requested``
    if given, else the current branch.
    """
    if state.top is None:
        return None
    if requested:
        return None if requested == state.branch else requested
    if state.mode != "clone":
        return None
    if state.branch is not None and state.branch != state.default_branch:
        return None
    base = f"analyze/{_sanitize(hostname)}"
    name, n = base, 1
    while _branch_exists(state.top, name):
        n += 1
        name = f"{base}-{n}"
    return name


def switch_branch(state: GitState, name: str) -> None:
    """Check out ``name``, creating it from ``HEAD`` when it does not exist.

    Creating a branch from ``HEAD`` never touches the working tree; switching
    to an existing branch is left to git (it refuses to clobber local edits).
    """
    assert state.top is not None
    if _branch_exists(state.top, name):
        _git(state.top, "checkout", name)
    else:
        _git(state.top, "checkout", "-b", name)
    state.branch = name


@dataclass
class CommitResult:
    sha: str | None
    committed: list[str] = field(default_factory=list)  # repo-relative paths
    skipped: dict[str, str] = field(default_factory=dict)  # path -> reason


def commit_changes(
    state: GitState,
    labs: Sequence[tuple[Path, Sequence[Change]]],
    message: str,
) -> CommitResult:
    """Commit ``changes`` applied to the ``HEAD`` version of each lab."""
    assert state.top is not None
    top = state.top
    res = CommitResult(None)
    if not state.has_head:
        for path, _ in labs:
            res.skipped[str(path)] = "the repository has no commits yet"
        return res
    entries: list[tuple[str, str, str, str]] = []  # rel, mode, old sha, new sha
    for path, changes in labs:
        rel = Path(path).resolve().relative_to(top).as_posix()
        tree = _out(top, "ls-tree", "HEAD", "--", rel)
        if tree is None:
            res.skipped[rel] = "not tracked by git"
            continue
        mode, _, old_sha = tree.split("\t", 1)[0].split()
        head = _git(top, "cat-file", "blob", old_sha).stdout
        try:
            new = apply_changes(head, changes, Path(path))
        except EveLabError as exc:
            res.skipped[rel] = f"differs from HEAD ({exc.code}); left uncommitted"
            continue
        if new == head:
            res.skipped[rel] = "no change against HEAD"
            continue
        sha = (
            _git(top, "hash-object", "-w", "--stdin", stdin=new).stdout.decode().strip()
        )
        entries.append((rel, mode, old_sha, sha))
    if not entries:
        return res
    with tempfile.TemporaryDirectory(prefix="eve-analyze-git-") as tmp:
        env = {"GIT_INDEX_FILE": str(Path(tmp) / "index")}
        _git(top, "read-tree", "HEAD", env=env)
        for rel, mode, _old, sha in entries:
            _git(top, "update-index", "--cacheinfo", f"{mode},{sha},{rel}", env=env)
        tree_sha = _git(top, "write-tree", env=env).stdout.decode().strip()
    parent = _git(top, "rev-parse", "HEAD").stdout.decode().strip()
    commit = (
        _git(
            top,
            "commit-tree",
            tree_sha,
            "-p",
            parent,
            "-F",
            "-",
            stdin=message.encode(),
        )
        .stdout.decode()
        .strip()
    )
    _git(top, "update-ref", "-m", "eve-analyze: commit", "HEAD", commit, parent)
    # Keep the real index in step: entries that were unstaged (still the old
    # HEAD blob) now point at the committed blob, so the commit does not show
    # up as a staged revert.
    for rel, mode, old_sha, sha in entries:
        staged = _out(top, "ls-files", "-s", "--", rel)
        if staged and staged.split()[1] == old_sha:
            _git(top, "update-index", "--cacheinfo", f"{mode},{sha},{rel}")
        res.committed.append(rel)
    res.sha = commit
    return res
