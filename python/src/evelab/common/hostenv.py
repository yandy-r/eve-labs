"""EVE host probes (design 12.1, 15 rows 56/72/73): bridges, running nodes,
tmp leftovers, image availability and the exclusive lock.

Every probe takes its filesystem roots as keyword arguments so tests can point
them at fake ``/proc``, ``/sys/class/net`` and ``/opt/unetlab`` trees. On a host
without those trees (Windows, a laptop) probes return empty results instead of
failing; use :func:`proc_available` / :func:`sys_net_available` to tell "none"
from "cannot tell".
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Collection, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Literal

from .errors import PreconditionError
from .findings import Finding
from .labmodel import Node

try:  # POSIX only; the O_EXCL lockfile covers everything else
    import fcntl
except ImportError:  # pragma: no cover - exercised via use_fcntl=False
    fcntl = None  # type: ignore[assignment]

SYS_NET = Path("/sys/class/net")
PROC = Path("/proc")
UNETLAB_TMP = Path("/opt/unetlab/tmp")
ADDONS = Path("/opt/unetlab/addons")

# Extend here to add a cloud kind (design 13.3): (kind, full-match regex).
BRIDGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("pnet", re.compile(r"pnet\d+")),
    ("nat", re.compile(r"nat\d+")),
    ("cloud", re.compile(r"cloud\d+")),
]

IFF_UP = 0x1

# --------------------------------------------------------------------------
# Bridges
# --------------------------------------------------------------------------


def bridge_kind(name: str) -> str | None:
    """``pnet``/``nat``/``cloud`` for a matching name, else ``None``."""
    for kind, pat in BRIDGE_PATTERNS:
        if pat.fullmatch(name):
            return kind
    return None


@dataclass(frozen=True)
class BridgeInfo:
    """State of one EVE cloud bridge as seen in ``/sys/class/net``."""

    name: str
    kind: str | None
    exists: bool
    up: bool = False  # administratively up (IFF_UP)
    operstate: str = ""
    carrier: bool | None = None  # <iface>/carrier (None when unreadable)
    is_bridge: bool = False  # has a bridge/ directory
    ports: tuple[str, ...] = ()
    # VLAN-aware info (cheap sysfs reads; None when not reported)
    vlan_filtering: bool | None = None
    default_pvid: int | None = None

    @property
    def state(self) -> str:
        """``missing``, ``down`` (admin down), ``no-carrier`` (admin up, no link)
        or ``up``.

        A bridge is only ``up`` when IFF_UP is set *and* the kernel reports a
        working link (operstate ``up``/``unknown``, or carrier when operstate is
        not reported): ``<NO-CARRIER,...,UP> state DOWN`` is ``no-carrier``.
        """
        if not self.exists:
            return "missing"
        if not self.up:
            return "down"
        if self.operstate:
            ok = self.operstate in ("up", "unknown")
        else:
            ok = self.carrier is not False
        return "up" if ok else "no-carrier"

    @property
    def note(self) -> str:
        """Short annotation for prompts, e.g. ``up, 4 ports, vlan-aware``."""
        if not self.exists:
            return "not on this host"
        parts = [self.state]
        if self.is_bridge:
            parts.append(f"{len(self.ports)} port{'s' if len(self.ports) != 1 else ''}")
            if self.vlan_filtering:
                parts.append("vlan-aware")
        return ", ".join(parts)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _read_int(path: Path, base: int = 0) -> int | None:
    text = _read(path)
    if text is None:
        return None
    try:
        return int(text, base)
    except ValueError:
        return None


def sys_net_available(sys_net: Path = SYS_NET) -> bool:
    """False on hosts without sysfs network info (Windows, containers)."""
    return sys_net.is_dir()


def bridge_info(name: str, *, sys_net: Path = SYS_NET) -> BridgeInfo:
    """Probe one bridge by name; ``exists`` is False when it is absent."""
    base = sys_net / name
    kind = bridge_kind(name)
    if not base.is_dir():
        return BridgeInfo(name=name, kind=kind, exists=False)
    flags = _read_int(base / "flags", 16)
    operstate = _read(base / "operstate") or ""
    up = bool(flags & IFF_UP) if flags is not None else operstate in ("up", "unknown")
    car = _read_int(base / "carrier")  # unreadable (EINVAL) when admin down
    br = base / "bridge"
    is_bridge = br.is_dir()
    ports: tuple[str, ...] = ()
    if (base / "brif").is_dir():
        try:
            ports = tuple(sorted(p.name for p in (base / "brif").iterdir()))
        except OSError:
            ports = ()
    vf = _read_int(br / "vlan_filtering") if is_bridge else None
    return BridgeInfo(
        name=name,
        kind=kind,
        exists=True,
        up=up,
        operstate=operstate,
        carrier=None if car is None else bool(car),
        is_bridge=is_bridge,
        ports=ports,
        vlan_filtering=None if vf is None else bool(vf),
        default_pvid=_read_int(br / "default_pvid") if is_bridge else None,
    )


def _natural(name: str) -> tuple[str, int]:
    m = re.fullmatch(r"(\D+)(\d+)", name)
    return (m.group(1), int(m.group(2))) if m else (name, -1)


def list_bridges(*, sys_net: Path = SYS_NET) -> dict[str, BridgeInfo]:
    """All ``pnetN``/``natN``/``cloudN`` interfaces present, in natural order."""
    if not sys_net.is_dir():
        return {}
    try:
        names = [p.name for p in sys_net.iterdir() if bridge_kind(p.name)]
    except OSError:
        return {}
    return {n: bridge_info(n, sys_net=sys_net) for n in sorted(names, key=_natural)}


def bridge_notes(names: Iterable[str], *, sys_net: Path = SYS_NET) -> dict[str, str]:
    """``{name: note}`` for prompt choice annotation (design 10.2 bridge row)."""
    return {n: bridge_info(n, sys_net=sys_net).note for n in names}


def is_eve_host(*, sys_net: Path = SYS_NET) -> bool:
    """True when this host has EVE cloud bridges (any ``pnetN``)."""
    return any(b.kind == "pnet" for b in list_bridges(sys_net=sys_net).values())


def bridge_findings(names: Iterable[str], *, sys_net: Path = SYS_NET) -> list[Finding]:
    """Warnings for target bridges that cannot carry traffic on this EVE host.

    ``BRIDGE_NOT_ON_HOST`` (missing) and ``BRIDGE_NO_CARRIER`` (admin down or no
    link). Silent on hosts that are not EVE hosts (no ``pnetN`` in sysfs, e.g. a
    laptop preparing a profile), where any name is accepted.
    """
    if not is_eve_host(sys_net=sys_net):
        return []
    out: list[Finding] = []
    for name in sorted(set(names), key=_natural):
        info = bridge_info(name, sys_net=sys_net)
        if info.state == "missing":
            out.append(
                Finding(
                    "BRIDGE_NOT_ON_HOST",
                    "warn",
                    f"target bridge {name!r} does not exist on this host",
                    [f"bridge:{name}"],
                )
            )
        elif info.state != "up":
            out.append(
                Finding(
                    "BRIDGE_NO_CARRIER",
                    "warn",
                    f"target bridge {name!r} is {info.state} on this host "
                    f"(operstate {info.operstate or '?'}): nodes on it get no link",
                    [f"bridge:{name}"],
                )
            )
    return out


def bridges_summary(bridges: dict[str, BridgeInfo]) -> str:
    """``bridges: pnet0 up, pnet1 down, nat0 up`` (design 10.5 header)."""
    if not bridges:
        return "bridges: none detected"
    return "bridges: " + ", ".join(f"{b.name} {b.state}" for b in bridges.values())


# --------------------------------------------------------------------------
# Running nodes and leftovers
# --------------------------------------------------------------------------

# argv0 / executable basename -> node kind
_KIND_RE: list[tuple[str, re.Pattern[str]]] = [
    ("qemu", re.compile(r"qemu")),
    ("iol", re.compile(r"iol|i86bi")),
    ("dynamips", re.compile(r"dynamips")),
    ("vpcs", re.compile(r"vpcs")),
    ("docker", re.compile(r"docker")),
]
# Launchers whose own argv0 says nothing; classify by the words they run.
_LAUNCHERS = {"sh", "dash", "script", "chroot", "env", "timeout", "nohup", "setsid"}


@dataclass(frozen=True)
class RunningNode:
    """A live process (or container) that belongs to a lab."""

    pid: int | None
    kind: str  # qemu | iol | dynamips | vpcs | docker
    node_id: str | None
    source: Literal["proc", "docker"]
    cwd: str = ""
    cmd: str = ""  # truncated command line, for messages


def _uuid_re(lab_id: str) -> re.Pattern[str]:
    if not lab_id.strip():
        raise ValueError("lab_id must not be empty")
    return re.compile(r"(?<![0-9A-Za-z-])" + re.escape(lab_id) + r"(?![0-9A-Za-z])")


def proc_available(proc: Path = PROC) -> bool:
    """False when there is no ``/proc`` to scan (Windows, macOS)."""
    return proc.is_dir()


def _classify(argv: list[str]) -> str | None:
    base = os.path.basename(argv[0]) if argv else ""
    for kind, pat in _KIND_RE:
        if pat.search(base):
            return kind
    if base in _LAUNCHERS:
        for arg in argv[1:]:
            for word in arg.split():
                wbase = os.path.basename(word)
                for kind, pat in _KIND_RE:
                    if pat.match(wbase):
                        return kind
    return None


def _node_id_from(argv: list[str], cwd: str, lab_re: re.Pattern[str]) -> str | None:
    m = lab_re.search(cwd)
    if m:
        rest = [p for p in cwd[m.end() :].split("/") if p]
        if rest and rest[0].isdigit():
            return rest[0]
    for i, arg in enumerate(argv[:-1]):
        if arg == "-D" and argv[i + 1].isdigit():
            return argv[i + 1]
    return None


def docker_container_names(timeout: float = 5.0) -> list[str]:
    """Names of running docker containers; ``[]`` if docker is missing/unusable."""
    exe = shutil.which("docker")
    if exe is None:
        return []
    try:
        res = subprocess.run(
            [exe, "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if res.returncode != 0:
        return []
    return [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]


def docker_image_names(timeout: float = 5.0) -> set[str]:
    """``repo:tag`` names known to the local docker daemon (``set()`` if none)."""
    exe = shutil.which("docker")
    if exe is None:
        return set()
    try:
        res = subprocess.run(
            [exe, "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if res.returncode != 0:
        return set()
    return {ln.strip() for ln in res.stdout.splitlines() if ln.strip()}


def _procs(proc: Path) -> Iterator[tuple[int, list[str], str]]:
    try:
        entries = list(proc.iterdir())
    except OSError:
        return
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
        if not argv:
            continue
        try:
            cwd = os.readlink(entry / "cwd")
        except OSError:
            cwd = ""
        yield int(entry.name), argv, cwd


def running_nodes(
    lab_id: str,
    *,
    proc: Path = PROC,
    tmp_root: Path = UNETLAB_TMP,
    docker_names: Callable[[], Iterable[str]] = docker_container_names,
    self_pid: int | None = None,
) -> list[RunningNode]:
    """Live qemu/iol/dynamips/vpcs/docker nodes of the lab (design 12.1).

    A process counts when it is a recognised node launcher (by ``argv[0]``, or
    by the program an ``sh -c`` wrapper runs) **and** is tied to the lab: its
    command line mentions the lab UUID, or its working directory lies under
    ``<tmp_root>/<pod>/<uuid>/``. Shells, editors and greps that merely mention
    the UUID are ignored. Docker containers are matched by name
    (``<uuid>-<pod>-<node>``). A leftover tmp directory alone is *not* running.
    """
    lab_re = _uuid_re(lab_id)
    me = os.getpid() if self_pid is None else self_pid
    tmp_prefix = str(tmp_root).rstrip("/") + "/"
    found: list[RunningNode] = []
    for pid, argv, cwd in _procs(proc):
        if pid == me:
            continue
        kind = _classify(argv)
        if kind is None:
            continue
        in_tmp = cwd.startswith(tmp_prefix) and bool(lab_re.search(cwd))
        if not (in_tmp or any(lab_re.search(a) for a in argv)):
            continue
        cmd = " ".join(argv)
        found.append(
            RunningNode(
                pid=pid,
                kind=kind,
                node_id=_node_id_from(argv, cwd, lab_re),
                source="proc",
                cwd=cwd,
                cmd=cmd if len(cmd) <= 160 else cmd[:159] + "…",
            )
        )
    for name in docker_names():
        m = lab_re.search(name)
        if not m:
            continue
        tail = name[m.end() :].strip("-").split("-")
        found.append(
            RunningNode(
                pid=None,
                kind="docker",
                node_id=tail[-1] if tail and tail[-1].isdigit() else None,
                source="docker",
                cmd=name,
            )
        )
    return sorted(found, key=lambda n: (n.kind, n.node_id or "", n.pid or 0))


def tmp_leftovers(lab_id: str, *, tmp_root: Path = UNETLAB_TMP) -> list[Path]:
    """``<tmp_root>/<pod>/<lab_id>`` directories (nodes not wiped, maybe stopped)."""
    if not lab_id.strip() or not tmp_root.is_dir():
        return []
    try:
        pods = sorted(p for p in tmp_root.iterdir() if p.is_dir())
    except OSError:
        return []
    return [p / lab_id for p in pods if (p / lab_id).is_dir()]


def runtime_findings(
    lab_id: str,
    *,
    force_running: bool = False,
    proc: Path = PROC,
    tmp_root: Path = UNETLAB_TMP,
    docker_names: Callable[[], Iterable[str]] = docker_container_names,
    self_pid: int | None = None,
) -> list[Finding]:
    """Preflight findings for one lab (design 12.1 and 15 row 56).

    * live nodes -> ``RUNNING_NODES`` blocker (``warn`` with ``force_running``);
    * no live nodes but a tmp dir -> ``NODES_NOT_WIPED`` info (not a blocker);
    * no ``/proc`` -> ``HOST_PROBE_SKIPPED`` info (running state unknown).
    """
    findings: list[Finding] = []
    if not proc_available(proc):
        findings.append(
            Finding(
                "HOST_PROBE_SKIPPED",
                "info",
                "no /proc here: cannot tell whether the lab's nodes are running",
            )
        )
    live = running_nodes(
        lab_id,
        proc=proc,
        tmp_root=tmp_root,
        docker_names=docker_names,
        self_pid=self_pid,
    )
    if live:
        by_kind: dict[str, int] = {}
        for n in live:
            by_kind[n.kind] = by_kind.get(n.kind, 0) + 1
        what = ", ".join(f"{k} x{v}" for k, v in sorted(by_kind.items()))
        nodes = sorted({n.node_id for n in live if n.node_id}, key=_natural)
        where = f" (nodes {', '.join(nodes)})" if nodes else ""
        sev: Literal["warn", "blocker"] = "warn" if force_running else "blocker"
        hint = "continuing (--force-running)" if force_running else "stop and wipe them"
        findings.append(
            Finding(
                "RUNNING_NODES",
                sev,
                f"lab has running nodes: {what}{where}; {hint}",
                refs=[f"pid:{n.pid}" if n.pid else f"docker:{n.cmd}" for n in live],
            )
        )
        return findings
    left = tmp_leftovers(lab_id, tmp_root=tmp_root)
    if left:
        findings.append(
            Finding(
                "NODES_NOT_WIPED",
                "info",
                "nodes not wiped (no live processes); tmp dir present: "
                + ", ".join(str(p) for p in left),
                refs=[str(p) for p in left],
            )
        )
    return findings


# --------------------------------------------------------------------------
# Images
# --------------------------------------------------------------------------


def image_path(node_type: str, image: str, *, addons: Path = ADDONS) -> Path | None:
    """Where EVE keeps the image for a node type, or ``None`` when not file-based."""
    if not image or "/" in image or image in (".", ".."):
        return None
    if node_type == "qemu":
        return addons / "qemu" / image
    if node_type == "iol":
        return addons / "iol" / "bin" / image
    if node_type == "dynamips":
        return addons / "dynamips" / image
    return None


def image_available(
    node_type: str,
    image: str,
    *,
    addons: Path = ADDONS,
    docker_images: Collection[str] | None = None,
) -> bool | None:
    """True/False when it can be decided, ``None`` when unknown.

    qemu/iol/dynamips look under ``addons``; docker needs ``docker_images``
    (see :func:`docker_image_names`; a bare name matches ``name:latest``);
    vpcs needs no image.
    """
    if node_type == "vpcs":
        return True
    if node_type == "docker":
        if docker_images is None or not image:
            return None
        return image in docker_images or (
            ":" not in image and f"{image}:latest" in docker_images
        )
    path = image_path(node_type, image, addons=addons)
    if path is None:
        return None
    return path.exists()


def missing_images(
    nodes: Iterable[Node],
    *,
    addons: Path = ADDONS,
    docker_images: Collection[str] | None = None,
) -> list[Node]:
    """Nodes whose image is definitely absent on this host (``scan --images``)."""
    return [
        n
        for n in nodes
        if image_available(n.type, n.image, addons=addons, docker_images=docker_images)
        is False
    ]


# --------------------------------------------------------------------------
# Lock
# --------------------------------------------------------------------------


def _pid_alive(pid: int) -> bool | None:
    """True/False on POSIX; ``None`` where liveness cannot be tested safely."""
    if os.name != "posix":
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


class Lock:
    """Exclusive lock on a file (design 12.1): ``fcntl.flock`` when available,
    else an ``O_CREAT|O_EXCL`` lockfile holding the PID.

    Use as a context manager or call :meth:`acquire` / :meth:`release`. Held by
    someone else -> :class:`~evelab.common.errors.PreconditionError` (code
    ``LOCK_HELD``, exit 4). ``use_fcntl=False`` forces the fallback (tests,
    non-POSIX). A stale fallback lockfile whose PID is dead is taken over on
    POSIX; elsewhere the message tells the user to delete it.
    """

    def __init__(self, path: Path, *, use_fcntl: bool | None = None) -> None:
        self.path = Path(path)
        self.use_fcntl = (fcntl is not None) if use_fcntl is None else use_fcntl
        if self.use_fcntl and fcntl is None:
            raise ValueError("fcntl is not available on this platform")
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def _holder(self) -> str:
        text = _read(self.path)
        if text and text.split()[0].isdigit():
            return f" by pid {text.split()[0]}"
        return ""

    def acquire(self) -> Lock:
        if self._fd is not None:
            raise RuntimeError("lock already held by this object")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.use_fcntl:
            self._acquire_flock()
        else:
            self._acquire_excl()
        return self

    def _acquire_flock(self) -> None:
        assert fcntl is not None
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            holder = self._holder()
            os.close(fd)
            raise PreconditionError(
                f"another evelab run holds the lock{holder}: {self.path}",
                code="LOCK_HELD",
            ) from exc
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        self._fd = fd

    def _acquire_excl(self) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        for attempt in (0, 1):
            try:
                fd = os.open(self.path, flags, 0o644)
            except FileExistsError:
                text = _read(self.path)
                pid = int(text.split()[0]) if text and text.split()[0].isdigit() else 0
                alive = _pid_alive(pid) if pid else None
                if alive is False and attempt == 0:
                    with contextlib.suppress(FileNotFoundError):
                        self.path.unlink()
                    continue
                hint = (
                    "" if alive is not None else f" (delete it if stale: {self.path})"
                )
                raise PreconditionError(
                    f"another evelab run holds the lock{self._holder()}: "
                    f"{self.path}{hint}",
                    code="LOCK_HELD",
                ) from None
            os.write(fd, f"{os.getpid()}\n".encode())
            self._fd = fd
            return

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if self.use_fcntl:
                assert fcntl is not None
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
            if not self.use_fcntl:
                with contextlib.suppress(FileNotFoundError):
                    self.path.unlink()

    def __enter__(self) -> Lock:
        return self.acquire()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()


def exclusive_lock(path: Path, *, use_fcntl: bool | None = None) -> Lock:
    """``with exclusive_lock(Path('.localize/lock')):`` (see :class:`Lock`)."""
    return Lock(path, use_fcntl=use_fcntl)
