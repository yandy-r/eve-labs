"""What this EVE host offers: images, templates, QEMU builds, bridges, CPU/RAM.

:func:`probe` reads the host (every root is a keyword argument so tests can
point it at a fake tree). :class:`HostInventory` round-trips through JSON
(``eve-analyze inventory``), so a lab checkout on a laptop can be analysed
against an inventory taken on the EVE host (``--inventory FILE``).

``None`` in a field means "could not tell" (no such tree, docker not
installed); checks that need that field are skipped instead of guessing.
"""

from __future__ import annotations

import json
import os
import re
import socket
from collections.abc import Callable, Collection, Mapping
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from evelab.common import hostenv
from evelab.common.errors import EveLabError

__all__ = ["INVENTORY_SCHEMA", "HostInventory", "HostRoots", "probe"]

INVENTORY_SCHEMA = 1

UNETLAB = Path("/opt/unetlab")
OPT = Path("/opt")
DEV_KVM = Path("/dev/kvm")

_QEMU_DIR = re.compile(r"qemu-(\d+(?:\.\d+)+)")
# Files that make a qemu image folder usable (EVE boots the first hdX/cdrom).
_QEMU_DISK = re.compile(r".*\.(qcow2|img|iso|vmdk|raw)", re.IGNORECASE)


@dataclass
class HostRoots:
    """Filesystem roots :func:`probe` reads (defaults: the real EVE paths)."""

    addons: Path = hostenv.ADDONS
    templates: Path = UNETLAB / "html" / "templates"
    icons: Path = UNETLAB / "html" / "images" / "icons"
    opt: Path = OPT
    sys_net: Path = hostenv.SYS_NET
    proc: Path = hostenv.PROC
    dev_kvm: Path = DEV_KVM
    docker_images: Callable[[], Collection[str] | None] = lambda: _docker_images()
    hostname: Callable[[], str] = socket.gethostname


def _docker_images() -> set[str] | None:
    """Local docker images, ``None`` when docker is not installed here."""
    import shutil

    if shutil.which("docker") is None:
        return None
    return hostenv.docker_image_names()


@dataclass
class HostInventory:
    """Snapshot of one EVE host. Lists are sorted; see the module docstring."""

    hostname: str = ""
    eve: bool = False  # /opt/unetlab/addons exists
    qemu_images: list[str] = field(default_factory=list)
    iol_images: list[str] = field(default_factory=list)
    dynamips_images: list[str] = field(default_factory=list)
    docker_images: list[str] | None = None
    templates: list[str] | None = None
    qemu_versions: list[str] | None = None
    bridges: dict[str, str] = field(default_factory=dict)  # name -> state
    cpus: int | None = None
    mem_mb: int | None = None
    kvm: bool | None = None
    iol_license: bool | None = None
    icons: list[str] | None = None
    empty_qemu_dirs: list[str] = field(default_factory=list)

    def images(self, node_type: str) -> list[str] | None:
        """Images of ``node_type`` on this host (``None``: cannot tell)."""
        return {
            "qemu": self.qemu_images,
            "iol": self.iol_images,
            "dynamips": self.dynamips_images,
            "docker": self.docker_images,
        }.get(node_type)

    def to_json(self) -> dict[str, Any]:
        return {"schema": INVENTORY_SCHEMA, **asdict(self)}

    @classmethod
    def from_json(
        cls, data: Mapping[str, Any], source: str = "inventory"
    ) -> HostInventory:
        if not isinstance(data, Mapping) or data.get("schema") != INVENTORY_SCHEMA:
            raise EveLabError(
                f"{source}: not an eve-analyze inventory (schema {INVENTORY_SCHEMA})",
                code="BAD_INVENTORY",
            )
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    @classmethod
    def load(cls, path: Path) -> HostInventory:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise EveLabError(f"{path}: {exc}", code="BAD_INVENTORY") from exc
        return cls.from_json(data, str(path))


def _names(path: Path, pred: Callable[[Path], bool]) -> list[str] | None:
    if not path.is_dir():
        return None
    try:
        return sorted(p.name for p in path.iterdir() if pred(p))
    except OSError:
        return None


def _has_disk(folder: Path) -> bool:
    try:
        return any(_QEMU_DISK.fullmatch(p.name) for p in folder.iterdir())
    except OSError:
        return False


def _templates(root: Path, proc: Path) -> list[str] | None:
    """Template names (``<name>.yml``): the CPU vendor's folder, else all."""
    vendor = "amd" if "AuthenticAMD" in _read(proc / "cpuinfo") else "intel"
    dirs = [root / vendor] if (root / vendor).is_dir() else []
    dirs = dirs or [d for d in (root / "intel", root / "amd", root) if d.is_dir()]
    if not dirs:
        return None
    out: set[str] = set()
    for d in dirs:
        out.update(n[:-4] for n in _names(d, lambda p: p.suffix == ".yml") or [])
    return sorted(out)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _mem_mb(proc: Path) -> int | None:
    m = re.search(r"^MemTotal:\s+(\d+)\s*kB", _read(proc / "meminfo"), re.M)
    return int(m.group(1)) // 1024 if m else None


def _cpus(proc: Path) -> int | None:
    n = len(re.findall(r"^processor\s*:", _read(proc / "cpuinfo"), re.M))
    return n or None


def _qemu_versions(opt: Path) -> list[str] | None:
    names = _names(opt, lambda p: p.is_dir() and bool(_QEMU_DIR.fullmatch(p.name)))
    if names is None:
        return None
    vers = [m.group(1) for n in names if (m := _QEMU_DIR.fullmatch(n))]
    return sorted(vers, key=lambda v: tuple(int(x) for x in v.split(".")))


def probe(roots: HostRoots | None = None) -> HostInventory:
    """Read this host (see :class:`HostRoots` for the paths)."""
    r = roots or HostRoots()
    addons = r.addons
    eve = addons.is_dir()
    qemu_dirs = _names(addons / "qemu", lambda p: p.is_dir()) or []
    usable = [n for n in qemu_dirs if _has_disk(addons / "qemu" / n)]
    iol = _names(addons / "iol" / "bin", lambda p: p.is_file() and p.suffix == ".bin")
    dyn = _names(addons / "dynamips", lambda p: p.is_file() and p.suffix == ".image")
    docker = r.docker_images()
    bridges = hostenv.list_bridges(sys_net=r.sys_net)
    icons = _names(r.icons, lambda p: p.is_file())
    return HostInventory(
        hostname=r.hostname(),
        eve=eve,
        qemu_images=usable,
        iol_images=iol or [],
        dynamips_images=dyn or [],
        docker_images=None if docker is None else sorted(docker),
        templates=_templates(r.templates, r.proc),
        qemu_versions=_qemu_versions(r.opt),
        bridges={name: b.state for name, b in bridges.items()},
        cpus=_cpus(r.proc) or (os.cpu_count() if r.proc == hostenv.PROC else None),
        mem_mb=_mem_mb(r.proc),
        kvm=r.dev_kvm.exists() if eve else None,
        iol_license=(addons / "iol" / "bin" / "iourc").is_file() if eve else None,
        icons=icons,
        empty_qemu_dirs=[n for n in qemu_dirs if n not in usable],
    )
