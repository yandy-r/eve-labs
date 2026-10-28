"""A fake EVE host tree (addons, templates, /opt/qemu-*, sysfs, /proc) for tests."""

from __future__ import annotations

import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path

from evelab.analyze.host import HostRoots

QEMU = (
    "nxosv9k-9300v-10.5.1.F",
    "nxosv9k-9500v-10.3.3.F",
    "c8000v-17.11.01a",
    "c8000v-17.15.01",
    "fortinet-FGT-v7-build3744",
    "viosl2-adventerprisek9-m.ssa.high_iron_20200929",
    "vjunosswitch-24.2R1-S1",
    "asav-918-2",
    "bigip-17.5.0-0.0.15",
    "csr1000vng-universalk9.17.03.06.Amsterdam",
    "winserver-2022",
    "vtedge-20.10.1",
    "vtsmart-20.10.1",
    "vtmgmt-20.10.1",
    "vtbond-20.10.1",
    "vios-adventerprisek9-m.spa.159-3.m6",
)
IOL = (
    "i86bi_LinuxL3-AdvEnterpriseK9-M2_157_3_May_2018.bin",
    "x86_64_crb_linux_l2-adventerprisek9-ms.bin",
)
TEMPLATES = [
    "nxosv9k",
    "c8000v",
    "fortinet",
    "viosl2",
    "vjunosswitch",
    "asav",
    "bigip",
    "csr1000vng",
    "winserver",
    "vtedge",
    "vtsmart",
    "vtmgmt",
    "vtbond",
    "vios",
    "iol",
    "win",
]


class FakeHost:
    """Build the tree in a temp dir; ``roots`` points :func:`probe` at it."""

    def __init__(
        self,
        *,
        qemu: Iterable[str] = QEMU,
        empty_qemu: Iterable[str] = ("emptyimg-1",),
        iol: Iterable[str] = IOL,
        dynamips: Iterable[str] = (),
        templates: Iterable[str] = TEMPLATES,
        qemu_versions: Iterable[str] = ("2.12.0", "6.0.0"),
        bridges: Mapping[str, bool] | None = None,
        cpus: int = 4,
        mem_mb: int = 12000,
        kvm: bool = True,
        iourc: bool = True,
        icons: Iterable[str] | None = None,
        docker: Iterable[str] | None = ("eve-gui-server:latest",),
        hostname: str = "eve2",
    ) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="evelab-fakehost-")
        t = self.base = Path(self._tmp.name)
        addons = t / "addons"
        for name in qemu:
            (addons / "qemu" / name).mkdir(parents=True)
            (addons / "qemu" / name / "virtioa.qcow2").write_bytes(b"")
        for name in empty_qemu:
            (addons / "qemu" / name).mkdir(parents=True)
        (addons / "iol" / "bin").mkdir(parents=True)
        for name in iol:
            (addons / "iol" / "bin" / name).write_bytes(b"")
        if iourc:
            (addons / "iol" / "bin" / "iourc").write_text("[license]\n")
        (addons / "dynamips").mkdir(parents=True)
        for name in dynamips:
            (addons / "dynamips" / name).write_bytes(b"")
        (t / "templates" / "intel").mkdir(parents=True)
        for name in templates:
            (t / "templates" / "intel" / f"{name}.yml").write_text("---\n")
        (t / "opt").mkdir()
        for v in qemu_versions:
            (t / "opt" / f"qemu-{v}").mkdir()
        net = t / "net"
        net.mkdir()
        for name, up in (bridges if bridges is not None else {"pnet0": True}).items():
            (net / name / "bridge").mkdir(parents=True)
            (net / name / "flags").write_text("0x1003\n" if up else "0x1002\n")
            (net / name / "operstate").write_text("up\n" if up else "down\n")
        proc = t / "proc"
        proc.mkdir()
        (proc / "cpuinfo").write_text(
            "".join(
                f"processor\t: {i}\nvendor_id\t: GenuineIntel\n" for i in range(cpus)
            )
        )
        (proc / "meminfo").write_text(f"MemTotal:       {mem_mb * 1024} kB\n")
        if kvm:
            (t / "kvm").write_text("")
        (t / "icons").mkdir()
        for name in icons if icons is not None else ():
            (t / "icons" / name).write_text("")
        self._docker = None if docker is None else set(docker)
        self.roots = HostRoots(
            addons=addons,
            templates=t / "templates",
            icons=t / "icons" if icons is not None else t / "no-icons",
            opt=t / "opt",
            sys_net=net,
            proc=proc,
            dev_kvm=t / "kvm",
            docker_images=lambda: self._docker,
            hostname=lambda: hostname,
        )

    def cleanup(self) -> None:
        self._tmp.cleanup()
