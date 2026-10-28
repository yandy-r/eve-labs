"""Mini lab and throwaway git repositories for eve-analyze tests."""

from __future__ import annotations

import io
import subprocess
import tempfile
from pathlib import Path

from evelab.analyze.cli import Runtime, main
from evelab.analyze.host import HostInventory, probe

from .fakehost import FakeHost

LAB_ID = "6b1d2a4e-0c1f-4d8e-9a55-2f0c3e7b9a10"

_NODE = (
    '      <node id="{id}" name="{name}" type="{type}" template="{template}" '
    'image="{image}" console="telnet" cpu="{cpu}" cpulimit="0" ram="{ram}" '
    'ethernet="4"{extra} delay="0" sat="0" icon="{icon}" config="0" '
    'left="100" top="100">\n'
    '        <interface id="0" name="e0" type="ethernet" network_id="{net}"/>\n'
    "      </node>\n"
)

NODES = (
    # id, name, type, template, image, cpu, ram, qemu_version, icon, net
    ("1", "leaf1", "qemu", "nxosv9k", "nxosv9k-9300v-10.3.3.F", "2", "16384", "4.1.0", "Nexus7K.png", "1"),
    ("2", "leaf2", "qemu", "nxosv9k", "nxosv9k-9300v-10.3.3.F", "2", "16384", "4.1.0", "Nexus7K.png", "3"),
    ("3", "r1", "qemu", "c8000v", "c8000v-17.11.01a", "8", "4096", "6.0.0", "Router.png", "3"),
    ("4", "sw1", "iol", "iol", "i86bi_linux_l2-adventerprisek9-ms.SSA.high_iron_20190423.bin", "1", "1024", "", "Switch.png", "3"),
    ("5", "srv", "docker", "docker", "eve-server-yr:latest", "1", "1024", "", "Server.png", "2"),
    ("6", "fw", "qemu", "paloalto", "paloalto-10.1.0", "2", "4096", "", "Firewall.png", "3"),
)  # fmt: skip


def mini_lab(lab_id: str = LAB_ID, nodes: tuple[tuple[str, ...], ...] = NODES) -> str:
    body = ""
    for nid, name, typ, tpl, image, cpu, ram, qv, icon, net in nodes:
        extra = f' qemu_version="{qv}"' if qv else ""
        body += _NODE.format(
            id=nid, name=name, type=typ, template=tpl, image=image, cpu=cpu,
            ram=ram, extra=extra, icon=icon, net=net,
        )  # fmt: skip
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<lab name="mini" id="{lab_id}" version="1" scripttimeout="300" lock="0">\n'
        "  <topology>\n"
        "    <nodes>\n"
        f"{body}"
        "    </nodes>\n"
        "    <networks>\n"
        '      <network id="1" type="pnet0" name="MGMT" left="1" top="1" visibility="1"/>\n'
        '      <network id="2" type="pnet3" name="INET" left="1" top="1" visibility="1"/>\n'
        '      <network id="3" type="bridge" name="p2p" left="1" top="1" visibility="0"/>\n'
        "    </networks>\n"
        "  </topology>\n"
        "</lab>\n"
    )


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


class Repo:
    """A temp checkout with ``labs/mini.unl`` (+ git when ``origin`` is set).

    ``origin=None`` with ``git=True`` means a repository without remotes.
    """

    def __init__(
        self, origin: str | None = None, *, use_git: bool = True, **host: object
    ) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="evelab-analyze-")
        self.root = Path(self._tmp.name).resolve()
        self.lab = self.root / "labs" / "mini.unl"
        self.lab.parent.mkdir(parents=True)
        self.lab.write_text(mini_lab(), encoding="utf-8")
        (self.root / "docker" / "eve-server-yr").mkdir(parents=True)
        (self.root / "docker" / "eve-server-yr" / "Dockerfile").write_text("FROM x\n")
        self.host = FakeHost(**host)  # type: ignore[arg-type]
        self.proc = self.root / ".fakeproc"
        self.proc.mkdir()
        if use_git:
            git(self.root, "init", "-q", "-b", "main")
            git(self.root, "config", "user.name", "Test")
            git(self.root, "config", "user.email", "test@example.com")
            git(self.root, "config", "commit.gpgsign", "false")
            git(self.root, "add", "labs", "docker")
            git(self.root, "commit", "-q", "-m", "init")
            if origin:
                git(self.root, "remote", "add", "origin", origin)

    def inventory(self) -> HostInventory:
        return probe(self.host.roots)

    def run(
        self, *argv: str, stdin: str = "", interactive: bool = False
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        rt = Runtime(
            stdin=io.StringIO(stdin),
            stdout=out,
            stderr=err,
            env={"NO_COLOR": "1"},
            interactive=interactive,
            roots=self.host.roots,
            proc=self.proc,
            tmp_root=self.root / ".faketmp",
            docker_names=list,
        )
        code = main([*argv, "--root", str(self.root)], rt)
        return code, out.getvalue(), err.getvalue()

    def cleanup(self) -> None:
        self.host.cleanup()
        self._tmp.cleanup()
