"""Tests for evelab.common.hostenv using fake /proc, /sys and /opt/unetlab trees."""

import os
import tempfile
import unittest
from pathlib import Path

from evelab.common import hostenv
from evelab.localize.errors import PreconditionError
from evelab.localize.model import Node

LAB = "2fd99c11-2334-45b3-ac61-ee23ab5c9d38"
OTHER = "aaaaaaaa-0000-4000-8000-bbbbbbbbbbbb"


def no_docker() -> list[str]:
    return []


class TempTree(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name)
        self.proc = self.root / "proc"
        self.sys_net = self.root / "sys_net"
        self.tmp = self.root / "unetlab" / "tmp"
        self.addons = self.root / "unetlab" / "addons"
        for d in (self.proc, self.sys_net, self.tmp, self.addons):
            d.mkdir(parents=True)

    def add_proc(self, pid: int, argv: list[str], cwd: str | None = None) -> None:
        d = self.proc / str(pid)
        d.mkdir()
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        if cwd is not None:
            try:
                os.symlink(cwd, d / "cwd")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")

    def lab_dir(self, lab: str = LAB, pod: str = "0", node: str = "2") -> Path:
        d = self.tmp / pod / lab / node
        d.mkdir(parents=True, exist_ok=True)
        return d


class BridgeTests(TempTree):
    def add_bridge(
        self,
        name: str,
        *,
        flags: str = "0x1003",
        oper: str = "up",
        ports: tuple[str, ...] = (),
        vlan: str | None = None,
        pvid: str | None = None,
        bridge: bool = True,
    ) -> None:
        d = self.sys_net / name
        d.mkdir()
        (d / "flags").write_text(flags + "\n")
        (d / "operstate").write_text(oper + "\n")
        if bridge:
            (d / "bridge").mkdir()
            if vlan is not None:
                (d / "bridge" / "vlan_filtering").write_text(vlan + "\n")
            if pvid is not None:
                (d / "bridge" / "default_pvid").write_text(pvid + "\n")
            (d / "brif").mkdir()
            for p in ports:
                (d / "brif" / p).mkdir()

    def test_kinds(self) -> None:
        self.assertEqual(hostenv.bridge_kind("pnet0"), "pnet")
        self.assertEqual(hostenv.bridge_kind("nat12"), "nat")
        self.assertEqual(hostenv.bridge_kind("cloud3"), "cloud")
        for bad in ("eth0", "pnet", "natmac", "xpnet0", "pnet0a", "Net-pnet0"):
            self.assertIsNone(hostenv.bridge_kind(bad), bad)

    def test_list_bridges_filters_and_sorts(self) -> None:
        for n in ("pnet10", "pnet2", "nat0", "eth0", "natmac", "docker0"):
            self.add_bridge(n)
        got = hostenv.list_bridges(sys_net=self.sys_net)
        self.assertEqual(list(got), ["nat0", "pnet2", "pnet10"])

    def test_info_up_down_vlan(self) -> None:
        self.add_bridge("pnet0", ports=("eth0", "vun1"), vlan="1", pvid="1")
        self.add_bridge("pnet1", flags="0x1002", oper="down")
        self.add_bridge("nat0", flags="0x1003", oper="unknown", vlan="0")
        up = hostenv.bridge_info("pnet0", sys_net=self.sys_net)
        self.assertTrue(up.exists and up.up and up.is_bridge)
        self.assertEqual(up.ports, ("eth0", "vun1"))
        self.assertIs(up.vlan_filtering, True)
        self.assertEqual(up.default_pvid, 1)
        self.assertEqual(up.state, "up")
        self.assertEqual(up.note, "up, 2 ports, vlan-aware")
        down = hostenv.bridge_info("pnet1", sys_net=self.sys_net)
        self.assertFalse(down.up)
        self.assertEqual(down.state, "down")
        nat = hostenv.bridge_info("nat0", sys_net=self.sys_net)
        self.assertEqual(nat.kind, "nat")
        self.assertIs(nat.vlan_filtering, False)
        self.assertTrue(nat.up)  # IFF_UP set even though operstate is unknown

    def test_missing_and_non_bridge(self) -> None:
        miss = hostenv.bridge_info("pnet7", sys_net=self.sys_net)
        self.assertFalse(miss.exists)
        self.assertEqual(miss.state, "missing")
        self.assertEqual(miss.note, "not on this host")
        self.add_bridge("pnet3", bridge=False)
        plain = hostenv.bridge_info("pnet3", sys_net=self.sys_net)
        self.assertTrue(plain.exists)
        self.assertFalse(plain.is_bridge)
        self.assertIsNone(plain.vlan_filtering)

    def test_operstate_fallback_without_flags(self) -> None:
        self.add_bridge("pnet4", oper="up")
        (self.sys_net / "pnet4" / "flags").unlink()
        self.assertTrue(hostenv.bridge_info("pnet4", sys_net=self.sys_net).up)

    def test_notes_and_summary(self) -> None:
        self.add_bridge("pnet0")
        self.add_bridge("pnet1", flags="0x1002", oper="down")
        notes = hostenv.bridge_notes(["pnet0", "pnet9"], sys_net=self.sys_net)
        self.assertEqual(notes["pnet9"], "not on this host")
        self.assertTrue(notes["pnet0"].startswith("up"))
        got = hostenv.list_bridges(sys_net=self.sys_net)
        self.assertEqual(hostenv.bridges_summary(got), "bridges: pnet0 up, pnet1 down")
        self.assertEqual(hostenv.bridges_summary({}), "bridges: none detected")

    def test_no_sysfs(self) -> None:
        gone = self.root / "nothing"
        self.assertFalse(hostenv.sys_net_available(gone))
        self.assertEqual(hostenv.list_bridges(sys_net=gone), {})
        self.assertTrue(hostenv.sys_net_available(self.sys_net))


class RunningNodeTests(TempTree):
    def run_nodes(self, **kw: object) -> list[hostenv.RunningNode]:
        return hostenv.running_nodes(
            LAB,
            proc=self.proc,
            tmp_root=self.tmp,
            docker_names=no_docker,
            self_pid=1,
            **kw,  # type: ignore[arg-type]
        )

    def test_qemu_wrapper_by_cmdline_and_cwd(self) -> None:
        cwd = self.lab_dir()
        self.add_proc(
            100,
            ["/opt/unetlab/wrappers/qemu_wrapper", "-D", "2", "-uuid", "x"],
            str(cwd),
        )
        got = self.run_nodes()
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0].pid, got[0].kind, got[0].node_id), (100, "qemu", "2"))
        self.assertEqual(got[0].source, "proc")

    def test_sh_chroot_wrapper_classified_by_program(self) -> None:
        cwd = self.lab_dir(node="7")
        self.add_proc(
            101,
            [
                "sh",
                "-c",
                "--",
                "TAG=T0D7- chroot . /opt/qemu-4.1.0/bin/qemu-system-x86_64 -m 1",
            ],
            str(cwd),
        )
        got = self.run_nodes()
        self.assertEqual([(n.kind, n.node_id) for n in got], [("qemu", "7")])

    def test_iol_and_vpcs_and_dynamips_by_uuid_arg(self) -> None:
        for pid, exe in (
            (10, "iol_wrapper"),
            (11, "/opt/vpcs/bin/vpcs"),
            (12, "dynamips"),
        ):
            self.add_proc(
                pid, [exe, "-T", "0", "-L", "1", f"/opt/unetlab/tmp/0/{LAB}/3"]
            )
        kinds = sorted(n.kind for n in self.run_nodes())
        self.assertEqual(kinds, ["dynamips", "iol", "vpcs"])

    def test_cmdline_without_cwd_symlink(self) -> None:
        self.add_proc(20, ["qemu_wrapper", "-t", "n", f"/x/{LAB}/4"])
        got = self.run_nodes()
        self.assertEqual(len(got), 1)
        self.assertIsNone(got[0].node_id)

    def test_other_lab_ignored(self) -> None:
        cwd = self.lab_dir(OTHER)
        self.add_proc(30, ["qemu_wrapper", "-D", "2"], str(cwd))
        self.add_proc(31, ["qemu_wrapper", "-uuid", OTHER])
        self.assertEqual(self.run_nodes(), [])

    def test_uuid_prefix_suffix_not_matched(self) -> None:
        self.add_proc(32, ["qemu_wrapper", LAB + "0"])
        self.add_proc(33, ["qemu_wrapper", "a" + LAB])
        self.assertEqual(self.run_nodes(), [])

    def test_unrelated_processes_mentioning_uuid_ignored(self) -> None:
        cwd = self.lab_dir()
        self.add_proc(40, ["bash"], str(cwd))  # a shell sitting in the lab tmp dir
        self.add_proc(41, ["grep", "-r", LAB, "/opt/unetlab"])
        self.add_proc(42, ["vim", f"/opt/unetlab/tmp/0/{LAB}/2/x.txt"])
        self.add_proc(43, ["python3", "eve-localize", "--lab", LAB])
        self.add_proc(44, ["bash", "-c", f"docker ps | grep {LAB}"])
        self.assertEqual(self.run_nodes(), [])

    def test_self_pid_excluded(self) -> None:
        self.add_proc(50, ["qemu_wrapper", LAB])
        got = hostenv.running_nodes(
            LAB, proc=self.proc, tmp_root=self.tmp, docker_names=no_docker, self_pid=50
        )
        self.assertEqual(got, [])

    def test_bad_proc_entries_skipped(self) -> None:
        (self.proc / "self").mkdir()
        (self.proc / "999").mkdir()  # no cmdline
        zombie = self.proc / "998"
        zombie.mkdir()
        (zombie / "cmdline").write_bytes(b"")
        self.assertEqual(self.run_nodes(), [])

    def test_docker_containers(self) -> None:
        names = [f"{LAB}-0-37", f"{LAB}-0-34", f"{OTHER}-0-1", "unrelated"]
        got = hostenv.running_nodes(
            LAB,
            proc=self.proc,
            tmp_root=self.tmp,
            docker_names=lambda: names,
            self_pid=1,
        )
        self.assertEqual(
            [(n.kind, n.node_id, n.source) for n in got],
            [
                ("docker", "34", "docker"),
                ("docker", "37", "docker"),
            ],
        )
        self.assertIsNone(got[0].pid)

    def test_empty_lab_id_rejected(self) -> None:
        with self.assertRaises(ValueError):
            hostenv.running_nodes(" ", proc=self.proc, docker_names=no_docker)

    def test_long_cmd_truncated(self) -> None:
        self.add_proc(60, ["qemu_wrapper", LAB, "x" * 500])
        self.assertLessEqual(len(self.run_nodes()[0].cmd), 160)

    def test_proc_available(self) -> None:
        self.assertTrue(hostenv.proc_available(self.proc))
        self.assertFalse(hostenv.proc_available(self.root / "none"))


class LeftoverFindingTests(TempTree):
    def findings(self, **kw: object):  # type: ignore[no-untyped-def]
        return hostenv.runtime_findings(
            LAB,
            proc=self.proc,
            tmp_root=self.tmp,
            docker_names=no_docker,
            self_pid=1,
            **kw,  # type: ignore[arg-type]
        )

    def test_leftovers_listed(self) -> None:
        self.lab_dir(pod="0")
        self.lab_dir(pod="3")
        self.lab_dir(OTHER, pod="0")
        (self.tmp / "index").write_text("x")
        got = hostenv.tmp_leftovers(LAB, tmp_root=self.tmp)
        self.assertEqual(got, [self.tmp / "0" / LAB, self.tmp / "3" / LAB])
        self.assertEqual(hostenv.tmp_leftovers(LAB, tmp_root=self.root / "none"), [])
        self.assertEqual(hostenv.tmp_leftovers("", tmp_root=self.tmp), [])

    def test_leftover_without_process_is_info_not_blocker(self) -> None:
        self.lab_dir()
        got = self.findings()
        self.assertEqual(
            [(f.code, f.severity) for f in got], [("NODES_NOT_WIPED", "info")]
        )
        self.assertIn("nodes not wiped", got[0].msg)
        self.assertNotIn("running", got[0].msg.replace("no live", ""))

    def test_nothing_at_all(self) -> None:
        self.assertEqual(self.findings(), [])

    def test_running_is_blocker(self) -> None:
        cwd = self.lab_dir(node="2")
        self.add_proc(100, ["qemu_wrapper", "-D", "2"], str(cwd))
        self.add_proc(101, ["qemu_wrapper", "-D", "2"], str(cwd))
        got = self.findings()
        self.assertEqual(
            [(f.code, f.severity) for f in got], [("RUNNING_NODES", "blocker")]
        )
        self.assertIn("qemu x2", got[0].msg)
        self.assertIn("nodes 2", got[0].msg)
        self.assertEqual(got[0].refs, ["pid:100", "pid:101"])

    def test_force_running_downgrades_to_warn(self) -> None:
        self.lab_dir()
        self.add_proc(100, ["qemu_wrapper", LAB])
        got = self.findings(force_running=True)
        self.assertEqual(got[0].severity, "warn")
        self.assertIn("--force-running", got[0].msg)

    def test_no_proc_reports_skipped(self) -> None:
        got = hostenv.runtime_findings(
            LAB,
            proc=self.root / "none",
            tmp_root=self.tmp,
            docker_names=no_docker,
        )
        self.assertEqual([f.code for f in got], ["HOST_PROBE_SKIPPED"])
        self.assertEqual(got[0].severity, "info")


class ImageTests(TempTree):
    def test_qemu_iol_dynamips(self) -> None:
        (self.addons / "qemu" / "c8000v-17.11.01a").mkdir(parents=True)
        (self.addons / "iol" / "bin").mkdir(parents=True)
        (self.addons / "iol" / "bin" / "i86bi_x.bin").write_text("")
        (self.addons / "dynamips").mkdir()
        (self.addons / "dynamips" / "c7200.image").write_text("")
        a = self.addons
        self.assertIs(
            hostenv.image_available("qemu", "c8000v-17.11.01a", addons=a), True
        )
        self.assertIs(hostenv.image_available("qemu", "nope", addons=a), False)
        self.assertIs(hostenv.image_available("iol", "i86bi_x.bin", addons=a), True)
        self.assertIs(hostenv.image_available("iol", "other.bin", addons=a), False)
        self.assertIs(
            hostenv.image_available("dynamips", "c7200.image", addons=a), True
        )

    def test_unknown_cases(self) -> None:
        a = self.addons
        self.assertIsNone(hostenv.image_available("qemu", "", addons=a))
        self.assertIsNone(hostenv.image_available("docker", "x:latest", addons=a))
        self.assertIsNone(hostenv.image_available("weird", "x", addons=a))
        self.assertIs(hostenv.image_available("vpcs", "", addons=a), True)

    def test_path_traversal_not_probed(self) -> None:
        self.assertIsNone(hostenv.image_path("qemu", "../etc", addons=self.addons))
        self.assertIsNone(hostenv.image_path("qemu", "a/b", addons=self.addons))
        self.assertIsNone(hostenv.image_path("qemu", "..", addons=self.addons))

    def test_docker_images(self) -> None:
        have = {"eve-server-yr:latest", "ubuntu:24.04"}
        f = hostenv.image_available
        self.assertIs(f("docker", "eve-server-yr:latest", docker_images=have), True)
        self.assertIs(f("docker", "eve-server-yr", docker_images=have), True)
        self.assertIs(f("docker", "ubuntu", docker_images=have), False)
        self.assertIs(f("docker", "ubuntu:22.04", docker_images=have), False)

    def test_missing_images(self) -> None:
        (self.addons / "qemu" / "have").mkdir(parents=True)

        def node(i: str, t: str, img: str) -> Node:
            return Node(i, f"n{i}", t, t, img, "0", [])

        nodes = [
            node("1", "qemu", "have"),
            node("2", "qemu", "gone"),
            node("3", "docker", "x:1"),
            node("4", "vpcs", ""),
            node("5", "docker", "y:1"),
        ]
        got = hostenv.missing_images(nodes, addons=self.addons, docker_images={"y:1"})
        self.assertEqual([n.id for n in got], ["2", "3"])
        # docker unknown without a docker image list
        got = hostenv.missing_images(nodes, addons=self.addons)
        self.assertEqual([n.id for n in got], ["2"])


class LockTests(TempTree):
    @unittest.skipIf(hostenv.fcntl is None, "fcntl unavailable")
    def test_flock_exclusive_and_release(self) -> None:
        path = self.root / ".localize" / "lock"
        with hostenv.exclusive_lock(path) as lk:
            self.assertTrue(lk.held)
            self.assertEqual(path.read_text().strip(), str(os.getpid()))
            with self.assertRaises(PreconditionError) as cm:
                hostenv.exclusive_lock(path).acquire()
            self.assertEqual(cm.exception.code, "LOCK_HELD")
            self.assertEqual(cm.exception.exit_code, 4)
            self.assertIn(f"pid {os.getpid()}", str(cm.exception))
        self.assertFalse(lk.held)
        with hostenv.exclusive_lock(path):  # free again
            pass

    @unittest.skipIf(hostenv.fcntl is None, "fcntl unavailable")
    def test_flock_released_on_exception(self) -> None:
        path = self.root / "lock"
        with self.assertRaises(RuntimeError), hostenv.exclusive_lock(path):
            raise RuntimeError("boom")
        hostenv.exclusive_lock(path).acquire().release()

    def test_fallback_excl_lockfile(self) -> None:
        path = self.root / "sub" / "lock"
        with hostenv.exclusive_lock(path, use_fcntl=False) as lk:
            self.assertTrue(path.exists())
            self.assertEqual(path.read_text().strip(), str(os.getpid()))
            with self.assertRaises(PreconditionError) as cm:
                hostenv.exclusive_lock(path, use_fcntl=False).acquire()
            self.assertEqual(cm.exception.code, "LOCK_HELD")
            self.assertIs(lk.held, True)
        self.assertFalse(path.exists())

    @unittest.skipUnless(os.name == "posix", "pid liveness needs POSIX")
    def test_fallback_takes_over_stale_lock(self) -> None:
        path = self.root / "lock"
        # a pid that cannot exist (above pid_max on Linux and most unixes)
        path.write_text("2147483646\n")
        with hostenv.exclusive_lock(path, use_fcntl=False):
            self.assertEqual(path.read_text().strip(), str(os.getpid()))

    def test_fallback_unparseable_lockfile_is_held(self) -> None:
        path = self.root / "lock"
        path.write_text("garbage")
        with self.assertRaises(PreconditionError) as cm:
            hostenv.exclusive_lock(path, use_fcntl=False).acquire()
        self.assertTrue(path.exists())
        self.assertIn("lock", str(cm.exception))

    def test_double_acquire_same_object(self) -> None:
        lk = hostenv.Lock(self.root / "lock", use_fcntl=False)
        lk.acquire()
        try:
            with self.assertRaises(RuntimeError):
                lk.acquire()
        finally:
            lk.release()
        lk.release()  # idempotent

    def test_use_fcntl_without_module_rejected(self) -> None:
        saved = hostenv.fcntl
        hostenv.fcntl = None  # type: ignore[assignment]
        try:
            with self.assertRaises(ValueError):
                hostenv.Lock(self.root / "lock", use_fcntl=True)
            self.assertFalse(hostenv.Lock(self.root / "lock").use_fcntl)
        finally:
            hostenv.fcntl = saved  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
