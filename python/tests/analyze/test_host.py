import json
import tempfile
import unittest
from pathlib import Path

from evelab.analyze.host import HostInventory, HostRoots, probe
from evelab.common.errors import EveLabError

from .fakehost import FakeHost


class ProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.host = FakeHost(
            icons=["Router.png"], bridges={"pnet0": True, "pnet1": False}
        )
        self.addCleanup(self.host.cleanup)

    def test_probe_reads_the_tree(self) -> None:
        inv = probe(self.host.roots)
        self.assertTrue(inv.eve)
        self.assertEqual(inv.hostname, "eve2")
        self.assertIn("nxosv9k-9300v-10.5.1.F", inv.qemu_images)
        self.assertNotIn("emptyimg-1", inv.qemu_images)
        self.assertEqual(inv.empty_qemu_dirs, ["emptyimg-1"])
        self.assertNotIn("iourc", inv.iol_images)
        self.assertEqual(inv.qemu_versions, ["2.12.0", "6.0.0"])
        self.assertIn("nxosv9k", inv.templates or [])
        self.assertEqual(inv.bridges, {"pnet0": "up", "pnet1": "down"})
        self.assertEqual((inv.cpus, inv.mem_mb), (4, 12000))
        self.assertTrue(inv.kvm)
        self.assertTrue(inv.iol_license)
        self.assertEqual(inv.icons, ["Router.png"])
        self.assertEqual(inv.docker_images, ["eve-gui-server:latest"])

    def test_json_roundtrip(self) -> None:
        inv = probe(self.host.roots)
        again = HostInventory.from_json(json.loads(json.dumps(inv.to_json())))
        self.assertEqual(again, inv)

    def test_bad_inventory(self) -> None:
        with self.assertRaises(EveLabError) as cm:
            HostInventory.from_json({"schema": 99})
        self.assertEqual(cm.exception.code, "BAD_INVENTORY")
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "inv.json"
            bad.write_text("{not json")
            with self.assertRaises(EveLabError):
                HostInventory.load(bad)

    def test_not_an_eve_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            inv = probe(
                HostRoots(
                    addons=t / "addons",
                    templates=t / "tpl",
                    icons=t / "icons",
                    opt=t / "opt",
                    sys_net=t / "net",
                    proc=t / "proc",
                    dev_kvm=t / "kvm",
                    docker_images=lambda: None,
                    hostname=lambda: "laptop",
                )
            )
        self.assertFalse(inv.eve)
        self.assertIsNone(inv.templates)
        self.assertIsNone(inv.kvm)
        self.assertIsNone(inv.docker_images)
        self.assertIsNone(inv.images("docker"))
        self.assertEqual(inv.images("qemu"), [])


if __name__ == "__main__":
    unittest.main()
