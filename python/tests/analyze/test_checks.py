import unittest
from pathlib import Path

from evelab.analyze.checks import KEEP, analyse_lab
from evelab.common.unl import RawLab

from .fakehost import FakeHost
from .helpers import Repo, mini_lab


def _lab(text: str | None = None) -> RawLab:
    return RawLab.from_bytes((text or mini_lab()).encode(), Path("mini.unl"))


class AnalyseLabTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo(origin=None, use_git=False)
        self.addCleanup(self.repo.cleanup)
        self.inv = self.repo.inventory()

    def report(self, latest: bool = False, inv=None):  # type: ignore[no-untyped-def]
        return analyse_lab(
            _lab(), "labs/mini.unl", inv or self.inv, latest=latest, root=self.repo.root
        )

    def q(self, rep, qid):  # type: ignore[no-untyped-def]
        return next(q for q in rep.questions if q.id == qid)

    def codes(self, rep) -> list[str]:  # type: ignore[no-untyped-def]
        return [f.code for f in rep.findings]

    def test_missing_image_is_required_and_grouped(self) -> None:
        rep = self.report()
        q = self.q(rep, "image/qemu/nxosv9k/nxosv9k-9300v-10.3.3.F")
        self.assertTrue(q.required)
        self.assertEqual(q.recommended, "nxosv9k-9300v-10.5.1.F")
        self.assertEqual([n for _, n in q.nodes], ["leaf1", "leaf2"])
        self.assertEqual(q.choices[-1].note, "other variant")
        self.assertIsNone(q.validate("nxosv9k-9500v-10.3.3.F"))
        self.assertIsNone(q.validate(KEEP))
        self.assertIsNotNone(q.validate("c8000v-17.15.01"))

    def test_iol_missing_image_offers_same_layer(self) -> None:
        rep = self.report()
        q = next(q for q in rep.questions if q.id.startswith("image/iol/"))
        self.assertEqual(q.recommended, "x86_64_crb_linux_l2-adventerprisek9-ms.bin")

    def test_upgrade_is_optional_unless_latest(self) -> None:
        q = self.q(self.report(), "image/qemu/c8000v/c8000v-17.11.01a")
        self.assertFalse(q.required)
        self.assertIsNone(q.recommended)
        self.assertEqual([c.value for c in q.choices], ["c8000v-17.15.01"])
        q2 = self.q(self.report(latest=True), "image/qemu/c8000v/c8000v-17.11.01a")
        self.assertEqual(q2.recommended, "c8000v-17.15.01")

    def test_qemu_version_closest_installed(self) -> None:
        q = self.q(self.report(), "qemu_version/4.1.0")
        self.assertEqual(q.recommended, "6.0.0")
        self.assertEqual([n for _, n in q.nodes], ["leaf1", "leaf2"])
        ids = [x.id for x in self.report().questions]
        self.assertNotIn("qemu_version/6.0.0", ids)

    def test_ram_and_cpu_caps(self) -> None:
        rep = self.report()
        ram = self.q(rep, "ram/16384")
        self.assertEqual(ram.recommended, "8192")
        self.assertIsNone(ram.validate("6000"))
        self.assertIsNotNone(ram.validate("20000"))
        cpu = self.q(rep, "cpu/8")
        self.assertEqual(cpu.recommended, "4")
        self.assertEqual(cpu.int_range, (1, 4))
        self.assertIn("LAB_RAM_EXCEEDS_HOST", self.codes(rep))

    def test_report_only_findings(self) -> None:
        rep = self.report()
        codes = self.codes(rep)
        self.assertIn("TEMPLATE_MISSING", codes)  # paloalto
        self.assertIn("IMAGE_MISSING", codes)  # paloalto + docker
        self.assertIn("BRIDGE_NOT_ON_HOST", codes)  # pnet3
        docker = next(f for f in rep.findings if "eve-server-yr" in f.msg)
        self.assertIn(
            "docker build -t eve-server-yr:latest docker/eve-server-yr", docker.msg
        )
        bridge = next(f for f in rep.findings if f.code == "BRIDGE_NOT_ON_HOST")
        self.assertIn("eve-localize --lab labs/mini.unl", bridge.msg)
        self.assertNotIn("KVM_MISSING", codes)
        self.assertNotIn("IOL_LICENSE_MISSING", codes)

    def test_host_feature_warnings(self) -> None:
        host = FakeHost(
            kvm=False,
            iourc=False,
            bridges={"pnet0": False},
            icons=["Router.png"],
            docker=None,
        )
        self.addCleanup(host.cleanup)
        from evelab.analyze.host import probe

        rep = self.report(inv=probe(host.roots))
        codes = self.codes(rep)
        for code in (
            "KVM_MISSING",
            "IOL_LICENSE_MISSING",
            "BRIDGE_NO_CARRIER",
            "ICON_MISSING",
            "DOCKER_UNKNOWN",
        ):
            self.assertIn(code, codes)

    def test_questions_order_required_first(self) -> None:
        rep = self.report()
        req = [q.required for q in rep.questions]
        self.assertEqual(req, sorted(req, reverse=True))

    def test_nothing_to_do_on_matching_host(self) -> None:
        nodes = (
            (
                "1",
                "r",
                "qemu",
                "c8000v",
                "c8000v-17.15.01",
                "2",
                "4096",
                "6.0.0",
                "Router.png",
                "1",
            ),
        )
        rep = analyse_lab(_lab(mini_lab(nodes=nodes)), "x.unl", self.inv)
        self.assertEqual(rep.questions, [])


if __name__ == "__main__":
    unittest.main()
