import unittest

from evelab.analyze.versions import candidates, family, newest, split_image

NX = [
    "nxosv9k-9300v-10.3.3.F",
    "nxosv9k-9300v-10.5.1.F",
    "nxosv9k-9300v-9.3.9",
    "nxosv9k-9500v-10.6.1.F",
    "c8000v-17.11.01a",
]


class SplitImageTest(unittest.TestCase):
    def test_variant_and_version(self) -> None:
        cases = {
            ("nxosv9k", "nxosv9k-9300v-10.3.3.F"): ("9300v", "10.3.3.F"),
            ("fortinet", "fortinet-FGT-v7-build2702"): ("FGT", "v7-build2702"),
            ("vjunosswitch", "vjunosswitch-24.2R1-S1"): ("", "24.2R1-S1"),
            ("viosl2", "viosl2-adventerprisek9-m.ssa.high_iron_20200929"): (
                "adventerprisek9",
                "m.ssa.high_iron_20200929",
            ),
            ("asav", "asav-918-2"): ("", "918-2"),
            ("bigip", "bigip-17.5.0-0.0.15"): ("", "17.5.0-0.0.15"),
        }
        for (tpl, image), want in cases.items():
            with self.subTest(image=image):
                self.assertEqual(split_image("qemu", tpl, image), want)

    def test_docker(self) -> None:
        self.assertEqual(split_image("docker", "docker", "a/b:1.2"), ("a/b", "1.2"))
        self.assertEqual(split_image("docker", "docker", "srv"), ("srv", "latest"))

    def test_families(self) -> None:
        self.assertEqual(family("qemu", "nxosv9k", "nxosv9k-x"), "nxosv9k")
        self.assertEqual(family("iol", "iol", "i86bi_LinuxL2-Adv.bin"), "l2")
        self.assertEqual(family("iol", "iol", "x86_64_crb_linux-adv.bin"), "l3")
        self.assertEqual(family("dynamips", "c7200", "c7200-adv-mz.152.image"), "c7200")
        self.assertEqual(family("docker", "docker", "repo:tag"), "repo")


class CandidatesTest(unittest.TestCase):
    def test_same_variant_newest_first_then_other_variants(self) -> None:
        got = candidates("qemu", "nxosv9k", "nxosv9k-9300v-10.3.3.F", NX)
        self.assertEqual(
            [c.image for c in got],
            ["nxosv9k-9300v-10.5.1.F", "nxosv9k-9300v-9.3.9", "nxosv9k-9500v-10.6.1.F"],
        )
        self.assertEqual([c.newer for c in got], [True, False, False])
        self.assertEqual(got[2].note, "other variant")
        self.assertEqual(newest(got).image, "nxosv9k-9300v-10.5.1.F")  # type: ignore[union-attr]

    def test_only_template_prefix_matches(self) -> None:
        self.assertEqual(candidates("qemu", "c8000v", "c8000v-17.1", ["c8000vx-1"]), [])

    def test_missing_image_without_same_variant_falls_back(self) -> None:
        got = candidates("qemu", "nxosv9k", "nxosv9k-9200v-10.1", NX)
        self.assertFalse(any(c.same_variant for c in got))
        self.assertEqual(newest(got).image, "nxosv9k-9500v-10.6.1.F")  # type: ignore[union-attr]

    def test_iol_and_docker_never_offer_upgrades(self) -> None:
        iol = candidates(
            "iol", "iol", "i86bi_linux_l2-a.bin", ["x86_64_crb_linux_l2-b.bin"]
        )
        self.assertEqual([c.image for c in iol], ["x86_64_crb_linux_l2-b.bin"])
        self.assertFalse(iol[0].newer)
        dock = candidates("docker", "docker", "srv:latest", ["srv:v2", "other:1"])
        self.assertEqual([c.image for c in dock], ["srv:v2"])
        self.assertFalse(dock[0].newer)

    def test_newest_of_nothing(self) -> None:
        self.assertIsNone(newest([]))


if __name__ == "__main__":
    unittest.main()
