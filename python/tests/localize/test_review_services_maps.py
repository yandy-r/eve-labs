"""Regression tests for the services-maps review fixes.

* [map.*] swaps and chains survive the post-write re-scan (no VALIDATION_RESCAN).
* service values inside the protected inventory (internal loopbacks, manifest
  ``protect``) are never asked and never rewritten (SERVICE_INTERNAL).
* azure_s2s refuses equal local/Azure ASNs (prompt + AZURE_ASN_EQUAL blocker) and
  warns on a non-public gateway address.
* service prompts validate per kind/dialect (domain is never an address; IPv4 only
  where the dialect cannot render host names).
* secrets: psk offered only with PSKs, Azure named only for Azure labs; the lab
  picker range skips non-selectable rows.

Real labs are only read; anything that writes works on temp copies.
"""

from __future__ import annotations

import unittest
from functools import cache

from evelab.localize import cli, manifest, planner, ui
from evelab.localize.discover import analyse
from evelab.localize.model import Analysis
from evelab.localize.profile import LabOverride, Profile, ScenarioAnswer
from evelab.localize.scenarios import PARAM_KINDS, apply_answer
from evelab.localize.scenarios.azure_s2s import AzureS2SScenario
from evelab.localize.scenarios.base import ValueMaps
from evelab.localize.scenarios.secrets import SecretsScenario
from evelab.localize.scenarios.services import ServicesScenario

from . import disco
from .labfiles import read_real
from .test_cli import SDWAN, TreeCase


def real(stem: str) -> Analysis:
    d = disco.real(stem)
    if d is None:
        raise unittest.SkipTest(f"{stem} lab not present")
    return d.analysis


@cache
def real_with_manifest(stem: str) -> Analysis:
    path = disco.real_path(stem)
    if path is None:
        raise unittest.SkipTest(f"{stem} lab not present")
    return analyse(read_real(path), manifest.find_for(path))


def qmap(questions: list) -> dict:
    return {q.id: q for q in questions}


# --------------------------------------------------------------------------- #
# finding 4: [map.*] swap / chain vs the re-scan


SWAP = """schema = 1
[map.dns]
"1.1.1.1" = "1.0.0.1"
"1.0.0.1" = "1.1.1.1"
[map.domain]
"netlab.local" = "lab"
"yandy.dev" = "netlab.local"
"""


class RescanAnswersTest(unittest.TestCase):
    def test_prunes_keys_that_are_targets(self) -> None:
        ans = Profile(
            maps={
                "dns": {"1.1.1.1": "1.0.0.1", "1.0.0.1": "1.1.1.1"},
                "domain": {"netlab.local": "lab", "yandy.dev": "netlab.local"},
                "ntp": {"pool.ntp.org": "time.example.net"},
            }
        )
        got = cli.rescan_answers(ans)
        self.assertEqual(
            got.maps,
            {
                "domain": {"yandy.dev": "netlab.local"},
                "ntp": {"pool.ntp.org": "time.example.net"},
            },
        )
        self.assertIn("dns", ans.maps)  # the caller's answers are not mutated
        plain = Profile(maps={"dns": {"1.1.1.1": "9.9.9.9"}})
        self.assertIs(cli.rescan_answers(plain), plain)


class SwapApplyTest(TreeCase):
    labs = (SDWAN,)

    def test_swap_and_chain_apply(self) -> None:
        site = self.t.write("swap.toml", SWAP)
        code, out, err = self.t.run(
            "apply",
            "--lab",
            SDWAN,
            "--answers",
            str(site),
            "--yes",
            "--allow-unpinned",
        )
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("VALIDATION_RESCAN", out + err)
        self.assertIn("localized", out)


# --------------------------------------------------------------------------- #
# findings 6 + 19: internal service values


class InternalServicesTest(unittest.TestCase):
    def test_sdwan_hub_loopback_probe_not_asked_or_rewritten(self) -> None:
        a = real(disco.SDWAN)
        qs = qmap(ServicesScenario().questions(a, None, Profile()))
        self.assertNotIn("services/probe:10.200.255.251", qs)
        self.assertIn("services/probe:8.8.8.8", qs)
        maps = ValueMaps(services={("probe", "10.200.255.251"): "8.8.4.4"})
        frag = ServicesScenario().plan(a, Profile(), maps)
        self.assertEqual(frag.claims, [])
        self.assertEqual([f.code for f in frag.findings], ["SERVICE_INTERNAL"])
        self.assertEqual(frag.findings[0].severity, "warn")

    def test_lab1_manifest_protect_ranges(self) -> None:
        a = real_with_manifest(disco.LAB1)
        qs = qmap(ServicesScenario().questions(a, None, Profile()))
        self.assertEqual(sorted(qs), ["services/ntp:34.202.215.187"])
        maps = ValueMaps(
            services={
                ("dns", "10.2.50.1"): "9.9.9.9",
                ("ntp", "10.40.40.2"): "8.8.8.8",
                ("dns", "27.27.27.27"): "1.2.3.4",
            }
        )
        frag = ServicesScenario().plan(a, Profile(), maps)
        self.assertEqual(frag.claims, [])
        self.assertEqual({f.code for f in frag.findings}, {"SERVICE_INTERNAL"})
        self.assertEqual(len(frag.findings), 3)

    def test_manifest_param_values_still_asked(self) -> None:
        # backbone declares its 10.25.0.51/52 resolvers as [[param]]: site settings
        a = real_with_manifest(disco.BACKBONE)
        qs = qmap(ServicesScenario().questions(a, None, Profile()))
        self.assertIn("services/dns:10.25.0.51", qs)


# --------------------------------------------------------------------------- #
# finding 24: per-kind prompt validation


class ServiceValidationTest(unittest.TestCase):
    def test_domain_kind_refuses_addresses(self) -> None:
        kind = PARAM_KINDS["domain"]
        self.assertIsNotNone(kind.validate("9.9.9.9", Profile()))
        self.assertIsNotNone(kind.validate("10.1.2.3.", Profile()))
        for ok in ("lab", "lab.example.net", "1a.example.net", "x.y9", ""):
            self.assertIsNone(kind.validate(ok, Profile()), ok)

    def test_junos_prompts(self) -> None:
        a = real(disco.JUNOS)
        qs = qmap(ServicesScenario().questions(a, None, Profile()))
        ans = Profile()
        err = apply_answer(ans, qs["services/dns:1.1.1.1"], "dns.example.com")
        self.assertIsNotNone(err)
        self.assertIn("IPv4", err or "")
        self.assertIsNone(apply_answer(ans, qs["services/dns:1.1.1.1"], "9.9.9.9"))
        dom = qs["services/domain:netlab.local"]
        self.assertIsNotNone(apply_answer(ans, dom, "9.9.9.9"))
        self.assertEqual(ans.maps, {"dns": {"1.1.1.1": "9.9.9.9"}})

    def test_fortios_only_group_accepts_host_names(self) -> None:
        a = real(disco.SDWAN)
        qs = qmap(ServicesScenario().questions(a, None, Profile()))
        q = qs["services/ntp:pool.ntp.org"]
        self.assertIsNone(apply_answer(Profile(), q, "time.example.net"))

    def test_profile_map_domain_address_is_dropped(self) -> None:
        a = real(disco.JUNOS)
        maps = ValueMaps(services={("domain", "netlab.local"): "9.9.9.9"})
        frag = ServicesScenario().plan(a, Profile(), maps)
        self.assertEqual(frag.claims, [])
        self.assertIn("BAD_VALUE", {f.code for f in frag.findings})


# --------------------------------------------------------------------------- #
# finding 22: azure ASN collision / private gateway


def azure_answers(a: Analysis, **options: object) -> Profile:
    ans = Profile()
    ans.labs[a.lab.lab_id] = LabOverride(
        scenarios={"azure_s2s": ScenarioAnswer(enabled=True, options=dict(options))}
    )
    return ans


class AzureAsnTest(unittest.TestCase):
    def test_prompt_validators(self) -> None:
        a = real(disco.AZURE)  # local 65101, Azure 65100
        qs = qmap(AzureS2SScenario().questions(a, None, Profile()))
        local, azure = qs["azure_s2s/local_asn"], qs["azure_s2s/azure_asn"]
        self.assertIsNotNone(local.validate("65100", Profile()))
        self.assertIsNotNone(local.validate("65515", Profile()))
        self.assertIsNone(local.validate("65010", Profile()))
        self.assertIsNotNone(azure.validate("65101", Profile()))
        self.assertIsNone(azure.validate("65515", Profile()))  # Azure's default
        self.assertIsNotNone(azure.validate("65516", Profile()))
        # an answered Azure ASN wins over the discovered one
        ans = azure_answers(a, azure_asn="65010")
        self.assertIsNotNone(local.validate("65010", ans))
        self.assertIsNone(local.validate("65100", ans))

    def test_plan_blocks_equal_asns(self) -> None:
        a = real(disco.AZURE)
        plan = planner.build_plan(
            a, azure_answers(a, local_asn="65100", peer_ip="10.1.1.1")
        )
        codes = {f.code: f.severity for f in plan.findings}
        self.assertEqual(codes.get("AZURE_ASN_EQUAL"), "blocker")
        self.assertEqual(codes.get("AZURE_PEER_PRIVATE"), "warn")
        self.assertTrue(plan.blocked)
        ok = planner.build_plan(a, azure_answers(a, local_asn="65010"))
        self.assertNotIn("AZURE_ASN_EQUAL", {f.code for f in ok.findings})
        self.assertFalse(ok.blocked, ok.findings)


# --------------------------------------------------------------------------- #
# finding 26: secrets copy / choices and picker ranges


class SecretsCopyTest(unittest.TestCase):
    def test_nexus_no_psk_no_azure(self) -> None:
        a = real(disco.NEXUS_VPC)
        (q,) = SecretsScenario().questions(a, None, Profile())
        self.assertEqual(q.choices, ["none", "all"])
        self.assertNotIn("Azure", " ".join(q.notes))
        self.assertIn("git history", " ".join(q.notes))
        self.assertIsNotNone(q.validate("psk", Profile()))
        self.assertIsNone(q.validate("all", Profile()))

    def test_azure_keeps_psk_and_provider_note(self) -> None:
        a = real(disco.AZURE)
        (q,) = SecretsScenario().questions(a, None, Profile())
        self.assertEqual(q.choices, ["none", "psk", "all"])
        self.assertIn("Azure VPN gateway", " ".join(q.notes))

    def test_picker_range_skips_unselectable(self) -> None:
        sel = [True, False, True, False, True]
        self.assertEqual(ui.parse_selection("2-4", 5, selectable=sel), [2])
        with self.assertRaises(ValueError):
            ui.parse_selection("2", 5, selectable=sel)
        with self.assertRaises(ValueError):
            ui.parse_selection("2-2", 5, selectable=sel)
        with self.assertRaises(ValueError):
            ui.parse_selection("4", 5, selectable=sel)


if __name__ == "__main__":
    unittest.main()
