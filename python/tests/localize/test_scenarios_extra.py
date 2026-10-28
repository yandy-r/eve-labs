"""Extra scenarios: services, site_routes, bgp_upstream, azure_s2s, secrets (T17).

Real labs are only read (cached discoveries); every test that writes works on a
temp copy (``copy_real``). Secret values are never printed: assertions compare
against the values read from the facts.
"""

from __future__ import annotations

import atexit
import json
import shutil
import tempfile
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from unittest import mock

from evelab.common.unl import RawLab
from evelab.localize import apply, dialects, planner
from evelab.localize.dialects.base import RenderCtx
from evelab.localize.discover import analyse
from evelab.localize.model import Analysis, Fact, Plan, Span, Store
from evelab.localize.profile import LabOverride, Profile, ScenarioAnswer, SecretRef
from evelab.localize.scenarios import PARAM_KINDS, SCENARIOS, apply_answer, load_builtin
from evelab.localize.scenarios.azure_s2s import (
    AzureS2SScenario,
    _offset_map,
    find_azure,
)
from evelab.localize.scenarios.base import Question, ValueMaps
from evelab.localize.scenarios.bgp_upstream import (
    BgpUpstreamScenario,
    community_map,
    find_upstreams,
)
from evelab.localize.scenarios.secrets import SecretsScenario, classify, is_hashed
from evelab.localize.scenarios.services import ServicesScenario, drop_edit
from evelab.localize.scenarios.site_routes import (
    SiteRoutesScenario,
    parse_site_routes,
    route_actions,
    site_routes,
)

from . import disco

NET = IPv4Network
ADDR = IPv4Address
EXTRA = ("services", "site_routes", "bgp_upstream", "azure_s2s", "secrets")


def real(stem: str) -> Analysis:
    d = disco.real(stem)
    if d is None:
        raise unittest.SkipTest(f"{stem} lab not present")
    return d.analysis


def copy_real(stem: str) -> Path:
    src = disco.real_path(stem)
    if src is None:
        raise unittest.SkipTest(f"{stem} lab not present")
    tmp = Path(tempfile.mkdtemp(prefix="evelab-localize-t17-"))
    atexit.register(shutil.rmtree, tmp, True)  # suite-wide temp copy
    dst = tmp / src.name
    shutil.copyfile(src, dst)
    for d in src.parent.iterdir():
        if d.is_dir() and d.name.startswith(src.stem) and d.name.endswith("_cfgs"):
            shutil.copytree(d, tmp / d.name)
    return dst


def write_changes(plan: Plan, lab: RawLab) -> None:
    ch = apply.build_changes(plan, apply.ApplyOptions(), lab=lab)
    for fc in ch.files:
        fc.dest.write_bytes(fc.after)


def qmap(questions: list[Question]) -> dict[str, Question]:
    return {q.id: q for q in questions}


def site_key(a: Analysis, key: str) -> str:
    return next(s.site_key for s in a.segments if s.key == key)


def secret_values(a: Analysis) -> set[str]:
    return {f.value for f in a.facts.values() if f.kind == "secret" and f.value}


def edits_of(plan: Plan, prefix: str) -> list:
    return [e for e in planner.enabled_edits(plan) if e.group.startswith(prefix)]


def roundtrip(stem: str, make_answers) -> tuple[Plan, Plan, Analysis]:
    """Plan on a temp copy, write it, re-analyse, re-plan with the same answers."""
    path = copy_real(stem)
    lab = RawLab.read(path)
    a = analyse(lab)
    ans = make_answers(a, lab)
    plan = planner.build_plan(a, ans)
    write_changes(plan, lab)
    a2 = analyse(RawLab.read(path))
    return plan, planner.build_plan(a2, ans), a2


def fake_fact(text: str, value: str, kind: str = "search_list") -> Fact:
    start = text.index(value)
    return Fact(
        id="x",
        kind=kind,
        value=value,
        store=Store("startup", "startup", "startup"),
        node_id="1",
        span=Span(start, start + len(value)),
        line=1,
        rule="t.rule",
        iface=None,
        parent=None,
    )


# --------------------------------------------------------------------------- #


class RegistryTest(unittest.TestCase):
    def test_registered_in_order(self) -> None:
        load_builtin()
        for sid in EXTRA:
            self.assertIn(sid, SCENARIOS)
        orders = [SCENARIOS[s].order for s in EXTRA]
        self.assertEqual(orders, sorted(orders))
        self.assertTrue(SCENARIOS["bgp_upstream"].gated)  # type: ignore[attr-defined]
        self.assertTrue(SCENARIOS["azure_s2s"].gated)  # type: ignore[attr-defined]
        self.assertFalse(getattr(SCENARIOS["services"], "gated", False))

    def test_site_routes_param_kind(self) -> None:
        kind = PARAM_KINDS["site_routes"]
        self.assertIsNone(kind.parse("keep"))
        self.assertIsNone(kind.parse(""))
        self.assertEqual(kind.parse("delete"), [])
        self.assertEqual(
            kind.parse("192.168.0.0/16, 10.0.0.0/8"),
            [NET("192.168.0.0/16"), NET("10.0.0.0/8")],
        )
        self.assertIsNotNone(kind.validate("10.0.0.0/33", Profile()))
        self.assertIsNotNone(kind.validate("0.0.0.0/0", Profile()))
        self.assertEqual(parse_site_routes("10.1.2.3/16"), [NET("10.1.0.0/16")])


# --------------------------------------------------------------------------- #


class ServicesTest(unittest.TestCase):
    def test_questions_sdwan(self) -> None:
        a = real(disco.SDWAN)
        qs = qmap(ServicesScenario().questions(a, None, Profile()))
        for qid in (
            "services/dns:1.1.1.1",
            "services/dns:1.0.0.1",
            "services/domain:netlab.local",
            "services/domain:plsnetlab.local",
            "services/domain:yandy.dev",
            "services/ntp:pool.ntp.org",
            "services/probe:8.8.8.8",
        ):
            self.assertIn(qid, qs)
        q = qs["services/dns:1.1.1.1"]
        self.assertEqual(q.group, "E Services")
        self.assertEqual(q.kind, "host")
        self.assertEqual(q.default, "1.1.1.1")  # keep without a map entry
        self.assertIn("fortios sidecar x7", q.prompt)
        # probe targets never count as DNS
        self.assertNotIn(
            "fortios", qs["services/dns:1.0.0.1"].prompt.split("fortios")[0]
        )
        self.assertTrue(
            any("advanced" in n for n in qs["services/probe:8.8.8.8"].notes)
        )
        # a domain that is a domain-name cannot be dropped; a search-only one can
        self.assertIsNotNone(qs["services/domain:netlab.local"].validate("", Profile()))
        self.assertIsNone(qs["services/domain:yandy.dev"].validate("", Profile()))
        self.assertIsNotNone(qs["services/dns:1.1.1.1"].validate("", Profile()))

    def test_map_default_and_setter(self) -> None:
        a = real(disco.SDWAN)
        prof = Profile(maps={"dns": {"1.1.1.1": "9.9.9.9"}})
        qs = qmap(ServicesScenario().questions(a, None, prof))
        q = qs["services/dns:1.1.1.1"]
        self.assertEqual((q.default, q.default_source), ("9.9.9.9", "map.dns"))
        ans = Profile()
        self.assertIsNone(apply_answer(ans, q, "192.0.2.53"))
        self.assertIsNone(apply_answer(ans, qs["services/ntp:pool.ntp.org"], "time.x"))
        self.assertEqual(ans.maps["dns"], {"1.1.1.1": "192.0.2.53"})
        self.assertEqual(ans.maps["ntp"], {"pool.ntp.org": "time.x"})
        self.assertIsNotNone(apply_answer(ans, q, "not a host!"))

    def test_plan_domain_rename_is_anchored(self) -> None:
        a = real(disco.SDWAN)
        maps = ValueMaps(services={("domain", "netlab.local"): "lab.example.net"})
        frag = ServicesScenario().plan(a, Profile(), maps)
        self.assertTrue(frag.claims)
        idx_texts = {(ct.store, ct.node_id): ct.text for ct in a.texts}
        for c in frag.claims:
            self.assertEqual(c.old, "netlab.local")
            text = idx_texts[(c.store, c.node_id)]
            self.assertNotEqual(text[c.start - 3 : c.start], "pls")  # plsnetlab.local
        plans = {c.fact_ids[0] for c in frag.claims}
        pls = [f.id for f in a.facts.values() if f.value == "plsnetlab.local"]
        self.assertFalse(plans & set(pls))

    def test_search_drop_and_refusals(self) -> None:
        a = real(disco.SDWAN)
        maps = ValueMaps(services={("domain", "yandy.dev"): ""})
        frag = ServicesScenario().plan(a, Profile(), maps)
        self.assertTrue(frag.claims)
        for c in frag.claims:
            self.assertEqual(c.new, "")
            self.assertEqual(c.old.strip(), "yandy.dev")
        # junos: plsnetlab.local is a domain-name and a single-entry domain-search
        j = real(disco.JUNOS)
        frag = ServicesScenario().plan(
            j, Profile(), ValueMaps(services={("domain", "plsnetlab.local"): ""})
        )
        codes = {f.code for f in frag.findings}
        self.assertIn("SERVICE_DROP_REFUSED", codes)
        junos_claims = [c for c in frag.claims if c.rule.startswith("junos.")]
        self.assertEqual(junos_claims, [])

    def test_drop_edit(self) -> None:
        text = "search netlab.local yandy.dev\n"
        self.assertEqual(
            text[slice(*drop_edit(text, fake_fact(text, "yandy.dev")))], " yandy.dev"
        )
        f = fake_fact(text, "netlab.local")
        s, e = drop_edit(text, f)
        self.assertEqual(text[:s] + text[e:], "search yandy.dev\n")
        text = "domain-search [a.b c.d];"
        s, e = drop_edit(text, fake_fact(text, "a.b"))
        self.assertEqual(text[:s] + text[e:], "domain-search [c.d];")

    def test_roundtrip_sdwan(self) -> None:
        def make(a: Analysis, lab: RawLab) -> Profile:
            return Profile(
                maps={
                    "dns": {"1.1.1.1": "9.9.9.9", "1.0.0.1": "149.112.112.112"},
                    "domain": {"netlab.local": "lab.example.net", "yandy.dev": ""},
                    "ntp": {"pool.ntp.org": "time.example.net"},
                }
            )

        plan, plan2, a2 = roundtrip(disco.SDWAN, make)
        self.assertFalse(plan.blocked, plan.findings)
        groups = {e.group for e in planner.enabled_edits(plan)}
        for g in ("services/dns", "services/domain", "services/ntp"):
            self.assertIn(g, groups)
        self.assertEqual(planner.enabled_edits(plan2), [])
        values = {f.value for f in a2.facts.values() if f.kind in ("dns_server",)}
        self.assertIn("9.9.9.9", values)
        self.assertNotIn("1.1.1.1", values)
        self.assertNotIn(
            "yandy.dev", {f.value for f in a2.facts.values() if f.kind == "search_list"}
        )


# --------------------------------------------------------------------------- #


class SiteRoutesTest(unittest.TestCase):
    def test_discovery_azure_and_sdwan(self) -> None:
        a = real(disco.AZURE)
        routes = site_routes(a)
        self.assertEqual(list(routes), ["MGMT-104"])
        nets = sorted({str(r.net) for r in routes["MGMT-104"]})
        self.assertEqual(nets, ["10.100.0.0/16", "10.25.0.0/16"])
        # the default route and the /32 host route to the Azure peer are excluded
        self.assertNotIn("172.173.204.134/32", nets)
        s = real(disco.SDWAN)
        nets = sorted({str(r.net) for r in site_routes(s)["MGMT-204"]})
        self.assertEqual(nets, ["10.100.0.0/16", "10.25.0.0/21", "192.168.0.0/24"])
        self.assertEqual(set(site_routes(s)), {"MGMT-204"})

    def test_question(self) -> None:
        a = real(disco.AZURE)
        qs = qmap(SiteRoutesScenario().questions(a, None, Profile()))
        sk = site_key(a, "MGMT-104")
        q = qs[f"{sk}/site_routes"]
        self.assertEqual(q.group, "F Site routes")
        self.assertEqual(q.current, "10.25.0.0/16, 10.100.0.0/16")
        self.assertEqual(q.default, "keep")
        ans = Profile()
        self.assertIsNone(apply_answer(ans, q, "192.168.0.0/16"))
        self.assertEqual(ans.site_routes[sk], [NET("192.168.0.0/16")])
        self.assertIsNone(apply_answer(ans, q, "keep"))
        self.assertNotIn(sk, ans.site_routes)
        self.assertIsNone(apply_answer(ans, q, "delete"))
        self.assertEqual(ans.site_routes[sk], [])
        prof = Profile(site_routes={sk: []})
        q2 = qmap(SiteRoutesScenario().questions(a, None, prof))[f"{sk}/site_routes"]
        self.assertEqual(q2.default, "delete")

    def test_route_actions(self) -> None:
        a, b, c, d, e = (NET(f"10.{i}.0.0/16") for i in range(5))
        acts, missing = route_actions([a, b, c], [c, d])
        self.assertEqual(acts, {c: c, a: d, b: None})
        self.assertEqual(missing, [])
        acts, missing = route_actions([a], [d, e])
        self.assertEqual(acts, {a: d})
        self.assertEqual(missing, [e])

    def test_replace_delete_roundtrip_sdwan(self) -> None:
        def make(a: Analysis, lab: RawLab) -> Profile:
            return Profile(
                site_routes={site_key(a, "MGMT-204"): [NET("192.168.0.0/16")]}
            )

        plan, plan2, a2 = roundtrip(disco.SDWAN, make)
        self.assertFalse(plan.blocked, plan.findings)
        route_edits = edits_of(plan, "MGMT-204/routes")
        deletions = [e for e in route_edits if e.text_edit.new == ""]
        self.assertTrue(deletions)
        for e in deletions:  # whole Forti "edit N ... next" stanzas
            self.assertTrue(e.text_edit.old.lstrip().startswith("edit "))
            self.assertTrue(e.text_edit.old.rstrip().endswith("next"))
        self.assertEqual(planner.enabled_edits(plan2), [])
        nets = sorted({str(r.net) for r in site_routes(a2)["MGMT-204"]})
        self.assertEqual(nets, ["192.168.0.0/16"])

    def test_azure_routes_and_not_added(self) -> None:
        def make(a: Analysis, lab: RawLab) -> Profile:
            return Profile(
                site_routes={
                    site_key(a, "MGMT-104"): [
                        NET("10.100.0.0/16"),
                        NET("192.168.0.0/16"),
                        NET("172.16.0.0/12"),
                    ]
                }
            )

        plan, plan2, _a2 = roundtrip(disco.AZURE, make)
        self.assertIn("ROUTES_NOT_ADDED", {f.code for f in plan.findings})
        olds = {e.text_edit.old for e in edits_of(plan, "MGMT-104/routes")}
        self.assertEqual(olds, {"10.25.0.0"})
        self.assertEqual(planner.enabled_edits(plan2), [])

    def test_delete_unsupported_is_blocker(self) -> None:
        a = real(disco.AZURE)
        sk = site_key(a, "MGMT-104")
        asa = type(dialects.get("asa"))
        with mock.patch.object(asa, "supports_stanza_delete", False, create=True):
            plan = planner.build_plan(
                a,
                Profile(site_routes={sk: []}),
                planner.PlanOptions(scenarios=["site_routes"]),
            )
        self.assertIn("ROUTE_DELETE_UNSUPPORTED", {f.code for f in plan.findings})
        self.assertTrue(plan.blocked)


# --------------------------------------------------------------------------- #


def bgp_answers(lab: RawLab, **options: object) -> Profile:
    ans = Profile()
    ans.labs[lab.lab_id] = LabOverride(
        scenarios={"bgp_upstream": ScenarioAnswer(enabled=True, options=dict(options))}
    )
    return ans


class BgpUpstreamTest(unittest.TestCase):
    def test_detection_junos(self) -> None:
        a = real(disco.JUNOS)
        ups = find_upstreams(a)
        self.assertEqual(sorted(u.node_id for u in ups), ["18", "9"])
        u9 = next(u for u in ups if u.node_id == "9")
        self.assertEqual(
            (u9.peer, u9.group, u9.local_as, u9.peer_as),
            ("172.31.240.1", "HOME", 65300, 65299),
        )
        self.assertEqual(u9.segment, "INET-1240")
        self.assertEqual(
            [str(p.net) for p in u9.prefixes],
            ["172.31.255.0/24", "192.168.64.0/18", "192.168.128.0/17"],
        )
        for stem in (disco.AZURE, disco.SDWAN):
            self.assertEqual(find_upstreams(real(stem)), [])

    def test_questions(self) -> None:
        a = real(disco.JUNOS)
        qs = qmap(BgpUpstreamScenario().questions(a, None, Profile()))
        gate = qs["bgp_upstream/enabled"]
        self.assertEqual(
            (gate.group, gate.kind, gate.default), ("G Scenarios", "bool", "no")
        )
        for qid in (
            "bgp_upstream/peer:172.31.240.1",
            "bgp_upstream/peer:172.31.242.1",
            "bgp_upstream/peer_as",
            "bgp_upstream/local_as",
            "bgp_upstream/prefixes",
        ):
            self.assertIn(qid, qs)
            self.assertEqual(qs[qid].depends_on, ["bgp_upstream/enabled"])
        self.assertTrue(
            any("172.31.255.0/24" in n for n in qs["bgp_upstream/prefixes"].notes)
        )
        ans = Profile()
        self.assertIsNone(apply_answer(ans, gate, "yes"))
        self.assertIsNone(apply_answer(ans, qs["bgp_upstream/peer_as"], "64999"))
        self.assertIsNone(
            apply_answer(ans, qs["bgp_upstream/peer:172.31.240.1"], "172.31.240.254")
        )
        sc = ans.labs[a.lab.lab_id].scenarios["bgp_upstream"]
        self.assertTrue(sc.enabled)
        self.assertEqual(sc.options["peer_as"], 64999)
        self.assertEqual(sc.options["peers"], {"172.31.240.1": "172.31.240.254"})
        self.assertIs(ans.scenario_enabled("bgp_upstream", a.lab.lab_id), True)

    def test_community_map(self) -> None:
        self.assertEqual(
            community_map("4279500901", 65300, 64600), str((64600 << 16) | 101)
        )
        self.assertEqual(community_map("65300:101", 65300, 64600), "64600:101")
        self.assertIsNone(community_map("65000:1", 65300, 64600))
        self.assertIsNone(community_map("4279500901", 65300, 4200000000))

    def test_gate_off_no_edits(self) -> None:
        a = real(disco.JUNOS)
        ans = bgp_answers(a.lab, peer_as="64999")
        ans.labs[a.lab.lab_id].scenarios["bgp_upstream"].enabled = None
        plan = planner.build_plan(a, ans)
        self.assertEqual(edits_of(plan, "bgp_upstream/"), [])

    def test_roundtrip_junos(self) -> None:
        def make(a: Analysis, lab: RawLab) -> Profile:
            return bgp_answers(
                lab,
                peers={"172.31.240.1": "172.31.240.254"},
                peer_as="64999",
                local_as="64600",
                prefixes=["172.31.255.0/24", "10.10.0.0/16"],
            )

        plan, plan2, a2 = roundtrip(disco.JUNOS, make)
        self.assertFalse(plan.blocked, plan.findings)
        groups = {e.group for e in edits_of(plan, "bgp_upstream/")}
        self.assertEqual(
            groups,
            {
                "bgp_upstream/peer_ip",
                "bgp_upstream/peer_as",
                "bgp_upstream/local_as",
                "bgp_upstream/prefixes",
            },
        )
        news = {e.text_edit.new for e in edits_of(plan, "bgp_upstream/local_as")}
        self.assertIn(str((64600 << 16) | 101), news)  # community recomputed
        self.assertIn("PREFIX_INTERNAL", {f.code for f in plan.findings})
        self.assertEqual(planner.enabled_edits(plan2), [])
        ups = find_upstreams(a2)
        self.assertEqual({u.local_as for u in ups}, {64600})
        self.assertEqual({u.peer_as for u in ups}, {64999})
        self.assertIn("172.31.240.254", {u.peer for u in ups})
        self.assertEqual(
            [str(p.net) for p in ups[0].prefixes], ["172.31.255.0/24", "10.10.0.0/16"]
        )


# --------------------------------------------------------------------------- #

NEW_PSK = "Test-Psk-0123"


def azure_answers(lab: RawLab, psk: bool = True, **options: object) -> Profile:
    ans = Profile()
    ans.labs[lab.lab_id] = LabOverride(
        scenarios={"azure_s2s": ScenarioAnswer(enabled=True, options=dict(options))}
    )
    if psk:
        ans.secrets["azure_s2s.psk"] = SecretRef(value=NEW_PSK)
    return ans


class AzureS2STest(unittest.TestCase):
    def test_detection(self) -> None:
        a = real(disco.AZURE)
        found = find_azure(a)
        self.assertEqual(len(found), 1)
        az = found[0]
        self.assertEqual((az.node_id, az.peer), ("1", "172.173.204.134"))
        self.assertEqual(az.tunnel_net, NET("169.254.21.0/30"))
        self.assertEqual(az.tunnel_ip, ADDR("169.254.21.1"))
        self.assertEqual(az.bgp_peer, "10.200.100.254")
        self.assertEqual((az.local_asn, az.azure_asn), (65101, 65100))
        self.assertEqual(len(az.psk_facts), 2)
        for stem in (disco.JUNOS, disco.SDWAN):
            self.assertEqual(find_azure(real(stem)), [])

    def test_questions_and_validators(self) -> None:
        a = real(disco.AZURE)
        qs = qmap(AzureS2SScenario().questions(a, None, Profile()))
        self.assertEqual(
            set(qs),
            {
                f"azure_s2s/{k}"
                for k in (
                    "enabled",
                    "peer_ip",
                    "tunnel_ip",
                    "azure_bgp_ip",
                    "local_asn",
                    "azure_asn",
                    "psk",
                )
            },
        )
        self.assertIsNotNone(
            qs["azure_s2s/tunnel_ip"].validate("169.254.30.1", Profile())
        )
        self.assertIsNone(qs["azure_s2s/tunnel_ip"].validate("169.254.22.9", Profile()))
        self.assertIsNotNone(qs["azure_s2s/local_asn"].validate("65515", Profile()))
        self.assertIsNone(qs["azure_s2s/local_asn"].validate("65010", Profile()))
        psk_q = qs["azure_s2s/psk"]
        self.assertEqual((psk_q.kind, psk_q.current), ("secret", "****"))
        secrets = secret_values(a)
        for q in qs.values():
            for s in secrets:
                self.assertNotIn(s, q.prompt + str(q.current) + str(q.default))
        ans = Profile()
        self.assertIsNone(apply_answer(ans, psk_q, NEW_PSK))
        self.assertEqual(ans.secret_value("azure_s2s.psk"), NEW_PSK)
        self.assertEqual(ans.secrets["azure_s2s.psk"].env, None)

    def test_offset_map(self) -> None:
        m = _offset_map(
            NET("169.254.21.0/30"), ADDR("169.254.21.1"), ADDR("169.254.22.5")
        )
        self.assertEqual(m[ADDR("169.254.21.1")], ADDR("169.254.22.5"))
        self.assertEqual(m[ADDR("169.254.21.2")], ADDR("169.254.22.6"))
        m = _offset_map(
            NET("169.254.21.0/30"), ADDR("169.254.21.1"), ADDR("169.254.21.2")
        )
        self.assertEqual(m[ADDR("169.254.21.2")], ADDR("169.254.21.1"))  # swap

    def test_gate_off_no_edits(self) -> None:
        a = real(disco.AZURE)
        ans = azure_answers(a.lab, peer_ip="198.51.100.7")
        ans.labs[a.lab.lab_id].scenarios["azure_s2s"].enabled = False
        plan = planner.build_plan(a, ans)
        self.assertEqual(edits_of(plan, "azure_s2s/"), [])

    def test_roundtrip(self) -> None:
        opts = {
            "peer_ip": "198.51.100.7",
            "tunnel_ip": "169.254.21.5",
            "azure_bgp_ip": "10.1.0.254",
            "local_asn": "65010",
            "azure_asn": "65515",
        }
        secrets_before = secret_values(real(disco.AZURE))
        plan, plan2, a2 = roundtrip(
            disco.AZURE, lambda a, lab: azure_answers(lab, **opts)
        )
        self.assertFalse(plan.blocked, plan.findings)
        edits = edits_of(plan, "azure_s2s/")
        # node 1 only, except the local ASN (ASAv-2 peers with it)
        self.assertEqual(
            {e.node_id for e in edits if e.group != "azure_s2s/local_asn"}, {"1"}
        )
        self.assertEqual(
            {e.node_id for e in edits if e.group == "azure_s2s/local_asn"}, {"1", "3"}
        )
        peer = [e for e in edits if e.group == "azure_s2s/peer_ip"]
        self.assertEqual(len(peer), 9)  # tunnel dst, host route, 7 object names
        psk = [e for e in edits if e.group == "azure_s2s/psk"]
        self.assertEqual(len(psk), 2)
        self.assertTrue(all(e.secret for e in psk))
        # internal Tunnel2 /30 (169.254.100.0/30) and 169.254.0.2 untouched
        olds = {e.text_edit.old for e in edits if not e.secret}
        self.assertFalse(
            any(o.startswith("169.254.100.") or o == "169.254.0.2" for o in olds)
        )
        dumped = planner.dumps_plan(plan)
        for s in secrets_before | {NEW_PSK}:
            self.assertNotIn(s, dumped)
            for f in plan.findings:
                self.assertNotIn(s, f.msg)
        self.assertIn("SECRET_HISTORY", {f.code for f in plan.findings})
        self.assertEqual(planner.enabled_edits(plan2), [])
        az = find_azure(a2)[0]
        self.assertEqual(az.peer, "198.51.100.7")
        self.assertEqual(az.tunnel_ip, ADDR("169.254.21.5"))
        self.assertEqual(az.bgp_peer, "10.1.0.254")
        self.assertEqual((az.local_asn, az.azure_asn), (65010, 65515))
        self.assertEqual({f.value for f in az.psk_facts}, {NEW_PSK})


# --------------------------------------------------------------------------- #


def secrets_answers(lab: RawLab, choice: str) -> Profile:
    ans = Profile()
    ans.labs[lab.lab_id] = LabOverride(
        scenarios={"secrets": ScenarioAnswer(options={"placeholders": choice})}
    )
    return ans


class SecretsTest(unittest.TestCase):
    def test_question(self) -> None:
        a = real(disco.AZURE)
        qs = qmap(SecretsScenario().questions(a, None, Profile()))
        q = qs["secrets/placeholders"]
        self.assertEqual((q.group, q.kind, q.default), ("H Secrets", "choice", "none"))
        self.assertEqual(q.choices, ["none", "psk", "all"])
        self.assertIn("git history", " ".join(q.notes))
        for s in secret_values(a):
            self.assertNotIn(s, q.prompt)
        ans = Profile()
        self.assertIsNotNone(apply_answer(ans, q, "everything"))
        self.assertIsNone(apply_answer(ans, q, "psk"))
        opts = ans.labs[a.lab.lab_id].scenarios["secrets"].options
        self.assertEqual(opts["placeholders"], "psk")

    def test_not_asked_without_secrets(self) -> None:
        a = disco.mini("l2lab").analysis
        self.assertFalse(SecretsScenario().applies(a, None))
        self.assertFalse(AzureS2SScenario().applies(a, None))
        # l2lab's R3 peers with its upstream inside INET-500 (eBGP signature)
        (up,) = find_upstreams(a)
        self.assertEqual((up.peer, up.segment), ("100.64.5.1", "INET-500"))

    def test_hashed_and_classify(self) -> None:
        for text, value, hashed, name in (
            ("enable secret 5 $1$abc$def\n", "$1$abc$def", True, "enable"),
            ("username u password 7 0822455D0A16\n", "0822455D0A16", True, "user"),
            ("enable password abc123 encrypted\n", "abc123", True, "enable"),
            ("    set psksecret ENC QmFzZTY0\n", "QmFzZTY0", True, "psk"),
            (
                " ikev2 local-authentication pre-shared-key s3cr3t\n",
                "s3cr3t",
                False,
                "psk",
            ),
            ("snmp-server community public RO\n", "public", False, "snmp"),
            ("enable password cisco\n", "cisco", False, "enable"),
        ):
            f = fake_fact(text, value, "secret")
            self.assertEqual(is_hashed(text, f), hashed, text)
            self.assertEqual(classify(text, f), name, text)

    def test_psk_only_plan_and_redaction(self) -> None:
        a = real(disco.AZURE)
        plan = planner.build_plan(
            a, secrets_answers(a.lab, "psk"), planner.PlanOptions(scenarios=["secrets"])
        )
        edits = edits_of(plan, "secrets/")
        self.assertTrue(edits)
        self.assertTrue(all(e.secret for e in edits))
        self.assertEqual({e.text_edit.new for e in edits}, {"CHANGE-ME-psk"})
        data = json.loads(planner.dumps_plan(plan))
        dumped = json.dumps(data)
        for s in secret_values(a):
            self.assertNotIn(s, dumped)
            for f in plan.findings:
                self.assertNotIn(s, f.msg)
        self.assertIn("SECRET_HISTORY", {f.code for f in plan.findings})
        none = planner.build_plan(a, secrets_answers(a.lab, "none"))
        self.assertEqual(edits_of(none, "secrets/"), [])

    def test_azure_psk_wins_and_rerun(self) -> None:
        def make(a: Analysis, lab: RawLab) -> Profile:
            ans = azure_answers(lab)
            ans.labs[lab.lab_id].scenarios["secrets"] = ScenarioAnswer(
                options={"placeholders": "all"}
            )
            return ans

        plan, plan2, a2 = roundtrip(disco.AZURE, make)
        self.assertFalse(plan.blocked, plan.findings)
        self.assertEqual(len(edits_of(plan, "azure_s2s/psk")), 2)
        self.assertEqual(planner.enabled_edits(plan2), [])
        values = {f.value for f in a2.facts.values() if f.kind == "secret"}
        self.assertIn(NEW_PSK, values)
        self.assertIn("CHANGE-ME-enable", values)


class RenderCtxSanityTest(unittest.TestCase):
    def test_asa_route_stanza_is_one_line(self) -> None:
        a = real(disco.AZURE)
        f = next(
            f
            for f in a.facts.values()
            if f.kind == "ip_route_dst" and f.value == "10.25.0.0" and f.node_id == "1"
        )
        text = next(
            ct.text for ct in a.texts if ct.store == f.store and ct.node_id == "1"
        )
        asa = dialects.get("asa")
        (edit,) = asa.delete_stanza(f, RenderCtx(text))  # type: ignore[attr-defined]
        self.assertTrue(edit.old.startswith("route mgmt 10.25.0.0 "))
        self.assertTrue(edit.old.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
