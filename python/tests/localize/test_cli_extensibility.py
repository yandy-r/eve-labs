"""Regression tests for the cli-extensibility review fixes (#25-#40).

* #25 review menu: edit ids listed (``i``), ``x`` takes a unique id prefix,
  xml attribute diffs name the network and attribute;
* #27 plugin dialects a localized lab used are recorded in ``state.json``;
  revert/check refuse (UNKNOWN_DIALECT) without them; ``$EVE_LOCALIZE_PLUGINS``;
* #28 real-lab lists are derived from the tree;
* #29 built-in dialect/scenario modules are auto-discovered;
* #30 ``ParamKind.render`` is documented as reserved;
* #31 two pack files declaring the same dialect raise DIALECT_DUPLICATE;
* #32 duplicate scenario ids raise SCENARIO_DUPLICATE (``override=True`` opts in);
* #35 a localized bridge never makes the example profile stale;
* #36 unknown ``--answers`` ids warn (error under ``--strict``);
* #37 a relative ``--lab`` path resolves against ``--root``;
* #38 ``check --all`` analyses each lab once; rule filter memoised per chain;
* #39 an exception in ``applies()`` is a SCENARIO_FAILED finding;
* #40 manifest ``[[rule]]`` tables apply to canvas textobjects.

Real labs are only read; every write goes to a temp tree (``--root``).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import textwrap
import unittest
from ipaddress import IPv4Network
from pathlib import Path
from unittest import mock

from evelab.localize import cli, dialects, planner, scenarios
from evelab.localize.dialects.base import PatternRule
from evelab.localize.discover import _parse_textobjects, analyse
from evelab.localize.discover.topology import ConfigIndex
from evelab.localize.errors import LocalizeError
from evelab.localize.model import ConfigText, Store
from evelab.localize.profile import Profile, SegmentAnswer
from evelab.localize.scenarios.base import ParamKind
from evelab.localize.ui import UI

from .goldlib import Tree, answers_path, real_stems
from .labfiles import (
    cloud_lab_stems,
    minilab,
    no_cloud_lab_stems,
    real_lab_paths,
)

AZURE = "azure_asa_vpn"
SDWAN = "vxlan_evpn_multi-site_sdwan_only"


def _need(*stems: str) -> None:
    for stem in stems:
        if stem not in real_stems():
            raise unittest.SkipTest(f"{stem} not present")


def run(
    tree: Tree, *argv: str, env: dict[str, str] | None = None, stdin: str = ""
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    rt = cli.Runtime(
        stdin=io.StringIO(stdin),
        stdout=out,
        stderr=err,
        env={"NO_COLOR": "1", **(env or {})},
        interactive=False,
        getpass_fn=lambda _prompt: "",
        proc=tree.tmp / "proc",
        tmp_root=tree.tmp / "unetlab_tmp",
        docker_names=list,
        sys_net=tree.tmp / "sys_net",
        check_labs_peers=[],
    )
    code = cli.main([*argv, "--root", str(tree.root), "--no-color"], rt)
    return code, out.getvalue(), err.getvalue()


def _session(tree: Tree, stdin: str = "", interactive: bool = False) -> cli.Session:
    out = io.StringIO()
    ui = UI(
        io.StringIO(stdin),
        out,
        out,
        interactive=interactive,
        color=False,
        env={"NO_COLOR": "1"},
    )
    args = cli.build_parser().parse_args(["--root", str(tree.root)])
    return cli.Session(
        "plan", args, ui, cli.Runtime(), tree.root, tree.root / ".localize"
    )


class TreeCase(unittest.TestCase):
    stems: tuple[str, ...] = (AZURE,)

    def setUp(self) -> None:
        _need(*self.stems)
        self.tree = Tree(*self.stems)
        self.addCleanup(self.tree.cleanup)

    def write(self, name: str, text: str) -> Path:
        path = self.tree.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path


# --------------------------------------------------------------------------- #
# #25 review menu
# --------------------------------------------------------------------------- #


class TestReviewMenu(TreeCase):
    def _plan(self, sess: cli.Session) -> tuple[cli.LabCtx, object]:
        lc = cli.load_lab(sess, self.tree.labs[AZURE])
        assert lc.analysis is not None
        prof = Profile()
        prof.segments["azure.mgmt"] = SegmentAnswer(
            bridge="pnet5", subnet=IPv4Network("192.168.104.0/24")
        )
        plan = planner.build_plan(
            lc.analysis, prof, planner.PlanOptions(manifest=lc.manifest)
        )
        return lc, plan

    def test_xml_diff_names_network_and_attribute_with_edit_id(self) -> None:
        sess = _session(self.tree)
        lc, plan = self._plan(sess)
        xml = [e for e in plan.edits if e.target == "xml_attr"]
        self.assertTrue(xml)
        ctx = cli._xml_attr_context(lc, xml[0])
        self.assertRegex(ctx, r"^network \S+ '.*' type:$")
        cli.show_diff(sess, lc, plan, "decoded")
        text = sess.ui._stdout.getvalue()  # type: ignore[attr-defined]
        self.assertIn(f"[{xml[0].id}] network ", text)

    def test_menu_lists_ids_and_explains_by_prefix(self) -> None:
        sess = _session(self.tree)
        lc, plan = self._plan(sess)
        eid = plan.edits[0].id
        sess = _session(
            self.tree, stdin=f"i\nx {eid[:6]}\nx zzz\nc\n", interactive=True
        )
        self.assertFalse(cli.review(sess, lc, plan, can_apply=False))
        text = sess.ui._stdout.getvalue()  # type: ignore[attr-defined]
        self.assertIn(eid, text)
        self.assertIn(f"edit {eid}:", text)
        self.assertIn("no edit 'zzz'", text)
        self.assertEqual(cli._find_edit(plan, eid), eid)
        self.assertGreater(len(plan.edits), 1)
        self.assertIsNone(cli._find_edit(plan, "e"))  # ambiguous prefix


# --------------------------------------------------------------------------- #
# #27 plugin persistence
# --------------------------------------------------------------------------- #

PLUGIN = textwrap.dedent("""\
    from evelab.localize.dialects import register
    from evelab.localize.dialects.linuxsh import LinuxSh


    @register
    class PlugLinux(LinuxSh):
        name = "plug_linux"
        priority = 10_000
    """)


class TestPluginPersistence(TreeCase):
    def setUp(self) -> None:
        super().setUp()
        self.plug = self.tree.tmp / "plug"
        self.plug.mkdir()
        (self.plug / "pluglinux.py").write_text(PLUGIN, encoding="utf-8")
        self.addCleanup(self._unregister)

    @staticmethod
    def _unregister() -> None:
        dialects.REGISTRY.pop("plug_linux", None)
        dialects.PLUGIN_SOURCES.pop("plug_linux", None)

    def state(self) -> dict:
        path = self.tree.root / ".localize" / "state.json"
        return json.loads(path.read_text()) if path.is_file() else {}

    def test_revert_and_check_refuse_without_the_plugin(self) -> None:
        lab = self.tree.labs[AZURE]
        before = lab.read_bytes()
        ans = str(answers_path(AZURE))
        code, out, err = run(
            self.tree, "apply", "--lab", AZURE, "--profile", ans, "--yes",
            "--plugins", str(self.plug),
        )  # fmt: skip
        self.assertEqual(code, 0, out + err)
        entry = next(iter(self.state().values()))
        self.assertIn("plug_linux", entry["plugin_dialects"])
        localized = lab.read_bytes()
        self.assertNotEqual(before, localized)

        self._unregister()
        for argv in (("revert", "--lab", AZURE, "--yes"), ("check", "--lab", AZURE)):
            with self.subTest(cmd=argv[0]):
                code, out, err = run(self.tree, *argv)
                self.assertNotEqual(code, 0, out + err)
                self.assertIn("UNKNOWN_DIALECT", err)
                self.assertIn(f"--plugins {self.plug}", err)
                self.assertEqual(lab.read_bytes(), localized)
                self.assertTrue(self.state())

        # the env var is a persistent plugin path
        env = {cli.PLUGINS_ENV: str(self.plug)}
        code, out, err = run(self.tree, "revert", "--lab", AZURE, "--yes", env=env)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(lab.read_bytes(), before)
        self.assertFalse(self.state())


# --------------------------------------------------------------------------- #
# #28 / #29 / #30 discovery of labs and modules
# --------------------------------------------------------------------------- #


class TestDerivedLists(unittest.TestCase):
    def test_lab_lists_partition_the_tree(self) -> None:
        stems = {p.stem for p in real_lab_paths()}
        self.assertEqual(set(cloud_lab_stems()) | set(no_cloud_lab_stems()), stems)
        self.assertFalse(set(cloud_lab_stems()) & set(no_cloud_lab_stems()))

    def test_roundtrip_skips_a_lab_without_goldens_with_a_clear_message(self) -> None:
        from .test_roundtrip import RoundTripCase

        case = RoundTripCase()
        with self.assertRaises(unittest.SkipTest) as ctx:
            case.need_answers("brand_new_lab")
        self.assertIn("brand_new_lab.answers.toml", str(ctx.exception))
        self.assertIn("Onboarding a new lab", str(ctx.exception))


class TestModuleDiscovery(unittest.TestCase):
    def _tmp_pkg(self, names: list[str]) -> str:
        tmp = tempfile.mkdtemp(prefix="evelab-localize-pkg-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        for n in names:
            Path(tmp, n).write_text("", encoding="utf-8")
        return tmp

    def test_dialect_modules_are_auto_discovered(self) -> None:
        here = Path(dialects.__file__).parent
        want = sorted(
            p.stem
            for p in here.glob("*.py")
            if not p.stem.startswith("_") and p.stem not in dialects.HELPER_MODULES
        )
        self.assertEqual(list(dialects.BUILTIN_MODULES), want)
        tmp = self._tmp_pkg(["eos.py", "_priv.py", "base.py", "blocks.py"])
        with mock.patch.object(dialects, "__path__", [tmp]):
            self.assertEqual(dialects._discover_modules(), ("eos",))

    def test_scenario_modules_are_auto_discovered(self) -> None:
        here = Path(scenarios.__file__).parent
        want = sorted(
            p.stem
            for p in here.glob("*.py")
            if not p.stem.startswith("_") and p.stem not in scenarios.HELPER_MODULES
        )
        self.assertEqual(list(scenarios.BUILTIN_MODULES), want)
        tmp = self._tmp_pkg(["syslog.py", "base.py", "extra_common.py"])
        with mock.patch.object(scenarios, "__path__", [tmp]):
            self.assertEqual(scenarios._discover_modules(), ("syslog",))

    def test_param_kind_render_is_reserved(self) -> None:
        self.assertIn("RESERVED", ParamKind.__doc__ or "")


# --------------------------------------------------------------------------- #
# #31 / #32 duplicate registrations
# --------------------------------------------------------------------------- #

PACK = 'dialect = "dup_pack"\ntemplates = ["{t}*"]\n'


class TestDuplicates(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="evelab-localize-dup-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        patch = mock.patch.dict(dialects.REGISTRY)
        patch.start()
        self.addCleanup(patch.stop)
        sp = mock.patch.dict(dialects.PLUGIN_SOURCES)
        sp.start()
        self.addCleanup(sp.stop)

    def test_two_pack_files_with_one_name_conflict(self) -> None:
        a, b = self.tmp / "a", self.tmp / "b"
        a.mkdir()
        b.mkdir()
        (a / "x.toml").write_text(PACK.format(t="aaa"), encoding="utf-8")
        (b / "y.toml").write_text(PACK.format(t="bbb"), encoding="utf-8")
        dialects.load_packs([a])
        dialects.load_packs([a])  # same file again: replaced quietly
        self.assertEqual(dialects.PLUGIN_SOURCES["dup_pack"], str(a / "x.toml"))
        with self.assertRaises(LocalizeError) as ctx:
            dialects.load_packs([b])
        self.assertEqual(ctx.exception.code, "DIALECT_DUPLICATE")
        self.assertEqual(dialects.REGISTRY["dup_pack"].templates, ("aaa*",))

    def test_scenario_duplicate_and_override(self) -> None:
        with mock.patch.dict(scenarios.SCENARIOS):

            class First:
                id = "dup_sc"
                order = 999

            class Second:
                id = "dup_sc"
                order = 999

            scenarios.register_scenario(First)
            scenarios.register_scenario(First)  # same class: fine
            with self.assertRaises(LocalizeError) as ctx:
                scenarios.register_scenario(Second)
            self.assertEqual(ctx.exception.code, "SCENARIO_DUPLICATE")
            scenarios.register_scenario(Second, override=True)
            self.assertIsInstance(scenarios.SCENARIOS["dup_sc"], Second)


class TestPluginScenarioClash(TreeCase):
    def test_plugin_scenario_with_a_builtin_id_is_an_error(self) -> None:
        plug = self.tree.tmp / "plug"
        plug.mkdir()
        (plug / "ov.py").write_text(
            textwrap.dedent("""\
                from evelab.localize.scenarios import register_scenario

                @register_scenario
                class Ov:
                    id = "services"
                    order = 50
                """),
            encoding="utf-8",
        )
        services = scenarios.SCENARIOS["services"]
        self.addCleanup(scenarios.SCENARIOS.__setitem__, "services", services)
        code, _out, err = run(self.tree, "scan", "--lab", AZURE, "--plugins", str(plug))
        self.assertNotEqual(code, 0)
        self.assertIn("SCENARIO_DUPLICATE", err)
        self.assertIs(scenarios.SCENARIOS["services"], services)


# --------------------------------------------------------------------------- #
# #35 example profile after a bridge localization
# --------------------------------------------------------------------------- #


class TestExampleAfterBridge(TreeCase):
    def test_bridge_localization_keeps_example_current(self) -> None:
        code, out, err = run(self.tree, "profile", "--example")
        self.assertEqual(code, 0, out + err)
        example = self.tree.root / cli.EXAMPLE_PROFILE
        want = example.read_text(encoding="utf-8")
        prof = self.write(
            "br.toml", 'schema = 1\n[segments."azure.inet"]\nbridge = "pnet4"\n'
        )
        code, out, err = run(
            self.tree, "apply", "--lab", AZURE, "--profile", str(prof), "--yes"
        )
        self.assertEqual(code, 0, out + err)
        code, out, err = run(self.tree, "check", "--all")
        self.assertNotIn("STALE_EXAMPLE", out + err)
        self.assertEqual(code, 0, out + err)
        code, out, err = run(self.tree, "profile", "--example")
        self.assertEqual(example.read_text(encoding="utf-8"), want)

    def test_baseline_bridge_comes_from_state(self) -> None:
        a = analyse(*_lab_and_manifest(self.tree.labs[AZURE]))
        seg = a.segments[0]
        cur = cli._baseline_bridge(a, seg, None)
        entry = {"localized": True, "baseline": {seg.key: {"bridge": "pnet9"}}}
        self.assertEqual(cli._baseline_bridge(a, seg, entry), "pnet9")
        by_net = {
            "localized": True,
            "baseline": {
                "RENAMED": {"networks": list(seg.network_ids), "bridge": "pnet8"}
            },
        }
        self.assertEqual(cli._baseline_bridge(a, seg, by_net), "pnet8")
        self.assertEqual(cli._baseline_bridge(a, seg, {"baseline": {}}), cur)


def _lab_and_manifest(path: Path):
    from evelab.common.unl import RawLab
    from evelab.localize import manifest

    return RawLab.read(path), manifest.find_for(path)


# --------------------------------------------------------------------------- #
# #36 unknown answer ids
# --------------------------------------------------------------------------- #


class TestUnknownAnswers(TreeCase):
    stems = (AZURE, SDWAN)

    def test_typo_is_an_error_under_strict_and_a_warning_otherwise(self) -> None:
        ans = self.write("a.json", json.dumps({"azure.mgmt/subnt": "10.50.4.0/24"}))
        base = ("apply", "--lab", AZURE, "--answers", str(ans), "--yes")
        code, out, err = run(self.tree, *base, "--non-interactive", "--strict")
        self.assertEqual(code, 1, out + err)
        self.assertIn("BAD_ANSWER", err)
        self.assertIn("azure.mgmt/subnet", err)  # did you mean
        self.assertFalse((self.tree.root / ".localize" / "state.json").exists())
        code, out, err = run(self.tree, *base, "--dry-run")
        self.assertEqual(code, 0, out + err)
        self.assertIn("azure.mgmt/subnt", err)

    def test_ids_of_other_labs_are_not_reported(self) -> None:
        ans = self.write(
            "b.json",
            json.dumps(
                {
                    "azure.mgmt/subnet": "10.50.4.0/24",
                    "site.mgmt_a/subnet": "10.60.0.0/24",  # sdwan's segment
                }
            ),
        )
        code, out, err = run(
            self.tree, "plan", "--lab", AZURE, "--answers", str(ans), "--yes",
            "--strict", "--non-interactive",
        )  # fmt: skip
        self.assertNotIn("BAD_ANSWER", err)
        self.assertNotIn("matches no question", err)
        self.assertEqual(code, 0, out + err)

    def test_profile_segment_key_known_nowhere_warns(self) -> None:
        prof = self.write(
            "p.toml", 'schema = 1\n[segments."azure.mgmnt"]\nsubnet = "10.9.0.0/24"\n'
        )
        code, out, err = run(
            self.tree, "plan", "--lab", AZURE, "--profile", str(prof), "--yes"
        )
        self.assertEqual(code, 0, out + err)
        self.assertIn("azure.mgmnt", err)
        self.assertIn("azure.mgmt", err)


# --------------------------------------------------------------------------- #
# #37 --lab relative to --root
# --------------------------------------------------------------------------- #


class TestLabResolution(TreeCase):
    def test_relative_lab_path_resolves_against_root(self) -> None:
        rel = self.tree.labs[AZURE].relative_to(self.tree.root)
        cwd = Path(tempfile.mkdtemp(prefix="evelab-localize-cwd-"))
        self.addCleanup(shutil.rmtree, cwd, ignore_errors=True)
        (cwd / rel).parent.mkdir(parents=True)
        shutil.copyfile(self.tree.labs[AZURE], cwd / rel)
        old = os.getcwd()
        os.chdir(cwd)
        self.addCleanup(os.chdir, old)
        sess = _session(self.tree)
        self.assertEqual(
            cli.resolve_labs(sess, [str(rel)]), [self.tree.labs[AZURE].resolve()]
        )
        self.tree.labs[AZURE].unlink()
        with self.assertRaises(LocalizeError) as ctx:
            cli.resolve_labs(sess, [str(rel)])
        self.assertEqual(ctx.exception.code, "LAB_OUTSIDE_ROOT")
        with self.assertRaises(LocalizeError) as ctx:
            cli.resolve_labs(sess, [str(cwd / rel)])
        self.assertEqual(ctx.exception.code, "LAB_OUTSIDE_ROOT")


# --------------------------------------------------------------------------- #
# #38 performance
# --------------------------------------------------------------------------- #


class TestPerformance(TreeCase):
    def test_check_all_analyses_each_lab_once(self) -> None:
        code, out, err = run(self.tree, "profile", "--example")
        self.assertEqual(code, 0, out + err)
        with mock.patch.object(cli, "analyse", wraps=cli.analyse) as spy:
            code, out, err = run(self.tree, "check", "--all")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(spy.call_count, len(self.tree.labs))

    def test_rule_filter_is_memoised_per_chain_kinds(self) -> None:
        from evelab.localize.dialects.blocks import Block

        d = dialects.get("ios")
        chain = (Block("interface", "Gi1", "interface/Gi1", 0, 0, 1),)
        first = d._rules_for_chain(chain)
        self.assertIs(d._rules_for_chain(chain), first)
        top = d._rules_for_chain(())
        self.assertTrue(all(r.block in (None, "top") for r, _rx, _role in top))
        self.assertEqual(
            [r.id for r, _rx, _role in first],
            [r.id for r in d.rules if r.block not in ("top",) and _ok(r, chain)],
        )


class TestParseCaches(unittest.TestCase):
    def test_cached_parse_hits_and_returns_independent_copies(self) -> None:
        from evelab.localize.discover import topology

        d = dialects.get("ios")
        text = "hostname r1\ninterface Gi1\n ip address 10.0.0.1 255.255.255.0\n"
        ct = ConfigText(
            Store("startup", "startup", "startup"), "1", text, "ios", None, None
        )
        with mock.patch.object(d, "parse", wraps=d.parse) as spy:
            first = topology.cached_parse(d, ct)
            first.facts[0].segment = "MUTATED"
            second = topology.cached_parse(d, ct)
        self.assertEqual(spy.call_count, 1)
        self.assertIsNone(second.facts[0].segment)
        self.assertEqual(
            [(f.kind, f.value) for f in first.facts],
            [(f.kind, f.value) for f in second.facts],
        )

    def test_tokenize_is_memoised_per_bytes(self) -> None:
        from evelab.common import unl

        raw = (REPO_LABS[0]).read_bytes() if REPO_LABS else b""
        if not raw:
            self.skipTest("no real lab")
        with mock.patch.object(
            unl, "_tokenize_uncached", wraps=unl._tokenize_uncached
        ) as spy:
            unl._TOKEN_CACHE.pop(raw, None)
            unl.RawLab.from_bytes(raw)
            unl.RawLab.from_bytes(raw)
        self.assertEqual(spy.call_count, 1)


REPO_LABS = real_lab_paths()


def _ok(rule: PatternRule, chain: tuple) -> bool:
    from evelab.localize.dialects.base import rule_applies

    return rule_applies(rule.block, chain)


# --------------------------------------------------------------------------- #
# #39 applies() exceptions
# --------------------------------------------------------------------------- #


class Boom:
    id = "zz_boom"
    order = 999
    gated = False

    def applies(self, a, m):
        raise RuntimeError("kaboom")


class TestScenarioFailures(unittest.TestCase):
    def test_applies_exception_is_a_finding(self) -> None:
        a = analyse(minilab("basic"))
        with mock.patch.dict(scenarios.SCENARIOS, {"zz_boom": Boom()}):
            planner.collect_questions(a, Profile())
            plan = planner.build_plan(a, Profile())
        codes = [(f.code, f.severity) for f in plan.findings]
        self.assertIn(("SCENARIO_FAILED", "error"), codes)
        msgs = [f.msg for f in a.findings if f.code == "SCENARIO_FAILED"]
        self.assertEqual(len(msgs), 1)  # deduplicated
        self.assertIn("zz_boom", msgs[0])
        self.assertIn("kaboom", msgs[0])

    def test_unknown_dialect_falls_back_with_a_warning(self) -> None:
        idx = ConfigIndex(None, [])  # type: ignore[arg-type]
        self.assertEqual(idx.dialect_for("no_such_dialect").name, "generic")
        self.assertEqual([n.code for n in idx.notes], ["UNKNOWN_DIALECT"])


# --------------------------------------------------------------------------- #
# #40 manifest rules on textobjects
# --------------------------------------------------------------------------- #


class TestTextobjectRules(unittest.TestCase):
    def test_manifest_rules_apply_to_textobjects(self) -> None:
        text = "<p>DNS 192.0.2.53</p>"
        ct = ConfigText(Store("textobject", "7", "-"), "", text, "eve_html", None, None)
        rule_all = PatternRule(
            "t.dns_all", r"DNS (?P<v>\d+\.\d+\.\d+\.\d+)", "dns_server"
        )
        idx = ConfigIndex(None, [], {"*": [rule_all]})  # type: ignore[arg-type]
        facts = _parse_textobjects([ct], [], idx)
        self.assertIn(("t.dns_all", "192.0.2.53"), {(f.rule, f.value) for f in facts})
        plain = _parse_textobjects([ct], [])
        self.assertNotIn("t.dns_all", {f.rule for f in plain})


if __name__ == "__main__":
    unittest.main()
