"""End-to-end CLI tests (design 14 item 10) on TEMP COPIES of the real labs.

Every test builds a repo-like tree (``<tmp>/repo/labs/...``) holding copies of the
labs it needs plus their ``*_cfgs`` sidecar dirs, and runs :func:`cli.main` with
``--root`` pointing there. Host probes (``/proc``, the EVE tmp dir, docker,
``/sys/class/net``) are fakes, so the running EVE lab on this host never matters.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from evelab.common.unl import RawLab
from evelab.localize import apply, cli

from .labfiles import REPO, real_lab_paths

SCRIPTS = REPO / "scripts"


def _real(fragment: str) -> Path:
    hits = [p for p in real_lab_paths() if fragment in p.name]
    if len(hits) != 1:
        raise unittest.SkipTest(f"real lab {fragment!r} not found")
    return hits[0]


SDWAN = "sdwan_only"
AZURE = "azure_asa_vpn"
JUNOS = "multi-site_junos"
NOCLOUD = "ccie_sec_v6"

SITE_B = """schema = 1
site = "site-b"
[segments."vxlan_evpn_multi-site_sdwan_only.MGMT-203"]
vlan = 20
subnet = "192.168.20.0/24"
gateway = "192.168.20.254"
[segments."vxlan_evpn_multi-site_sdwan_only.MGMT-204"]
vlan = 30
subnet = "192.168.30.0/24"
[segments."vxlan_evpn_multi-site_sdwan_only.INET-201"]
vlan = 301
subnet = "198.51.100.0/24"
[map.dns]
"1.1.1.1" = "9.9.9.9"
"""


class Tree:
    """A temp repo-like tree with copies of some real labs."""

    def __init__(self, *fragments: str) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="evelab-localize-cli-"))
        self.root = self.tmp / "repo"
        self.labs: dict[str, Path] = {}
        for frag in fragments:
            src = _real(frag)
            rel = src.relative_to(REPO)
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            for d in src.parent.iterdir():
                if (
                    d.is_dir()
                    and d.name.startswith(src.stem)
                    and d.name.endswith("_cfgs")
                ):
                    shutil.copytree(d, dest.parent / d.name)
            self.labs[frag] = dest
        for name in ("proc", "unetlab_tmp", "sys_net"):
            (self.tmp / name).mkdir()

    def cleanup(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def snapshot(self) -> dict[str, bytes]:
        return {
            str(p.relative_to(self.root)): p.read_bytes()
            for p in sorted((self.root / "labs").rglob("*"))
            if p.is_file()
        }

    def write(self, name: str, text: str) -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def run(
        self,
        *argv: str,
        stdin: str | None = None,
        interactive: bool | None = False,
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        rt = cli.Runtime(
            stdin=io.StringIO(stdin or ""),
            stdout=out,
            stderr=err,
            env={"NO_COLOR": "1"},
            interactive=interactive,
            getpass_fn=lambda _prompt: "",
            proc=self.tmp / "proc",
            tmp_root=self.tmp / "unetlab_tmp",
            docker_names=list,
            sys_net=self.tmp / "sys_net",
            check_labs_peers=[],
        )
        code = cli.main([*argv, "--root", str(self.root), "--no-color"], rt)
        return code, out.getvalue(), err.getvalue()


class TreeCase(unittest.TestCase):
    labs: tuple[str, ...] = ()

    def setUp(self) -> None:
        self.t = Tree(*self.labs)
        self.addCleanup(self.t.cleanup)


class ShimTests(unittest.TestCase):
    def test_help_via_shim(self) -> None:
        res = subprocess.run(
            [sys.executable, str(SCRIPTS / "eve-localize"), "--help"],
            capture_output=True,
            text=True,
            env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
            check=False,
            timeout=60,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("usage: eve-localize", res.stdout)
        for word in ("scan", "revert", "undo", "discover", "exit codes"):
            self.assertIn(word, res.stdout)

    def test_command_split(self) -> None:
        self.assertEqual(cli._split_command(["scan", "x"]), ("scan", ["x"]))
        self.assertEqual(cli._split_command(["-v", "list"]), ("scan", ["-v"]))
        self.assertEqual(cli._split_command(["sdwan"]), ("run", ["sdwan"]))
        self.assertEqual(cli._split_command(["localize-check"]), ("check", []))

    def test_worst_exit_code(self) -> None:
        self.assertEqual(cli.worst([1, 2, 5, 4]), 5)
        self.assertEqual(cli.worst([2, 3]), 3)
        self.assertEqual(cli.worst([]), 0)

    def test_json_answers_parsing(self) -> None:
        doc = {
            "labs": [
                {
                    "questions": [
                        {"id": "a/vlan", "answer": 20},
                        {"id": "b/enabled", "answer": False},
                        {"id": "c/subnet", "answer": None},
                    ]
                }
            ]
        }
        self.assertEqual(
            cli.parse_json_answers(doc, "x"), {"a/vlan": "20", "b/enabled": "no"}
        )
        self.assertEqual(
            cli.parse_json_answers({"answers": {"q": ["1.1.1.1", "2.2.2.2"]}}, "x"),
            {"q": "1.1.1.1, 2.2.2.2"},
        )


class ScanTests(TreeCase):
    labs = (AZURE, NOCLOUD)

    def test_scan_list(self) -> None:
        code, out, _ = self.t.run("scan", "--list")
        self.assertEqual(code, 0)
        self.assertIn("nothing to localize", out)
        self.assertIn("labs/cloud/azure/azure_asa_", out)

    def test_scan_matrix(self) -> None:
        code, out, _ = self.t.run("scan", "--all")
        self.assertEqual(code, 0)
        self.assertIn("INTERNET-105", out)
        self.assertIn("unpinned: no manifest", out)
        self.assertIn("Nothing to localize", out)

    def test_ambiguous_and_missing_lab(self) -> None:
        code, _, err = self.t.run("scan", "--lab", "doesnotexist")
        self.assertEqual(code, 1)
        self.assertIn("NO_LAB", err)
        code, _, err = self.t.run("scan", "--lab", "labs/")
        self.assertEqual(code, 1)
        self.assertIn("AMBIGUOUS_LAB", err)

    def test_no_externals_lab_exits_zero_without_writes(self) -> None:
        before = self.t.snapshot()
        code, out, _ = self.t.run(
            "apply", "--lab", NOCLOUD, "--yes", "--allow-unpinned"
        )
        self.assertEqual(code, 0)
        self.assertIn("Nothing to localize", out)
        self.assertEqual(before, self.t.snapshot())
        self.assertFalse((self.t.root / ".localize" / "journal.json").exists())

    def test_strict_non_interactive_unanswered_exits_3(self) -> None:
        code, _, err = self.t.run(
            "plan", "--lab", AZURE, "--non-interactive", "--strict", "--allow-unpinned"
        )
        self.assertEqual(code, 3, err)
        self.assertIn("unanswered", err)

    def test_json_schema_round_trips_through_answers(self) -> None:
        code, out, _ = self.t.run("scan", "--json", "--lab", AZURE)
        self.assertEqual(code, 0)
        doc = json.loads(out)
        lab = doc["labs"][0]
        self.assertFalse(lab["nothing_to_localize"])
        qs = {q["id"]: q for q in lab["questions"]}
        sub = "azure_asa_vpn.INTERNET-105/subnet"
        self.assertEqual(qs[sub]["kind"], "cidr")
        self.assertEqual(qs[sub]["current"], "10.100.105.0/24")
        for q in lab["questions"]:
            q["answer"] = q["default"]
        qs[sub]["answer"] = "198.51.100.0/24"
        qs["azure_asa_vpn.INTERNET-105/gateway"]["answer"] = "198.51.100.1"
        filled = self.t.write("filled.json", json.dumps(doc))
        before = self.t.snapshot()
        code, out, err = self.t.run(
            "plan",
            "--lab",
            AZURE,
            "--answers",
            str(filled),
            "--non-interactive",
            "--strict",
            "--allow-unpinned",
            "--json",
        )
        self.assertEqual(code, 0, err)
        plans = json.loads(out)["labs"]
        news = {e["new"] for e in plans[0]["plan"]["edits"]}
        self.assertTrue(any(n.startswith("198.51.100.") for n in news), news)
        self.assertEqual(before, self.t.snapshot())

    def test_unpinned_non_interactive_apply_needs_flag(self) -> None:
        answers = self.t.write(
            "a.json",
            json.dumps({"answers": {"azure_asa_vpn.MGMT-104/bridge": "pnet3"}}),
        )
        before = self.t.snapshot()
        code, _, err = self.t.run("apply", "--lab", AZURE, "--answers", str(answers))
        self.assertEqual(code, 4)
        self.assertIn("--allow-unpinned", err)
        self.assertEqual(before, self.t.snapshot())

    def test_bad_answer_is_an_error(self) -> None:
        answers = self.t.write(
            "a.json", json.dumps({"azure_asa_vpn.INTERNET-105/subnet": "nonsense"})
        )
        code, _, err = self.t.run("plan", "--lab", AZURE, "--answers", str(answers))
        self.assertEqual(code, 1)
        self.assertIn("BAD_ANSWER", err)

    def test_explain_and_discover_print_only(self) -> None:
        before = self.t.snapshot()
        code, out, _ = self.t.run("explain", "--lab", AZURE)
        self.assertEqual(code, 0)
        self.assertIn("ip_host", out)
        code, out, _ = self.t.run("discover", AZURE)
        self.assertEqual(code, 0)
        self.assertIn("lab_id", out)
        self.assertEqual(before, self.t.snapshot())

    def test_discover_write_creates_draft_in_temp_tree(self) -> None:
        code, out, _ = self.t.run("discover", AZURE, "--write")
        self.assertEqual(code, 0, out)
        lab = self.t.labs[AZURE]
        draft = lab.with_name(lab.stem + ".localize.toml.draft")
        self.assertTrue(draft.is_file())
        code, _, err = self.t.run("discover", AZURE, "--update")
        self.assertEqual(code, 1)
        self.assertIn("no manifest", err)

    def test_quit_in_interactive_session_writes_nothing(self) -> None:
        before = self.t.snapshot()
        code, out, _ = self.t.run("--lab", AZURE, stdin="y\nq\n", interactive=True)
        self.assertEqual(code, 0)
        self.assertIn("nothing written", out)
        self.assertEqual(before, self.t.snapshot())

    def test_plugins_dir(self) -> None:
        plug = self.t.tmp / "plugins"
        plug.mkdir()
        (plug / "noop.py").write_text("X = 1\n", encoding="utf-8")
        code, _, err = self.t.run("scan", "--lab", AZURE, "--plugins", str(plug))
        self.assertEqual(code, 0, err)
        code, _, err = self.t.run(
            "scan", "--lab", AZURE, "--plugins", str(self.t.tmp / "missing")
        )
        self.assertEqual(code, 1)
        self.assertIn("PLUGIN_DIR", err)

    def test_picker_needs_tty(self) -> None:
        code, _, err = self.t.run("plan")
        self.assertEqual(code, 3)
        self.assertIn("lab selection needs a TTY", err)


class InteractiveTests(TreeCase):
    labs = (AZURE,)

    def test_interactive_full_flow_with_back_and_apply(self) -> None:
        lab = self.t.labs[AZURE]
        before = lab.read_bytes()
        # matrix ok; INTERNET-105 bridge: typo pnet7 then back (b) -> re-asked
        # -> pnet3; everything else default; review menu: diff, then apply.
        stdin = "y\npnet7\nb\npnet3\n" + "\n" * 40 + "d\na\n"
        code, out, err = self.t.run(
            "--lab", AZURE, "--allow-unpinned", stdin=stdin, interactive=True
        )
        self.assertEqual(code, 0, out + err)
        self.assertIn("[A Clouds]", out)
        self.assertIn("INTERNET-105 bridge", out)
        self.assertIn("Run ", out)
        after = RawLab.read(lab)
        types = {n.id: n.get("type") for n in after.networks()}
        net = next(n for n in after.networks() if n.get("name") == "Internet-105")
        self.assertEqual(types[net.id], "pnet3")
        self.assertNotEqual(before, lab.read_bytes())
        state = apply.load_state(
            apply.ApplyOptions(state_dir=self.t.root / ".localize")
        )
        entry = state[after.lab_id]
        self.assertTrue(entry["localized"])
        self.assertEqual(entry["values"]["INTERNET-105"]["bridge"], "pnet3")
        self.assertEqual(entry["baseline"]["INTERNET-105"]["bridge"], "pnet0")
        # revert restores the original bytes from the recorded baseline
        code, out, err = self.t.run("revert", "--lab", AZURE, "--yes")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(before, lab.read_bytes())

    def test_undo_restores_backup(self) -> None:
        lab = self.t.labs[AZURE]
        before = lab.read_bytes()
        answers = self.t.write(
            "a.json",
            json.dumps(
                {"answers": {"azure_asa_vpn.MGMT-104/subnet": "192.168.4.0/24"}}
            ),
        )
        code, out, err = self.t.run(
            "apply", "--lab", AZURE, "--answers", str(answers), "--allow-unpinned"
        )
        self.assertEqual(code, 0, out + err)
        self.assertNotEqual(before, lab.read_bytes())
        code, out, _ = self.t.run("runs")
        self.assertEqual(code, 0)
        self.assertIn("in-place", out)
        code, out, err = self.t.run("undo")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(before, lab.read_bytes())
        code, _, err = self.t.run("undo")
        self.assertEqual(code, 4)
        self.assertIn("NO_RUN", err)

    def test_out_copy_mode_new_lab_id(self) -> None:
        lab = self.t.labs[AZURE]
        before = self.t.snapshot()
        out_dir = self.t.tmp / "copies"
        answers = self.t.write(
            "a.json", json.dumps({"azure_asa_vpn.MGMT-104/bridge": "pnet3"})
        )
        code, out, err = self.t.run(
            "apply",
            "--lab",
            AZURE,
            "--answers",
            str(answers),
            "--allow-unpinned",
            "--out",
            str(out_dir),
        )
        self.assertEqual(code, 0, out + err)
        self.assertEqual(before, self.t.snapshot())
        copies = list(out_dir.rglob("*.unl"))
        self.assertEqual(len(copies), 1)
        new = RawLab.read(copies[0])
        self.assertNotEqual(new.lab_id, RawLab.read(lab).lab_id)
        rc, msg = apply.run_check_labs([copies[0], lab])
        self.assertEqual(rc, 0, msg)


class SdwanTests(TreeCase):
    labs = (SDWAN, JUNOS)

    def test_apply_idempotent_check_revert(self) -> None:
        site = self.t.write("site.toml", SITE_B)
        before = self.t.snapshot()
        common = ("--lab", SDWAN, "--answers", str(site))
        code, out, err = self.t.run("plan", *common, "--diff", "decoded")
        self.assertEqual(code, 0, err)
        self.assertIn("+ encapsulation dot1Q 20", out)
        self.assertIn("192.168.20.75 255.255.255.0", out)
        self.assertEqual(before, self.t.snapshot())

        code, out, err = self.t.run(
            "apply",
            *common,
            "--yes",
            "--allow-unpinned",
            "--save-answers",
            str(self.t.tmp / "saved.toml"),
        )
        self.assertEqual(code, 0, out + err)
        self.assertIn("localized", out)
        self.assertTrue((self.t.tmp / "saved.toml").is_file())
        lab = self.t.labs[SDWAN]
        rc, msg = apply.run_check_labs([lab])
        self.assertEqual(rc, 0, msg)

        code, out, err = self.t.run("apply", *common, "--yes", "--allow-unpinned")
        self.assertEqual(code, 0, err)
        self.assertIn("0 edits", out)

        code, out, err = self.t.run("check", "--lab", SDWAN)
        self.assertEqual(code, 0, out + err)
        code, out, err = self.t.run("check", "--lab", SDWAN, "--strict")
        self.assertEqual(code, 1)  # UNPINNED warning is fatal under --strict

        code, out, err = self.t.run("revert", "--lab", SDWAN, "--yes")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(before, self.t.snapshot())

    def test_reverted_by_eve_detected(self) -> None:
        site = self.t.write("site.toml", SITE_B)
        lab = self.t.labs[SDWAN]
        original = lab.read_bytes()
        code, out, err = self.t.run(
            "apply",
            "--lab",
            SDWAN,
            "--answers",
            str(site),
            "--yes",
            "--allow-unpinned",
            "--scope",
            "startup,sdwan-vxlan-evpn,sidecar",
        )
        self.assertEqual(code, 0, out + err)
        lab.write_bytes(original)  # "EVE saved its own copy"
        code, out, _ = self.t.run("check", "--lab", SDWAN)
        self.assertIn("REVERTED_BY_EVE", out)

    def test_all_carries_answers_forward(self) -> None:
        # junos first (sorted path order: datacenter/cisco < datacenter/junos is
        # reversed here by --lab order): answer DNS 1.1.1.1 in junos, then the
        # sdwan DNS question defaults to the carried value.
        junos_prefix = "y\n" + "\n" * 12 + "9.9.9.9\n"
        stdin = junos_prefix + "\n" * 200
        code, out, err = self.t.run(
            "plan", "--lab", JUNOS, "--lab", SDWAN, stdin=stdin, interactive=True
        )
        self.assertEqual(code, 0, out + err)
        self.assertIn("DNS 1.1.1.1", out)
        self.assertEqual(out.count("[9.9.9.9 map.dns]"), 1, out)


if __name__ == "__main__":
    unittest.main()
