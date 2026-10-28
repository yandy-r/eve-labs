import json
import unittest

from .helpers import LAB_ID, Repo, git

UP = "https://github.com/yandy-r/eve-labs.git"
NX = "image/qemu/nxosv9k/nxosv9k-9300v-10.3.3.F"


class CliTest(unittest.TestCase):
    def repo(self, origin: str | None = UP, **kw: object) -> Repo:
        r = Repo(origin, **kw)  # type: ignore[arg-type]
        self.addCleanup(r.cleanup)
        return r

    def test_scan_text_and_json(self) -> None:
        r = self.repo()
        code, out, err = r.run("scan")
        self.assertEqual(code, 0, err)
        self.assertIn("host eve2: 4 CPUs, 12000 MB RAM", out)
        self.assertIn(f"[fix] {NX}", out)
        self.assertIn("TEMPLATE_MISSING", out)
        code, out, _ = r.run("scan", "--json")
        doc = json.loads(out)
        self.assertEqual(doc["host"]["hostname"], "eve2")
        lab = doc["labs"][0]
        self.assertEqual((lab["lab"], lab["lab_id"]), ("labs/mini.unl", LAB_ID))
        self.assertIn(NX, [q["id"] for q in lab["questions"]])
        self.assertEqual(r.run("scan", "--strict")[0], 2)

    def test_inventory_roundtrip_and_not_eve_host(self) -> None:
        r = self.repo()
        code, out, _ = r.run("inventory")
        self.assertEqual(code, 0)
        inv = r.root / "host.json"
        inv.write_text(out)
        self.assertEqual(r.run("scan", "--inventory", str(inv))[0], 0)
        data = json.loads(out)
        data["eve"] = False
        inv.write_text(json.dumps(data))
        code, _, err = r.run("scan", "--inventory", str(inv))
        self.assertEqual(code, 4)
        self.assertIn("NOT_EVE_HOST", err)

    def test_plan_never_writes(self) -> None:
        r = self.repo()
        before = r.lab.read_bytes()
        code, out, _ = r.run("plan", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("image: nxosv9k-9300v-10.3.3.F -> nxosv9k-9300v-10.5.1.F", out)
        self.assertIn("Dry run", out)
        self.assertEqual(r.lab.read_bytes(), before)

    def test_apply_yes_in_clone_commits_on_new_branch(self) -> None:
        r = self.repo()
        code, out, err = r.run("apply", "--yes")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(git(r.root, "branch", "--show-current"), "analyze/eve2")
        self.assertEqual(git(r.root, "rev-list", "--count", "main"), "1")
        self.assertIn("committed", out)
        head = git(r.root, "show", "HEAD:labs/mini.unl")
        self.assertIn('image="nxosv9k-9300v-10.5.1.F"', head)
        self.assertIn('ram="8192"', head)
        self.assertIn('cpu="4"', head)
        self.assertIn('qemu_version="6.0.0"', head)
        self.assertIn('image="c8000v-17.11.01a"', head)  # upgrade kept by default
        self.assertEqual(git(r.root, "status", "--porcelain", "--", "labs"), "")
        self.assertTrue((r.root / ".analyze" / "backups").is_dir())

    def test_latest_takes_upgrades(self) -> None:
        r = self.repo()
        self.assertEqual(r.run("apply", "--yes", "--latest")[0], 0)
        self.assertIn('image="c8000v-17.15.01"', r.lab.read_text())

    def test_fork_commits_on_current_branch(self) -> None:
        r = self.repo("git@github.com:someone/eve-labs.git")
        self.assertEqual(r.run("apply", "--yes")[0], 0)
        self.assertEqual(git(r.root, "branch", "--show-current"), "main")
        self.assertEqual(git(r.root, "rev-list", "--count", "main"), "2")

    def test_no_commit_and_no_git(self) -> None:
        r = self.repo()
        self.assertEqual(r.run("apply", "--yes", "--no-commit")[0], 0)
        self.assertEqual(git(r.root, "rev-list", "--count", "HEAD"), "1")
        self.assertEqual(git(r.root, "branch", "--show-current"), "main")
        self.assertIn("nxosv9k-9300v-10.5.1.F", r.lab.read_text())
        plain = self.repo(None, use_git=False)
        code, out, _ = plain.run("apply", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("not a git checkout", out)
        self.assertIn("nxosv9k-9300v-10.5.1.F", plain.lab.read_text())

    def test_answers_files(self) -> None:
        r = self.repo()
        toml = r.root / "a.toml"
        toml.write_text(
            f'schema = 1\n[answers]\n"{NX}" = "nxosv9k-9500v-10.3.3.F"\n'
            + '"ram/16384" = "keep"\n'
        )
        code, _, err = r.run("apply", "--answers", str(toml), "--no-commit")
        self.assertEqual(code, 0, err)
        text = r.lab.read_text()
        self.assertIn('image="nxosv9k-9500v-10.3.3.F"', text)
        self.assertIn('ram="16384"', text)
        self.assertIn('qemu_version="4.1.0"', text)  # unanswered: kept
        self.assertIn("required question(s) unanswered", err)

    def test_json_answers_and_bad_answer(self) -> None:
        r = self.repo()
        good = r.root / "a.json"
        good.write_text(json.dumps({"qemu_version/4.1.0": "2.12.0"}))
        self.assertEqual(r.run("apply", "--answers", str(good), "--no-commit")[0], 0)
        self.assertIn('qemu_version="2.12.0"', r.lab.read_text())
        bad = r.root / "b.json"
        bad.write_text(json.dumps({"cpu/8": "64"}))
        code, _, err = r.run("apply", "--answers", str(bad), "--no-commit")
        self.assertEqual(code, 1)
        self.assertIn("BAD_ANSWER", err)

    def test_filled_scan_json_is_an_answers_file(self) -> None:
        r = self.repo()
        doc = json.loads(r.run("scan", "--json")[1])
        for q in doc["labs"][0]["questions"]:
            if q["id"] == NX:
                q["answer"] = "nxosv9k-9500v-10.3.3.F"
        f = r.root / "filled.json"
        f.write_text(json.dumps(doc))
        self.assertEqual(r.run("apply", "--answers", str(f), "--no-commit")[0], 0)
        self.assertIn("nxosv9k-9500v-10.3.3.F", r.lab.read_text())

    def test_strict_unanswered(self) -> None:
        r = self.repo()
        code, _, err = r.run("apply", "--strict", "--no-commit")
        self.assertEqual(code, 3)
        self.assertIn("unanswered", err)

    def test_interactive_numbers_keep_and_save_answers(self) -> None:
        r = self.repo()
        saved = r.root / ".analyze" / "answers.toml"
        # picker: Enter (the only lab); iol: Enter (recommended); nx image: 2
        # (9500v); qemu: k; cpu: 2; ram: 7000; c8000v upgrade: Enter (keep); confirm: y
        code, out, err = r.run(
            "--save-answers", str(saved), "--no-commit",
            stdin="\n\n2\nk\n2\n7000\n\ny\n", interactive=True,
        )  # fmt: skip
        self.assertEqual(code, 0, out + err)
        text = r.lab.read_text()
        self.assertIn('image="nxosv9k-9500v-10.3.3.F"', text)
        self.assertIn('image="x86_64_crb_linux_l2-adventerprisek9-ms.bin"', text)
        self.assertIn('qemu_version="4.1.0"', text)
        self.assertIn('cpu="2"', text)
        self.assertIn('ram="7000"', text)
        self.assertIn('image="c8000v-17.11.01a"', text)
        answers = saved.read_text()
        self.assertIn('"qemu_version/4.1.0" = "keep"', answers)
        self.assertIn('"cpu/8" = "2"', answers)

    def test_interactive_decline_writes_nothing(self) -> None:
        r = self.repo()
        before = r.lab.read_bytes()
        code, out, _ = r.run(stdin="\n\n\n\n\n\n\nn\n", interactive=True)
        self.assertEqual(code, 0)
        self.assertIn("Nothing written.", out)
        self.assertEqual(r.lab.read_bytes(), before)

    def test_quit(self) -> None:
        r = self.repo()
        code, out, _ = r.run(stdin="q\n", interactive=True)
        self.assertEqual(code, 0)
        self.assertIn("Quit: nothing written.", out)

    def test_run_non_interactive_without_yes_writes_nothing(self) -> None:
        r = self.repo()
        before = r.lab.read_bytes()
        code, out, _ = r.run("--answers", str(self._nx_answers(r)))
        self.assertEqual(code, 0)
        self.assertIn("nothing written", out)
        self.assertEqual(r.lab.read_bytes(), before)

    def _nx_answers(self, r: Repo):  # type: ignore[no-untyped-def]
        f = r.root / "nx.json"
        f.write_text(json.dumps({NX: "nxosv9k-9300v-10.5.1.F"}))
        return f

    def test_running_nodes_block_the_write(self) -> None:
        r = self.repo()
        pid = r.proc / "4242"
        pid.mkdir()
        (pid / "cmdline").write_bytes(
            b"/opt/qemu/bin/qemu-system-x86_64\0-name\0" + LAB_ID.encode() + b"\0"
        )
        before = r.lab.read_bytes()
        code, out, err = r.run("apply", "--yes")
        self.assertEqual(code, 4)
        self.assertIn("RUNNING_NODES", out)
        self.assertIn("stop and wipe its nodes first", err)
        self.assertEqual(r.lab.read_bytes(), before)
        self.assertEqual(git(r.root, "branch", "--show-current"), "main")


if __name__ == "__main__":
    unittest.main()
