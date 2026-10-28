import unittest

from evelab.analyze import gitops
from evelab.analyze.writer import Change

from .helpers import Repo, git

UP = "https://github.com/yandy-r/eve-labs.git"
NX = "image/qemu/nxosv9k/nxosv9k-9300v-10.3.3.F"


def _changes() -> list[Change]:
    return [
        Change("1", "leaf1", "image", "nxosv9k-9300v-10.3.3.F", "nxosv9k-9300v-10.5.1.F", NX),
        Change("2", "leaf2", "image", "nxosv9k-9300v-10.3.3.F", "nxosv9k-9300v-10.5.1.F", NX),
    ]  # fmt: skip


class SlugTest(unittest.TestCase):
    def test_forms(self) -> None:
        for url in (
            "https://github.com/Yandy-R/eve-labs.git",
            "git@github.com:yandy-r/eve-labs.git",
            "ssh://git@github.com/yandy-r/eve-labs",
            "https://github.com/yandy-r/eve-labs/",
        ):
            with self.subTest(url=url):
                self.assertEqual(gitops.remote_slug(url), "yandy-r/eve-labs")
        self.assertIsNone(gitops.remote_slug("not a url"))


class DetectTest(unittest.TestCase):
    def repo(self, origin: str | None, use_git: bool = True) -> Repo:
        r = Repo(origin, use_git=use_git)
        self.addCleanup(r.cleanup)
        return r

    def test_clone_fork_none(self) -> None:
        self.assertEqual(gitops.detect(self.repo(UP).root).mode, "clone")
        self.assertEqual(
            gitops.detect(self.repo("git@github.com:me/eve-labs.git").root).mode, "fork"
        )
        self.assertEqual(gitops.detect(self.repo(None).root).mode, "fork")
        self.assertEqual(
            gitops.detect(self.repo(None, use_git=False).root).mode, "none"
        )

    def test_upstream_override(self) -> None:
        r = self.repo("git@github.com:me/eve-labs.git")
        self.assertEqual(gitops.detect(r.root, upstream="me/eve-labs").mode, "clone")

    def test_branch_name(self) -> None:
        r = self.repo(UP)
        st = gitops.detect(r.root)
        self.assertEqual(gitops.branch_name(st, "EVE 2!"), "analyze/eve-2")
        git(r.root, "branch", "analyze/eve-2")
        self.assertEqual(gitops.branch_name(st, "EVE 2!"), "analyze/eve-2-2")
        self.assertEqual(gitops.branch_name(st, "x", "mine"), "mine")
        git(r.root, "checkout", "-q", "-b", "local-work")
        st = gitops.detect(r.root)
        self.assertIsNone(gitops.branch_name(st, "eve2"))  # already off main
        fork = gitops.detect(self.repo("git@github.com:me/eve-labs.git").root)
        self.assertIsNone(gitops.branch_name(fork, "eve2"))


class CommitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.r = Repo(UP)
        self.addCleanup(self.r.cleanup)

    def test_commit_contains_only_analyze_edits(self) -> None:
        r = self.r
        # uncommitted local work (e.g. eve-localize) in the same file
        local = r.lab.read_text().replace('name="MGMT"', 'name="MY-MGMT"')
        r.lab.write_text(local)
        new = local.replace("nxosv9k-9300v-10.3.3.F", "nxosv9k-9300v-10.5.1.F")
        r.lab.write_text(new)
        st = gitops.detect(r.root)
        res = gitops.commit_changes(st, [(r.lab, _changes())], "chore(labs): test\n")
        self.assertEqual(res.committed, ["labs/mini.unl"])
        committed = git(r.root, "show", "HEAD:labs/mini.unl")
        self.assertIn("nxosv9k-9300v-10.5.1.F", committed)
        self.assertNotIn("MY-MGMT", committed)
        self.assertEqual(git(r.root, "log", "-1", "--format=%s"), "chore(labs): test")
        # the localize edit stays an unstaged change; nothing is staged
        self.assertEqual(git(r.root, "diff", "--cached", "--name-only"), "")
        self.assertIn("MY-MGMT", git(r.root, "diff"))
        self.assertNotIn("nxosv9k", git(r.root, "diff"))

    def test_head_differs_is_skipped(self) -> None:
        r = self.r
        stale = [Change("1", "leaf1", "image", "other", "x", NX)]
        res = gitops.commit_changes(gitops.detect(r.root), [(r.lab, stale)], "m\n")
        self.assertIsNone(res.sha)
        self.assertIn("labs/mini.unl", res.skipped)

    def test_untracked_lab_is_skipped(self) -> None:
        r = self.r
        extra = r.root / "labs" / "new.unl"
        extra.write_text(r.lab.read_text())
        res = gitops.commit_changes(gitops.detect(r.root), [(extra, _changes())], "m\n")
        self.assertEqual(res.skipped, {"labs/new.unl": "not tracked by git"})

    def test_switch_branch_keeps_working_tree(self) -> None:
        r = self.r
        r.lab.write_text(r.lab.read_text() + "<!-- x -->\n")
        st = gitops.detect(r.root)
        gitops.switch_branch(st, "analyze/eve2")
        self.assertEqual(git(r.root, "branch", "--show-current"), "analyze/eve2")
        self.assertIn("<!-- x -->", r.lab.read_text())


if __name__ == "__main__":
    unittest.main()
