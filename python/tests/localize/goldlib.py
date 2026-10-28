"""Shared helpers for the golden acceptance suite (design section 14, items 7-8).

* :class:`Tree`: a temp repo-like tree holding copies of real labs, their
  ``*_cfgs`` sidecar dirs and their committed ``<stem>.localize.toml`` manifests;
  :meth:`Tree.run` drives :func:`evelab.localize.cli.main` with fake host probes (empty
  ``/proc``, EVE tmp dir and docker list; a fake ``/sys/class/net`` that has the
  site-B bridges), so the running EVE lab on this host never matters and the real
  labs are never written.
* :func:`golden_doc`: the per-lab discovery golden (``scan --json`` entry plus the
  protected inventory and look-alikes).
* ``UPDATE_GOLDEN=1`` makes the golden tests rewrite ``golden/<stem>.scan.json``.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from evelab.common.textutil import VlanList
from evelab.common.unl import RawLab
from evelab.localize import cli, manifest
from evelab.localize.discover import analyse
from evelab.localize.discover.inventory import lookalikes
from evelab.localize.model import Analysis

from .labfiles import REPO, real_lab_paths

GOLDEN = Path(__file__).resolve().parent / "golden"
UPDATE = os.environ.get("UPDATE_GOLDEN", "") not in ("", "0")

# Bridges the fake host offers (baseline + site B), all up.
SITE_BRIDGES = ("pnet0", "pnet2", "pnet4", "pnet5", "pnet6", "nat0", "nat1")


def real_stems() -> list[str]:
    """Stems of every tracked real lab (sorted by path)."""
    return [p.stem for p in real_lab_paths()]


def real_path(stem: str) -> Path:
    for path in real_lab_paths():
        if path.stem == stem:
            return path
    raise FileNotFoundError(stem)


def answers_path(stem: str) -> Path:
    return GOLDEN / f"{stem}.answers.toml"


def scan_path(stem: str) -> Path:
    return GOLDEN / f"{stem}.scan.json"


class Tree:
    """A temp repo-like tree with copies of some real labs (+ sidecars, manifests)."""

    def __init__(self, *stems: str) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="evelab-localize-golden-"))
        self.root = self.tmp / "repo"
        self.labs: dict[str, Path] = {}
        for stem in stems:
            src = real_path(stem)
            dest = self.root / src.relative_to(REPO)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            mpath = manifest.manifest_path_for(src)
            if mpath.is_file():
                shutil.copyfile(mpath, manifest.manifest_path_for(dest))
            for d in src.parent.iterdir():
                if d.is_dir() and d.name.startswith(stem) and d.name.endswith("_cfgs"):
                    shutil.copytree(d, dest.parent / d.name)
            self.labs[stem] = dest
        for name in ("proc", "unetlab_tmp", "sys_net"):
            (self.tmp / name).mkdir()
        for bridge in SITE_BRIDGES:
            d = self.tmp / "sys_net" / bridge
            (d / "bridge").mkdir(parents=True)
            (d / "flags").write_text("0x1003\n")
            (d / "operstate").write_text("up\n")

    def cleanup(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def lab_files(self, stem: str) -> dict[str, bytes]:
        """Bytes of the lab file and its sidecars (keyed by tree-relative path)."""
        lab = self.labs[stem]
        files = [lab]
        for d in lab.parent.iterdir():
            if d.is_dir() and d.name.startswith(stem) and d.name.endswith("_cfgs"):
                files.extend(p for p in d.rglob("*") if p.is_file())
        return {str(p.relative_to(self.root)): p.read_bytes() for p in sorted(files)}

    def analysis(self, stem: str) -> Analysis:
        path = self.labs[stem]
        return analyse(RawLab.read(path), manifest.find_for(path))

    def run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        rt = cli.Runtime(
            stdin=io.StringIO(""),
            stdout=out,
            stderr=err,
            env={"NO_COLOR": "1"},
            interactive=False,
            getpass_fn=lambda _prompt: "",
            proc=self.tmp / "proc",
            tmp_root=self.tmp / "unetlab_tmp",
            docker_names=list,
            sys_net=self.tmp / "sys_net",
            check_labs_peers=[],
        )
        code = cli.main([*argv, "--root", str(self.root), "--no-color"], rt)
        return code, out.getvalue(), err.getvalue()


def protected_doc(a: Analysis) -> dict[str, Any]:
    """Protected inventory + per-segment look-alikes (stable, JSON-ready)."""
    looks: dict[str, Any] = {}
    for seg in a.segments:
        facts = lookalikes(a.facts, seg)
        if facts:
            looks[seg.key] = {
                "count": len(facts),
                "values": sorted({f"{f.kind} {f.value}" for f in facts}),
            }
    return {
        "vlans": {
            scope: VlanList.from_vlans(v).render()
            for scope, v in sorted(a.protected_vlans.items())
            if v
        },
        "prefixes": sorted(str(p) for p in a.protected_prefixes),
        "lookalikes": looks,
    }


def golden_docs(tree: Tree) -> dict[str, dict[str, Any]]:
    """``{stem: golden doc}`` for every lab in ``tree`` (one ``scan --json`` run)."""
    code, out, err = tree.run("scan", "--json")
    if code != 0:
        raise AssertionError(f"scan --json exited {code}: {err}")
    docs: dict[str, dict[str, Any]] = {}
    for entry in json.loads(out)["labs"]:
        stem = Path(entry["lab"]).stem
        if stem not in tree.labs:
            continue
        doc = dict(entry)
        doc["protected"] = protected_doc(tree.analysis(stem))
        docs[stem] = doc
    return docs


def dumps(doc: object) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False, default=str) + "\n"
