"""Compare one lab with a :class:`~evelab.analyze.host.HostInventory`.

The result is a :class:`LabReport`: *questions* (a node attribute this host
can satisfy differently: image, QEMU build, CPU, RAM) and *findings* (things
only the user can fix: a missing template, no KVM, a missing cloud bridge).

A question covers every node of the lab that shares the same current value, and
its id (``image/qemu/nxosv9k/nxosv9k-9300v-10.3.3.F``) is the same in every lab,
so one answer serves the whole repository.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from evelab.common import hostenv
from evelab.common.findings import Finding
from evelab.common.unl import RawLab, RawNode

from .host import HostInventory
from .versions import candidates, newest, version_key

__all__ = ["KEEP", "Choice", "LabReport", "Question", "analyse_lab"]

KEEP = "keep"
QuestionKind = Literal["image", "qemu_version", "cpu", "ram"]
FILE_IMAGES = ("qemu", "iol", "dynamips", "docker")


@dataclass(frozen=True)
class Choice:
    value: str
    note: str = ""


@dataclass
class Question:
    """One substitution to offer. ``recommended`` ``None`` means keep."""

    id: str
    kind: QuestionKind
    attr: str
    current: str
    choices: list[Choice]
    recommended: str | None
    required: bool  # the current value cannot work on this host
    reason: str
    nodes: list[tuple[str, str]] = field(default_factory=list)  # (id, name)
    # ``cpu``/``ram``: any integer in this range is accepted, not just choices
    int_range: tuple[int, int] | None = None

    def validate(self, value: str) -> str | None:
        """Error message for an answer, ``None`` when acceptable."""
        if value in (KEEP, self.current):
            return None
        if any(c.value == value for c in self.choices):
            return None
        if self.int_range is not None:
            lo, hi = self.int_range
            if value.isdigit() and lo <= int(value) <= hi:
                return None
            return f"expected a number from {lo} to {hi}"
        return "not one of: " + ", ".join(c.value for c in self.choices)

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "attr": self.attr,
            "current": self.current,
            "choices": [{"value": c.value, "note": c.note} for c in self.choices],
            "recommended": self.recommended,
            "required": self.required,
            "reason": self.reason,
            "nodes": [{"id": i, "name": n} for i, n in self.nodes],
        }


@dataclass
class LabReport:
    path: Path
    rel: str
    lab: RawLab
    questions: list[Question]
    findings: list[Finding]

    def node(self, node_id: str) -> RawNode:
        return next(n for n in self.lab.nodes() if n.id == node_id)


def _warn(code: str, msg: str, refs: Sequence[str] = ()) -> Finding:
    return Finding(code, "warn", msg, list(refs))


def _info(code: str, msg: str, refs: Sequence[str] = ()) -> Finding:
    return Finding(code, "info", msg, list(refs))


def _names(nodes: Sequence[RawNode]) -> str:
    shown = ", ".join(n.name for n in nodes[:6])
    return shown + (f" +{len(nodes) - 6}" if len(nodes) > 6 else "")


class _Builder:
    def __init__(
        self, rep: LabReport, inv: HostInventory, latest: bool, root: Path | None
    ) -> None:
        self.rep = rep
        self.inv = inv
        self.latest = latest
        self.root = root
        self.questions: dict[str, Question] = {}

    def add(self, q: Question, node: RawNode) -> None:
        have = self.questions.setdefault(q.id, q)
        have.nodes.append((node.id, node.name))

    # ------------------------------------------------------------- images

    def images(self, nodes: Sequence[RawNode]) -> None:
        groups: dict[tuple[str, str, str], list[RawNode]] = {}
        for n in nodes:
            t = n.elem.get("type")
            if t in FILE_IMAGES:
                key = (t, n.elem.get("template"), n.elem.get("image"))
                groups.setdefault(key, []).append(n)
        for (ntype, template, image), members in groups.items():
            host = self.inv.images(ntype)
            if host is None:
                if ntype == "docker":
                    self.rep.findings.append(
                        _info(
                            "DOCKER_UNKNOWN",
                            f"docker is not available here: cannot check "
                            f"{image or '(no image)'} ({_names(members)})",
                        )
                    )
                continue
            present = bool(image) and image in host
            if ntype == "docker" and not present and ":" not in image:
                present = f"{image}:latest" in host
            cands = candidates(ntype, template, image, host)
            qid = f"image/{ntype}/{template}/{image or '-'}"
            if not present:
                if not cands:
                    self.rep.findings.append(self._no_image(ntype, image, members))
                    continue
                best = newest(cands)
                for n in members:
                    self.add(
                        Question(
                            id=qid,
                            kind="image",
                            attr="image",
                            current=image,
                            choices=[Choice(c.image, c.note) for c in cands],
                            recommended=best.image if best else None,
                            required=True,
                            reason=(
                                f"{ntype} image {image!r} is not on this host"
                                if image
                                else f"{ntype} node has no image set"
                            ),
                        ),
                        n,
                    )
                continue
            upgrades = [c for c in cands if c.newer]
            if upgrades:
                for n in members:
                    self.add(
                        Question(
                            id=qid,
                            kind="image",
                            attr="image",
                            current=image,
                            choices=[Choice(c.image, c.note) for c in upgrades],
                            recommended=upgrades[0].image if self.latest else None,
                            required=False,
                            reason=f"newer {template} image available on this host",
                        ),
                        n,
                    )

    def _no_image(self, ntype: str, image: str, members: Sequence[RawNode]) -> Finding:
        where = {
            "qemu": "/opt/unetlab/addons/qemu/<template>-<version>/",
            "iol": "/opt/unetlab/addons/iol/bin/",
            "dynamips": "/opt/unetlab/addons/dynamips/",
        }.get(ntype, "")
        hint = f"; install it under {where}" if where else ""
        if ntype == "docker":
            repo = image.partition(":")[0]
            df = self.root / "docker" / repo / "Dockerfile" if self.root else None
            if df is not None and df.is_file():
                hint = f"; build it: docker build -t {image} docker/{repo}"
            else:
                hint = f"; pull or build {image}"
        return _warn(
            "IMAGE_MISSING",
            (
                f"{ntype} image {image} is not on this host"
                if image
                else f"{ntype} node has no image set"
            )
            + f" and no image of the same family is ({_names(members)}){hint}",
            [f"node:{n.id}" for n in members],
        )

    # ------------------------------------------------------------- qemu build

    def qemu_versions(self, nodes: Sequence[RawNode]) -> None:
        have = self.inv.qemu_versions
        if not have:
            return
        for n in nodes:
            cur = n.elem.get("qemu_version")
            if n.elem.get("type") != "qemu" or not cur or cur in have:
                continue
            ck = version_key(cur)
            above = [v for v in have if version_key(v) >= ck]
            best = above[0] if above else have[-1]
            choices = [Choice(v, "closest" if v == best else "") for v in have]
            self.add(
                Question(
                    id=f"qemu_version/{cur}",
                    kind="qemu_version",
                    attr="qemu_version",
                    current=cur,
                    choices=choices,
                    recommended=best,
                    required=True,
                    reason=f"QEMU {cur} is not installed (/opt/qemu-{cur})",
                ),
                n,
            )

    # ------------------------------------------------------------- CPU / RAM

    def resources(self, nodes: Sequence[RawNode]) -> None:
        mem, cpus = self.inv.mem_mb, self.inv.cpus
        total = 0
        for n in nodes:
            ram = n.elem.get("ram")
            if ram.isdigit():
                total += int(ram)
                if mem and int(ram) > mem:
                    cap = max(512, int(mem * 0.75) // 1024 * 1024)
                    self.add(
                        Question(
                            id=f"ram/{ram}",
                            kind="ram",
                            attr="ram",
                            current=ram,
                            choices=[Choice(str(cap), "75% of host RAM")],
                            recommended=str(cap),
                            required=True,
                            reason=f"{ram} MB RAM is more than this host has "
                            f"({mem} MB)",
                            int_range=(64, mem),
                        ),
                        n,
                    )
            cpu = n.elem.get("cpu")
            if cpus and cpu.isdigit() and int(cpu) > cpus:
                self.add(
                    Question(
                        id=f"cpu/{cpu}",
                        kind="cpu",
                        attr="cpu",
                        current=cpu,
                        choices=[Choice(str(cpus), "all host CPUs")],
                        recommended=str(cpus),
                        required=True,
                        reason=f"{cpu} vCPUs is more than this host has ({cpus})",
                        int_range=(1, cpus),
                    ),
                    n,
                )
        if mem and total > mem:
            self.rep.findings.append(
                _info(
                    "LAB_RAM_EXCEEDS_HOST",
                    f"all nodes together ask for {total} MB RAM; this host has "
                    f"{mem} MB (start a subset, or rely on KSM/overcommit)",
                )
            )

    # ------------------------------------------------------------- report-only

    def host_features(self, nodes: Sequence[RawNode]) -> None:
        inv, f = self.inv, self.rep.findings
        types = {n.elem.get("type") for n in nodes}
        if inv.templates is not None:
            missing: dict[str, list[RawNode]] = {}
            for n in nodes:
                t, tpl = n.elem.get("type"), n.elem.get("template")
                if t in ("qemu", "iol", "dynamips") and tpl not in inv.templates:
                    missing.setdefault(tpl, []).append(n)
            for tpl, members in sorted(missing.items()):
                f.append(
                    _warn(
                        "TEMPLATE_MISSING",
                        f"node template {tpl!r} is not installed on this host "
                        f"({_names(members)}); EVE cannot open these nodes",
                        [f"node:{n.id}" for n in members],
                    )
                )
        if "qemu" in types and inv.kvm is False:
            f.append(
                _warn(
                    "KVM_MISSING",
                    "/dev/kvm is missing: QEMU nodes run without hardware "
                    "acceleration (enable nested virtualization / VT-x)",
                )
            )
        if "iol" in types and inv.iol_license is False:
            f.append(
                _warn(
                    "IOL_LICENSE_MISSING",
                    "no /opt/unetlab/addons/iol/bin/iourc: IOL nodes will not start",
                )
            )
        if inv.icons is not None:
            icons = set(inv.icons)
            gone = sorted({n.elem.get("icon") for n in nodes} - icons - {""})
            if gone:
                f.append(
                    _info(
                        "ICON_MISSING",
                        "icons not on this host (EVE shows a default): "
                        + ", ".join(gone),
                    )
                )

    def bridges(self) -> None:
        inv = self.inv
        if not inv.eve:
            return
        hint = f"remap with: ./scripts/eve-localize --lab {self.rep.rel}"
        seen: set[str] = set()
        for net in self.rep.lab.networks():
            name = net.get("type")
            if hostenv.bridge_kind(name) is None or name in seen:
                continue
            seen.add(name)
            state = inv.bridges.get(name, "missing")
            label = net.get("name")
            if state == "missing":
                self.rep.findings.append(
                    _warn(
                        "BRIDGE_NOT_ON_HOST",
                        f"cloud {name} ({label}) does not exist on this host; {hint}",
                        [f"bridge:{name}"],
                    )
                )
            elif state != "up":
                self.rep.findings.append(
                    _warn(
                        "BRIDGE_NO_CARRIER",
                        f"cloud {name} ({label}) is {state} on this host; nodes on "
                        f"it get no link; {hint}",
                        [f"bridge:{name}"],
                    )
                )


def analyse_lab(
    lab: RawLab,
    rel: str,
    inv: HostInventory,
    *,
    latest: bool = False,
    root: Path | None = None,
) -> LabReport:
    """Questions and findings for ``lab`` on the host described by ``inv``.

    ``latest`` recommends the newest same-variant image even when the lab's
    image is present. ``root`` (the repository) lets a missing docker image
    point at ``docker/<name>/Dockerfile``.
    """
    rep = LabReport(path=lab.path, rel=rel, lab=lab, questions=[], findings=[])
    b = _Builder(rep, inv, latest, root)
    nodes = lab.nodes()
    b.images(nodes)
    b.qemu_versions(nodes)
    b.resources(nodes)
    b.host_features(nodes)
    b.bridges()
    order = {"image": 0, "qemu_version": 1, "cpu": 2, "ram": 3}
    rep.questions = sorted(
        b.questions.values(), key=lambda q: (not q.required, order[q.kind], q.id)
    )
    return rep
