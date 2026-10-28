"""Real-lab config texts for the T11 dialect tests (decoded via unl + codec).

Read-only: the real labs are parsed, never written.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from evelab.common.codec import decode_blob
from evelab.localize.model import ConfigText, Node, Store

from .labfiles import read_real, real_lab_paths


@dataclass(frozen=True)
class RealText:
    lab: Path
    kind: str  # "config" | "textobject"
    ident: str  # node id or textobject id
    scope: str
    node: Node | None
    text: str

    def ct(self, dialect: str) -> ConfigText:
        store = (
            Store("textobject", self.ident, "-")
            if self.kind == "textobject"
            else Store("startup", "startup", self.scope)
        )
        return ConfigText(
            store=store,
            node_id=None if self.kind == "textobject" else self.ident,
            text=self.text,
            dialect=dialect,
            blob=None,
            path=None,
        )


@cache
def real_texts() -> tuple[RealText, ...]:
    out: list[RealText] = []
    for path in real_lab_paths():
        lab = read_real(path)
        nodes = lab.node_models()
        for b in lab.config_blobs():
            d = decode_blob(b.b64) if not b.self_closing else None
            if d is not None:
                out.append(
                    RealText(
                        path, "config", b.node_id, b.scope, nodes.get(b.node_id), d.text
                    )
                )
        for b in lab.textobjects():
            d = decode_blob(b.b64) if not b.self_closing else None
            if d is not None:
                out.append(RealText(path, "textobject", b.id, "-", None, d.text))
    return tuple(out)


def configs_with_template(*templates: str) -> Iterator[RealText]:
    for rt in real_texts():
        if (
            rt.kind == "config"
            and rt.node is not None
            and rt.node.template in templates
        ):
            yield rt


def textobjects() -> Iterator[RealText]:
    return (rt for rt in real_texts() if rt.kind == "textobject")
