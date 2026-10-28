"""Decoded configs of the real labs, read through ``evelab.common.unl`` + ``evelab.common.codec``.

Replaces the old ad-hoc ``/tmp/an/*.txt`` dumps (T21): every embedded config blob
(startup and configsets) of a real lab is decoded and returned as
``(header, text)`` sections, header ``----- [<scope>] <node id> <node name>``.
Read-only and cached per test process.
"""

from __future__ import annotations

import unittest
from functools import cache

from evelab.common.codec import decode_blob

from .labfiles import read_real, real_lab_paths

# old dump file name -> real lab stem
DUMP_STEMS = {
    "sdwan.txt": "vxlan_evpn_multi-site_sdwan_only",
    "bb.txt": "vxlan_evpn_multi-site_with_backbone",
    "junos.txt": "vxlan_evpn_multi-site_junos",
    "azure_asa_vpn.txt": "azure_asa_vpn",
    "lab1-ei-v01.txt": "lab1-ei-v01",
    "cisco_nexus_9000v_vpc_concept_lab.txt": "cisco_nexus_9000v_vpc_concept_lab",
}


@cache
def lab_sections(stem: str) -> tuple[tuple[str, str], ...]:
    """Decoded config blobs of ``labs/**/<stem>.unl`` (empty when absent)."""
    path = next((p for p in real_lab_paths() if p.stem == stem), None)
    if path is None:
        return ()
    lab = read_real(path)
    names = {n.id: n.name for n in lab.nodes()}
    out: list[tuple[str, str]] = []
    for blob in lab.config_blobs():
        decoded = decode_blob(blob.b64)
        if decoded is None or not decoded.text:
            continue
        node = blob.node_id or ""
        out.append((f"----- [{blob.scope}] {node} {names.get(node, '')}", decoded.text))
    return tuple(out)


def sections(name: str) -> list[tuple[str, str]]:
    """Sections for an old dump name (``"sdwan.txt"``) or a lab stem."""
    return list(lab_sections(DUMP_STEMS.get(name, name)))


def text(name: str) -> str:
    """All sections of a lab joined like the old dumps; skips the test if absent."""
    parts = sections(name)
    if not parts:
        raise unittest.SkipTest(f"real lab for {name} not present")
    return "".join(f"{header}\n{body}\n" for header, body in parts)
