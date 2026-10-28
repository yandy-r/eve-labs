"""Cached discovery runs shared by test_l2trace / test_segments (read-only).

Discovery of the backbone lab takes a few seconds; each real lab and minilab is
analysed once per test process.  Results must not be mutated by tests.
"""

from __future__ import annotations

from functools import cache

from evelab.localize.discover import AnalyseOptions, Discovery, discover

from .labfiles import minilab, no_cloud_lab_stems, read_real, real_lab_paths

SDWAN = "vxlan_evpn_multi-site_sdwan_only"
BACKBONE = "vxlan_evpn_multi-site_with_backbone"
JUNOS = "vxlan_evpn_multi-site_junos"
AZURE = "azure_asa_vpn"
LAB1 = "lab1-ei-v01"
NEXUS_VPC = "cisco_nexus_9000v_vpc_concept_lab"
CCIE_EI = "ccie_enterprise_infrastructure_practice_lab"
# derived from the tree (labs without cloud networks), not a hand-kept list
NO_CLOUD = no_cloud_lab_stems()


def real_path(stem: str):
    for path in real_lab_paths():
        if path.stem == stem:
            return path
    return None


@cache
def real(stem: str) -> Discovery | None:
    """Discovery of the real lab ``labs/**/<stem>.unl`` (None when absent)."""
    path = real_path(stem)
    if path is None:
        return None
    return discover(read_real(path))


@cache
def mini(stem: str, include_outliers: bool = False) -> Discovery:
    return discover(
        minilab(stem), None, AnalyseOptions(include_outliers=include_outliers)
    )
