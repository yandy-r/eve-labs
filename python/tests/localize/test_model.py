"""Tests for the frozen contract in evelab.localize.model and evelab.localize.errors."""

import dataclasses
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from evelab import localize
from evelab.localize import errors
from evelab.localize.model import (
    CORE_FACT_KINDS,
    Analysis,
    Confidence,
    ConfigText,
    Edit,
    Fact,
    Finding,
    NameToken,
    Network,
    Node,
    Plan,
    Scheme,
    Segment,
    Span,
    Store,
    TextEdit,
)


def make_fact(**kw: object) -> Fact:
    base: dict[str, object] = {
        "id": "abc123def456",
        "kind": "vlan_tag",
        "value": "203",
        "store": Store("startup", "startup", "startup"),
        "node_id": "1",
        "span": Span(10, 13),
        "line": 4,
        "rule": "iosxe.encap_dot1q",
        "iface": "gi16.2",
        "parent": "gi16",
    }
    base.update(kw)
    return Fact(**base)  # type: ignore[arg-type]


def make_plan(findings: list[Finding]) -> Plan:
    return Plan(
        schema=localize.SCHEMA,
        lab=Path("labs/x.unl"),
        lab_id="L",
        base_sha256={},
        answers_digest="",
        edits=[],
        enabled_groups=set(),
        findings=findings,
    )


class PackageTests(unittest.TestCase):
    def test_version_and_schema(self) -> None:
        self.assertIsInstance(localize.__version__, str)
        self.assertEqual(localize.SCHEMA, 1)


class ConfidenceTests(unittest.TestCase):
    def test_ordering(self) -> None:
        self.assertLess(Confidence.HEURISTIC, Confidence.CORRELATED)
        self.assertLess(Confidence.CORRELATED, Confidence.PROVEN)
        self.assertEqual(
            max(Confidence.HEURISTIC, Confidence.PROVEN), Confidence.PROVEN
        )

    def test_values(self) -> None:
        self.assertEqual(
            [int(c) for c in Confidence],
            [1, 2, 3],
        )


class StoreSpanTests(unittest.TestCase):
    def test_store_is_tuple_and_hashable(self) -> None:
        s = Store("sidecar", "x_cfgs/01_r1.txt", "startup")
        kind, name, scope = s
        self.assertEqual(
            (kind, name, scope), ("sidecar", "x_cfgs/01_r1.txt", "startup")
        )
        self.assertEqual({s: 1}[Store("sidecar", "x_cfgs/01_r1.txt", "startup")], 1)

    def test_span_frozen(self) -> None:
        sp = Span(1, 2)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            sp.start = 5  # type: ignore[misc]
        self.assertEqual(hash(sp), hash(Span(1, 2)))
        self.assertEqual(sp, Span(1, 2))

    def test_name_token_frozen(self) -> None:
        tok = NameToken("203", Span(5, 8), "octet3", 203)
        self.assertEqual(tok.kind, "octet3")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            tok.value = 1  # type: ignore[misc]


class NetworkTests(unittest.TestCase):
    def test_is_cloud(self) -> None:
        self.assertFalse(Network("1", "bridge", "br", {}).is_cloud)
        for t in ("pnet0", "nat0", "cloud3", "weird"):
            self.assertTrue(Network("2", t, "n", {}).is_cloud, t)

    def test_name_never_decides(self) -> None:
        self.assertFalse(Network("1", "bridge", "pnet0", {}).is_cloud)


class FactTests(unittest.TestCase):
    def test_defaults(self) -> None:
        f = make_fact()
        self.assertIsNone(f.mask_span)
        self.assertEqual(f.mask_form, "none")
        self.assertIsNone(f.list_value)
        self.assertIsNone(f.group)
        self.assertIsNone(f.segment)
        self.assertIs(f.confidence, Confidence.HEURISTIC)
        self.assertEqual(f.evidence, "")
        self.assertFalse(f.orphan)
        self.assertEqual(f.flags, frozenset())

    def test_mutable_attribution(self) -> None:
        f = make_fact()
        f.segment = "MGMT-203"
        f.confidence = Confidence.PROVEN
        self.assertEqual(f.segment, "MGMT-203")

    def test_core_kinds(self) -> None:
        for kind in ("ip_host", "vlan_tag", "secret", "ipv6_literal", "cloud_ref"):
            self.assertIn(kind, CORE_FACT_KINDS)
        # 25 built-in kinds (24 from section 4 + log_server, T9); packs and
        # plugins may register more at runtime, so this is a lower bound.
        self.assertGreaterEqual(len(CORE_FACT_KINDS), 25)
        self.assertIn("log_server", CORE_FACT_KINDS)


class DefaultFactoryTests(unittest.TestCase):
    def test_segment_defaults_not_shared(self) -> None:
        def seg() -> Segment:
            return Segment(
                key="k",
                site_key="lab.k",
                role=None,
                network_ids=["1"],
                cloud_types={"pnet0"},
                labels={"1": "mgmt"},
                attachments=[],
                schemes=[],
                status="UNKNOWN",
            )

        a, b = seg(), seg()
        a.carries.append("x")
        a.notes.append("n")
        a.name_hints["1"] = []
        self.assertEqual((b.carries, b.notes, b.name_hints), ([], [], {}))

    def test_finding_refs_not_shared(self) -> None:
        a, b = Finding("X", "info", "m"), Finding("X", "info", "m")
        a.refs.append("r")
        self.assertEqual(b.refs, [])


class PlanTests(unittest.TestCase):
    def test_blocked(self) -> None:
        self.assertFalse(make_plan([]).blocked)
        self.assertFalse(
            make_plan([Finding("A", "info", "m"), Finding("B", "warn", "m")]).blocked
        )
        for sev in ("conflict", "blocker", "error"):
            plan = make_plan([Finding("A", "info", "m"), Finding("B", sev, "m")])  # type: ignore[arg-type]
            self.assertTrue(plan.blocked, sev)


class ConstructionTests(unittest.TestCase):
    def test_scheme_and_tag(self) -> None:
        s = Scheme(
            tag=203,
            subnet=IPv4Network("10.100.203.0/24"),
            gateway=IPv4Address("10.100.203.1"),
            scopes={"startup"},
            members=["f1"],
            outliers=[],
        )
        self.assertEqual(s.subnet.prefixlen if s.subnet else None, 24)
        self.assertEqual(Scheme("untagged", None, None, set(), [], []).tag, "untagged")

    def test_node_edit_config_text(self) -> None:
        node = Node("1", "R1", "iol", "iol", "i86bi", "0", [])
        ct = ConfigText(
            Store("startup", "startup", "startup"), node.id, "x", "ios", None, None
        )
        self.assertIsNone(ct.mirror_of)
        self.assertFalse(ct.opaque)
        te = TextEdit(0, 1, "a", "b")
        edit = Edit(
            id="e1",
            file=Path("x.unl"),
            target="blob",
            store=ct.store,
            node_id=node.id,
            text_edit=te,
            category="vlan",
            group="MGMT/vlan",
            confidence=Confidence.PROVEN,
            secret=False,
            provenance=["q", "f", "r", "ev"],
        )
        self.assertEqual(edit.text_edit.new, "b")

    def test_analysis_fields(self) -> None:
        names = [f.name for f in dataclasses.fields(Analysis)]
        self.assertEqual(
            names,
            [
                "lab",
                "nodes",
                "networks",
                "texts",
                "facts",
                "segments",
                "protected_vlans",
                "protected_prefixes",
                "active_scope",
                "findings",
                "pinned",
            ],
        )


class ErrorTests(unittest.TestCase):
    def test_hierarchy_and_codes(self) -> None:
        classes = [
            errors.LabParseError,
            errors.UnsupportedLayout,
            errors.PreconditionError,
            errors.BlockedError,
            errors.ConflictError,
            errors.ValidationError,
        ]
        codes = set()
        for cls in classes:
            self.assertTrue(issubclass(cls, errors.LocalizeError))
            self.assertIsInstance(cls.code, str)
            codes.add(cls.code)
        self.assertEqual(len(codes), len(classes))

    def test_message_code_override(self) -> None:
        e = errors.ConflictError("overlap", refs=["e1", "e2"])
        self.assertEqual(str(e), "overlap")
        self.assertEqual(e.code, "CONFLICT")
        self.assertEqual(e.refs, ["e1", "e2"])
        e2 = errors.ConflictError("x", code="SPLICE_OVERLAP")
        self.assertEqual(e2.code, "SPLICE_OVERLAP")
        self.assertEqual(errors.ConflictError.code, "CONFLICT")

    def test_exit_codes(self) -> None:
        self.assertEqual(errors.PreconditionError.exit_code, 4)
        self.assertEqual(errors.ValidationError.exit_code, 5)
        self.assertEqual(errors.BlockedError.exit_code, 2)
        self.assertEqual(errors.ConflictError.exit_code, 2)
        self.assertEqual(errors.LabParseError.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
