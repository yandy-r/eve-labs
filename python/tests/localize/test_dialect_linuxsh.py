"""linuxsh + vpcs dialects (T11): real docker/VPCS configs and sidecars."""

from __future__ import annotations

import unittest

from evelab.localize import dialects

from .labfiles import REPO
from .t11_real import configs_with_template
from .test_dialect_contract import DialectContractMixin, make_ct

SIDECARS = REPO / "labs/datacenter/cisco/vxlan_evpn_multi-site_with_backbone_dmvpn_cfgs"


def parse(name: str, text: str):
    return dialects.get(name).parse(make_ct(text, name))


class TestLinuxShContract(DialectContractMixin, unittest.TestCase):
    dialect_name = "linuxsh"
    require_snippets = True
    require_rule_coverage = True


class TestVpcsContract(DialectContractMixin, unittest.TestCase):
    dialect_name = "vpcs"
    require_snippets = True
    require_rule_coverage = True


class TestLinuxShRealLabs(unittest.TestCase):
    def setUp(self) -> None:
        self.texts = [rt for rt in configs_with_template("docker") if rt.text.strip()]

    def test_every_docker_config_is_linuxsh_with_address_and_gateway(self) -> None:
        self.assertGreaterEqual(len(self.texts), 40)
        d = dialects.get("linuxsh")
        for rt in self.texts:
            with self.subTest(lab=rt.lab.name, node=rt.ident):
                self.assertEqual(dialects.pick(rt.node, rt.text).name, "linuxsh")
                pc = d.parse(rt.ct("linuxsh"))
                hosts = [f for f in pc.facts if f.kind == "ip_host" and f.iface]
                self.assertEqual(len(hosts), 1, [f.value for f in hosts])
                self.assertEqual(hosts[0].iface, "eth0")
                self.assertIsNotNone(hosts[0].mask_span)
                self.assertEqual(
                    len([f for f in pc.facts if f.kind == "ip_gateway"]), 1
                )
                self.assertEqual(pc.ifaces["eth0"].mode, "routed")
                self.assertFalse([f for f in pc.facts if f.kind == "vlan_tag"])

    def test_linux_sidecars_by_content(self) -> None:
        files = [
            p
            for p in sorted(SIDECARS.glob("*.txt"))
            if p.read_text(encoding="utf-8").startswith("cat << EOF")
        ]
        self.assertGreaterEqual(len(files), 20)
        for p in files:
            text = p.read_text(encoding="utf-8")
            with self.subTest(sidecar=p.name):
                self.assertEqual(dialects.pick(None, text).name, "linuxsh")
                pc = parse("linuxsh", text)
                kinds = {f.kind for f in pc.facts}
                self.assertLessEqual(
                    {"dns_server", "search_list", "ip_host", "ip_gateway"}, kinds
                )

    def test_resolv_heredoc_variants(self) -> None:
        for head in ("cat << EOF > /etc/resolv.conf", "cat > /etc/resolv.conf << EOF"):
            pc = parse(
                "linuxsh", f"{head}\nnameserver 10.3.70.1\ndomain lab.local\nEOF\n"
            )
            self.assertEqual(
                [(f.kind, f.value) for f in pc.facts],
                [("dns_server", "10.3.70.1"), ("domain", "lab.local")],
            )

    def test_hosts_lines_only_inside_hosts_heredoc(self) -> None:
        pc = parse("linuxsh", "169.1.100.16 dc2-srv16\n")
        self.assertEqual(pc.facts, [])


class TestVpcsRealLabs(unittest.TestCase):
    def test_vpcs_nodes(self) -> None:
        texts = list(configs_with_template("vpcs"))
        self.assertGreaterEqual(len(texts), 4)
        d = dialects.get("vpcs")
        with_ip = 0
        for rt in texts:
            with self.subTest(node=rt.ident):
                pc = d.parse(rt.ct("vpcs"))
                if rt.text.strip() == "ff":  # lab1 VPC: garbage blob, no facts
                    self.assertEqual(pc.facts, [])
                    continue
                if "ip " in rt.text:
                    with_ip += 1
                    self.assertEqual(dialects.pick(rt.node, rt.text).name, "vpcs")
                    host = next(f for f in pc.facts if f.kind == "ip_host")
                    self.assertEqual(host.iface, "eth0")
                    self.assertEqual(pc.ifaces["eth0"].mode, "routed")
        self.assertGreaterEqual(with_ip, 3)

    def test_vpcs_is_not_linuxsh(self) -> None:
        text = "ip 10.3.80.100/24 10.3.80.1\n"
        self.assertEqual(dialects.pick(None, text).name, "vpcs")
        self.assertEqual(parse("linuxsh", text).facts, [])


if __name__ == "__main__":
    unittest.main()
