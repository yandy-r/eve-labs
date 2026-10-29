# Cartio test lab

A safe network for developing and testing Cartio's collector and drivers (Linear YAN-1647). This
is **phase 2**: the ISP, site A, site B and an IPsec tunnel between the two FortiGates. Phase 3 adds
the deep-inspection and proxy runs, the on-site store and any real FortiSwitch or FortiAP.

Lab file: `cartio_test_lab.unl`. FortiGate configs: `cartio_test_lab_cfgs/2_fgt-a.txt` and
`cartio_test_lab_cfgs/7_fgt-b.txt` (paste them, EVE has no startup config for FortiGate). Every
other node boots its startup config.

## Nodes

| Node   | Image                                             | vCPU / RAM | What it exercises                                                                         |
| ------ | ------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| isp    | `vios-adventerprisek9-m.spa.159-3.m6`             | 1 / 1 GB   | Fake internet: eBGP AS 64500, NTP master, NAT to the management LAN                       |
| fgt-a  | `fortinet-FGT-v7-build3744`                       | 2 / 2 GB   | FortiGate driver (REST and SSH), OSPF, eBGP, IPsec, LLDP, deep inspection (phase 3)       |
| core-a | `c8000v-17.11.01a`                                | 1 / 4 GB   | IOS-XE driver, OSPF, CDP and LLDP, SNMPv3 authPriv only, passing checks                   |
| acc-a  | `viosl2-adventerprisek9-m.ssa.high_iron_20200929` | 1 / 1 GB   | Classic IOS driver, CDP and LLDP, failing checks (Telnet, v2c `public`, no NTP or syslog) |
| srv-a  | `eve-server-yr:latest` (docker)                   | 1 / 1 GB   | SNMP-only device (net-snmp with lldpd over AgentX), syslog server for the lab             |
| coll-a | `eve-server-yr:latest` (docker)                   | 2 / 4 GB   | Site A collector host; its only way out is through fgt-a                                  |
| fgt-b  | `fortinet-FGT-v7-build2463`                       | 2 / 2 GB   | Older FortiOS (drift), multi-VDOM (root and guest), IPsec, failing checks                 |
| rtr-b  | `c8000v-17.15.01a`                                | 1 / 4 GB   | Same model as core-a on a newer release (drift), OSPF and EIGRP, inconsistent NTP         |
| leg-b  | `vios-adventerprisek9-m.spa.159-3.m6`             | 1 / 1 GB   | EIGRP neighbor, old IOS release for the EoL check                                         |
| sw-b   | `viosl2-adventerprisek9-m.ssa.high_iron_20200929` | 1 / 1 GB   | Site B access switch, passing checks                                                      |
| srv-b  | `veos-4.30.0F`                                    | 1 / 2 GB   | Second SNMP-only device, a third vendor (Arista); LLDP transmit off, so one-sided link    |
| coll-b | `eve-server-yr:latest` (docker)                   | 2 / 4 GB   | Site B collector host, for two collectors producing one merged inventory                  |

About 27 GB of RAM in total.

## Addressing

| Segment                 | Subnet          | Addresses                             |
| ----------------------- | --------------- | ------------------------------------- |
| Management LAN (pnet0)  | DHCP            | isp Gi0/0                             |
| isp to fgt-a            | 198.51.100.0/30 | isp .1, fgt-a .2                      |
| isp to fgt-b            | 198.51.100.4/30 | isp .5, fgt-b .6                      |
| isp loopback (NTP)      | 198.51.100.254  | isp                                   |
| IPsec tunnel            | 172.30.254.0/30 | fgt-a .1, fgt-b .2                    |
| fgt-a to core-a         | 172.30.0.0/30   | fgt-a .1, core-a .2                   |
| Site A mgmt VLAN 10     | 172.30.10.0/24  | core-a .1, acc-a .11                  |
| Site A servers VLAN 20  | 172.30.20.0/24  | core-a .1, srv-a .21, coll-a .50      |
| fgt-b to rtr-b          | 172.30.100.0/30 | fgt-b .1, rtr-b .2                    |
| rtr-b to leg-b          | 172.30.100.4/30 | rtr-b .5, leg-b .6                    |
| Site B mgmt VLAN 110    | 172.30.110.0/24 | rtr-b .1, sw-b .11                    |
| Site B servers VLAN 120 | 172.30.120.0/24 | rtr-b .1, srv-b .21, coll-b .50       |
| Site B guest VLAN 130   | 172.30.130.0/24 | fgt-b port3 .1 (guest VDOM, isolated) |
| Loopbacks               | 172.30.255.0/24 | core-a .1, rtr-b .11, leg-b .12       |

Routing: OSPF area 0 inside each site (each FortiGate originates the default), EIGRP 100 between
rtr-b and leg-b with mutual redistribution on rtr-b, eBGP from each FortiGate to isp (AS 65010 and
65020 to AS 64500), and eBGP between the FortiGates over the IPsec tunnel. Site-to-site traffic
prefers the tunnel because its AS path is shorter than the one through isp. isp Gi0/3 is reserved
for a controller segment (203.0.113.0/24) in phase 3.

To reach the lab from a laptop or a dev controller on the management LAN, read isp's DHCP address
(`show ip interface brief` on isp) and add a route:

```bash
sudo ip route add 172.30.0.0/16 via <isp-address>
sudo ip route add 198.51.100.0/24 via <isp-address>
```

isp does not NAT traffic to the management LAN, so these flows stay untranslated in both directions.

The management LAN is assumed to be 10.100.51.0/24. On another EVE host, eve-localize moves the
bridge and label, but these values are written in device configs and need a manual edit: the
`NAT-OUT` ACL on isp, the `SNMP-RO` ACLs on core-a, rtr-b, leg-b and sw-b, and on both FortiGates
the `mgmt-lan` address, the API trusthosts and the `cartio-ro` admin's trusthosts.

## Bring-up

1. Start fgt-a, fgt-b, core-a and rtr-b first; they take a few minutes to boot. srv-b (vEOS) is
   also slow.
2. On each FortiGate, set the admin password at the console prompt, apply the VM license, then
   paste its file from `cartio_test_lab_cfgs/` section by section. fgt-b logs you out after it
   switches to multi-VDOM mode; log back in and continue with the next section.
3. On isp, core-a, acc-a, rtr-b, leg-b and sw-b, generate SSH keys once:
   `crypto key generate rsa modulus 2048`, then `write memory`.
4. Check the tunnel: `get vpn ipsec tunnel summary` and `get router info bgp summary` on either
   FortiGate.
5. Add the collector accounts below.
6. On coll-a and coll-b, install the Cartio collector from the cartio repository and enroll both
   with your dev controller.

## Collector accounts (after first boot)

Credentials stay in the password manager, never in this repository (ADR-0003). The startup configs
create the read-only profiles; add the accounts with values from the password manager:

```text
! core-a, rtr-b, leg-b (IOS-XE and IOS): privilege 5 runs show commands,
! including "show running-config view full"
username cartio-ro privilege 5 secret <from password manager>
snmp-server user cartio-snmp CARTIO-RO v3 auth sha <auth> priv aes 128 <priv>
! sw-b (vIOS-L2): SNMPv3 only
snmp-server user cartio-snmp CARTIO-RO v3 auth sha <auth> priv aes 128 <priv>
```

```text
# fgt-a (FortiOS): read-only SSH admin, API key, SNMPv3 user
config system admin
    edit "cartio-ro"
        set accprofile "cartio-ro"
        set password <from password manager>
        set trusthost1 172.30.20.0 255.255.255.0
        set trusthost2 10.100.51.0 255.255.255.0
        set trusthost3 172.30.120.0 255.255.255.0
    next
end
execute api-user generate-key cartio-ro-api
config system snmp user
    edit "cartio-snmp"
        set security-level auth-priv
        set auth-proto sha256
        set auth-pwd <auth>
        set priv-proto aes256
        set priv-pwd <priv>
        set notify-hosts 172.30.20.50
    next
end
```

```text
# fgt-b (FortiOS, multi-VDOM): the same, from the global context, with access to both VDOMs
config global
    config system admin
        edit "cartio-ro"
            set accprofile "cartio-ro"
            set vdom "root" "guest"
            set password <from password manager>
            set trusthost1 172.30.120.0 255.255.255.0
            set trusthost2 172.30.20.0 255.255.255.0
            set trusthost3 10.100.51.0 255.255.255.0
        next
    end
    execute api-user generate-key cartio-ro-api
    config system snmp user
        edit "cartio-snmp"
            set security-level auth-priv
            set auth-proto sha256
            set auth-pwd <auth>
            set priv-proto aes256
            set priv-pwd <priv>
            set notify-hosts 172.30.120.50
        next
    end
end
```

```bash
# srv-a (net-snmp): SNMPv3 SHA/AES user
svc stop snmpd
net-snmp-create-v3-user -ro -a SHA -A '<auth>' -x AES -X '<priv>' cartio-snmp
svc start snmpd
```

```text
! srv-b (vEOS): SNMPv3 SHA/AES user
snmp-server user cartio-snmp CARTIO-RO v3 auth sha <auth> priv aes <priv>
```

acc-a keeps only SNMPv2c with community `public` on purpose, for the failing checks.

## Deliberate findings

| Check (YAN-1665)    | Passing                    | Failing                                   |
| ------------------- | -------------------------- | ----------------------------------------- |
| Insecure management | core-a, rtr-b, leg-b, sw-b | acc-a (Telnet, v2c public), fgt-b (HTTP)  |
| NTP and syslog      | core-a, fgt-a, leg-b, sw-b | acc-a (neither), fgt-b (no syslog), rtr-b |
| SNMPv3 in use       | everything but acc-a       | acc-a                                     |
| Firmware drift      | -                          | core-a vs rtr-b (c8000v), fgt-a vs fgt-b  |
| EoL or EoS          | -                          | acc-a, isp, leg-b (old IOS)               |

rtr-b's NTP points at 192.0.2.123 while everything else uses isp (198.51.100.254), which is the
inconsistency. acc-a, isp and leg-b fail EoL only if the EoL data file lists their IOS releases.

## Test scenarios

- **Discovery (YAN-1660):** seed core-a from coll-a with scope 172.30.0.0/16; site B is found over
  the tunnel. isp, 198.51.100.0/24 and the management LAN show up as neighbors but stay out of
  scope.
- **Two collectors (YAN-1672):** give coll-a a scope that also covers rtr-b's loopback, so rtr-b
  and both FortiGates are seen by both collectors and must merge into one record each.
- **One-sided links (YAN-1663):** srv-b sends no LLDP to sw-b, and fgt-b receives LLDP from rtr-b
  but sends none.
- **Multi-VDOM (YAN-1657):** fgt-b's guest VDOM holds port3 and its own policy; nothing from it
  should appear in root's data or the reverse.

## To verify on first boot

- `show running-config view full` works for the privilege 5 user on core-a, rtr-b and leg-b.
- The `cartio-ro` admin profile can read the config backup over the REST API; FortiOS may need a
  wider profile for backups.
- srv-a answers the LLDP-MIB (`snmpwalk ... 1.0.8802.1.1.2`) once lldpd runs with `-x`.
- srv-b (vEOS) boots its startup config in EVE; if not, paste it from the node's startup config in
  the EVE UI and save it with `write memory`.
- EIGRP on leg-b learns the default route that rtr-b redistributes from OSPF.
