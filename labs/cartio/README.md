# Cartio test lab

A safe network for developing and testing Cartio's collector and drivers (Linear YAN-1647). This
is **phase 1**: the ISP and site A. Phase 2 adds site B and an IPsec tunnel; phase 3 adds the
deep-inspection and proxy runs, the on-site store and any real FortiSwitch or FortiAP.

Lab file: `cartio_test_lab.unl`. FortiGate config: `cartio_test_lab_cfgs/2_fgt-a.txt` (paste it,
EVE has no startup config for FortiGate). Every other node boots its startup config.

## Nodes

| Node   | Image                                             | vCPU / RAM | What it exercises                                                                         |
| ------ | ------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| isp    | `vios-adventerprisek9-m.spa.159-3.m6`             | 1 / 1 GB   | Fake internet: eBGP AS 64500, NTP master, NAT to the management LAN                       |
| fgt-a  | `fortinet-FGT-v7-build3744`                       | 2 / 2 GB   | FortiGate driver (REST and SSH), OSPF, eBGP, LLDP, deep inspection (phase 3)              |
| core-a | `c8000v-17.11.01a`                                | 1 / 4 GB   | IOS-XE driver, OSPF, CDP and LLDP, SNMPv3 authPriv only, passing checks                   |
| acc-a  | `viosl2-adventerprisek9-m.ssa.high_iron_20200929` | 1 / 1 GB   | Classic IOS driver, CDP and LLDP, failing checks (Telnet, v2c `public`, no NTP or syslog) |
| srv-a  | `eve-server-yr:latest` (docker)                   | 1 / 1 GB   | SNMP-only device (net-snmp with lldpd over AgentX), syslog server for site A              |
| coll-a | `eve-server-yr:latest` (docker)                   | 2 / 4 GB   | Site A collector host; its only way out is through fgt-a                                  |

About 13 GB of RAM in total.

## Addressing

| Segment                | Subnet          | Addresses                        |
| ---------------------- | --------------- | -------------------------------- |
| Management LAN (pnet0) | DHCP            | isp Gi0/0                        |
| isp to fgt-a           | 198.51.100.0/30 | isp .1, fgt-a .2                 |
| isp loopback (NTP)     | 198.51.100.254  | isp                              |
| fgt-a to core-a        | 172.30.0.0/30   | fgt-a .1, core-a .2              |
| Site A mgmt VLAN 10    | 172.30.10.0/24  | core-a .1, acc-a .11             |
| Site A servers VLAN 20 | 172.30.20.0/24  | core-a .1, srv-a .21, coll-a .50 |
| Loopbacks              | 172.30.255.0/24 | core-a .1                        |

Routing: OSPF area 0 between fgt-a and core-a (fgt-a originates the default), eBGP between fgt-a
(AS 65010) and isp (AS 64500). Phase 2 reserves isp Gi0/2 for fgt-b and Gi0/3 for a controller
segment (203.0.113.0/24).

To reach the lab from a laptop or a dev controller on the management LAN, read isp's DHCP address
(`show ip interface brief` on isp) and add a route:

```bash
sudo ip route add 172.30.0.0/16 via <isp-address>
sudo ip route add 198.51.100.0/24 via <isp-address>
```

isp does not NAT traffic to the management LAN, so these flows stay untranslated in both directions.

The management LAN is assumed to be 10.100.51.0/24. On another EVE host, eve-localize moves the
bridge and label, but these values are written in device configs and need a manual edit: the
`NAT-OUT` ACL on isp, the `SNMP-RO` ACL on core-a, and the `mgmt-lan` address and API trusthost on
fgt-a.

## Bring-up

1. Start fgt-a and core-a first; they take a few minutes to boot.
2. On fgt-a, set the admin password at the console prompt, apply the VM license, then paste
   `cartio_test_lab_cfgs/2_fgt-a.txt` section by section.
3. On core-a, generate SSH keys once: `crypto key generate rsa modulus 2048`, then `write memory`.
4. Add the collector accounts below.
5. On coll-a, install the Cartio collector from the cartio repository and enroll it with your dev
   controller.

## Collector accounts (after first boot)

Credentials stay in the password manager, never in this repository (ADR-0003). The startup configs
create the read-only profiles; add the accounts with values from the password manager:

```text
! core-a (IOS-XE): privilege 5 runs show commands, including "show running-config view full"
username cartio-ro privilege 5 secret <from password manager>
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

```bash
# srv-a (net-snmp): SNMPv3 SHA/AES user
svc stop snmpd
net-snmp-create-v3-user -ro -a SHA -A '<auth>' -x AES -X '<priv>' cartio-snmp
svc start snmpd
```

acc-a keeps only SNMPv2c with community `public` on purpose, for the failing checks.

## Deliberate findings

| Check (YAN-1665)    | Passing       | Failing                    |
| ------------------- | ------------- | -------------------------- |
| Insecure management | core-a        | acc-a (Telnet, v2c public) |
| NTP and syslog      | core-a, fgt-a | acc-a (neither set)        |
| SNMPv3 in use       | core-a        | acc-a                      |
| EoL or EoS          | -             | acc-a, isp (old IOS)       |

acc-a and isp fail EoL only if the EoL data file lists their IOS releases. Firmware drift needs a
second device of the same model, so it arrives with phase 2 (core-a on 17.11 against a c8000v on
17.15 at site B).

## To verify on first boot

- `show running-config view full` works for the privilege 5 user on core-a.
- The `cartio-ro` admin profile can read the config backup over the REST API; FortiOS may need a
  wider profile for backups.
- srv-a answers the LLDP-MIB (`snmpwalk ... 1.0.8802.1.1.2`) once lldpd runs with `-x`.
