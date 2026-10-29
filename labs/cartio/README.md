# Cartio test lab

A safe network for developing and testing Cartio's collector and drivers (Linear YAN-1647). This
is **phase 3**: the ISP, site A, site B, an IPsec tunnel between the two FortiGates, an in-lab
controller on a fake cloud segment, an on-site store at site B, and the ADR-0009 deep-inspection and
explicit-proxy runs. A real FortiSwitch or FortiAP is still to come; fgt-a port3 stays reserved for
one.

Lab file: `cartio_test_lab.unl`. FortiGate configs: `cartio_test_lab_cfgs/2_fgt-a.txt` and
`cartio_test_lab_cfgs/7_fgt-b.txt` (paste them, EVE has no startup config for FortiGate). Every
other node boots its startup config, except ctrl and store-b (Ubuntu VMs, set up after first boot).
Setup script for the store: `scripts/store-b-setup.sh`.

## Nodes

| Node    | Image                                             | vCPU / RAM | What it exercises                                                                         |
| ------- | ------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| isp     | `vios-adventerprisek9-m.spa.159-3.m6`             | 1 / 1 GB   | Fake internet: eBGP AS 64500, NTP master, NAT to the management LAN                       |
| fgt-a   | `fortinet-FGT-v7-build3744`                       | 2 / 2 GB   | FortiGate driver (REST and SSH), OSPF, eBGP, IPsec, LLDP, deep inspection, explicit proxy |
| core-a  | `c8000v-17.11.01a`                                | 1 / 4 GB   | IOS-XE driver, OSPF, CDP and LLDP, SNMPv3 authPriv only, passing checks                   |
| acc-a   | `viosl2-adventerprisek9-m.ssa.high_iron_20200929` | 1 / 1 GB   | Classic IOS driver, CDP and LLDP, failing checks (Telnet, v2c `public`, no NTP or syslog) |
| srv-a   | `eve-server-yr:latest` (docker)                   | 1 / 1 GB   | SNMP-only device (net-snmp with lldpd over AgentX), syslog server for the lab             |
| coll-a  | `eve-server-yr:latest` (docker)                   | 2 / 4 GB   | Site A collector host; its only way out is through fgt-a                                  |
| fgt-b   | `fortinet-FGT-v7-build2463`                       | 2 / 2 GB   | Older FortiOS (drift), multi-VDOM (root and guest), IPsec, failing checks                 |
| rtr-b   | `c8000v-17.15.01a`                                | 1 / 4 GB   | Same model as core-a on a newer release (drift), OSPF and EIGRP, inconsistent NTP         |
| leg-b   | `vios-adventerprisek9-m.spa.159-3.m6`             | 1 / 1 GB   | EIGRP neighbor, old IOS release for the EoL check                                         |
| sw-b    | `viosl2-adventerprisek9-m.ssa.high_iron_20200929` | 1 / 1 GB   | Site B access switch, passing checks                                                      |
| srv-b   | `veos-4.30.0F`                                    | 1 / 2 GB   | Second SNMP-only device, a third vendor (Arista); LLDP transmit off, so one-sided link    |
| coll-b  | `eve-server-yr:latest` (docker)                   | 2 / 4 GB   | Site B collector host, for two collectors producing one merged inventory                  |
| ctrl    | `linux-ubuntu-22.04.02-server`                    | 4 / 8 GB   | Dev controller on CLOUD, standing in for the hosted controller (ADR-0009 runs)            |
| store-b | `linux-ubuntu-22.04.02-server`                    | 2 / 4 GB   | On-site store for site B: PostgreSQL, an SMB share and an NFS export (YAN-1670)           |

About 39 GB of RAM in total.

## Addressing

| Segment                 | Subnet          | Addresses                                    |
| ----------------------- | --------------- | -------------------------------------------- |
| Management LAN (pnet0)  | DHCP            | isp Gi0/0                                    |
| isp to fgt-a            | 198.51.100.0/30 | isp .1, fgt-a .2                             |
| isp to fgt-b            | 198.51.100.4/30 | isp .5, fgt-b .6                             |
| isp loopback (NTP)      | 198.51.100.254  | isp                                          |
| IPsec tunnel            | 172.30.254.0/30 | fgt-a .1, fgt-b .2                           |
| fgt-a to core-a         | 172.30.0.0/30   | fgt-a .1, core-a .2                          |
| Site A mgmt VLAN 10     | 172.30.10.0/24  | core-a .1, acc-a .11                         |
| Site A servers VLAN 20  | 172.30.20.0/24  | core-a .1, srv-a .21, coll-a .50             |
| fgt-b to rtr-b          | 172.30.100.0/30 | fgt-b .1, rtr-b .2                           |
| rtr-b to leg-b          | 172.30.100.4/30 | rtr-b .5, leg-b .6                           |
| Site B mgmt VLAN 110    | 172.30.110.0/24 | rtr-b .1, sw-b .11                           |
| Site B servers VLAN 120 | 172.30.120.0/24 | rtr-b .1, srv-b .21, coll-b .50, store-b .60 |
| CLOUD (controller)      | 203.0.113.0/24  | isp .1, ctrl .10                             |
| Site B guest VLAN 130   | 172.30.130.0/24 | fgt-b port3 .1 (guest VDOM, isolated)        |
| Loopbacks               | 172.30.255.0/24 | core-a .1, rtr-b .11, leg-b .12              |

Routing: OSPF area 0 inside each site (each FortiGate originates the default), EIGRP 100 between
rtr-b and leg-b with mutual redistribution on rtr-b, eBGP from each FortiGate to isp (AS 65010 and
65020 to AS 64500), and eBGP between the FortiGates over the IPsec tunnel. Site-to-site traffic
prefers the tunnel because its AS path is shorter than the one through isp. isp advertises CLOUD
(203.0.113.0/24) to both FortiGates, so each collector reaches ctrl through its own site's FortiGate,
the way it would reach the hosted controller.

To reach the lab from a laptop or a dev controller on the management LAN, read isp's DHCP address
(`show ip interface brief` on isp) and add a route:

```bash
sudo ip route add 172.30.0.0/16 via <isp-address>
sudo ip route add 198.51.100.0/24 via <isp-address>
sudo ip route add 203.0.113.0/24 via <isp-address>
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
6. Set up ctrl and store-b (below).
7. On coll-a and coll-b, install the Cartio collector from the cartio repository and enroll both
   with the controller on ctrl, or with a dev controller on your workstation.

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

## ctrl and store-b (after first boot)

Both are Ubuntu 22.04 VMs with no startup config. Log in on the VNC console with the image's own
account, give each its address, then do the rest over SSH from the EVE host or your laptop (with the
routes above):

```bash
# ctrl console: find the NIC name with "ip -br link", then
sudo ip addr add 203.0.113.10/24 dev <nic> && sudo ip route add default via 203.0.113.1
# store-b console
sudo ip addr add 172.30.120.60/24 dev <nic> && sudo ip route add default via 172.30.120.1
```

Make the address permanent with netplan (a static address, gateway as above, DNS 1.1.1.1), and set
the hostname to `ctrl` or `store-b` so LLDP and logs read well.

**ctrl.** Install the Genius controller from the cartio repository, following its own install
steps, and serve it on 203.0.113.10:443. Give it a certificate from a lab CA that coll-a, coll-b and
fgt-a trust, with `IP:203.0.113.10` in its subject alternative names, since collectors enroll by
address. Collectors at both sites then enroll against `https://203.0.113.10`.

**store-b.** Copy the setup script over and run it. It asks for the PostgreSQL and SMB passwords
(take them from the password manager) and allows only coll-b (172.30.120.50) to connect:

```bash
scp labs/cartio/scripts/store-b-setup.sh <user>@172.30.120.60:
ssh -t <user>@172.30.120.60 sudo ./store-b-setup.sh
```

It ends by printing the three store addresses to give the site B collector at onboarding:
PostgreSQL `cartio@172.30.120.60:5432/cartio`, SMB `//172.30.120.60/cartio` and NFS
`172.30.120.60:/srv/cartio/nfs`.

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
- **On-site store (YAN-1670):** onboard a test customer as On site with site B's collector. Start a
  capture on ctrl first (`tcpdump -i <nic> -w ctrl-onsite.pcap host 172.30.120.50`) and leave it
  running while you run a job once with the PostgreSQL store and once with the folder store (SMB,
  then NFS). Then stop the capture and inspect it and ctrl's database. The network data and
  credentials should be on store-b only; ctrl should hold collector health and job status and
  nothing more.

## Transport runs (ADR-0009)

CI already covers mitmproxy as a proxy and as a TLS inspector; these are the one-off runs against a
real FortiGate. coll-b to ctrl through fgt-b is the uninspected baseline throughout.

Before run 2, import the lab CA that signed ctrl's certificate into fgt-a as a trusted CA (System >
Certificates > Import > CA Certificate). Without it fgt-a can't validate ctrl and re-signs with
`Fortinet_CA_Untrusted` instead of `Fortinet_CA_SSL`, so run 3 would still fail.

Run each step from coll-a and note what the collector reports about its path:

1. **Direct, uninspected.** Policy `coll-a-deep-inspection` disabled (as shipped). The collector
   connects and reports a direct path.
2. **Deep inspection, FortiGate CA not trusted.** On fgt-a, `config firewall policy`, `edit 1`,
   `set status enable`. The collector should fail with a clear certificate error, not hang.
3. **Deep inspection, CA trusted.** Download `Fortinet_CA_SSL` from fgt-a (System > Certificates),
   then on coll-a copy it to `/usr/local/share/ca-certificates/fgt-a-ca.crt` and run
   `update-ca-certificates`. The collector should work and report that its path is inspected (the
   pinned server key no longer matches).
4. **Require uninspected path.** Turn on the customer's "Require uninspected path" setting with
   step 3 still in place. The collector should refuse to send and say why. Turn the setting and
   policy 1 off again afterwards.
5. **Explicit proxy, no auth.** Point coll-a's collector at `http://172.30.0.1:8080` (its proxy
   setting or `HTTPS_PROXY`). It should connect through proxy policy `coll-a-explicit-proxy`, and ctrl
   should see fgt-a's WAN address (198.51.100.2) instead of 172.30.20.50.
6. **Explicit proxy, basic auth.** Add the proxy account on fgt-a with a password from the password
   manager, then give the collector the same user and password:

   ```text
   config user local
       edit "cartio-proxy"
           set type password
           set passwd <from password manager>
       next
   end
   config user group
       edit "cartio-proxy-users"
           set member "cartio-proxy"
       next
   end
   config firewall proxy-policy
       edit 1
           set groups "cartio-proxy-users"
       next
   end
   ```

   With a wrong password the collector should report a proxy authentication error.

7. **Proxy and deep inspection together.** On proxy policy 1, `set utm-status enable` and
   `set ssl-ssh-profile "deep-inspection"`. With the CA from step 3 trusted, the collector should
   work and report both the proxy and the inspection.

## Fixture captures

Record these during the runs above, sanitize them with the cartio repository's fixture tooling and
commit them there:

- Packet captures on coll-a (`tcpdump -i eth0 -w <run>.pcap host 203.0.113.10 or host 172.30.0.1`)
  for runs 1, 3, 5 and 7.
- The certificate chain the collector sees in each mode, from coll-a:
  `openssl s_client -connect 203.0.113.10:443 -showcerts </dev/null` for runs 1 and 3, and with
  `-proxy 172.30.0.1:8080` added for run 5. Run 7 keeps run 6's basic auth, so add the proxy
  account too, with the password read into the environment instead of typed on the command line:
  `read -rs CARTIO_PROXY_PASS && export CARTIO_PROXY_PASS`, then add
  `-proxy_user cartio-proxy -proxy_pass env:CARTIO_PROXY_PASS`.
- fgt-a's forward traffic and proxy logs for the same runs (`execute log filter category 0`, then
  `execute log display`).

## To verify on first boot

- `show running-config view full` works for the privilege 5 user on core-a, rtr-b and leg-b.
- The `cartio-ro` admin profile can read the config backup over the REST API; FortiOS may need a
  wider profile for backups.
- srv-a answers the LLDP-MIB (`snmpwalk ... 1.0.8802.1.1.2`) once lldpd runs with `-x`.
- srv-b (vEOS) boots its startup config in EVE; if not, paste it from the node's startup config in
  the EVE UI and save it with `write memory`.
- EIGRP on leg-b learns the default route that rtr-b redistributes from OSPF.
- fgt-a (FortiOS 7.6) takes the explicit proxy section as written: `web-proxy explicit`, the
  authentication scheme and rule, and a `proxy-policy` with no source interface.
- The Ubuntu image brings up its NIC and SSH server on first boot; if it ships a netplan file with
  DHCP, remove it before adding the static one.
- PostgreSQL on store-b picks up `conf.d/cartio.conf` (Ubuntu's `postgresql.conf` includes `conf.d`
  by default) and listens on 172.30.120.60.
