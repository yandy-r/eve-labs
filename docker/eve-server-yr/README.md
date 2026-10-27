# eve-server-yr

Headless, prod-like Ubuntu 24.04 server image for EVE-NG docker nodes. It's the image the
`*-srv*` and `*-pc*` nodes in `labs/datacenter/cisco/vxlan_evpn_multi-site_sdwan_only.unl` use.

## Build

On the EVE host. The host has no buildx, so use the legacy builder:

```bash
cd /opt/unetlab/labs/docker/eve-server-yr
DOCKER_BUILDKIT=0 docker build -t eve-server-yr:latest .
```

Back up the built image with `docker save eve-server-yr:latest | gzip > eve-server-yr.tar.gz`.

## Access

- Console: EVE telnet console (root shell).
- SSH: `root` / `eve` or `netops` / `eve` (sudo).

EVE's startup config (`resolv.conf`, `ip addr`, `/etc/hosts`) runs unchanged.

## Services

`eve-server-init` starts the services listed in `/etc/eve-server/services` (or in `$SERVICES`).
Manage them at runtime with `svc list` and `svc start|stop|restart <name>`.

| Name     | Default | Port         | Purpose                                     |
| -------- | ------- | ------------ | ------------------------------------------- |
| `ssh`    | on      | 22/tcp       | OpenSSH                                     |
| `nginx`  | on      | 80, 443/tcp  | `/health`, `/whoami`, `/files/` (1M-1G)     |
| `iperf3` | on      | 5201/tcp+udp | Throughput target                           |
| `lldpd`  | on      | —            | LLDP + CDP neighbor to the switch           |
| `snmpd`  | on      | 161/udp      | Read-only community `public`                |
| `tftp`   | on      | 69/udp       | `/srv/tftp` (writable, `1M.bin`, `10M.bin`) |
| `echo`   | on      | 7/tcp+udp    | socat echo                                  |
| `ftp`    | off     | 21/tcp       | vsftpd; anonymous is read-only              |
| `app`    | off     | 8080/tcp     | Python HTTP server on `/srv/app`            |
| `syslog` | off     | 514/udp      | Writes to `/var/log/remote-syslog.log`      |

## Tools

- Diagnostics: ping, fping, arping, traceroute, tcptraceroute, mtr, dig, whois, ethtool,
  ip, ss, conntrack, ipcalc, sipcalc
- Scanning and sockets: nmap, ncat, nc (openbsd), socat, hping3
- Capture and replay: tcpdump, tshark, tcpreplay, scapy
- Load: iperf3, iperf, ab, curl, wget
- Protocol clients: ssh, telnet, ftp, lftp, tftp, snmp
- Automation: `ansible-core`, netmiko, ncclient, paramiko, textfsm, ntc-templates and ttp.
  These live in `/opt/netops`. Installed collections: `ansible.netcommon`, `ansible.utils`,
  `ansible.posix`, `community.general`, `cisco.ios`, `cisco.iosxr`, `cisco.nxos`.

`install-tools.sh` is the single package list. The Dockerfile uses it, and it also
provisions an existing Ubuntu 24.04 docker node in place:

```bash
docker cp install-tools.sh <container>:/root/ && docker exec <container> bash /root/install-tools.sh
```
