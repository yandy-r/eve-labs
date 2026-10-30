# Linux lab images

Reproducible builds of the Ubuntu server and desktop QEMU images used in the labs. The images
themselves are not committed; rebuild them on the EVE host whenever the tools drift.

```bash
sudo images/linux/build.sh            # server + desktop
sudo images/linux/build.sh server     # just one
```

The script downloads the official Ubuntu cloud image, grows it to `DISK_SIZE` (thin qcow2), provisions it
offline with `virt-customize`, strips per-instance state with `virt-sysprep` and compresses it with
`virt-sparsify`. The output goes to `/opt/unetlab/addons/qemu/linux-ubuntu-<ver>-{server,desktop}/virtioa.qcow2`,
with a `MANIFEST.txt` that lists the tool versions. The existing image folders are not touched.

| Variable                           | Default                    | Purpose                      |
| ---------------------------------- | -------------------------- | ---------------------------- |
| `UBUNTU_VERSION`/`UBUNTU_CODENAME` | `24.04` / `noble`          | Base release                 |
| `DISK_SIZE`                        | `40G`                      | Virtual disk size (thin)     |
| `BUILD_DIR`                        | `/var/tmp/eve-image-build` | Scratch space (~30 GB)       |
| `NODE_MAJOR`                       | `24`                       | Node.js line from NodeSource |

Host requirements: `libguestfs-tools` (`virt-customize`, `virt-copy-out`, `virt-sysprep`, `virt-sparsify`)
and internet access.

## What's in the images

**Login:** `admin` / `admin123` with sudo. Root is locked and can't log in over SSH. SSH accepts passwords.
SSH host keys and `machine-id` are regenerated on first boot, so cloned nodes don't collide.

**Network:** DHCP on the first NIC (`ens3`) only. The remaining NICs are left for lab config.
cloud-init and snapd are removed.

**Dev:** build-essential, git/git-lfs/gh, Docker CE + compose/buildx, Python 3 + uv + pipx,
Node.js LTS + pnpm, Go, Rust (rustup, for `admin`), OpenJDK 21, kubectl, helm, k9s, terraform,
OpenTofu, packer, ansible, pre-commit, neovim, tmux, zsh, fzf, ripgrep, fd, bat, yq, jq,
database clients (psql, mariadb, redis-cli, sqlite3).

**AI clients (installed, not signed in):** Claude Code, Codex CLI, Gemini CLI, opencode, aider,
ollama (CPU only, no models). The desktop image also has the Claude Desktop and ChatGPT apps.

**Connectivity testing:** iperf/iperf3, nuttcp, mtr, traceroute/tcptraceroute, fping, hping3, nmap/ncat,
arp-scan, socat/netcat, tcpdump, tshark/termshark, ngrep, netsniff-ng, scapy, dig/ldns, httpie, curl,
speedtest-cli, lldpd, FRR, BIRD 2, strongSwan, WireGuard, OpenVPN, SNMP tools, radtest, ldap-utils,
smbclient, nfs-common.

**Monitoring:** htop, btop, glances, atop, sysstat, iotop-c, iftop, nload, bmon, vnstat, nethogs,
iptraf-ng, lnav, Prometheus node_exporter, qemu-guest-agent.

Services that are installed but **disabled** by default, so idle nodes stay quiet: frr, bird,
strongswan, openvpn, prometheus-node-exporter. Enable them per lab with `systemctl enable --now`.

**Desktop:** XFCE on LightDM, logging in automatically as `admin` on EVE's VNC console, with no
screen lock. Apps: Firefox (Mozilla apt), VS Code, Wireshark, Remmina, FileZilla, Meld, Claude Desktop,
ChatGPT. Claude Desktop is installed without its recommended QEMU packages, so Cowork is unavailable
inside the VM.

## EVE node settings

Use the `linux` template. Suggested sizing: server 2 vCPU / 4 GB, desktop 4 vCPU / 8 GB (the Electron
apps are heavy). Console `vnc`, NIC `virtio-net-pci`.
