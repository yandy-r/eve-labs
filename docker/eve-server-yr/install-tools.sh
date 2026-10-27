#!/usr/bin/env bash
# Install the eve-server-yr toolset on Ubuntu 24.04.
# Used by the Dockerfile and to provision an already-running EVE docker node.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
NETOPS_VENV="${NETOPS_VENV:-/opt/netops}"

APT_PACKAGES=(
  # base system
  bash-completion ca-certificates curl wget less nano vim-tiny tmux htop procps psmisc
  lsof strace sudo git rsync jq unzip zip file tzdata locales iputils-ping iproute2
  # L2/L3 diagnostics
  arping bridge-utils dnsutils ethtool fping ipcalc iputils-tracepath lldpd mtr-tiny
  net-tools sipcalc tcptraceroute traceroute vlan whois isc-dhcp-client
  # scanning, sockets, capture, replay
  conntrack hping3 iptables ncat netcat-openbsd nftables nmap socat tcpdump tcpreplay tshark
  # traffic / load generation
  apache2-utils iperf iperf3
  # application protocols (clients + servers)
  ftp lftp nginx openssh-client openssh-server openssl snmp snmpd
  telnet tftp-hpa tftpd-hpa vsftpd
  # automation runtime
  python3 python3-venv python3-pip sshpass
)

PIP_PACKAGES=(
  ansible-core ansible-pylibssh jmespath netaddr jinja2 pyyaml requests
  netmiko ncclient paramiko scapy textfsm ntc-templates ttp
)

ANSIBLE_COLLECTIONS=(
  ansible.netcommon ansible.utils ansible.posix community.general
  cisco.ios cisco.iosxr cisco.nxos
)

# Skip packages whose role an existing package already fills (e.g. eve-gui-server nodes).
declare -A ALREADY_COVERED_BY=([mtr-tiny]=mtr [tftpd-hpa]=atftpd [vim-tiny]=vim)
packages=()
for pkg in "${APT_PACKAGES[@]}"; do
  covered="${ALREADY_COVERED_BY[$pkg]:-}"
  if [[ -n "$covered" ]] && dpkg -s "$covered" >/dev/null 2>&1; then
    continue
  fi
  packages+=("$pkg")
done

echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections

# Keep package postinst scripts from starting daemons; the entrypoint owns services.
printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
trap 'rm -f /usr/sbin/policy-rc.d' EXIT

apt-get update
apt-get install -y --no-install-recommends "${packages[@]}"

python3 -m venv "$NETOPS_VENV"
"$NETOPS_VENV/bin/pip" install --no-cache-dir --upgrade pip
"$NETOPS_VENV/bin/pip" install --no-cache-dir "${PIP_PACKAGES[@]}"
for bin in "$NETOPS_VENV"/bin/ansible* "$NETOPS_VENV"/bin/scapy; do
  ln -sf "$bin" "/usr/local/bin/$(basename "$bin")"
done

# Galaxy downloads are flaky; retry before failing the build.
for attempt in 1 2 3 4 5; do
  ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    "$NETOPS_VENV/bin/ansible-galaxy" collection install --timeout 120 \
    -p /usr/share/ansible/collections "${ANSIBLE_COLLECTIONS[@]}" && break
  [[ $attempt -eq 5 ]] && exit 1
  sleep $((attempt * 10))
done

apt-get clean
rm -rf /var/lib/apt/lists/* /root/.cache /tmp/*
