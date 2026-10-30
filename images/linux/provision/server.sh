#!/usr/bin/env bash
# Server layer: system config, dev tools, AI CLIs, connectivity testing, monitoring.
#   server.sh <hostname>
# shellcheck source=images/linux/provision/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

readonly HOSTNAME_NEW="${1:-ubuntu-server}"
readonly NODE_MAJOR="${NODE_MAJOR:-24}"

base_system() {
  log "Base system"
  # cloud-init and snapd are purged in cleanup.sh: removing them here breaks DNS in the appliance.
  cat >/etc/apt/preferences.d/no-snapd <<'EOF'
Package: snapd
Pin: release *
Pin-Priority: -10
EOF
  apt-get update
  apt-get -y -o Dpkg::Options::=--force-confold dist-upgrade
  apt_install ca-certificates curl wget gnupg jq zstd xz-utils unzip zip \
    software-properties-common apt-transport-https sudo locales tzdata \
    openssh-server qemu-guest-agent bash-completion man-db less vim nano

  echo "$HOSTNAME_NEW" >/etc/hostname
  sed -i '/^127\.0\.1\.1/d' /etc/hosts
  echo "127.0.1.1 $HOSTNAME_NEW" >>/etc/hosts
}

networking() {
  log "Networking: DHCP on the first NIC (ens3) only"
  rm -f /etc/netplan/*.yaml
  cat >/etc/netplan/01-eve.yaml <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    ens3:
      dhcp4: true
      dhcp6: false
      optional: true
EOF
  chmod 0600 /etc/netplan/01-eve.yaml
  systemctl mask systemd-networkd-wait-online.service
}

user_and_ssh() {
  log "User $LAB_USER and SSH"
  # Ubuntu ships a legacy "admin" group (granted sudo in /etc/sudoers); reuse it as primary.
  if ! id "$LAB_USER" &>/dev/null; then
    if getent group "$LAB_USER" >/dev/null; then
      useradd -m -s /bin/bash -g "$LAB_USER" "$LAB_USER"
    else
      useradd -m -s /bin/bash -U "$LAB_USER"
    fi
  fi
  echo "$LAB_USER:$LAB_PASSWORD" | chpasswd
  usermod -aG sudo,adm "$LAB_USER"
  passwd -l root

  rm -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
  cat >/etc/ssh/sshd_config.d/01-eve-lab.conf <<'EOF'
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
  # Host keys are wiped by sysprep; regenerate on first start (cloud-init used to do this).
  install -d /etc/systemd/system/ssh.service.d
  cat >/etc/systemd/system/ssh.service.d/10-hostkeys.conf <<'EOF'
[Service]
ExecStartPre=
ExecStartPre=/usr/bin/ssh-keygen -A
ExecStartPre=/usr/sbin/sshd -t
EOF
  systemctl enable ssh.socket qemu-guest-agent || true
}

network_tools() {
  log "Connectivity testing and monitoring tools"
  echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
  echo "iperf3 iperf3/start_daemon boolean false" | debconf-set-selections
  apt_install \
    iproute2 iputils-ping iputils-tracepath iputils-arping net-tools ethtool \
    bridge-utils vlan ifenslave iptables nftables conntrack ipset \
    dnsutils bind9-host ldnsutils whois ipcalc sipcalc \
    traceroute tcptraceroute mtr-tiny fping hping3 nmap ncat netcat-openbsd socat \
    tcpdump tshark termshark ngrep netsniff-ng python3-scapy \
    iperf iperf3 nuttcp speedtest-cli curl httpie lftp tftp-hpa telnet openssl \
    lldpd frr frr-pythontools bird2 strongswan wireguard-tools openvpn \
    snmp freeradius-utils ldap-utils arp-scan nbtscan smbclient nfs-common \
    iftop nload bmon vnstat nethogs iptraf-ng \
    htop btop glances atop sysstat iotop-c lsof strace ltrace ncdu duf \
    lnav prometheus-node-exporter smartmontools pciutils usbutils dmidecode
  # Installed for use in labs, but off by default so idle nodes stay quiet.
  systemctl disable frr bird strongswan-starter openvpn prometheus-node-exporter 2>/dev/null || true
  systemctl enable lldpd sysstat vnstat
  usermod -aG wireshark "$LAB_USER"
}

dev_tools() {
  log "Dev tools (apt)"
  apt_install build-essential gdb make cmake ninja-build pkg-config autoconf automake libtool \
    git git-lfs tig shellcheck direnv tmux screen zsh fzf ripgrep fd-find bat tree rsync \
    neovim python3 python3-dev python3-pip python3-venv pipx \
    openjdk-21-jdk-headless sqlite3 postgresql-client mariadb-client redis-tools \
    libssl-dev libffi-dev zlib1g-dev
  ln -sf /usr/bin/batcat /usr/local/bin/bat
  ln -sf /usr/bin/fdfind /usr/local/bin/fd

  log "Third-party apt repos"
  add_apt_repo docker https://download.docker.com/linux/ubuntu/gpg \
    "https://download.docker.com/linux/ubuntu $CODENAME stable"
  add_apt_repo github-cli https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    "https://cli.github.com/packages stable main"
  add_apt_repo hashicorp https://apt.releases.hashicorp.com/gpg \
    "https://apt.releases.hashicorp.com $CODENAME main"
  add_apt_repo nodesource https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    "https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main"
  apt-get update
  apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
    gh terraform packer nodejs
  usermod -aG docker "$LAB_USER"

  log "Binary tools: go, kubectl, helm, k9s, yq, opentofu, uv"
  local v
  v="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
  rm -rf /usr/local/go
  curl -fsSL "https://go.dev/dl/${v}.linux-amd64.tar.gz" | tar -C /usr/local -xz
  # shellcheck disable=SC2016  # expanded at login, not now
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >/etc/profile.d/golang.sh

  v="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
  curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${v}/bin/linux/amd64/kubectl"
  chmod 0755 /usr/local/bin/kubectl

  v="$(gh_latest helm/helm)"
  curl -fsSL "https://get.helm.sh/helm-${v}-linux-amd64.tar.gz" |
    tar -xz -C /usr/local/bin --strip-components=1 linux-amd64/helm

  curl -fsSLo /tmp/k9s.deb https://github.com/derailed/k9s/releases/latest/download/k9s_linux_amd64.deb
  apt_install /tmp/k9s.deb

  curl -fsSLo /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
  chmod 0755 /usr/local/bin/yq

  v="$(gh_latest opentofu/opentofu)"
  curl -fsSLo /tmp/tofu.deb "https://github.com/opentofu/opentofu/releases/download/${v}/tofu_${v#v}_amd64.deb"
  apt_install /tmp/tofu.deb

  curl -fsSL https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh

  log "Global Python tools via uv (ansible)"
  export UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin UV_PYTHON_INSTALL_DIR=/opt/uv-python
  uv tool install --with ansible ansible-core
  uv tool install pre-commit

  log "Global npm tools (pnpm, AI CLIs)"
  npm install -g pnpm @openai/codex @google/gemini-cli opencode-ai
  npm cache clean --force

  log "Per-user toolchains for $LAB_USER (rustup, Claude Code)"
  as_user 'curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal -c rustfmt,clippy'
  as_user 'curl -fsSL https://claude.ai/install.sh | bash'
}

ai_tools() {
  log "aider (uv tool) and ollama (CPU build, no models)"
  export UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin UV_PYTHON_INSTALL_DIR=/opt/uv-python
  uv tool install --python 3.12 aider-chat

  # Lab nodes have no GPU: drop the CUDA/Vulkan runtimes, which are most of the download.
  curl -fsSL https://ollama.com/download/ollama-linux-amd64.tar.zst |
    zstd -d | tar -x -C /usr/local --exclude='lib/ollama/cuda_*' --exclude='lib/ollama/vulkan*'
  id ollama &>/dev/null || useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
  cat >/etc/systemd/system/ollama.service <<'EOF'
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl enable ollama
}

main() {
  ensure_network
  base_system
  networking
  user_and_ssh
  network_tools
  dev_tools
  ai_tools
  bash "$(dirname "${BASH_SOURCE[0]}")/manifest.sh" server
}

main
