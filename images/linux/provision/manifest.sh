#!/usr/bin/env bash
# Write /etc/lab-image-release: build info and the versions of the headline tools.
#   manifest.sh <flavor>
# shellcheck source=images/linux/provision/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
set +e

ver() { LANG=C.UTF-8 "$@" 2>/dev/null | grep -v -i "^warning" | head -1; }
pkg() { dpkg-query -W -f='${Version}' "$1" 2>/dev/null; }

{
  echo "EVE lab image: ubuntu-$(sed -n 's/^VERSION_ID="\(.*\)"/\1/p' /etc/os-release)-$1"
  echo "Built: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "Login: $LAB_USER (sudo); DHCP on ens3"
  echo
  echo "kernel        $(find /boot -name 'vmlinuz-*' -printf '%f\n' | sed 's/^vmlinuz-//' | sort -V | tail -1)"
  echo "docker        $(pkg docker-ce)"
  echo "node          $(ver node --version)"
  echo "pnpm          $(ver pnpm --version)"
  echo "python        $(ver python3 --version)"
  echo "uv            $(ver uv --version)"
  echo "go            $(ver /usr/local/go/bin/go version)"
  echo "rust          $(ver sudo -u "$LAB_USER" -H bash -lc 'rustc --version')"
  echo "java          $(pkg openjdk-21-jdk-headless)"
  echo "gh            $(ver gh --version)"
  echo "terraform     $(ver terraform version)"
  echo "tofu          $(ver tofu version)"
  echo "packer        $(ver packer version)"
  echo "kubectl       $(ver kubectl version --client)"
  echo "helm          $(ver helm version --short)"
  echo "k9s           $(pkg k9s)"
  echo "ansible       $(ver ansible --version)"
  echo "claude-code   $(ver sudo -u "$LAB_USER" -H bash -lc 'claude --version')"
  echo "codex         $(ver codex --version)"
  echo "gemini        $(ver gemini --version)"
  echo "opencode      $(ver opencode --version)"
  echo "aider         $(ver aider --version)"
  echo "ollama        $(ver ollama --version)"
  echo "frr           $(pkg frr)"
  echo "bird          $(pkg bird2)"
  echo "tshark        $(pkg tshark)"
  echo "iperf3        $(pkg iperf3)"
  if [[ $1 == desktop ]]; then
    echo "firefox       $(pkg firefox)"
    echo "vscode        $(pkg code)"
    echo "claude-desk   $(pkg claude-desktop)"
    echo "chatgpt       $(dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | grep -i chatgpt)"
  fi
} >/etc/lab-image-release
cat /etc/lab-image-release
