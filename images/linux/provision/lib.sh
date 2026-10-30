# shellcheck shell=bash
# Shared helpers for the provisioning scripts (run inside the guest via virt-customize).
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
# virt-customize runs commands with a minimal PATH that lacks /usr/local.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin"
readonly LAB_USER="admin"
# shellcheck disable=SC2034  # used by the scripts that source this file
readonly LAB_PASSWORD="admin123"
readonly KEYRINGS=/etc/apt/keyrings
# shellcheck disable=SC2034  # used by the scripts that source this file
CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
readonly CODENAME

log() { printf '\n--> %s\n' "$*"; }

# Fail on any unreachable repo instead of silently using stale/empty lists.
apt-get() {
  if [[ $1 == update ]]; then
    command apt-get update --error-on=any
  else
    command apt-get "$@"
  fi
}

apt_install() {
  apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold "$@"
}

# add_apt_repo <name> <key-url> <deb-line-without-signed-by...>
add_apt_repo() {
  local name="$1" key_url="$2"
  shift 2
  install -d -m 0755 "$KEYRINGS"
  local key
  key="$(mktemp)"
  curl -fsSL -o "$key" "$key_url"
  if grep -q 'BEGIN PGP' "$key"; then
    gpg --dearmor --yes -o "$KEYRINGS/$name.gpg" "$key"
  else
    install -m 0644 "$key" "$KEYRINGS/$name.gpg"
  fi
  rm -f "$key"
  chmod 0644 "$KEYRINGS/$name.gpg"
  echo "deb [arch=amd64 signed-by=$KEYRINGS/$name.gpg] $*" >"/etc/apt/sources.list.d/$name.list"
}

# Latest release tag of a GitHub repo (e.g. "v1.2.3").
gh_latest() {
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" | jq -r .tag_name
}

# The libguestfs appliance only gets an address via dhclient, which the EVE host lacks
# (it falls back to dhcpcd, which leaves eth0 down). Configure QEMU's user-mode network
# statically, and point DNS at it until the calling script exits.
ensure_network() {
  if ! ip route | grep -q '^default'; then
    ip link set eth0 up
    ip addr add 169.254.2.15/16 dev eth0
    ip route add default via 169.254.2.2
  fi
  # virt-customize moves the resolv.conf symlink aside during a run and restores it after,
  # so only the temporary file needs removing.
  if ! getent hosts archive.ubuntu.com >/dev/null; then
    rm -f /etc/resolv.conf
    echo "nameserver 169.254.2.3" >/etc/resolv.conf
    trap 'rm -f /etc/resolv.conf' EXIT
  fi
  getent hosts archive.ubuntu.com >/dev/null
}

as_user() {
  sudo -u "$LAB_USER" -H bash -lc "$*"
}
