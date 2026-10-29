#!/usr/bin/env bash
# store-b-setup.sh: turn store-b (Ubuntu 22.04) into the Cartio lab's on-site store (YAN-1670).
#
# Sets up both store types the collector can be pointed at, each reachable only from coll-b:
#   - PostgreSQL: database "cartio", role "cartio", listening on the lab address
#   - a folder on a file share: /srv/cartio/smb over SMB (share "cartio") and /srv/cartio/nfs over NFS
#
# Run as root on store-b once its address is set (labs/cartio/README.md). Passwords come from the
# environment (PG_PASSWORD, SMB_PASSWORD) or a prompt and are never written to this repository
# (ADR-0003). Safe to run again: it rewrites the access rules it manages, so only the current
# COLLECTOR_ADDR keeps access, and resets the two passwords.
set -euo pipefail

LISTEN_ADDR="${LISTEN_ADDR:-172.30.120.60}"
COLLECTOR_ADDR="${COLLECTOR_ADDR:-172.30.120.50}"
STORE_USER="${STORE_USER:-cartio}"
STORE_DB="${STORE_DB:-cartio}"
STORE_ROOT="${STORE_ROOT:-/srv/cartio}"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if [[ -z "${PG_PASSWORD:-}" ]]; then
  read -rsp "PostgreSQL password for ${STORE_USER}: " PG_PASSWORD
  echo
fi
if [[ -z "${SMB_PASSWORD:-}" ]]; then
  read -rsp "SMB password for ${STORE_USER}: " SMB_PASSWORD
  echo
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends postgresql samba nfs-kernel-server

# Local account that owns the share folders; it has no login shell.
if ! id "$STORE_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$STORE_USER"
fi
install -d -o "$STORE_USER" -g "$STORE_USER" -m 0770 "$STORE_ROOT/smb" "$STORE_ROOT/nfs"
store_uid="$(id -u "$STORE_USER")"
store_gid="$(id -g "$STORE_USER")"

#### PostgreSQL
pg_conf_dir="$(find /etc/postgresql -mindepth 2 -maxdepth 2 -type d -name main | sort -V | tail -n 1)"
cat >"$pg_conf_dir/conf.d/cartio.conf" <<EOF
# Cartio lab on-site store
listen_addresses = 'localhost,${LISTEN_ADDR}'
password_encryption = scram-sha-256
EOF
# The rule this script manages carries a marker, so a rerun replaces it instead of adding another.
hba="$pg_conf_dir/pg_hba.conf"
sed -i '/# cartio-store$/d' "$hba"
echo "host ${STORE_DB} ${STORE_USER} ${COLLECTOR_ADDR}/32 scram-sha-256 # cartio-store" >>"$hba"
systemctl restart postgresql

# The password reaches psql through the environment, not its command line, so ps can't show it.
export PG_PASSWORD
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -v role="$STORE_USER" -v db="$STORE_DB" <<'SQL'
\set pw `printenv PG_PASSWORD`
SELECT format('CREATE ROLE %I LOGIN', :'role')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
ALTER ROLE :"role" PASSWORD :'pw';
SELECT format('CREATE DATABASE %I OWNER %I', :'db', :'role')
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \gexec
SQL

#### SMB share
# The share lives in its own file, rewritten on every run and included once from smb.conf.
smb_conf=/etc/samba/smb.conf
include_line="include = /etc/samba/cartio.conf"
grep -qxF "$include_line" "$smb_conf" || printf '\n%s\n' "$include_line" >>"$smb_conf"
cat >/etc/samba/cartio.conf <<EOF
[cartio]
   comment = Cartio lab on-site store
   path = ${STORE_ROOT}/smb
   valid users = ${STORE_USER}
   hosts allow = ${COLLECTOR_ADDR}
   read only = no
   smb encrypt = required
   create mask = 0660
   directory mask = 0770
EOF
printf '%s\n%s\n' "$SMB_PASSWORD" "$SMB_PASSWORD" | smbpasswd -s -a "$STORE_USER"
smbpasswd -e "$STORE_USER" >/dev/null
testparm -s >/dev/null
systemctl restart smbd

#### NFS export
# Its own exports file, rewritten on every run.
install -d /etc/exports.d
echo "${STORE_ROOT}/nfs ${COLLECTOR_ADDR}(rw,sync,no_subtree_check,all_squash,anonuid=${store_uid},anongid=${store_gid})" \
  >/etc/exports.d/cartio.exports
exportfs -ra
systemctl enable --now nfs-server >/dev/null

echo
echo "store-b is ready for ${COLLECTOR_ADDR}:"
echo "  PostgreSQL  postgresql://${STORE_USER}@${LISTEN_ADDR}:5432/${STORE_DB}"
echo "  SMB         //${LISTEN_ADDR}/cartio (user ${STORE_USER})"
echo "  NFS         ${LISTEN_ADDR}:${STORE_ROOT}/nfs"
