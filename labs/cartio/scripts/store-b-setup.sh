#!/usr/bin/env bash
# store-b-setup.sh: turn store-b (Ubuntu 22.04) into the Cartio lab's on-site store (YAN-1670).
#
# Sets up both store types the collector can be pointed at, each reachable only from coll-b:
#   - PostgreSQL: database "cartio", role "cartio", listening on the lab address
#   - a folder on a file share: /srv/cartio/smb over SMB (share "cartio") and /srv/cartio/nfs over NFS
#
# Run as root on store-b once its address is set (labs/cartio/README.md). Passwords come from the
# environment (PG_PASSWORD, SMB_PASSWORD) or a prompt and are never written to this repository
# (ADR-0003). Safe to run again: it re-applies the config and resets the two passwords.
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
hba="$pg_conf_dir/pg_hba.conf"
hba_line="host ${STORE_DB} ${STORE_USER} ${COLLECTOR_ADDR}/32 scram-sha-256"
grep -qxF "$hba_line" "$hba" || echo "$hba_line" >>"$hba"
systemctl restart postgresql

runuser -u postgres -- psql -v ON_ERROR_STOP=1 -v role="$STORE_USER" -v db="$STORE_DB" \
  -v pw="$PG_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'role')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
ALTER ROLE :"role" PASSWORD :'pw';
SELECT format('CREATE DATABASE %I OWNER %I', :'db', :'role')
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \gexec
SQL

#### SMB share
smb_conf=/etc/samba/smb.conf
if ! grep -q '^\[cartio\]' "$smb_conf"; then
  cat >>"$smb_conf" <<EOF

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
fi
printf '%s\n%s\n' "$SMB_PASSWORD" "$SMB_PASSWORD" | smbpasswd -s -a "$STORE_USER"
smbpasswd -e "$STORE_USER" >/dev/null
testparm -s >/dev/null
systemctl restart smbd

#### NFS export
nfs_line="${STORE_ROOT}/nfs ${COLLECTOR_ADDR}(rw,sync,no_subtree_check,all_squash,anonuid=${store_uid},anongid=${store_gid})"
grep -qxF "$nfs_line" /etc/exports || echo "$nfs_line" >>/etc/exports
exportfs -ra
systemctl enable --now nfs-server >/dev/null

echo
echo "store-b is ready for ${COLLECTOR_ADDR}:"
echo "  PostgreSQL  postgresql://${STORE_USER}@${LISTEN_ADDR}:5432/${STORE_DB}"
echo "  SMB         //${LISTEN_ADDR}/cartio (user ${STORE_USER})"
echo "  NFS         ${LISTEN_ADDR}:${STORE_ROOT}/nfs"
