#!/usr/bin/env bash
# Build EVE-NG Ubuntu lab images (server + desktop) from the official cloud image.
#
#   sudo images/linux/build.sh [server|desktop|all]
#
# The server image is built first; the desktop image is the server image plus
# the desktop layer. Results land in $EVE_QEMU_DIR/linux-ubuntu-<ver>-{server,desktop}.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly PROVISION_DIR="$SCRIPT_DIR/provision"

readonly UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"
readonly UBUNTU_CODENAME="${UBUNTU_CODENAME:-noble}"
readonly DISK_SIZE="${DISK_SIZE:-40G}"
readonly BUILD_DIR="${BUILD_DIR:-/var/tmp/eve-image-build}"
readonly EVE_QEMU_DIR="${EVE_QEMU_DIR:-/opt/unetlab/addons/qemu}"
readonly CLOUD_IMG_URL="https://cloud-images.ubuntu.com/${UBUNTU_CODENAME}/current/${UBUNTU_CODENAME}-server-cloudimg-amd64.img"

# libguestfs appliance sizing: package installs are much faster with more RAM/CPUs.
export LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}"
export LIBGUESTFS_MEMSIZE="${LIBGUESTFS_MEMSIZE:-8192}"
readonly APPLIANCE_SMP="${APPLIANCE_SMP:-8}"

log() { printf '\n==> %s\n' "$*"; }

customize() {
  local image="$1"
  shift
  virt-customize -a "$image" --smp "$APPLIANCE_SMP" --network \
    --copy-in "$PROVISION_DIR:/root" "$@"
}

copy_manifest() {
  virt-copy-out -a "$BUILD_DIR/$1.qcow2" /etc/lab-image-release "$BUILD_DIR"
  mv "$BUILD_DIR/lab-image-release" "$BUILD_DIR/$1.manifest"
}

fetch_base() {
  mkdir -p "$BUILD_DIR"
  local cloud_img="$BUILD_DIR/${UBUNTU_CODENAME}-cloudimg.img"
  log "Downloading $CLOUD_IMG_URL"
  curl -fL --time-cond "$cloud_img" -o "$cloud_img" "$CLOUD_IMG_URL"

  # Grow root in place: virt-resize renumbers the partitions (/boot is sda16 on noble), and the
  # GRUB core image in the BIOS boot partition still points at the old number, so it won't boot.
  log "Expanding root filesystem to $DISK_SIZE"
  qemu-img convert -O qcow2 "$cloud_img" "$BUILD_DIR/base.qcow2"
  qemu-img resize "$BUILD_DIR/base.qcow2" "$DISK_SIZE"
  virt-customize -a "$BUILD_DIR/base.qcow2" --no-network \
    --run-command 'growpart /dev/sda 1 && resize2fs /dev/sda1'
}

build_server() {
  fetch_base
  cp --sparse=always "$BUILD_DIR/base.qcow2" "$BUILD_DIR/server.qcow2"
  log "Provisioning server image"
  customize "$BUILD_DIR/server.qcow2" \
    --run-command "bash /root/provision/server.sh ubuntu-server"
  copy_manifest server
}

build_desktop() {
  [[ -f "$BUILD_DIR/server.qcow2" ]] || build_server
  cp --sparse=always "$BUILD_DIR/server.qcow2" "$BUILD_DIR/desktop.qcow2"
  log "Provisioning desktop image"
  customize "$BUILD_DIR/desktop.qcow2" \
    --run-command "bash /root/provision/desktop.sh ubuntu-desktop"
  copy_manifest desktop
}

# Strip per-instance state, compress, and install into EVE's image folder.
finalize() {
  local flavor="$1"
  local src="$BUILD_DIR/${flavor}.qcow2"
  local dest_dir="$EVE_QEMU_DIR/linux-ubuntu-${UBUNTU_VERSION}-${flavor}"

  log "Sysprep + sparsify ($flavor)"
  customize "$src" --run-command "bash /root/provision/cleanup.sh"
  virt-sysprep -a "$src" \
    --operations machine-id,ssh-hostkeys,logfiles,bash-history,tmp-files,dhcp-client-state,package-manager-cache,net-hwaddr
  virt-sparsify --compress "$src" "$BUILD_DIR/${flavor}-final.qcow2"

  log "Installing to $dest_dir"
  mkdir -p "$dest_dir"
  mv "$BUILD_DIR/${flavor}-final.qcow2" "$dest_dir/virtioa.qcow2"
  cp "$BUILD_DIR/${flavor}.manifest" "$dest_dir/MANIFEST.txt"
  if [[ -x /opt/unetlab/wrappers/unl_wrapper ]]; then
    /opt/unetlab/wrappers/unl_wrapper -a fixpermissions
  fi
  qemu-img info "$dest_dir/virtioa.qcow2" | grep -E 'virtual size|disk size'
}

main() {
  [[ $EUID -eq 0 ]] || {
    echo "run as root" >&2
    exit 1
  }
  local target="${1:-all}"
  case "$target" in
    # One command per line: `a && b` would disable set -e inside a and b.
    server)
      build_server
      finalize server
      ;;
    desktop)
      build_desktop
      finalize desktop
      ;;
    all)
      build_server
      build_desktop
      finalize server
      finalize desktop
      ;;
    *)
      echo "usage: $0 [server|desktop|all]" >&2
      exit 2
      ;;
  esac
}

main "$@"
