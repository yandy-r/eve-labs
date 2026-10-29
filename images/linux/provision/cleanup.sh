#!/usr/bin/env bash
# Final cleanup before sysprep/sparsify: drop caches and the provisioning scripts.
# shellcheck source=images/linux/provision/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# cloud-init needs a datasource EVE doesn't provide; snapd is unused and heavy.
# Purged last: removing them earlier breaks DNS inside the build appliance.
apt-get purge -y cloud-init snapd
apt-get autoremove -y --purge
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache /root/.npm \
  "/home/$LAB_USER/.cache" "/home/$LAB_USER/.npm" "/home/$LAB_USER/.rustup/downloads" \
  "/home/$LAB_USER/.rustup/tmp"
journalctl --vacuum-time=1s 2>/dev/null || true
rm -rf /root/provision
fstrim -av 2>/dev/null || true
