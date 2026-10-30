#!/usr/bin/env bash
# Desktop layer (on top of the server image): XFCE for EVE's VNC console plus GUI apps.
#   desktop.sh <hostname>
# shellcheck source=images/linux/provision/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

readonly HOSTNAME_NEW="${1:-ubuntu-desktop}"

xfce() {
  log "XFCE + LightDM (autologin $LAB_USER)"
  apt-get update
  apt_install xorg xserver-xorg-video-all dbus-x11 lightdm lightdm-gtk-greeter \
    xfce4 xfce4-terminal xfce4-whiskermenu-plugin xfce4-taskmanager xfce4-screenshooter \
    xfce4-notifyd xfce4-pulseaudio-plugin thunar-archive-plugin mousepad ristretto \
    gnome-keyring libsecret-1-0 seahorse adwaita-icon-theme-full elementary-xfce-icon-theme \
    fonts-dejavu fonts-liberation fonts-noto-color-emoji xdg-utils at-spi2-core

  install -d /etc/lightdm/lightdm.conf.d
  cat >/etc/lightdm/lightdm.conf.d/50-eve-lab.conf <<EOF
[Seat:*]
autologin-user=$LAB_USER
autologin-session=xfce
user-session=xfce
EOF
  groupadd -f autologin
  usermod -aG autologin "$LAB_USER"
  systemctl set-default graphical.target

  # No screen locking / blanking in a lab console.
  apt-get purge -y light-locker xfce4-screensaver 2>/dev/null || true
  install -d /etc/xdg/autostart
  cat >/etc/xdg/autostart/eve-no-blank.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Disable screen blanking
Exec=xset s off -dpms
EOF

  echo "$HOSTNAME_NEW" >/etc/hostname
  sed -i "s/^127\.0\.1\.1 .*/127.0.1.1 $HOSTNAME_NEW/" /etc/hosts
}

gui_apps() {
  log "GUI apps: Firefox, VS Code, Wireshark, Remmina"
  add_apt_repo mozilla https://packages.mozilla.org/apt/repo-signing-key.gpg \
    "https://packages.mozilla.org/apt mozilla main"
  cat >/etc/apt/preferences.d/mozilla <<'EOF'
Package: *
Pin: origin packages.mozilla.org
Pin-Priority: 1000
EOF
  echo "code code/add-microsoft-repo boolean false" | debconf-set-selections
  add_apt_repo vscode https://packages.microsoft.com/keys/microsoft.asc \
    "https://packages.microsoft.com/repos/code stable main"
  apt-get update
  apt_install firefox code wireshark remmina remmina-plugin-rdp remmina-plugin-vnc \
    filezilla meld gnome-calculator evince

  log "AI desktop apps: Claude Desktop, ChatGPT (not signed in)"
  # Anthropic's apt repo; recommends (QEMU/OVMF for Cowork) skipped to keep the image small.
  install -d -m 0755 /usr/share/keyrings
  curl -fsSLo /usr/share/keyrings/claude-desktop-archive-keyring.asc https://downloads.claude.ai/claude-desktop/key.asc
  gpg --show-keys /usr/share/keyrings/claude-desktop-archive-keyring.asc | grep -q 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/claude-desktop-archive-keyring.asc] https://downloads.claude.ai/claude-desktop/apt/stable stable main" \
    >/etc/apt/sources.list.d/claude-desktop.list
  apt-get update
  apt_install claude-desktop

  curl -fsSLo /tmp/chatgpt.deb https://persistent.oaistatic.com/codex-app-prod/linux/deb/latest/chatgpt_amd64.deb
  apt_install /tmp/chatgpt.deb
  rm -f /tmp/chatgpt.deb
}

main() {
  ensure_network
  xfce
  gui_apps
  bash "$(dirname "${BASH_SOURCE[0]}")/manifest.sh" desktop
}

main
