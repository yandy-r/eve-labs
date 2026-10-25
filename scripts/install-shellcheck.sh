#!/usr/bin/env bash
# Download pinned shellcheck from GitHub releases into repo-local tools/ (gitignored).
# Idempotent. Version is provided by scripts/lib/shellcheck-version.sh.
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/shellcheck-version.sh
source "$SCRIPT_DIR/lib/shellcheck-version.sh"

VERSION="$(shellcheck_pinned_version)"
if [ -z "$VERSION" ]; then
  echo "install-shellcheck: could not resolve shellcheck version" >&2
  exit 1
fi

DEST="${ROOT}/tools/shellcheck"
mkdir -p "${ROOT}/tools"

if [ -x "$DEST" ]; then
  cur="$("$DEST" --version 2>/dev/null | grep -E '^version:' | head -n1 | awk '{print $2}')"
  if [ "$cur" = "$VERSION" ]; then
    echo "shellcheck ${VERSION} already installed at ${DEST}"
    exit 0
  fi
fi

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) echo "install-shellcheck: unsupported OS: ${OS}" >&2; exit 1 ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) echo "install-shellcheck: unsupported architecture: ${ARCH}" >&2; exit 1 ;;
esac

TAG="v${VERSION}"
NAME="shellcheck-${TAG}.${OS}.${ARCH}"
URL="https://github.com/koalaman/shellcheck/releases/download/${TAG}/${NAME}.tar.xz"

TMPDIR="${TMPDIR:-/tmp}"
TMP="${TMPDIR}/shellcheck-install.$$"
cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP"

echo "Downloading ${URL} ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "${TMP}/archive.tar.xz"
elif command -v wget >/dev/null 2>&1; then
  wget -q "$URL" -O "${TMP}/archive.tar.xz"
else
  echo "install-shellcheck: need curl or wget" >&2
  exit 1
fi

(
  cd "$TMP" || exit 1
  xz -dc "${TMP}/archive.tar.xz" | tar -xf -
)

BIN=""
for candidate in "$TMP/shellcheck" "$TMP/shellcheck-${TAG}/shellcheck"; do
  if [ -f "$candidate" ]; then
    BIN="$candidate"
    break
  fi
done
if [ -z "$BIN" ]; then
  BIN="$(find "$TMP" -name shellcheck -type f 2>/dev/null | head -n1)"
fi
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
  echo "install-shellcheck: could not find shellcheck binary in archive" >&2
  exit 1
fi

cp "$BIN" "$DEST"
chmod +x "$DEST"
echo "Installed shellcheck ${VERSION} at ${DEST}"
