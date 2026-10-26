#!/usr/bin/env bash
# Restore EVE-NG ownership/modes on the labs tree only (lighter than
# `unl_wrapper -a fixpermissions`, which walks all of /opt/unetlab).
# Run on host `eve` as root after git pull/checkout/merge/rebase.
#
# Usage: scripts/fix-lab-permissions.sh [--dry-run] [LABS_DIR]
#   LABS_DIR defaults to the repo root (i.e. /opt/unetlab/labs on the host).
#   .git/ and node_modules/ are skipped so git keeps working as the invoking user.
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OWNER="${EVE_LAB_OWNER:-www-data:www-data}"
DIR_MODE="2775"
FILE_MODE="664"
SCRIPT_MODE="775"

DRY_RUN=0
LABS_DIR="$ROOT"
for arg in "$@"; do
  case "$arg" in
  -n | --dry-run) DRY_RUN=1 ;;
  -h | --help)
    sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  -*)
    echo "fix-lab-permissions: unknown option: $arg" >&2
    exit 2
    ;;
  *) LABS_DIR="$arg" ;;
  esac
done

if [ ! -d "$LABS_DIR" ]; then
  echo "fix-lab-permissions: not a directory: $LABS_DIR" >&2
  exit 1
fi
if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  echo "fix-lab-permissions: must run as root (try: sudo $0 $*)" >&2
  exit 1
fi
if ! id -u "${OWNER%%:*}" >/dev/null 2>&1; then
  echo "fix-lab-permissions: user ${OWNER%%:*} not found (is this the EVE host?)" >&2
  exit 1
fi

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '+ %s\n' "$*"
  else
    "$@"
  fi
}

# Everything under LABS_DIR except git internals and dev tooling.
prune=(\( -path "$LABS_DIR/.git" -o -path "$LABS_DIR/node_modules" \) -prune -o)

echo "Fixing EVE lab permissions in $LABS_DIR (owner $OWNER)"
run find "$LABS_DIR" "${prune[@]}" -exec chown "$OWNER" {} +
run find "$LABS_DIR" "${prune[@]}" -type d -exec chmod "$DIR_MODE" {} +
run find "$LABS_DIR" "${prune[@]}" -type f ! -name '*.sh' ! -name '*.py' -exec chmod "$FILE_MODE" {} +
run find "$LABS_DIR" "${prune[@]}" -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod "$SCRIPT_MODE" {} +
echo "Done."
