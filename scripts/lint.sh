#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_PATH" ]]; do
  SCRIPT_BASE_DIR="$(cd -P "$(dirname "$SCRIPT_PATH")" >/dev/null 2>&1 && pwd)"
  SCRIPT_PATH="$(readlink "$SCRIPT_PATH")"

  if [[ "$SCRIPT_PATH" != /* ]]; then
    SCRIPT_PATH="${SCRIPT_BASE_DIR}/${SCRIPT_PATH}"
  fi
done
SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_PATH")" >/dev/null 2>&1 && pwd)"

exec "$SCRIPT_DIR/style.sh" lint "$@"
