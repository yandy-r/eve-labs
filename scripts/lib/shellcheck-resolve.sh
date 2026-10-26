# shellcheck shell=bash
# Resolve which shellcheck binary to run and warn when it differs from the pinned helper.
# Call after PROJECT_ROOT or REPO_ROOT is set. Defines:
#   resolve_shellcheck_bin  -> sets SHELLCHECK_BIN, returns 0 on success
#
# If scripts/lib/shellcheck-version.sh is missing, read_shellcheck_pinned_version
# succeeds with no output; version comparison is skipped unless a pin is present.
#
# When SHELLCHECK_RESOLVE_OPTIONAL is non-empty and no shellcheck binary is found,
# resolve_shellcheck_bin returns 1 without printing the "Missing required command" message
# (for optional checks that print their own skip message).
#
# Preference order: <repo>/tools/shellcheck, $HOME/.local/bin/shellcheck, then PATH.

read_shellcheck_pinned_version() {
  local root="$1"
  local helper="${root}/scripts/lib/shellcheck-version.sh"
  if [[ ! -f "$helper" ]]; then
    return 0
  fi
  local v
  # shellcheck disable=SC1090
  source "$helper"
  if ! declare -F shellcheck_pinned_version >/dev/null 2>&1; then
    return 0
  fi
  v="$(shellcheck_pinned_version)"
  if [[ -z "$v" ]]; then
    return 0
  fi
  printf '%s\n' "$v"
}

shellcheck_repo_root() {
  if [[ -n "${REPO_ROOT:-}" ]]; then
    printf '%s\n' "$REPO_ROOT"
  elif [[ -n "${PROJECT_ROOT:-}" ]]; then
    printf '%s\n' "$PROJECT_ROOT"
  else
    echo "shellcheck-resolve: set REPO_ROOT or PROJECT_ROOT" >&2
    return 1
  fi
}

shellcheck_binary_version() {
  local bin="$1"
  "$bin" --version 2>/dev/null | grep -E '^version:' | head -n1 | awk '{print $2}'
}

resolve_shellcheck_bin() {
  local root want_ver chosen ver
  SHELLCHECK_BIN=""

  root="$(shellcheck_repo_root)" || return 1
  want_ver="$(read_shellcheck_pinned_version "$root")"

  for chosen in "${root}/tools/shellcheck" "${HOME}/.local/bin/shellcheck"; do
    if [[ -n "$chosen" && -x "$chosen" ]]; then
      SHELLCHECK_BIN="$chosen"
      break
    fi
  done

  if [[ -z "$SHELLCHECK_BIN" ]] && command -v shellcheck >/dev/null 2>&1; then
    SHELLCHECK_BIN="$(command -v shellcheck)"
  fi

  if [[ -z "$SHELLCHECK_BIN" ]]; then
    if [[ -z "${SHELLCHECK_RESOLVE_OPTIONAL:-}" ]]; then
      echo "Missing required command: shellcheck (install via scripts/install-shellcheck.sh)" >&2
    fi
    return 1
  fi

  ver="$(shellcheck_binary_version "$SHELLCHECK_BIN")"
  if [[ -n "$want_ver" && -n "$ver" && "$ver" != "$want_ver" ]]; then
    echo "warn: using system shellcheck ${ver}; pinned version is ${want_ver} (install via scripts/install-shellcheck.sh)" >&2
  fi

  return 0
}
