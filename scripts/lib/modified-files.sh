#!/usr/bin/env bash

if [[ -n "${MODIFIED_FILES_SH_LOADED:-}" ]]; then
  return 0
fi
readonly MODIFIED_FILES_SH_LOADED=1

# Load the canonical well-known-path exclusion list (STYLE_EXCLUDES).
# shellcheck source=./excludes.sh
. "${BASH_SOURCE%/*}/excludes.sh"

resolve_script_path() {
  local source_path="$1"

  while [[ -L "$source_path" ]]; do
    local source_dir
    source_dir="$(cd -P "$(dirname "$source_path")" >/dev/null 2>&1 && pwd)"
    source_path="$(readlink "$source_path")"

    if [[ "$source_path" != /* ]]; then
      source_path="${source_dir}/${source_path}"
    fi
  done

  local resolved_dir
  resolved_dir="$(cd -P "$(dirname "$source_path")" >/dev/null 2>&1 && pwd)"
  printf '%s/%s\n' "$resolved_dir" "$(basename "$source_path")"
}

resolve_script_dir() {
  dirname "$(resolve_script_path "$1")"
}

canonicalize_dir() {
  local dir_path="$1"
  (cd "$dir_path" >/dev/null 2>&1 && pwd -P)
}

is_git_repo() {
  local root_dir="$1"
  git -C "$root_dir" rev-parse --show-toplevel >/dev/null 2>&1
}

detect_project_root() {
  if [[ -n "${PROJECT_ROOT:-}" ]]; then
    canonicalize_dir "$PROJECT_ROOT"
    return
  fi

  local start_dir="$PWD"
  if is_git_repo "$start_dir"; then
    git -C "$start_dir" rev-parse --show-toplevel
    return
  fi

  canonicalize_dir "$start_dir"
}

path_relative_to_root() {
  local root_dir="${1%/}"
  local path_value="${2%/}"

  if [[ "$path_value" == "$root_dir" ]]; then
    printf '\n'
    return 0
  fi

  if [[ "$path_value" == "$root_dir/"* ]]; then
    printf '%s\n' "${path_value#"$root_dir"/}"
    return 0
  fi

  return 1
}

list_scoped_repo_files() {
  local root_dir="${1:-$(detect_project_root)}"
  local scope="${2:-all}"

  if ! is_git_repo "$root_dir"; then
    return 0
  fi

  case "$scope" in
    all|staged|unstaged) ;;
    *)
      echo "list_scoped_repo_files: unknown scope '${scope}' (expected: all|staged|unstaged)" >&2
      return 1
      ;;
  esac

  (
    cd "$root_dir" || return
    case "$scope" in
      all)
        {
          git diff --name-only --diff-filter=ACMR
          git diff --cached --name-only --diff-filter=ACMR
          git ls-files --others --exclude-standard
        } | awk 'NF && !seen[$0]++'
        ;;
      staged)
        git diff --cached --name-only --diff-filter=ACMR | awk 'NF && !seen[$0]++'
        ;;
      unstaged)
        {
          git diff --name-only --diff-filter=ACMR
          git ls-files --others --exclude-standard
        } | awk 'NF && !seen[$0]++'
        ;;
    esac
  )
}

list_modified_repo_files() {
  local root_dir="${1:-$(detect_project_root)}"
  list_scoped_repo_files "$root_dir" all
}

list_repo_files() {
  local root_dir="${1:-$(detect_project_root)}"

  if is_git_repo "$root_dir"; then
    (
      cd "$root_dir" || return
      git ls-files --cached --others --exclude-standard | awk 'NF && !seen[$0]++'
    )
    return
  fi

  find "$root_dir" -type f ! -path '*/.git/*' -print |
    awk -v root_prefix="${root_dir%/}/" 'index($0, root_prefix) == 1 { print substr($0, length(root_prefix) + 1) }'
}

path_matches_filter() {
  local path_value="$1"
  local prefix="$2"
  shift 2

  [[ -n "$prefix" && "$path_value" != "$prefix"* ]] && return 1
  path_is_excluded "$path_value" && return 1

  if (( $# == 0 )); then
    return 0
  fi

  local suffix
  for suffix in "$@"; do
    if [[ "$path_value" == *"$suffix" ]]; then
      return 0
    fi
  done
  return 1
}

symlink_target_is_linted() {
  local root_dir="${1%/}"
  local link_rel="$2"
  local prefix="$3"
  shift 3

  local resolved_root resolved_target target_rel
  resolved_root="$(canonicalize_dir "$root_dir" 2>/dev/null)" || return 1
  [[ -e "$root_dir/$link_rel" ]] || return 1
  resolved_target="$(resolve_script_path "$root_dir/$link_rel" 2>/dev/null)" || return 1
  target_rel="$(path_relative_to_root "$resolved_root" "$resolved_target")" || return 1
  [[ -n "$target_rel" && ! -L "$root_dir/$target_rel" ]] || return 1

  is_git_repo "$root_dir" || return 1
  git -C "$root_dir" ls-files --error-unmatch -- ":(literal)$target_rel" >/dev/null 2>&1 || return 1

  path_matches_filter "$target_rel" "$prefix" "$@"
}

filter_repo_paths() {
  local root_dir="$1"
  local prefix="$2"
  shift 2

  local path_value
  while IFS= read -r path_value; do
    path_matches_filter "$path_value" "$prefix" "$@" || continue

    # Several tools (notably Prettier) reject explicitly named symlinks. Skip
    # silently only when the resolved target is a tracked repo path that this
    # same filter includes; otherwise warn on stderr so unlinted targets stay
    # visible while still keeping the symlink off the tool's argument list.
    if [[ -L "$root_dir/$path_value" ]]; then
      if ! symlink_target_is_linted "$root_dir" "$path_value" "$prefix" "$@"; then
        printf '[WARN] skipping symlink %s (target is not covered by this lint pass)\n' "$path_value" >&2
      fi
      continue
    fi

    printf '%s/%s\n' "$root_dir" "$path_value"
  done
}

list_modified_repo_paths() {
  local scope="$1"
  local prefix="$2"
  shift 2

  case "$scope" in
    all|staged|unstaged) ;;
    *)
      echo "list_modified_repo_paths: unknown scope '${scope}' (expected: all|staged|unstaged)" >&2
      return 1
      ;;
  esac

  local root_dir="${PROJECT_ROOT:-$(detect_project_root)}"
  list_scoped_repo_files "$root_dir" "$scope" | filter_repo_paths "$root_dir" "$prefix" "$@"
}

list_repo_paths() {
  local prefix="$1"
  shift

  local root_dir="${PROJECT_ROOT:-$(detect_project_root)}"
  list_repo_files "$root_dir" | filter_repo_paths "$root_dir" "$prefix" "$@"
}
