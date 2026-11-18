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

# shellcheck source=bin/lib/modified-files.sh
source "$SCRIPT_DIR/lib/modified-files.sh"
# shellcheck source=bin/lib/shellcheck-resolve.sh
source "$SCRIPT_DIR/lib/shellcheck-resolve.sh"

PROJECT_ROOT="$(detect_project_root)"
readonly PROJECT_ROOT
style_load_extra_excludes "$PROJECT_ROOT"
readonly TS_PROJECT_DIR="${TS_PROJECT_DIR:-$PROJECT_ROOT}"
readonly DOCS_PROJECT_DIR="${DOCS_PROJECT_DIR:-$PROJECT_ROOT}"
readonly PYTHON_PROJECT_DIR="${PYTHON_PROJECT_DIR:-$PROJECT_ROOT}"

print_skip() {
  local section_name="$1"
  local reason="$2"
  echo "=== ${section_name} ==="
  echo "Skipping: ${reason}"
}

scope_noun() {
  case "${1:-all}" in
    staged) printf 'staged\n' ;;
    unstaged) printf 'unstaged\n' ;;
    *) printf 'modified\n' ;;
  esac
}

require_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    return 1
  fi
}

# Node CLIs must come from the project's own node_modules so the version the
# lockfile pins is the version that runs. A bare `npx <tool>` silently falls back
# to a registry download or a stale ~/.npm/_npx cache entry whenever node_modules
# is missing, which lints against an arbitrary version and disagrees with CI.
resolve_node_bin() {
  local start_dir="$1"
  local bin_name="$2"
  local package_name="$3"

  local search_dir="$start_dir"
  local previous_dir=''
  while [[ -n "$search_dir" && "$search_dir" != "$previous_dir" ]]; do
    if [[ -x "$search_dir/node_modules/.bin/$bin_name" ]]; then
      printf '%s\n' "$search_dir/node_modules/.bin/$bin_name"
      return 0
    fi

    previous_dir="$search_dir"
    search_dir="$(dirname "$search_dir")"
  done

  echo "Missing local ${bin_name} (package ${package_name}): no node_modules/.bin/${bin_name} in ${start_dir} or any parent directory." >&2
  echo "Run your package manager's install (for example 'pnpm install') so lint and format use the lockfile-pinned version." >&2
  echo "Refusing to fall back to 'npx', which resolves an arbitrary version and disagrees with CI." >&2
  return 1
}

# Run a Node CLI out of the project's node_modules/.bin, with that project as cwd.
run_node_tool() {
  local project_dir="$1"
  local bin_name="$2"
  local package_name="$3"
  shift 3

  local tool_bin
  tool_bin="$(resolve_node_bin "$project_dir" "$bin_name" "$package_name")" || return 1

  (cd "$project_dir" && "$tool_bin" "$@")
}

run_biome() {
  local project_dir="$1"
  shift
  run_node_tool "$project_dir" biome "@biomejs/biome" "$@"
}

run_prettier() {
  local project_dir="$1"
  shift
  run_node_tool "$project_dir" prettier prettier "$@"
}

run_markdownlint() {
  local project_dir="$1"
  shift
  run_node_tool "$project_dir" markdownlint markdownlint-cli "$@"
}

relativize_paths() {
  local base_dir="${1%/}"
  shift

  local path_value
  for path_value in "$@"; do
    if [[ "$path_value" == "$base_dir/"* ]]; then
      printf '%s\n' "${path_value#"$base_dir"/}"
    elif [[ "$path_value" == "$base_dir" ]]; then
      printf '.\n'
    fi
  done
}

path_prefix_for() {
  local target_dir="$1"
  local prefix

  prefix="$(path_relative_to_root "$PROJECT_ROOT" "$target_dir" || true)"
  if [[ -n "$prefix" ]]; then
    printf '%s/\n' "$prefix"
  else
    printf '\n'
  fi
}

directory_has_suffixes() {
  local target_dir="$1"
  shift

  # Ignore-aware detection: enumerate the same set the linter operates on
  # (git ls-files honoring .gitignore, or a find fallback for non-git dirs) and
  # skip STYLE_EXCLUDES, so a stray source file inside node_modules/dist/vendor
  # no longer flips a detect_*_project result. dir_has_source_suffix is provided
  # by excludes.sh, sourced transitively via modified-files.sh above.
  dir_has_source_suffix "$target_dir" "$@"
}

detect_docs_project() {
  local target_dir="$DOCS_PROJECT_DIR"

  [[ -f "$target_dir/.markdownlint.json" ]] ||
    [[ -f "$target_dir/.markdownlint.jsonc" ]] ||
    [[ -f "$target_dir/.markdownlint.yaml" ]] ||
    [[ -f "$target_dir/.markdownlint.yml" ]] ||
    [[ -f "$target_dir/.prettierrc" ]] ||
    [[ -f "$target_dir/.prettierrc.json" ]] ||
    [[ -f "$target_dir/.prettierrc.yml" ]] ||
    [[ -f "$target_dir/.prettierrc.yaml" ]] ||
    directory_has_suffixes "$target_dir" ".md" ".mdx" ".yaml" ".yml" ||
    (docs_track_uses_json_files "$target_dir" && directory_has_suffixes "$target_dir" ".json" ".jsonc")
}

detect_python_project() {
  local target_dir="$PYTHON_PROJECT_DIR"

  [[ -f "$target_dir/pyproject.toml" ]] ||
    [[ -f "$target_dir/requirements.txt" ]] ||
    [[ -f "$target_dir/setup.py" ]] ||
    directory_has_suffixes "$target_dir" ".py" ".pyi"
}

detect_ts_project() {
  local target_dir="${1:-$TS_PROJECT_DIR}"

  compgen -G "$target_dir/tsconfig*.json" >/dev/null ||
    [[ -f "$target_dir/biome.json" ]] ||
    [[ -f "$target_dir/biome.jsonc" ]] ||
    directory_has_suffixes "$target_dir" ".ts" ".tsx" ".mts" ".cts" ".js" ".jsx" ".mjs" ".cjs"
}

docs_track_uses_json_files() {
  local target_dir="${1:-$DOCS_PROJECT_DIR}"

  ! detect_ts_project "$target_dir"
}

docs_track_label() {
  local target_dir="${1:-$DOCS_PROJECT_DIR}"

  if docs_track_uses_json_files "$target_dir"; then
    printf 'Docs/JSON/YAML\n'
  else
    printf 'Docs\n'
  fi
}

docs_owned_suffixes() {
  local target_dir="${1:-$DOCS_PROJECT_DIR}"

  printf '%s\n' ".md" ".mdx" ".yaml" ".yml"
  if docs_track_uses_json_files "$target_dir"; then
    printf '%s\n' ".json" ".jsonc"
  fi
}

ts_owned_suffixes() {
  printf '%s\n' ".ts" ".tsx" ".js" ".jsx" ".mjs" ".cjs" ".mts" ".cts" ".css" ".json" ".jsonc"
}

run_ts_lint() {
  local fix="$1"
  local git_scope="$2"
  local exit_code=0

  if [[ ! -f "$TS_PROJECT_DIR/package.json" ]]; then
    print_skip "TypeScript" "no package.json found in ${TS_PROJECT_DIR}"
    return 0
  fi

  local ts_prefix
  ts_prefix="$(path_prefix_for "$TS_PROJECT_DIR")"
  local -a ts_suffixes=()
  mapfile -t ts_suffixes < <(ts_owned_suffixes)

  if [[ -n "$git_scope" ]]; then
    local -a ts_biome_files=()
    mapfile -t ts_biome_files < <(list_modified_repo_paths "$git_scope" "$ts_prefix" "${ts_suffixes[@]}")

    if (( ${#ts_biome_files[@]} == 0 )); then
      echo "=== TypeScript ==="
      echo "No $(scope_noun "$git_scope") frontend source files."
    else
      echo "=== TypeScript/JavaScript: biome ==="
      local -a ts_relative_biome_files=()
      mapfile -t ts_relative_biome_files < <(relativize_paths "$TS_PROJECT_DIR" "${ts_biome_files[@]}")

      if (( fix )); then
        run_biome "$TS_PROJECT_DIR" check --fix "${ts_relative_biome_files[@]}" || exit_code=1
      else
        run_biome "$TS_PROJECT_DIR" ci "${ts_relative_biome_files[@]}" || exit_code=1
      fi
    fi

    return "$exit_code"
  fi

  local -a ts_biome_files=()
  mapfile -t ts_biome_files < <(list_repo_paths "$ts_prefix" "${ts_suffixes[@]}")
  if (( ${#ts_biome_files[@]} == 0 )); then
    echo "=== TypeScript/JavaScript ==="
    echo "No frontend source or JSON files found."
  else
    echo "=== TypeScript/JavaScript: biome ==="
    local -a ts_relative_biome_files=()
    mapfile -t ts_relative_biome_files < <(relativize_paths "$TS_PROJECT_DIR" "${ts_biome_files[@]}")
    run_biome "$TS_PROJECT_DIR" ci "${ts_relative_biome_files[@]}" || exit_code=1
  fi

  return "$exit_code"
}

run_shell_lint() {
  local git_scope="$1"

  if ! resolve_shellcheck_bin; then
    return 1
  fi

  local -a shell_files=()
  if [[ -n "$git_scope" ]]; then
    mapfile -t shell_files < <(list_modified_repo_paths "$git_scope" "" ".sh")
    if (( ${#shell_files[@]} == 0 )); then
      echo "=== Shell ==="
      echo "No $(scope_noun "$git_scope") shell scripts."
      return 0
    fi
  else
    mapfile -t shell_files < <(list_repo_paths "" ".sh")
    if (( ${#shell_files[@]} == 0 )); then
      echo "=== Shell ==="
      echo "No shell scripts found."
      return 0
    fi
  fi

  echo "=== Shell: shellcheck ==="
  "$SHELLCHECK_BIN" --severity=warning "${shell_files[@]}"
}

run_python_lint() {
  local fix="$1"
  local git_scope="$2"
  local exit_code=0

  if ! detect_python_project; then
    print_skip "Python" "no Python files or config found in ${PYTHON_PROJECT_DIR}"
    return 0
  fi

  if ! require_command ruff; then
    return 1
  fi
  if ! require_command black; then
    return 1
  fi

  local python_prefix
  python_prefix="$(path_prefix_for "$PYTHON_PROJECT_DIR")"

  # User excludes (.style-excludes / STYLE_EXTRA_EXCLUDES) never reach a bare
  # `ruff check .`, so a full run with any declared uses the filtered file list.
  if [[ -n "$git_scope" ]] || (( ${#STYLE_USER_EXCLUDES[@]} )); then
    local -a python_files=()
    if [[ -n "$git_scope" ]]; then
      mapfile -t python_files < <(list_modified_repo_paths "$git_scope" "$python_prefix" ".py" ".pyi")
    else
      mapfile -t python_files < <(list_repo_paths "$python_prefix" ".py" ".pyi")
    fi

    if (( ${#python_files[@]} == 0 )); then
      echo "=== Python ==="
      echo "No ${git_scope:+$(scope_noun "$git_scope") }Python files."
      return 0
    fi

    echo "=== Python: ruff ==="
    local -a python_relative_files=()
    mapfile -t python_relative_files < <(relativize_paths "$PYTHON_PROJECT_DIR" "${python_files[@]}")
    if (( fix )); then
      (cd "$PYTHON_PROJECT_DIR" && ruff check --fix "${python_relative_files[@]}") || exit_code=1
      (cd "$PYTHON_PROJECT_DIR" && black "${python_relative_files[@]}") || exit_code=1
    else
      (cd "$PYTHON_PROJECT_DIR" && ruff check "${python_relative_files[@]}") || exit_code=1
      echo "=== Python: black ==="
      (cd "$PYTHON_PROJECT_DIR" && black --check "${python_relative_files[@]}") || exit_code=1
    fi

    return "$exit_code"
  fi

  echo "=== Python: ruff ==="
  if (( fix )); then
    (cd "$PYTHON_PROJECT_DIR" && ruff check --fix .) || exit_code=1
    echo "=== Python: black ==="
    (cd "$PYTHON_PROJECT_DIR" && black .) || exit_code=1
  else
    (cd "$PYTHON_PROJECT_DIR" && ruff check .) || exit_code=1
    echo "=== Python: black ==="
    (cd "$PYTHON_PROJECT_DIR" && black --check .) || exit_code=1
  fi

  return "$exit_code"
}

run_docs_lint() {
  local fix="$1"
  local git_scope="$2"
  local exit_code=0
  local docs_label
  docs_label="$(docs_track_label "$DOCS_PROJECT_DIR")"

  if ! detect_docs_project; then
    print_skip "$docs_label" "no docs-owned files or docs config found in ${DOCS_PROJECT_DIR}"
    return 0
  fi

  local docs_prefix
  docs_prefix="$(path_prefix_for "$DOCS_PROJECT_DIR")"
  local -a docs_suffixes=()
  mapfile -t docs_suffixes < <(docs_owned_suffixes "$DOCS_PROJECT_DIR")

  local -a docs_files=()
  if [[ -n "$git_scope" ]]; then
    mapfile -t docs_files < <(list_modified_repo_paths "$git_scope" "$docs_prefix" "${docs_suffixes[@]}")
    if (( ${#docs_files[@]} == 0 )); then
      echo "=== ${docs_label} ==="
      echo "No $(scope_noun "$git_scope") docs files."
      return 0
    fi
  else
    mapfile -t docs_files < <(list_repo_paths "$docs_prefix" "${docs_suffixes[@]}")
    if (( ${#docs_files[@]} == 0 )); then
      echo "=== ${docs_label} ==="
      echo "No docs files found."
      return 0
    fi
  fi

  local -a docs_relative_files=()
  mapfile -t docs_relative_files < <(relativize_paths "$DOCS_PROJECT_DIR" "${docs_files[@]}")

  local -a markdownlint_args=()
  if [[ -f "$DOCS_PROJECT_DIR/.markdownlintignore" ]]; then
    markdownlint_args+=(--ignore-path "$DOCS_PROJECT_DIR/.markdownlintignore")
  fi

  local markdownlint_config=''
  local markdownlint_candidate
  for markdownlint_candidate in \
    .markdownlint.json \
    .markdownlint.jsonc \
    .markdownlint.yaml \
    .markdownlint.yml
  do
    if [[ -f "$DOCS_PROJECT_DIR/$markdownlint_candidate" ]]; then
      markdownlint_config="$DOCS_PROJECT_DIR/$markdownlint_candidate"
      break
    fi
  done
  if [[ -n "$markdownlint_config" ]]; then
    markdownlint_args+=(--config "$markdownlint_config")
  fi

  local -a prettier_args=()
  if [[ -f "$DOCS_PROJECT_DIR/.prettierignore" ]]; then
    prettier_args+=(--ignore-path "$DOCS_PROJECT_DIR/.prettierignore")
  fi
  if [[ -f "$DOCS_PROJECT_DIR/.prettierrc" ]]; then
    prettier_args+=(--config "$DOCS_PROJECT_DIR/.prettierrc")
  fi

  echo "=== Markdown: markdownlint ==="
  local -a markdown_relative_files=()
  local docs_relative_file
  for docs_relative_file in "${docs_relative_files[@]}"; do
    case "$docs_relative_file" in
      *.md|*.mdx) markdown_relative_files+=("$docs_relative_file") ;;
    esac
  done

  if (( ${#markdown_relative_files[@]} == 0 )); then
    echo "No Markdown files to lint."
  elif (( fix )); then
    run_markdownlint "$DOCS_PROJECT_DIR" --fix "${markdownlint_args[@]}" "${markdown_relative_files[@]}" || exit_code=1
  else
    run_markdownlint "$DOCS_PROJECT_DIR" "${markdownlint_args[@]}" "${markdown_relative_files[@]}" || exit_code=1
  fi

  echo "=== Docs: prettier ==="
  if (( fix )); then
    run_prettier "$DOCS_PROJECT_DIR" --write "${docs_relative_files[@]}" "${prettier_args[@]}" || exit_code=1
  else
    run_prettier "$DOCS_PROJECT_DIR" --check "${docs_relative_files[@]}" "${prettier_args[@]}" || exit_code=1
  fi

  return "$exit_code"
}

run_ts_format() {
  local git_scope="$1"

  if [[ ! -f "$TS_PROJECT_DIR/package.json" ]]; then
    print_skip "TypeScript/JavaScript" "no package.json found in ${TS_PROJECT_DIR}"
    return 0
  fi

  local ts_prefix
  ts_prefix="$(path_prefix_for "$TS_PROJECT_DIR")"
  local -a ts_suffixes=()
  mapfile -t ts_suffixes < <(ts_owned_suffixes)

  if [[ -n "$git_scope" ]]; then
    local -a ts_files=()
    mapfile -t ts_files < <(list_modified_repo_paths "$git_scope" "$ts_prefix" "${ts_suffixes[@]}")

    if (( ${#ts_files[@]} == 0 )); then
      echo "=== TypeScript/JavaScript ==="
      echo "No $(scope_noun "$git_scope") frontend source files."
      return 0
    fi

    echo "=== TypeScript/JavaScript: biome ==="
    local -a ts_relative_files=()
    mapfile -t ts_relative_files < <(relativize_paths "$TS_PROJECT_DIR" "${ts_files[@]}")
    run_biome "$TS_PROJECT_DIR" format --write "${ts_relative_files[@]}"
    run_biome "$TS_PROJECT_DIR" check --fix "${ts_relative_files[@]}"
    return 0
  fi

  local -a ts_files=()
  mapfile -t ts_files < <(list_repo_paths "$ts_prefix" "${ts_suffixes[@]}")
  if (( ${#ts_files[@]} == 0 )); then
    echo "=== TypeScript/JavaScript ==="
    echo "No frontend source or JSON files found."
    return 0
  fi

  echo "=== TypeScript/JavaScript: biome ==="
  local -a ts_relative_files=()
  mapfile -t ts_relative_files < <(relativize_paths "$TS_PROJECT_DIR" "${ts_files[@]}")
  run_biome "$TS_PROJECT_DIR" format --write "${ts_relative_files[@]}"
  run_biome "$TS_PROJECT_DIR" check --fix "${ts_relative_files[@]}"
}

run_docs_format() {
  local git_scope="$1"
  local docs_label
  docs_label="$(docs_track_label "$DOCS_PROJECT_DIR")"

  if ! detect_docs_project; then
    print_skip "$docs_label" "no docs-owned files or docs config found in ${DOCS_PROJECT_DIR}"
    return 0
  fi

  local docs_prefix
  docs_prefix="$(path_prefix_for "$DOCS_PROJECT_DIR")"
  local -a docs_suffixes=()
  mapfile -t docs_suffixes < <(docs_owned_suffixes "$DOCS_PROJECT_DIR")

  local -a prettier_args=()
  if [[ -f "$DOCS_PROJECT_DIR/.prettierignore" ]]; then
    prettier_args+=(--ignore-path "$DOCS_PROJECT_DIR/.prettierignore")
  fi
  if [[ -f "$DOCS_PROJECT_DIR/.prettierrc" ]]; then
    prettier_args+=(--config "$DOCS_PROJECT_DIR/.prettierrc")
  fi

  local -a docs_files=()
  if [[ -n "$git_scope" ]]; then
    mapfile -t docs_files < <(list_modified_repo_paths "$git_scope" "$docs_prefix" "${docs_suffixes[@]}")
    if (( ${#docs_files[@]} == 0 )); then
      echo "=== ${docs_label} ==="
      echo "No $(scope_noun "$git_scope") docs files."
      return 0
    fi
  else
    mapfile -t docs_files < <(list_repo_paths "$docs_prefix" "${docs_suffixes[@]}")
    if (( ${#docs_files[@]} == 0 )); then
      echo "=== ${docs_label} ==="
      echo "No docs files found."
      return 0
    fi
  fi

  echo "=== Docs: prettier ==="
  local -a docs_relative_files=()
  mapfile -t docs_relative_files < <(relativize_paths "$DOCS_PROJECT_DIR" "${docs_files[@]}")
  run_prettier "$DOCS_PROJECT_DIR" --write "${docs_relative_files[@]}" "${prettier_args[@]}"
}

run_python_format() {
  local git_scope="$1"

  if ! detect_python_project; then
    print_skip "Python" "no Python files or config found in ${PYTHON_PROJECT_DIR}"
    return 0
  fi

  if ! require_command black; then
    return 1
  fi

  local python_prefix
  python_prefix="$(path_prefix_for "$PYTHON_PROJECT_DIR")"

  # User excludes (.style-excludes / STYLE_EXTRA_EXCLUDES) never reach a bare
  # `ruff check .`, so a full run with any declared uses the filtered file list.
  if [[ -n "$git_scope" ]] || (( ${#STYLE_USER_EXCLUDES[@]} )); then
    local -a python_files=()
    if [[ -n "$git_scope" ]]; then
      mapfile -t python_files < <(list_modified_repo_paths "$git_scope" "$python_prefix" ".py" ".pyi")
    else
      mapfile -t python_files < <(list_repo_paths "$python_prefix" ".py" ".pyi")
    fi

    if (( ${#python_files[@]} == 0 )); then
      echo "=== Python ==="
      echo "No ${git_scope:+$(scope_noun "$git_scope") }Python files."
      return 0
    fi

    echo "=== Python: black ==="
    local -a python_relative_files=()
    mapfile -t python_relative_files < <(relativize_paths "$PYTHON_PROJECT_DIR" "${python_files[@]}")
    (cd "$PYTHON_PROJECT_DIR" && black "${python_relative_files[@]}")
    return 0
  fi

  echo "=== Python: black ==="
  (cd "$PYTHON_PROJECT_DIR" && black .)
}

style_usage() {
  cat <<'EOF'
Usage: style.sh <command> [options]

Commands:
  lint     Run linters for the current project root
  format   Format files for the current project root

Git scope flags (mutually exclusive; accepted by lint and format):
  --modified   All modified files: staged + unstaged + untracked
  --staged     Only files staged in the git index
  --unstaged   Only unstaged working-tree changes + untracked files

Examples:
  style.sh lint --fix --python
  style.sh format --modified --docs
  style.sh lint --staged --shell --python
  style.sh format --unstaged --docs
EOF
}

lint_usage() {
  cat <<'EOF'
Usage: style.sh lint [--fix] [--modified|--staged|--unstaged] [--ts] [--docs] [--python] [--shell] [--all]

Environment overrides:
  PROJECT_ROOT       Explicit project root. Defaults to the git root for $PWD.
  TS_PROJECT_DIR     Directory for package.json / tsconfig.json / biome runs.
                     Defaults to PROJECT_ROOT.
  DOCS_PROJECT_DIR   Directory for markdownlint and prettier runs. Defaults to PROJECT_ROOT.
  PYTHON_PROJECT_DIR Directory for Python config and source files. Defaults to PROJECT_ROOT.

Options:
  --fix       Apply auto-fixes where supported
  --modified  Limit file-based linting to all modified files (staged + unstaged + untracked)
  --staged    Limit file-based linting to files staged in the git index
  --unstaged  Limit file-based linting to unstaged working-tree changes + untracked files
  --ts        TypeScript / JavaScript / JSON only (biome)
  --docs      Docs only (Markdown/YAML; JSON/JSONC when no TS/JS track is detected)
  --python    Python only (ruff + black --check)
  --shell     Shell scripts only (shellcheck)
  --all       All supported lint checks (default)

--modified, --staged, and --unstaged are mutually exclusive.
EOF
}

format_usage() {
  cat <<'EOF'
Usage: style.sh format [--modified|--staged|--unstaged] [--ts] [--docs] [--python] [--all]

Environment overrides:
  PROJECT_ROOT       Explicit project root. Defaults to the git root for $PWD.
  TS_PROJECT_DIR     Directory for package.json / biome runs. Defaults to PROJECT_ROOT.
  DOCS_PROJECT_DIR   Directory for prettier runs. Defaults to PROJECT_ROOT.
  PYTHON_PROJECT_DIR Directory for Python config and source files. Defaults to PROJECT_ROOT.

Options:
  --modified  Limit file-based formatting to all modified files (staged + unstaged + untracked)
  --staged    Limit file-based formatting to files staged in the git index
  --unstaged  Limit file-based formatting to unstaged working-tree changes + untracked files
  --ts        TypeScript / JavaScript / JSON only (biome)
  --docs      Docs only (Markdown/YAML; JSON/JSONC when no TS/JS track is detected)
  --python    Python only (black)
  --all       All supported formatters (default)

--modified, --staged, and --unstaged are mutually exclusive.
EOF
}

_set_git_scope_or_die() {
  local -n _scope_ref="$1"
  local new_scope="$2"
  local usage_fn="$3"

  if [[ -n "$_scope_ref" ]]; then
    echo "Cannot combine --modified, --staged, and --unstaged (already set to '${_scope_ref}')." >&2
    "$usage_fn" >&2
    exit 1
  fi
  _scope_ref="$new_scope"
}

run_lint_command() {
  local fix=0
  local git_scope=""
  local run_ts=0
  local run_docs=0
  local run_python=0
  local run_shell=0
  local exit_code=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fix) fix=1; shift ;;
      --modified) _set_git_scope_or_die git_scope all lint_usage; shift ;;
      --staged) _set_git_scope_or_die git_scope staged lint_usage; shift ;;
      --unstaged) _set_git_scope_or_die git_scope unstaged lint_usage; shift ;;
      --ts) run_ts=1; shift ;;
      --docs) run_docs=1; shift ;;
      --python) run_python=1; shift ;;
      --shell) run_shell=1; shift ;;
      --all) run_ts=1; run_docs=1; run_python=1; run_shell=1; shift ;;
      --help|-h) lint_usage; exit 0 ;;
      *) echo "Unknown arg for lint: $1" >&2; lint_usage >&2; exit 1 ;;
    esac
  done

  if (( !run_ts && !run_docs && !run_python && !run_shell )); then
    run_ts=1
    run_docs=1
    run_python=1
    run_shell=1
  fi

  if (( run_ts )); then
    run_ts_lint "$fix" "$git_scope" || exit_code=1
  fi
  if (( run_docs )); then
    run_docs_lint "$fix" "$git_scope" || exit_code=1
  fi
  if (( run_python )); then
    run_python_lint "$fix" "$git_scope" || exit_code=1
  fi
  if (( run_shell )); then
    run_shell_lint "$git_scope" || exit_code=1
  fi

  exit "$exit_code"
}

run_format_command() {
  local git_scope=""
  local run_ts=0
  local run_docs=0
  local run_python=0
  local exit_code=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --modified) _set_git_scope_or_die git_scope all format_usage; shift ;;
      --staged) _set_git_scope_or_die git_scope staged format_usage; shift ;;
      --unstaged) _set_git_scope_or_die git_scope unstaged format_usage; shift ;;
      --ts) run_ts=1; shift ;;
      --docs) run_docs=1; shift ;;
      --python) run_python=1; shift ;;
      --all) run_ts=1; run_docs=1; run_python=1; shift ;;
      --help|-h) format_usage; exit 0 ;;
      *) echo "Unknown arg for format: $1" >&2; format_usage >&2; exit 1 ;;
    esac
  done

  if (( !run_ts && !run_docs && !run_python )); then
    run_ts=1
    run_docs=1
    run_python=1
  fi

  if (( run_ts )); then
    run_ts_format "$git_scope" || exit_code=1
  fi
  if (( run_docs )); then
    run_docs_format "$git_scope" || exit_code=1
  fi
  if (( run_python )); then
    run_python_format "$git_scope" || exit_code=1
  fi

  if (( exit_code == 0 )); then
    echo "All formatting complete."
  fi
  exit "$exit_code"
}

main() {
  if (( $# == 0 )); then
    style_usage
    exit 1
  fi

  local command="$1"
  shift

  case "$command" in
    lint)
      run_lint_command "$@"
      ;;
    format)
      run_format_command "$@"
      ;;
    --help|-h|help)
      style_usage
      ;;
    *)
      echo "Unknown command: $command" >&2
      style_usage >&2
      exit 1
      ;;
  esac
}

main "$@"
