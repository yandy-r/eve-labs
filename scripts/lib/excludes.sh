#!/usr/bin/env bash
# excludes.sh — canonical list of well-known paths every formatter/linter skips.
#
# Source from any script that filters repo paths:
#   # shellcheck source=./excludes.sh
#   . "${BASH_SOURCE%/*}/excludes.sh"
#
# Consumers: modified-files.sh filter step. Tool-config templates under
# ../templates/ maintain parallel lists by hand — keep them aligned with this
# array (see the "canonical excludes" comment at the top of each template).

if [[ -n "${STYLE_EXCLUDES_LOADED:-}" ]]; then
    return 0
fi
readonly STYLE_EXCLUDES_LOADED=1

# Paths are matched against repo-relative file paths via path_is_excluded():
# every STYLE_EXCLUDES entry matches ROOT-RELATIVE — a path is excluded when it
# equals the entry OR begins with "<entry>/". Entries that are ALSO listed in
# STYLE_EXCLUDES_ANY_DEPTH additionally match at any depth (so nested vendored
# copies like packages/x/node_modules/... are pruned too). Keep entries in the
# form they appear in the worktree (no leading or trailing slash).
STYLE_EXCLUDES=(
    # Language package / build output
    node_modules
    target
    build
    dist
    out
    coverage
    vendor

    # Python environments & cache
    .venv
    venv
    env
    __pycache__
    .mypy_cache
    .pytest_cache
    .ruff_cache

    # JS meta-framework caches
    .next
    .nuxt
    .cache

    # Infrastructure tooling
    .terraform

    # Generated plugin bundles (this repo's source-of-truth pattern; harmless
    # as defaults because these names are specific to ycc).
    .cursor-plugin
    packages/cursor
    .codex-plugin
    .opencode-plugin

    # Managed formatter bundle assets copied into downstream repos. Keep these
    # as exact file paths so user-authored files under scripts/templates/ still lint.
    scripts/templates/biome.json
    scripts/templates/clippy.toml
    scripts/templates/markdownlint.json
    scripts/templates/markdownlintignore
    scripts/templates/prettierrc.json
    scripts/templates/prettierignore
    scripts/templates/python-pyproject.toml
    scripts/templates/rustfmt.toml
    scripts/templates/tsconfig.json
)

# Subset of STYLE_EXCLUDES whose names must NEVER hold first-class source and are
# therefore pruned at ANY depth (not just repo root). Generic words that can
# legitimately name a nested source directory (env, build, out, dist, coverage,
# target, ...) are deliberately NOT here — they stay root-relative so tracked
# nested source is never silently dropped from detection or linting.
STYLE_EXCLUDES_ANY_DEPTH=(
    node_modules
    vendor
    .venv
    venv
    __pycache__
    .mypy_cache
    .pytest_cache
    .ruff_cache
)

# path_is_excluded REL_PATH
#   Return 0 when the repo-relative path REL_PATH is covered by an exclude entry.
#   All STYLE_EXCLUDES entries match root-relative (equal, or under "<entry>/");
#   STYLE_EXCLUDES_ANY_DEPTH names additionally match nested occurrences. Shared
#   by detection (dir_has_source_suffix) and linting (filter_repo_paths) so the
#   two can never disagree about what counts as project source.
path_is_excluded() {
    local rel="$1" entry
    for entry in "${STYLE_EXCLUDES[@]}"; do
        if [[ "$rel" == "$entry" || "$rel" == "$entry"/* ]]; then
            return 0
        fi
    done
    for entry in "${STYLE_EXCLUDES_ANY_DEPTH[@]}"; do
        if [[ "$rel" == */"$entry" || "$rel" == */"$entry"/* ]]; then
            return 0
        fi
    done
    return 1
}

# User-declared excludes loaded by style_load_extra_excludes (also appended to
# STYLE_EXCLUDES). Kept separately so tools that scan the tree themselves can be
# switched to the filtered file list when the user has declared any.
STYLE_USER_EXCLUDES=()

# style_load_extra_excludes ROOT
# Append user excludes to STYLE_EXCLUDES (root-relative, same matching as the
# defaults): tokens from STYLE_EXTRA_EXCLUDES (whitespace- or colon-separated)
# and lines of ROOT/.style-excludes (blank lines, `#` lines and whitespace-
# preceded ` # ...` trailing comments ignored).
# Leading "./" and trailing "/" are stripped. Call once, after ROOT is known.
style_load_extra_excludes() {
    local root="${1:-}" entry line
    local -a entries=()
    if [[ -n "${STYLE_EXTRA_EXCLUDES:-}" ]]; then
        read -ra entries <<<"${STYLE_EXTRA_EXCLUDES//:/ }"
    fi
    if [[ -n "$root" && -f "$root/.style-excludes" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            read -r line <<<"$line" || true
            [[ -z "$line" || "$line" == \#* ]] && continue
            line="${line%%[[:space:]]#*}"
            read -r line <<<"$line" || true
            entries+=("$line")
        done <"$root/.style-excludes"
    fi
    # ${arr[@]+...} keeps empty arrays safe under `set -u` on bash < 4.4.
    for entry in ${entries[@]+"${entries[@]}"}; do
        entry="${entry#./}"
        entry="${entry%/}"
        [[ -n "$entry" ]] && STYLE_USER_EXCLUDES+=("$entry")
    done
    STYLE_EXCLUDES+=(${STYLE_USER_EXCLUDES[@]+"${STYLE_USER_EXCLUDES[@]}"})
    return 0
}

# style_list_source_files DIR
#   Emit newline-delimited files under DIR, DIR-relative. Git worktrees honor
#   .gitignore via ls-files (tracked + untracked-but-not-ignored); non-git dirs
#   fall back to find, pruning only .git/. `git -C DIR` scopes enumeration to DIR
#   and emits DIR-relative paths, keeping output consistent with path_is_excluded.
style_list_source_files() {
    local dir="$1"
    if git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git -C "$dir" ls-files --cached --others --exclude-standard 2>/dev/null
    else
        (cd "$dir" 2>/dev/null && find . -type f ! -path './.git/*' 2>/dev/null | sed 's|^\./||')
    fi
}

# dir_has_source_suffix DIR SUFFIX...
#   Return 0 if at least one non-excluded source file under DIR ends with any
#   given SUFFIX. Short-circuits on the first match. The read consumes a PROCESS
#   SUBSTITUTION (not a pipe), so an early `return 0` is safe under
#   `set -euo pipefail` (no SIGPIPE / exit 141).
dir_has_source_suffix() {
    local dir="$1"
    shift
    (($#)) || return 1

    local rel suffix
    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        path_is_excluded "$rel" && continue
        for suffix in "$@"; do
            if [[ "$rel" == *"$suffix" ]]; then
                return 0
            fi
        done
    done < <(style_list_source_files "$dir")

    return 1
}
