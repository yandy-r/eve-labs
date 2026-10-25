#!/usr/bin/env bash
# install-lefthook.sh — idempotent lefthook bootstrap for eve-labs
#
# Ensures the `lefthook` binary is installed and activates hooks via `lefthook install`.
# Safe to re-run on every checkout. Supports macOS, Linux, and Git Bash on Windows.
# Native Windows PowerShell is not supported — use WSL or Git Bash.

set -euo pipefail

log()  { printf '[install-lefthook] %s\n' "$*"; }
warn() { printf '[install-lefthook] WARN: %s\n' "$*" >&2; }
die()  { printf '[install-lefthook] ERROR: %s\n' "$*" >&2; exit 1; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

repo_root() {
    if command_exists git && git rev-parse --show-toplevel >/dev/null 2>&1; then
        git rev-parse --show-toplevel
    else
        pwd
    fi
}

REPO_ROOT="$(repo_root)"
cd "$REPO_ROOT"

if [[ ! -f "$REPO_ROOT/lefthook.yml" && ! -f "$REPO_ROOT/lefthook.yaml" ]]; then
    die "no lefthook.yml / lefthook.yaml found at $REPO_ROOT. Run this from a repo scaffolded with 'ycc:init --git'."
fi

# -----------------------------------------------------------------------------
# Pre-flight: warn on foreign hook manager
# -----------------------------------------------------------------------------
if [[ -f "$REPO_ROOT/.pre-commit-config.yaml" ]]; then
    warn ".pre-commit-config.yaml detected — this repo may still be wired to the pre-commit framework."
    warn "Run 'pre-commit uninstall' (and optionally delete .pre-commit-config.yaml) before continuing."
fi
if [[ -d "$REPO_ROOT/.husky" ]]; then
    warn ".husky/ directory detected — husky may still be wired. Remove it if you're migrating to lefthook."
fi

# -----------------------------------------------------------------------------
# Ensure lefthook binary is available
# -----------------------------------------------------------------------------
install_lefthook_binary() {
    # Prefer the project's own package manager if it can install lefthook.
    # pnpm was detected at init time.
    if [[ -f "$REPO_ROOT/package.json" ]]; then
        log "package.json present — running 'pnpm install' to pull devDependencies."
        local pm="pnpm"
        case "$pm" in
            pnpm) pnpm install ;;
            yarn) yarn install ;;
            bun)  bun install ;;
            *)    npm install ;;
        esac
        if command_exists lefthook || [[ -x "$REPO_ROOT/node_modules/.bin/lefthook" ]]; then
            return 0
        fi
    fi

    if command_exists lefthook; then
        return 0
    fi

    log "lefthook not on PATH — attempting system install."

    local uname_s
    uname_s="$(uname -s 2>/dev/null || echo unknown)"
    case "$uname_s" in
        Darwin)
            if command_exists brew; then
                log "installing via Homebrew"
                brew install lefthook
                return 0
            fi
            ;;
        Linux|MSYS*|MINGW*|CYGWIN*)
            if command_exists brew; then
                log "installing via Homebrew"
                brew install lefthook
                return 0
            fi
            ;;
    esac

    if command_exists go; then
        log "installing via 'go install'"
        GO111MODULE=on go install github.com/evilmartians/lefthook@latest
        return 0
    fi

    if command_exists cargo; then
        log "installing via 'cargo install'"
        cargo install lefthook
        return 0
    fi

    if command_exists pipx; then
        log "installing via pipx"
        pipx install lefthook
        return 0
    fi

    die "could not auto-install lefthook. Install it manually: https://github.com/evilmartians/lefthook#installation"
}

install_lefthook_binary

# -----------------------------------------------------------------------------
# Resolve the binary path (project-local node_modules wins over global)
# -----------------------------------------------------------------------------
LEFTHOOK_BIN=""
if [[ -x "$REPO_ROOT/node_modules/.bin/lefthook" ]]; then
    LEFTHOOK_BIN="$REPO_ROOT/node_modules/.bin/lefthook"
elif command_exists lefthook; then
    LEFTHOOK_BIN="$(command -v lefthook)"
else
    die "lefthook binary still not found after install attempts."
fi

log "using lefthook at: $LEFTHOOK_BIN"

# -----------------------------------------------------------------------------
# Activate hooks
# -----------------------------------------------------------------------------
"$LEFTHOOK_BIN" install

log "done. Hooks wired at $REPO_ROOT/.git/hooks/."
log "verify with: $LEFTHOOK_BIN dump"
log "bypass once with: git commit --no-verify"
