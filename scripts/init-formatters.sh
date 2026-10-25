#!/usr/bin/env bash
# ================================================================
# Formatter Config Initializer
# ================================================================
# Initializes formatter and linter configuration files in a target project:
# - Docs: .markdownlint.json, .markdownlintignore, .prettierrc, .prettierignore
# - Rust: rustfmt.toml, clippy.toml
# - TypeScript/Node: biome.json, tsconfig.json, package.json
# - Python: pyproject.toml with Ruff + Black config
# - Go: .golangci.yml via go-tools.sh --generate
# - Shellcheck installer support: .gitignore entry for /tools/shellcheck

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() {
  echo -e "${GREEN}[INFO]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
  echo -e "${RED}[ERROR]${NC} $*"
}

success() {
  echo -e "${BLUE}[SUCCESS]${NC} $*"
}

usage() {
  cat <<'EOF'
Usage:
  init-formatters.sh [options] [target-directory]

Options:
  --docs               Initialize markdownlint and Prettier config files
  --md                 Initialize markdownlint config files
  --prettier           Initialize Prettier config files
  --rust               Initialize rustfmt and clippy config files
  --ts                 Initialize Node/TypeScript linting config files
  --ts-node            Alias for --ts
  --python             Initialize Python Ruff + Black config via pyproject.toml
  --go                 Initialize .golangci.yml via go-tools.sh --generate
  --shell              Initialize shell tooling support (.gitignore for /tools/shellcheck)
  --all                Initialize docs, Rust, TS, Python, Go, and shell tooling support
  -t, --target <dir>   Target directory (default: current directory)
  --force              Overwrite existing files without prompt
  -y, --yes            Non-interactive mode (skip overwrite prompts, keep existing files)
  --dry-run            Show actions without writing files
  -h, --help           Show this help

Examples:
  init-formatters.sh --all ~/projects/my-app
  init-formatters.sh --rust --ts --target ~/projects/my-app
  init-formatters.sh --go --dry-run .
EOF
}

resolve_script_dir() {
  local source="${BASH_SOURCE[0]}"
  while [[ -L "${source}" ]]; do
    local dir
    dir="$(cd -P "$(dirname "${source}")" && pwd)"
    source="$(readlink "${source}")"
    [[ "${source}" != /* ]] && source="${dir}/${source}"
  done
  cd -P "$(dirname "${source}")" && pwd
}

SCRIPT_DIR="$(resolve_script_dir)"
readonly SCRIPT_DIR
readonly TEMPLATE_DIR="${SCRIPT_DIR}/templates"
readonly GO_TOOLS_SCRIPT="${SCRIPT_DIR}/go-tools.sh"
readonly BIOME_VERSION="2.3.11"
readonly TYPESCRIPT_VERSION="^5.6.3"
readonly PRETTIER_VERSION="^3.3.3"
readonly MARKDOWNLINT_CLI_VERSION="^0.42.0"

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
  error "Template directory not found: ${TEMPLATE_DIR}"
  exit 1
fi

INIT_DOCS=false
INIT_MD=false
INIT_PRETTIER=false
INIT_RUST=false
INIT_TS=false
INIT_PYTHON=false
INIT_GO=false
INIT_SHELL=false
FORCE=false
DRY_RUN=false
ASSUME_YES=false
TARGET_DIR="${PWD}"
TARGET_SET=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docs)
      INIT_DOCS=true
      INIT_MD=true
      INIT_PRETTIER=true
      shift
      ;;
    --md)
      INIT_MD=true
      shift
      ;;
    --prettier)
      INIT_PRETTIER=true
      shift
      ;;
    --rust)
      INIT_RUST=true
      shift
      ;;
    --ts|--ts-node)
      INIT_TS=true
      shift
      ;;
    --python)
      INIT_PYTHON=true
      shift
      ;;
    --go)
      INIT_GO=true
      shift
      ;;
    --shell)
      INIT_SHELL=true
      shift
      ;;
    --all)
      INIT_DOCS=true
      INIT_MD=true
      INIT_PRETTIER=true
      INIT_RUST=true
      INIT_TS=true
      INIT_PYTHON=true
      INIT_GO=true
      INIT_SHELL=true
      shift
      ;;
    -t|--target)
      if [[ $# -lt 2 ]]; then
        error "Missing value for $1"
        usage
        exit 1
      fi
      TARGET_DIR="$2"
      TARGET_SET=true
      shift 2
      ;;
    --force)
      FORCE=true
      shift
      ;;
    -y|--yes)
      ASSUME_YES=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      error "Unknown option: $1"
      usage
      exit 1
      ;;
    *)
      if [[ "${TARGET_SET}" == true ]]; then
        error "Target directory already set. Unexpected argument: $1"
        usage
        exit 1
      fi
      TARGET_DIR="$1"
      TARGET_SET=true
      shift
      ;;
  esac
done

if [[ "${INIT_DOCS}" == true ]]; then
  INIT_MD=true
  INIT_PRETTIER=true
fi

if [[ "${INIT_MD}" == false && "${INIT_PRETTIER}" == false && "${INIT_RUST}" == false && "${INIT_TS}" == false && "${INIT_PYTHON}" == false && "${INIT_GO}" == false && "${INIT_SHELL}" == false ]]; then
  info "No formatter selection provided. Defaulting to --all."
  INIT_DOCS=true
  INIT_MD=true
  INIT_PRETTIER=true
  INIT_RUST=true
  INIT_TS=true
  INIT_PYTHON=true
  INIT_GO=true
  INIT_SHELL=true
fi

if [[ ! -d "${TARGET_DIR}" ]]; then
  error "Target directory does not exist: ${TARGET_DIR}"
  exit 1
fi

TARGET_DIR="$(cd "${TARGET_DIR}" && pwd)"

created=0
overwritten=0
skipped=0
failed=0

copy_template() {
  local src_rel="$1"
  local dest_rel="$2"
  local src="${TEMPLATE_DIR}/${src_rel}"
  local dest="${TARGET_DIR}/${dest_rel}"
  local action="create"

  if [[ ! -f "${src}" ]]; then
    error "Template not found: ${src}"
    ((failed++)) || true
    return
  fi

  mkdir -p "$(dirname "${dest}")"

  if [[ -e "${dest}" ]]; then
    action="overwrite"
    if [[ "${DRY_RUN}" == true ]]; then
      if [[ "${FORCE}" != true && "${ASSUME_YES}" == true ]]; then
        info "[dry-run] Would keep existing file: ${dest}"
        ((skipped++)) || true
        return
      fi
      info "[dry-run] Would ${action}: ${dest}"
      ((overwritten++)) || true
      return
    fi

    if [[ "${FORCE}" != true ]]; then
      if [[ "${ASSUME_YES}" == true ]]; then
        warn "Exists, keeping current file: ${dest}"
        ((skipped++)) || true
        return
      fi

      read -r -p "Overwrite existing file ${dest}? [y/N] " response
      if [[ ! "${response}" =~ ^[Yy]$ ]]; then
        info "Keeping existing file: ${dest}"
        ((skipped++)) || true
        return
      fi
    fi
  fi

  if [[ "${DRY_RUN}" == true ]]; then
    info "[dry-run] Would ${action}: ${dest}"
    if [[ "${action}" == "overwrite" ]]; then
      ((overwritten++)) || true
    else
      ((created++)) || true
    fi
    return
  fi

  cp "${src}" "${dest}"
  if [[ "${action}" == "overwrite" ]]; then
    success "Overwrote: ${dest}"
    ((overwritten++)) || true
  else
    success "Created: ${dest}"
    ((created++)) || true
  fi
}

ensure_gitignore_entry() {
  local entry="$1"
  local dest="${TARGET_DIR}/.gitignore"

  if [[ -f "${dest}" ]] && grep -Fqx "${entry}" "${dest}"; then
    info "Keeping existing ignore rule in ${dest}: ${entry}"
    ((skipped++)) || true
    return
  fi

  if [[ -f "${dest}" ]]; then
    if [[ "${DRY_RUN}" == true ]]; then
      if [[ "${FORCE}" == true ]]; then
        info "[dry-run] Would append ignore rule to ${dest}: ${entry}"
        ((overwritten++)) || true
      elif [[ "${ASSUME_YES}" == true ]]; then
        info "[dry-run] Would keep existing file: ${dest}"
        ((skipped++)) || true
      else
        info "[dry-run] Would prompt to append ignore rule to ${dest}: ${entry}"
      fi
      return
    fi

    if [[ "${FORCE}" != true ]]; then
      if [[ "${ASSUME_YES}" == true ]]; then
        warn "Exists, keeping current file: ${dest}"
        ((skipped++)) || true
        return
      fi

      read -r -p "Append ignore rule ${entry} to existing file ${dest}? [y/N] " response
      if [[ ! "${response}" =~ ^[Yy]$ ]]; then
        info "Keeping existing file: ${dest}"
        ((skipped++)) || true
        return
      fi
    fi

    if [[ -s "${dest}" && "$(tail -c 1 "${dest}" 2>/dev/null || true)" != $'\n' ]]; then
      printf '\n' >> "${dest}"
    fi
    printf '%s\n' "${entry}" >> "${dest}"
    success "Updated: ${dest} (${entry})"
    ((overwritten++)) || true
    return
  fi

  if [[ "${DRY_RUN}" == true ]]; then
    info "[dry-run] Would create ${dest} with ignore rule: ${entry}"
    ((created++)) || true
    return
  fi

  printf '%s\n' "${entry}" > "${dest}"
  success "Created: ${dest}"
  ((created++)) || true
}

generate_go_config() {
  local dest="${TARGET_DIR}/.golangci.yml"
  local action="create"

  if [[ -e "${dest}" ]]; then
    action="overwrite"
  fi

  if [[ "${DRY_RUN}" == true ]]; then
    info "[dry-run] Would ${action}: ${dest}"
    if [[ "${action}" == "overwrite" ]]; then
      ((overwritten++)) || true
    else
      ((created++)) || true
    fi
    return
  fi

  if GO_TOOLS_FORCE="${FORCE}" GO_TOOLS_ASSUME_YES="${ASSUME_YES}" GO_TOOLS_DRY_RUN=false \
    "${GO_TOOLS_SCRIPT}" "${TARGET_DIR}" --generate; then
    if [[ "${action}" == "overwrite" ]]; then
      ((overwritten++)) || true
    else
      ((created++)) || true
    fi
  else
    ((failed++)) || true
  fi
}

write_ts_package_json() {
  local dest="${TARGET_DIR}/package.json"
  local action="create"

  if [[ -e "${dest}" ]]; then
    action="overwrite"
  fi

  local docs_dev_dependencies=''
  if [[ "${INIT_MD}" == true || "${INIT_PRETTIER}" == true ]]; then
    docs_dev_dependencies=$(cat <<EOF
    "markdownlint-cli": "${MARKDOWNLINT_CLI_VERSION}",
    "prettier": "${PRETTIER_VERSION}",
EOF
)
  fi

  local rendered
  rendered=$(cat <<EOF
{
  "name": "project",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "lint": "./scripts/style.sh lint",
    "lint:fix": "./scripts/style.sh lint --fix",
    "lint:modified": "./scripts/style.sh lint --modified",
    "format": "./scripts/style.sh format",
    "format:modified": "./scripts/style.sh format --modified"
  },
  "devDependencies": {
    "@biomejs/biome": "${BIOME_VERSION}",
${docs_dev_dependencies}    "typescript": "${TYPESCRIPT_VERSION}"
  }
}
EOF
)

  if [[ "${DRY_RUN}" == true ]]; then
    info "[dry-run] Would ${action}: ${dest}"
    if [[ "${action}" == "overwrite" ]]; then
      ((overwritten++)) || true
    else
      ((created++)) || true
    fi
    return
  fi

  printf '%s\n' "${rendered}" > "${dest}"
  if [[ "${action}" == "overwrite" ]]; then
    success "Overwrote: ${dest}"
    ((overwritten++)) || true
  else
    success "Created: ${dest}"
    ((created++)) || true
  fi
}

init_python_config() {
  local dest="${TARGET_DIR}/pyproject.toml"

  if [[ -e "${dest}" ]]; then
    error "Refusing to overwrite existing Python project file: ${dest}"
    error "Merge the Ruff/Black settings from scripts/templates/python-pyproject.toml manually."
    ((failed++)) || true
    return
  fi

  copy_template "python-pyproject.toml" "pyproject.toml"
}

init_ts_config() {
  copy_template "biome.json" "biome.json"
  copy_template "tsconfig.json" "tsconfig.json"

  if [[ -e "${TARGET_DIR}/package.json" ]]; then
    warn "Refusing to overwrite existing package.json: ${TARGET_DIR}/package.json"
    warn "Merge the TypeScript style scripts and required devDependencies manually."
    ((skipped++)) || true
    return
  fi

  write_ts_package_json
}

info "Target directory: ${TARGET_DIR}"
info "Selected initializers:"
[[ "${INIT_MD}" == true ]] && info "  - markdownlint"
[[ "${INIT_PRETTIER}" == true ]] && info "  - prettier"
[[ "${INIT_RUST}" == true ]] && info "  - rust"
[[ "${INIT_TS}" == true ]] && info "  - ts"
[[ "${INIT_PYTHON}" == true ]] && info "  - python"
[[ "${INIT_GO}" == true ]] && info "  - go"
[[ "${INIT_SHELL}" == true ]] && info "  - shell"
[[ "${DRY_RUN}" == true ]] && warn "Dry run mode enabled; no files will be written"

if [[ "${INIT_MD}" == true ]]; then
  copy_template "markdownlint.json" ".markdownlint.json"
  copy_template "markdownlintignore" ".markdownlintignore"
fi

if [[ "${INIT_PRETTIER}" == true ]]; then
  copy_template "prettierrc.json" ".prettierrc"
  copy_template "prettierignore" ".prettierignore"
fi

if [[ "${INIT_RUST}" == true ]]; then
  copy_template "rustfmt.toml" "rustfmt.toml"
  copy_template "clippy.toml" "clippy.toml"
fi

if [[ "${INIT_TS}" == true ]]; then
  init_ts_config
fi

if [[ "${INIT_PYTHON}" == true ]]; then
  init_python_config
fi

if [[ "${INIT_GO}" == true ]]; then
  generate_go_config
fi

if [[ "${INIT_SHELL}" == true ]]; then
  ensure_gitignore_entry "/tools/shellcheck"
fi

echo
info "Summary:"
echo "  Created: ${created}"
echo "  Overwritten: ${overwritten}"
echo "  Skipped: ${skipped}"
echo "  Failed: ${failed}"

if [[ "${failed}" -gt 0 ]]; then
  exit 1
fi

success "Formatter initialization complete."
