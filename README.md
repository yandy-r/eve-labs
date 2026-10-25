# eve-labs

EVE-NG Pro lab files (`/opt/unetlab/labs` on host `eve`, EVE-NG Pro 7.2).

## Layout
- `Yandy/` – personal labs (CCIE, Datacenter, Cloud, Customers)
- `Clients/` – client labs
- `Shared/`, `Users/` – EVE default folders

## Conventions (this host)
- Cloud networks: `pnet0` = management/device access (untagged mgmt LAN 10.100.51.0/24, trunk);
  `pnet2` = VM traffic trunk for VLANs 1240-1243. `pnet1`, `pnet3`-`pnet9` are not brought up.
- Every `.unl` needs a unique `id` attribute on `<lab>` (EVE 7 rejects labs without one).
- Lab files must be owned by `www-data` so EVE can save them.
- Default device login in startup configs: `admin123`.

## Workflow
Commit from the host after changing labs in the UI:

    cd /opt/unetlab/labs && git add -A && git commit -m "..." && git push

Ignored: the code-search `index`, `.updated` marker, lock/temp files.

## Linting & Formatting

This project uses a self-contained lint/format bundle rooted in `scripts/style.sh`. Run it directly, via the package-manager aliases below, or wire it into CI.

### One-command bootstrap

If you cloned this repo fresh and `scripts/style.sh` is missing (it ships managed), re-run `ycc:formatters --sync` from Claude Code to reinstall the bundle.

### Daily commands

```bash
./scripts/style.sh lint                  # full lint pass (all detected languages)
./scripts/style.sh lint --fix            # auto-fix what is auto-fixable
./scripts/style.sh lint --modified       # staged + unstaged + untracked
./scripts/style.sh lint --staged         # only files staged in the git index
./scripts/style.sh lint --unstaged       # only unstaged + untracked changes
./scripts/style.sh lint --fix --modified # fast pre-push loop
./scripts/style.sh format                # format everything
./scripts/style.sh format --modified     # format modified files
./scripts/style.sh format --staged       # format only staged files
./scripts/style.sh format --unstaged     # format only unstaged + untracked
```

### Per-language tools

- **Docs**: `markdownlint` + `prettier` (`.markdownlint.json`, `.prettierrc`) for Markdown/YAML. In docs-only repos, Prettier also owns JSON/JSONC.

- **Shell**: `shellcheck --severity=warning` on `*.sh`.

### CI

To wire lint into CI, run `ycc:formatters --ci` (installs both `lint.yml` and `lint-autofix.yml`) or pair it with `--no-autofix` to skip the autofix workflow.

### Pre-commit hook (optional)

A pre-commit hook is installed. It runs `./scripts/style.sh lint --modified --fix` before every commit. To bypass once: `git commit --no-verify`.

### Advanced

- **Upgrade the bundle**: re-run `ycc:formatters --sync` from Claude Code. This prunes stale managed files and copies the latest scripts.
- **Ignore paths**: add entries to `.prettierignore`, `.markdownlintignore`, `.gitignore`, or tool-native ignore keys (`ruff exclude`, `biome files.ignore`, `.golangci.yml issues.exclude-rules`).
- **Modified-only mode** reads `git diff --name-only HEAD` — untracked files are included when `scripts/lib/modified-files.sh` sees them with `git status --porcelain`.
