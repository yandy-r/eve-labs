# eve-labs

EVE-NG Pro lab files (`/opt/unetlab/labs` on host `eve`, EVE-NG Pro 7.2).

## Layout

- `Yandy/` – personal labs (CCIE, Datacenter, Cloud, Customers)
- `Shared/`, `Users/` – EVE default folders

## Conventions (this host)

- Cloud networks: `pnet0` = management/device access (untagged mgmt LAN 10.100.51.0/24, trunk);
  `pnet2` = VM traffic trunk for VLANs 1240-1243. `pnet1`, `pnet3`-`pnet9` are not brought up.
- Every `.unl` needs a unique `id` attribute on `<lab>` (EVE 7 rejects labs without one).
- Lab files must be owned by `www-data` so EVE can save them.
- Default device login in startup configs: `admin123`.

## Workflow

Commit from the host after changing labs in the UI:

```bash
cd /opt/unetlab/labs && git add -A && git commit -m "..." && git push
```

Ignored: the code-search `index`, `.updated` marker, lock/temp files.

## Development

Tooling runs on a workstation clone, not on the EVE host. Requires Node (LTS) with pnpm,
Python 3.11+, and `make`.

```bash
pnpm install                       # pinned prettier, markdownlint, biome, commitlint
bash scripts/install-lefthook.sh   # wire pre-commit / pre-push / commit-msg hooks
git config commit.template .gitmessage
```

| Task            | Command                                                       |
| --------------- | ------------------------------------------------------------- |
| Test            | `make test` (or `pnpm test`) — `.unl` XML + unique `<lab id>` |
| Lint            | `make lint` (or `./scripts/style.sh lint`)                    |
| Lint, auto-fix  | `make lint-fix`                                               |
| Format          | `make format`                                                 |
| Commit messages | Conventional Commits, enforced by commitlint and PR-title CI  |

CI runs `Lint`, `Test`, and `PR title` on every pull request; `Lint autofix` pushes
formatting fixes back to same-repo PR branches.

## Releasing

Releases are trunk-only: tags `vX.Y.Z` cut from `main` by a maintainer. See
[`RELEASING.md`](RELEASING.md) for the rules and steps.

## License

[MIT](LICENSE)

## Linting & Formatting

This project uses a self-contained lint/format bundle rooted in `scripts/style.sh`. Run it directly,
via the package-manager aliases below, or wire it into CI.

### One-command bootstrap

If you cloned this repo fresh and `scripts/style.sh` is missing (it ships managed), re-run
`ycc:formatters --sync` from Claude Code to reinstall the bundle.

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

- **Docs**: `markdownlint` + `prettier` (`.markdownlint.json`, `.prettierrc`) for Markdown/YAML.
- **JSON**: `biome` (`biome.json`).
- **Python**: `ruff` + `black` for `scripts/*.py`.

- **Shell**: `shellcheck --severity=warning` on `*.sh`.

### CI

`.github/workflows/lint.yml` runs the check; `lint-autofix.yml` applies fixes on PRs.

### Hooks

`lefthook.yml` runs `style.sh lint --staged --fix`, `style.sh format --staged`, and
`check-labs.py` on commit, `lint` + `make test` on push, and commitlint on the message.
To bypass once: `git commit --no-verify`.

### Advanced

- **Upgrade the bundle**: re-run `ycc:formatters --sync` from Claude Code. This prunes stale managed
  files and copies the latest scripts.
- **Ignore paths**: add entries to `.prettierignore`, `.markdownlintignore`, `.gitignore`, or
  tool-native ignore keys (`ruff exclude`, `biome files.ignore`, `.golangci.yml
issues.exclude-rules`).
- **Modified-only mode** reads `git diff --name-only HEAD` — untracked files are included when
  `scripts/lib/modified-files.sh` sees them with `git status --porcelain`.
