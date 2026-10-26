# eve-labs

EVE-NG Pro lab files (`/opt/unetlab/labs` on host `eve`, EVE-NG Pro 7.2).

## Layout

- `labs/CCIE/`, `labs/Datacenter/`, `labs/Cloud/` – personal labs
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

## Host maintenance (after git pull/push)

Git operations on the host run as your shell user (usually `root`), so pulled or checked-out
files lose the `www-data` ownership and modes EVE needs. Symptoms: labs won't open or save,
"permission denied" or empty lab reads, nodes failing to start. Run these on host `eve`.

Restore EVE permissions (run after every `git pull`, checkout, merge, or rebase):

```bash
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions
```

Faster alternative that fixes only the labs tree (skips `.git/` and `node_modules/`):

```bash
/opt/unetlab/labs/scripts/fix-lab-permissions.sh            # owner www-data:www-data; dirs 2775; files 664; scripts 775
/opt/unetlab/labs/scripts/fix-lab-permissions.sh --dry-run  # print the commands only
```

Or `make fix-perms` / `make fix-perms-dry-run` from `/opt/unetlab/labs` (`make` ships on the
Ubuntu host; `pnpm fix-perms` also works where Node is installed).

One-time git setup in the host clone:

```bash
cd /opt/unetlab/labs
git config --global --add safe.directory /opt/unetlab/labs  # repo owned by www-data, git run as root
git config core.fileMode false                               # ignore chmod churn from fixpermissions
```

Optional: fix permissions automatically after pulls and checkouts with git hooks:

```bash
cd /opt/unetlab/labs
for h in post-merge post-checkout post-rewrite; do
  printf '#!/bin/sh\nexec ./scripts/fix-lab-permissions.sh\n' > ".git/hooks/$h"
  chmod +x ".git/hooks/$h"
done
```

If a lab still misbehaves, close it in the UI and stop its nodes before pulling; pulling over a
lab that is open or running can leave EVE's copy out of sync with the file on disk.

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
