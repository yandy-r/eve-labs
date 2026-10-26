# Lefthook — Git Hooks for eve-labs

This project uses [lefthook](https://github.com/evilmartians/lefthook) — a fast,
cross-platform git hook manager — to run linters, formatters, and validation
automatically around git operations.

---

## First-time setup

Run the bootstrap once per checkout:

```bash
./scripts/install-lefthook.sh
```

When `package.json` is present the script runs `pnpm install`, then uses `lefthook`
from `node_modules/.bin` or `PATH`. Lefthook is not a pnpm dependency; if neither
binary exists, the script installs it with Homebrew, Go, Cargo, or pipx, then runs
`lefthook install`. Safe to re-run.

---

## What the hooks do

| Stage        | Purpose                                                         | When it fires            |
| ------------ | --------------------------------------------------------------- | ------------------------ |
| `pre-commit` | Lint and format staged files; `check-labs.py` on staged `*.unl` | Before each `git commit` |
| `pre-push`   | `style.sh lint` and `make test`                                 | Before each `git push`   |
| `commit-msg` | `pnpm exec commitlint --edit {1}`                               | On the commit message    |

Lint runs `./scripts/style.sh lint --staged --fix` and format runs
`./scripts/style.sh format --staged`. Both read the git index. `check-labs.py` is
the only pre-commit command that receives `{staged_files}`, and only for `*.unl`.
Auto-fixed files are re-staged (`stage_fixed: true`).

---

## Bypassing hooks

- **One commit**: `git commit --no-verify`
- **One push**: `git push --no-verify`
- **In CI**: lefthook checks the `CI=true` env var and skips hooks automatically.
  No special config is needed for GitHub Actions or similar platforms.

---

## Extending the config

Edit `lefthook.yml` at the project root. Common additions:

```yaml
pre-commit:
  commands:
    custom-check:
      run: <your command>
      glob: "*.<extension>"
```

See the [lefthook documentation](https://github.com/evilmartians/lefthook/blob/master/docs/configuration.md)
for the full schema, placeholders (`{staged_files}`, `{all_files}`, `{1}`, etc.),
and available lifecycle stages (`pre-commit`, `commit-msg`, `pre-push`,
`post-checkout`, `post-merge`, …).

---

## Troubleshooting

- **Hook didn't fire**: run `lefthook dump` to confirm the config is loaded, then
  `ls -la .git/hooks/` to confirm the hook files are present.
- **Hook fires but fails immediately**: the binary may not be on `$PATH`. The
  install script sets up a local `node_modules/.bin/lefthook` for Node projects
  or installs globally otherwise. Re-run `./scripts/install-lefthook.sh`.
- **Need to skip a specific file**: add an `exclude:` glob under the command in
  `lefthook.yml`. See the docs linked above.

---

## Migrating from another hook manager

If contributors previously used `pre-commit` (the Python framework) or `husky`:

```bash
# pre-commit framework
pre-commit uninstall

# husky
rm -rf .husky
```

Then run `./scripts/install-lefthook.sh` to rewrite `.git/hooks/` cleanly.
