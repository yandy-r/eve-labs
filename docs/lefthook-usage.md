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

The script installs the `lefthook` binary (prefers the project's package manager,
falls back to Homebrew, Go, Cargo, or pipx) and wires hooks via `lefthook install`.
It is safe to re-run.

---

## What the hooks do

| Stage        | Purpose                                     | When it fires            |
| ------------ | ------------------------------------------- | ------------------------ |
| `pre-commit` | Lint + format staged files (stack-specific) | Before each `git commit` |
| `pre-push`   | Not configured (no test command detected)   | —                        |

Pre-commit commands receive `{staged_files}` from lefthook so they only touch
files in the git index — fast, focused feedback. Files auto-fixed by the linter
are re-staged via `stage_fixed: true`.

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
