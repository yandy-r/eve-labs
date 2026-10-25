# eve-labs — Copilot instructions

Canonical repository policy lives in `AGENTS.md` at the repo root. Read it if your tool can;
the essentials are repeated here in case it cannot follow links.

## Commands

```bash
pnpm install                 # dev tooling (prettier, markdownlint, biome, commitlint)
bash scripts/install-lefthook.sh  # git hooks
```

```bash
make test                    # validate .unl labs (XML + unique <lab id>); also `pnpm test`
```

```bash
make lint                    # ./scripts/style.sh lint; `make format` to auto-format
```

## Essentials

- Never commit secrets (`.env`, tokens, API keys).
- Use Conventional Commits 1.0.0 for commits and PR titles: `type(scope): description`.
- Link the issue in the PR (`Closes #…`) and follow `.github/pull_request_template.md` when present.

## Branching & releases

[`RELEASING.md`](../RELEASING.md) is the source of truth for branches and releases. Branch
off `main` and PR back into it; every release is tagged from `main`. Never merge one
long-lived branch into another to sync it.
