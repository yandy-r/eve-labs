# --- ycc:formatters managed block (do not edit by hand) ---
.PHONY: lint lint-modified lint-staged lint-unstaged lint-fix lint-fix-modified \
        format format-modified format-staged format-unstaged

lint:
	./scripts/style.sh lint

lint-modified:
	./scripts/style.sh lint --modified

lint-staged:
	./scripts/style.sh lint --staged

lint-unstaged:
	./scripts/style.sh lint --unstaged

lint-fix:
	./scripts/style.sh lint --fix

lint-fix-modified:
	./scripts/style.sh lint --fix --modified

format:
	./scripts/style.sh format

format-modified:
	./scripts/style.sh format --modified

format-staged:
	./scripts/style.sh format --staged

format-unstaged:
	./scripts/style.sh format --unstaged
# --- end ycc:formatters managed block ---

.PHONY: test check-labs

test: check-labs

check-labs:
	./scripts/check-labs.py

.PHONY: fix-perms fix-perms-dry-run

fix-perms:
	./scripts/fix-lab-permissions.sh

fix-perms-dry-run:
	./scripts/fix-lab-permissions.sh --dry-run
