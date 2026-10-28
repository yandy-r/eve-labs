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

test: check-labs localize-test localize-check

check-labs:
	./scripts/check-labs.py

# eve-localize (scripts/eve-localize -> python/src/evelab/localize; guide: localize/README.md)
.PHONY: localize localize-check localize-test localize-sync

localize:
	./scripts/eve-localize

localize-check:
	./scripts/eve-localize check --all --strict

# runs every Python test (common, localize, analyze)
localize-test:
	cd python && python3 -I -B -m unittest discover -s tests -t .

localize-sync:
	@echo "Upstream sync (run these yourself):"
	@echo "  1) ./scripts/eve-localize revert --all --yes"
	@echo "  2) git pull --ff-only"
	@echo "  3) ./scripts/eve-localize apply --all --answers .localize/site.toml --yes"

# eve-analyze (scripts/eve-analyze -> python/src/evelab/analyze; guide: analyze/README.md)
.PHONY: analyze analyze-scan

analyze:
	./scripts/eve-analyze

analyze-scan:
	./scripts/eve-analyze scan

.PHONY: fix-perms fix-perms-dry-run

fix-perms:
	./scripts/fix-lab-permissions.sh

fix-perms-dry-run:
	./scripts/fix-lab-permissions.sh --dry-run
