# evelab

Python tooling for the EVE-NG lab repository (stdlib only, Python 3.11+).

| Package           | Purpose                                                                      |
| ----------------- | ---------------------------------------------------------------------------- |
| `evelab.common`   | Tool-agnostic building blocks: `.unl` parsing, codecs, text/TOML helpers     |
| `evelab.localize` | `eve-localize`: relocate labs to a new site (guide: `../localize/README.md`) |
| `evelab.analyze`  | `eve-analyze`: fit labs to the host's images and resources (`../analyze/`)   |

## Run

From a checkout, no install needed:

```bash
../scripts/eve-localize --help
../scripts/eve-analyze --help
```

Optional editable install (adds the `eve-localize` and `eve-analyze` console scripts):

```bash
pip install -e python/
```

## Test and lint

```bash
cd python && python3 -I -B -m unittest discover -s tests -t .   # or: make localize-test
ruff check python scripts/check-labs.py && black --check python scripts   # or: make lint
```

## Layout

```text
src/evelab/common/    shared building blocks (must not import a tool package)
src/evelab/localize/  eve-localize
src/evelab/analyze/   eve-analyze
tests/common/         tests for common
tests/localize/       tests, fixtures and goldens for eve-localize
tests/analyze/        tests for eve-analyze (fake EVE host tree, throwaway git repos)
```

A new tool is a new subpackage under `src/evelab/`, a `[project.scripts]` entry, a
`tests/<tool>/` directory and a thin shim in `scripts/`.
