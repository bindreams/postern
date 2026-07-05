# Contributing

The full contributor documentation — local stack setup, all test suites, code style, and the vendored-code workflow — lives in [docs/development/](docs/development/index.md) (rendered at <https://postern.readthedocs.io>).

## Setup

```bash
cd portal
uv sync --all-extras   # runtime + dev deps into portal/.venv
cd ..
prek install           # git hooks (pre-commit + commit-msg)
```

## Before opening a PR

1. `cd portal && uv run pytest` — all tests pass.
1. `prek run --all-files` — clean.
1. `external/` unchanged, unless the PR is intentionally pulling a new upstream ref.
1. Commit subjects are single-line [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

If your change touches anything under the "architecture invariants" list in [CLAUDE.md](CLAUDE.md), explicitly call out why the invariant still holds (or why you updated all the linked locations together).
