#!/usr/bin/env bash
# Runs every prek hook over the whole tree for the `lint` job in
# .github/workflows/test.yaml, then proves no hook silently matched zero
# files. `--color=always` is deliberately omitted: ANSI escapes in the status
# lines would break the greps below, and GitHub renders the plain output
# fine. Run from the repo root.
set -euo pipefail
shopt -s inherit_errexit

# .tmp/ is gitignored, so a log left behind by an aborted run can't trip
# scripts/deploy.sh's dirty-worktree check or get swept into a `git add -A`.
SCRATCH_DIR=".tmp/ci-lint"
mkdir -p "$SCRATCH_DIR"
LOG="$SCRATCH_DIR/prek.log"

set +e
uv run --project portal --group dev prek run --all-files --show-diff-on-failure >"$LOG" 2>&1
status=$?
set -e
cat "$LOG"

grep -qE '^[A-Za-z].*\.\.\.\.+(Passed|Failed)' "$LOG" ||
  { echo "prek ran no hooks at all -- install/clone failure, not a lint result"; exit 1; }

# The grep below is line-anchored to a hook status line. `--show-diff-on-failure`
# puts every rewritten file's diff into this same log -- an unanchored search
# would fire on mdformat's or yapf's own diff and report "the gate is dead"
# for a routine formatting failure.
#
# It catches a matcher that selects NOTHING and nothing more -- a hook that
# merely lost some of its files still prints `Passed`. Partial narrowing is
# portal/tests/test_ci_lint_job.py's job (shell scripts) and the dry-run diff
# below (every other file); a narrowed shellcheck manifest is
# scripts/ci-lint-selftest.sh's.
if grep -qE '^[A-Za-z].*\(no files to check\)Skipped$' "$LOG"; then
  echo "a hook matched no files -- its half of the gate is dead:"
  grep -E '^[A-Za-z].*\(no files to check\)Skipped$' "$LOG"
  exit 1
fi

# `exclude` (or a hook's own matcher) can drop a first-party file from EVERY
# hook's coverage, not just shellcheck's -- portal/tests/test_ci_lint_job.py
# only checks shell scripts specifically. Ask prek for its own resolved file
# lists (ground truth, immune to the Python-re-vs-Rust-regex dialect gap and
# to a hook's own default `types` -- editorconfig-checker, mixed-line-ending
# and the two shebang hooks carry no explicit `types` and between them cover
# nearly every tracked file, which a hand-enumerated language-tag set
# previously missed) instead of reimplementing its matcher rules.
DRY_RUN_LOG="$SCRATCH_DIR/dry-run.log"
uv run --project portal --group dev prek run --dry-run --all-files -vv >"$DRY_RUN_LOG" 2>&1
grep -E '^  - ' "$DRY_RUN_LOG" | sed 's/^  - //' | sort -u >"$SCRATCH_DIR/covered.txt"
test -s "$SCRATCH_DIR/covered.txt" ||
  { echo "prek --dry-run reported no covered files at all -- install/clone failure?"; cat "$DRY_RUN_LOG"; exit 1; }

uv run --project portal --group dev python -c "
import sys
sys.path.insert(0, 'portal/tests')
from test_ci_lint_job import VENDORED, _tags_for_first_party_file, _tracked_files

covered = set(open('$SCRATCH_DIR/covered.txt').read().splitlines())
uncovered = [
    path for path in _tracked_files()
    if not path.startswith(VENDORED) and path not in covered
    and (tags := _tags_for_first_party_file(path)) is not None and 'binary' not in tags
]
if uncovered:
    print('no prek hook would run on these first-party, non-binary tracked files:')
    for path in uncovered:
        print(' ', path)
    raise SystemExit(1)
"

exit "$status"
