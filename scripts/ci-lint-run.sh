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
# mktemp -d, not a fixed name: this script and scripts/ci-lint-selftest.sh
# both scratch under .tmp/ci-lint*, and a fixed shared name means a second
# concurrent invocation of either script can read or delete the other's
# in-progress log.
mkdir -p .tmp
SCRATCH_DIR="$(mktemp -d .tmp/ci-lint-run-XXXXXX)"
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
# portal/tests/test_ci_lint_job.py's job (shell scripts) and the dry-run
# checks below (every other hook).
if grep -qE '^[A-Za-z].*\(no files to check\)Skipped$' "$LOG"; then
  echo "a hook matched no files -- its half of the gate is dead:"
  grep -E '^[A-Za-z].*\(no files to check\)Skipped$' "$LOG"
  exit 1
fi

# `exclude`/`files`/`default_stages` (or a hook's own matcher, including one
# pinned upstream by a `rev =` and invisible in prek.toml's own text) can drop
# a first-party file from coverage with none of the above noticing. Ask prek
# for its own resolved per-hook file lists -- ground truth, immune to the
# Python-re-vs-Rust-regex dialect gap -- instead of reimplementing its
# matcher rules. Wrapped in set +e/status capture and cat unconditionally,
# like the real run above: a dry-run failure (bad config, unreachable hook
# repo) must not exit silently with nothing to explain it.
DRY_RUN_LOG="$SCRATCH_DIR/dry-run.log"
set +e
uv run --project portal --group dev prek run --dry-run --all-files -vv >"$DRY_RUN_LOG" 2>&1
dry_run_status=$?
set -e
cat "$DRY_RUN_LOG"
test "$dry_run_status" -eq 0 || { echo "prek --dry-run failed -- install/clone/config failure?"; exit 1; }

# The parsing/diffing logic itself -- including the newline-safety check on
# `tracked`, since prek's plain-text dry-run output has no NUL-safe mode --
# lives in scripts/ci_lint_lib.py, a tracked module, not a string literal
# here: yapf and ty cover it, and portal/tests/test_ci_lint_lib.py unit-tests
# it against canned transcripts.
uv run --project portal --group dev python -c "
import sys

sys.path.insert(0, 'scripts')
from ci_lint_lib import find_dry_run_coverage_gaps, tracked_files, VENDORED

tracked = [path for path in tracked_files() if not path.startswith(VENDORED)]
log = open('$DRY_RUN_LOG', encoding='utf-8').read()
problems = find_dry_run_coverage_gaps(log, tracked)
if problems:
    for problem in problems:
        print(problem)
    raise SystemExit(1)
"

exit "$status"
