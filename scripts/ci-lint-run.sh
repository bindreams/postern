#!/usr/bin/env bash
# Runs every prek hook over the whole tree for the `lint` job in
# .github/workflows/test.yaml, then proves no hook silently matched zero
# files. `--color=always` is deliberately omitted: ANSI escapes in the status
# lines would break the greps below, and GitHub renders the plain output
# fine. Run from the repo root.
set -uo pipefail
shopt -s inherit_errexit

set +e
uv run --project portal --group dev prek run --all-files --show-diff-on-failure >prek.log 2>&1
status=$?
set -e
cat prek.log

grep -qE '^[A-Za-z].*\.\.\.\.+(Passed|Failed)' prek.log ||
  { echo "prek ran no hooks at all -- install/clone failure, not a lint result"; exit 1; }

# The grep below is line-anchored to a hook status line. `--show-diff-on-failure`
# puts every rewritten file's diff into this same log -- an unanchored search
# would fire on mdformat's or yapf's own diff and report "the gate is dead"
# for a routine formatting failure.
#
# It catches a matcher that selects NOTHING and nothing more -- a hook that
# merely lost some of its files still prints `Passed`. Partial narrowing is
# portal/tests/test_ci_lint_job.py's job; a narrowed shellcheck manifest is
# scripts/ci-lint-selftest.sh's.
if grep -qE '^[A-Za-z].*\(no files to check\)Skipped$' prek.log; then
  echo "a hook matched no files -- its half of the gate is dead:"
  grep -E '^[A-Za-z].*\(no files to check\)Skipped$' prek.log
  exit 1
fi

exit "$status"
