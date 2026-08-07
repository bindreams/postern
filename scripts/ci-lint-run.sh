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

uv run --project portal --group dev python -c "
import re
import sys

sys.path.insert(0, 'portal/tests')
from test_ci_lint_job import VENDORED, _tags_for_first_party_file, _tracked_files

log = open('$DRY_RUN_LOG', encoding='utf-8').read()

# Per-hook file lists, keyed by the display-name status line (e.g.
# 'mdformat (myst)....Dry Run'), NOT '- hook id: <id>' or the backtick-quoted
# name in 'would be run on' -- both of those repeat the bare hook id
# 'mdformat' for both same-id mdformat entries, while only the status line
# carries the distinguishing '(myst)' suffix. Same reasoning as
# test_no_hook_narrows_its_own_file_set_unexpectedly's name-first keying.
sections = re.split(r'(?=^\S.*\.+Dry Run\$)', log, flags=re.MULTILINE)
by_name: dict[str, list[str]] = {}
for section in sections:
    match = re.match(r'(\S.*?)\.+Dry Run\$', section, re.MULTILINE)
    if not match:
        continue
    hook_name = match.group(1)
    files = re.findall(r'^  - (.+)\$', section, re.MULTILINE)
    by_name.setdefault(hook_name, []).extend(files)

if not by_name:
    print('prek --dry-run reported no hooks at all -- install/clone failure?')
    raise SystemExit(1)

tracked = [path for path in _tracked_files() if not path.startswith(VENDORED)]
# A tracked path containing a literal newline would corrupt the newline-delimited
# parse above (prek's own dry-run output has no NUL-safe mode); flag it explicitly
# rather than silently mis-parsing it as multiple paths.
newline_paths = [path for path in tracked if '\n' in path]
if newline_paths:
    print(f'tracked paths containing a literal newline break the dry-run parse above: {newline_paths}')
    raise SystemExit(1)

# Union coverage: catches exclude/files/default_stages narrowing, which drops
# a file from every hook at once, including the file/executable-wide hooks
# (mixed-line-ending, the two shebang hooks) that dominate the union and make
# it blind to any single OTHER hook narrowing on its own -- 'text' (not
# 'binary' not in tags) also excludes symlinks and directory/gitlink entries,
# which no hook matches and are not a coverage gap.
covered = {path for files in by_name.values() for path in files}
uncovered = [
    path for path in tracked
    if path not in covered and (tags := _tags_for_first_party_file(path)) is not None and 'text' in tags
]
if uncovered:
    print('no prek hook would run on these first-party tracked text files:')
    for path in uncovered:
        print(' ', path)
    raise SystemExit(1)

# Per-hook checks for the hooks whose type restriction is entirely upstream
# (pinned by a shellcheck-py/yapf/mdformat 'rev =', not written in prek.toml)
# and would otherwise be invisible to both the union check above (dominated
# by the file/executable-wide hooks) and
# test_no_hook_narrows_its_own_file_set_unexpectedly (which only sees keys
# actually present in prek.toml). shellcheck already has its own live
# per-file reachability loop in scripts/ci-lint-selftest.sh. The
# file/executable-wide hooks (mixed-line-ending, the two shebang hooks) and
# the hooks whose narrowing keys ARE all in prek.toml (format-section-comments,
# ty, editorconfig-checker) are covered by the checks above and don't need a
# language oracle here.
per_hook_checks = [
    ('yapf', lambda tags: 'python' in tags, lambda path: True),
    ('mdformat', lambda tags: 'markdown' in tags, lambda path: not path.startswith('docs/')),
    ('mdformat (myst)', lambda tags: 'markdown' in tags, lambda path: path.startswith('docs/')),
]
for hook_name, tag_matches, in_scope in per_hook_checks:
    hook_files = set(by_name.get(hook_name, []))
    missing = [
        path for path in tracked
        if in_scope(path) and (tags := _tags_for_first_party_file(path)) is not None
        and tag_matches(tags) and path not in hook_files
    ]
    if missing:
        print(f'{hook_name} would not run on these in-scope first-party files -- its upstream matcher narrowed: {missing}')
        raise SystemExit(1)
"

exit "$status"
