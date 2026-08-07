#!/usr/bin/env bash
# Fixture self-test for the `lint` job in .github/workflows/test.yaml. Proves
# the shellcheck and ty hooks still catch a known-bad file, that prek's
# zero-match reporting still matches the phrase scripts/ci-lint-run.sh greps
# for, and that shellcheck's own hook manifest (pinned upstream by
# prek.toml's `rev =`, not written there) still reaches every first-party
# shell script. Run from the repo root.
set -euo pipefail
shopt -s inherit_errexit

# Exclusive lock, held for this script's entire run, shared with
# scripts/ci-lint-run.sh (same lock file): the ty fixture below briefly
# exists as a real file under portal/src/postern/, and ty's
# `pass_filenames = false` hook scans that whole directory regardless of git
# tracking -- so a concurrent `ci-lint-run.sh` (a second terminal during
# local debugging, or a retried job) would see the fixture as a genuine type
# error in the real run, not just in this script's own fixtures. `mkdir -p`
# both so a from-scratch checkout has somewhere for the lock file to live.
#
# Scope: this lock only serializes THIS script against `ci-lint-run.sh`
# specifically (the pair that matters in CI, where they run as two steps of
# the same job). It does NOT serialize against an unrelated concurrent
# `prek run` / `git commit` (the installed pre-commit hook) / `git add -A` in
# the same working tree -- those don't take this lock either, so the two
# fixture files below are gitignored as a second line of defense: a leak from
# that scenario can't be staged or trip scripts/deploy.sh's dirty-worktree
# check, even though it can still transiently misdiagnose a concurrent manual
# `prek run ty` as a real type error. Don't run this script while also
# running `prek`/`git commit` by hand in the same checkout.
mkdir -p .tmp
exec 9>.tmp/ci-lint.lock
flock -x 9

# Scratch output lives under .tmp/ (gitignored) so a run that aborts before
# the trap-based cleanup below can't trip scripts/deploy.sh's dirty-worktree
# check or get swept into a `git add -A`. The two fixture files below are the
# exception: prek matches them by their real, meaningful path (repo root for
# `--files`, portal/src/postern/ for ty's whole-project scan), so they can't
# move into the scratch dir -- both patterns are in .gitignore for the same
# reason as a leftover .tmp/ scratch dir. mktemp'd rather than fixed names, as
# defense in depth alongside the flock above and for a clearer diagnostic if
# the lock is ever bypassed (e.g. a future edit that drops it from one of the
# two scripts).
#
# The trap is installed BEFORE any of the three `mktemp` calls, not after: an
# empty-string path in the trap body is a harmless `rm -rf ""` no-op, but a
# trap installed only after all three succeed leaves a window where the
# 2nd/3rd `mktemp` failing (disk full, a permissions issue) aborts under
# `set -e` with whatever the 1st/2nd already created never cleaned up -- for
# TY_FIXTURE specifically, that's the same poisoning risk this whole trap
# exists to prevent.
SCRATCH_DIR="" FIXTURE_SH="" TY_FIXTURE=""
trap 'rm -rf "$SCRATCH_DIR" "$FIXTURE_SH" "$TY_FIXTURE"' EXIT
SCRATCH_DIR="$(mktemp -d .tmp/ci-lint-selftest-XXXXXX)"
FIXTURE_SH="$(mktemp --suffix=.sh .prek-gate-fixture-XXXXXX)"
TY_FIXTURE="$(mktemp --suffix=.py portal/src/postern/_ty_gate_fixture_XXXXXX)"

cat >"$FIXTURE_SH" <<'FIXTURE'
#!/usr/bin/env bash
set -e
f() { false; }
if f; then echo yes; fi
export REV=$(git rev-parse HEAD)
echo $REV
FIXTURE
test -s "$FIXTURE_SH" || { echo "could not write the shell fixture -- setup failure"; exit 1; }

set +e
uv run --project portal --group dev prek run shellcheck \
  --files "$FIXTURE_SH" >"$SCRATCH_DIR/shellcheck-fixture.log" 2>&1
sc_status=$?
set -e
rm "$FIXTURE_SH"

printf 'x: int = "not an int"\n' >"$TY_FIXTURE"
test -s "$TY_FIXTURE" || { echo "could not write the ty fixture -- setup failure"; exit 1; }

set +e
uv run --project portal --group dev prek run ty --all-files >"$SCRATCH_DIR/ty-fixture.log" 2>&1
ty_status=$?
set -e
rm "$TY_FIXTURE"

echo "--- shellcheck fixture ---"
cat "$SCRATCH_DIR/shellcheck-fixture.log"
echo "--- ty fixture ---"
cat "$SCRATCH_DIR/ty-fixture.log"

# Assert the hook RAN before judging what it found: a prek install failure or
# an unreachable hook repo also produces "no SC2155", and reporting that as a
# dead lint gate would misdiagnose an outage. The alternation includes the
# `(no files to check)Skipped` status prek prints when a hook's matcher
# selects nothing -- that status contains neither `Failed` nor `Passed`, so a
# narrower grep here would misreport a narrowed-out fixture as an install
# failure instead of letting the status-code check below call it what it is.
grep -qE '^shellcheck\.+(Failed|Passed|\(no files to check\)Skipped)$' "$SCRATCH_DIR/shellcheck-fixture.log" ||
  { echo "prek never ran the shellcheck hook -- install/clone failure?"; exit 1; }
test "$sc_status" -ne 0 ||
  { echo "shellcheck passed a known-bad script -- the shell gate is dead"; exit 1; }
grep -q SC2155 "$SCRATCH_DIR/shellcheck-fixture.log" || { echo "no SC2155 finding -- the shell gate is dead"; exit 1; }
grep -q SC2086 "$SCRATCH_DIR/shellcheck-fixture.log" || { echo "no SC2086 finding -- the shell gate is dead"; exit 1; }
# SC2310 only fires with the optional check-set-e-suppressed enabled
# (prek.toml's `args` on this hook) -- proves that arg still reaches the
# linter, not just that the hook runs at all.
grep -q SC2310 "$SCRATCH_DIR/shellcheck-fixture.log" ||
  { echo "no SC2310 finding -- check-set-e-suppressed is not reaching shellcheck"; exit 1; }

grep -qE '^ty check\.+(Failed|Passed|\(no files to check\)Skipped)$' "$SCRATCH_DIR/ty-fixture.log" ||
  { echo "prek never ran the ty hook -- install failure?"; exit 1; }
test "$ty_status" -ne 0 ||
  { echo "ty passed a known-bad annotation -- the type gate is dead"; exit 1; }
grep -q 'invalid-assignment' "$SCRATCH_DIR/ty-fixture.log" || { echo "no invalid-assignment -- the type gate is dead"; exit 1; }
grep -q '_ty_gate_fixture' "$SCRATCH_DIR/ty-fixture.log" || { echo "ty never saw the fixture -- the type gate is dead"; exit 1; }

# scripts/ci-lint-run.sh's zero-match grep rests on an assumption -- that prek
# reports a hook matching no files as `Skipped` with this exact phrase and
# exit 0 -- that nothing above has exercised. Prove it against real prek
# output, the same way the two fixtures above prove the `Failed|Passed`
# format. README.md is never shell, so shellcheck matches nothing -- but prek
# reports the identical `(no files to check)Skipped` line and exit 0 for a
# *missing* path too, distinguished only by an extra warning line, so this
# fixture asserts that warning is absent from the captured output rather than
# pre-checking README.md's existence (which a later, separate command could
# race).
set +e
uv run --project portal --group dev prek run shellcheck \
  --files README.md >"$SCRATCH_DIR/zero-match-fixture.log" 2>&1
zm_status=$?
set -e
echo "--- zero-match fixture ---"
cat "$SCRATCH_DIR/zero-match-fixture.log"
test "$zm_status" -eq 0 ||
  { echo "prek exited nonzero on a hook matching no files -- the zero-match assumption is already wrong"; exit 1; }
! grep -q 'does not exist and will be ignored' "$SCRATCH_DIR/zero-match-fixture.log" ||
  { echo "prek treated README.md as a missing path -- pick another always-present non-shell fixture file"; exit 1; }
grep -qE '^shellcheck\.+\(no files to check\)Skipped$' "$SCRATCH_DIR/zero-match-fixture.log" ||
  { echo "prek's zero-match output no longer matches the grep in ci-lint-run.sh -- update it"; exit 1; }

# The shellcheck hook's OWN matcher config -- types/exclude_types/stages --
# is pinned by prek.toml's `rev =`, not written there, so it is invisible to
# portal/tests/test_ci_lint_job.py, which only ever reads prek.toml's own
# text. Ask prek directly whether it still reaches every real first-party
# shell script instead of inferring from static config. NUL-TERMINATED
# (trailing NUL after every path, not just between paths) on both ends --
# `git ls-files -z` (ci_lint_lib.tracked_files, this oracle's own source) is
# NUL-safe both so a tracked filename containing a literal newline round-trips
# intact AND so `while read -d ''` on the far end doesn't silently drop the
# last entry (a '\0'.join(...) separator would).
uv run --project portal --group dev python -c "
import sys
sys.path.insert(0, 'scripts')
from ci_lint_lib import first_party_shell_scripts
sys.stdout.write(''.join(path + '\0' for path in first_party_shell_scripts()))
" >"$SCRATCH_DIR/shell-scripts.nul"
test -s "$SCRATCH_DIR/shell-scripts.nul" || { echo "no first-party shell scripts found -- the oracle broke"; exit 1; }
while IFS= read -r -d '' path; do
  set +e
  uv run --project portal --group dev prek run shellcheck --files "$path" >"$SCRATCH_DIR/reach.log" 2>&1
  reach_status=$?
  set -e
  # The liveness grep must accept the `(no files to check)Skipped` status
  # too, not just `Failed|Passed`: that status is exactly what a narrowed-out
  # $path produces, and it contains neither word. A narrower grep here would
  # misreport the one failure this loop exists to catch -- shellcheck's own
  # upstream matcher having dropped $path -- as an unrelated install/clone
  # failure, and the dedicated diagnostic in the `if` below would never run.
  grep -qE '^shellcheck\.+(Failed|Passed|\(no files to check\)Skipped)$' "$SCRATCH_DIR/reach.log" ||
    { echo "prek never ran the shellcheck hook for $path -- install/clone failure?"; cat "$SCRATCH_DIR/reach.log"; exit 1; }
  # Anchored the same way as the liveness grep above, NOT a bare substring
  # match: this file (a first-party shell script this very loop lints) prints
  # the literal phrase "(no files to check)Skipped" in several unescaped
  # comments and grep patterns, so an unanchored match could fire on the
  # linter's own quoted-source-line output for a genuine finding here and
  # misreport a real lint error as an upstream matcher regression.
  if grep -qE '^shellcheck\.+\(no files to check\)Skipped$' "$SCRATCH_DIR/reach.log"; then
    echo "shellcheck skipped $path -- its upstream hook manifest narrowed to exclude it:"
    cat "$SCRATCH_DIR/reach.log"
    exit 1
  fi
  if [ "$reach_status" -ne 0 ]; then
    echo "shellcheck found a real issue in $path -- fix it, this is not a coverage gap:"
    cat "$SCRATCH_DIR/reach.log"
    exit 1
  fi
done <"$SCRATCH_DIR/shell-scripts.nul"
