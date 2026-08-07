#!/usr/bin/env bash
# Fixture self-test for the `lint` job in .github/workflows/test.yaml. Proves
# the shellcheck and ty hooks still catch a known-bad file, that prek's
# zero-match reporting still matches the phrase scripts/ci-lint-run.sh greps
# for, and that shellcheck's own hook manifest (pinned upstream by
# prek.toml's `rev =`, not written there) still reaches every first-party
# shell script. Run from the repo root.
set -euo pipefail
shopt -s inherit_errexit

# Scratch output lives under .tmp/ (gitignored) so a run that aborts before
# the trap-based cleanup below can't trip scripts/deploy.sh's dirty-worktree
# check or get swept into a `git add -A`. The two fixture files below are the
# exception: prek matches them by their real, meaningful path (repo root for
# `--files`, portal/src/postern/ for ty's whole-project scan), so they can't
# move into the scratch dir.
SCRATCH_DIR=".tmp/ci-lint"
mkdir -p "$SCRATCH_DIR"

# A hard abort (SIGINT, a CI job cancel, any `exit 1` below) between creating
# a fixture and its matching `rm` would otherwise leave it on disk -- and a
# stray ty fixture left in portal/src/postern/ would poison the real prek run
# in scripts/ci-lint-run.sh and be misread as a genuine type error. The trap
# covers every exit path in one place instead of relying on in-line ordering.
trap 'rm -rf "$SCRATCH_DIR" .prek-gate-fixture.sh portal/src/postern/_ty_gate_fixture.py' EXIT

cat >.prek-gate-fixture.sh <<'FIXTURE'
#!/usr/bin/env bash
set -e
f() { false; }
if f; then echo yes; fi
export REV=$(git rev-parse HEAD)
echo $REV
FIXTURE
test -s .prek-gate-fixture.sh || { echo "could not write the shell fixture -- setup failure"; exit 1; }

set +e
uv run --project portal --group dev prek run shellcheck \
  --files .prek-gate-fixture.sh >"$SCRATCH_DIR/shellcheck-fixture.log" 2>&1
sc_status=$?
set -e
rm .prek-gate-fixture.sh

printf 'x: int = "not an int"\n' >portal/src/postern/_ty_gate_fixture.py
test -s portal/src/postern/_ty_gate_fixture.py ||
  { echo "could not write the ty fixture -- setup failure"; exit 1; }

set +e
uv run --project portal --group dev prek run ty --all-files >"$SCRATCH_DIR/ty-fixture.log" 2>&1
ty_status=$?
set -e
rm portal/src/postern/_ty_gate_fixture.py
test ! -e portal/src/postern/_ty_gate_fixture.py ||
  { echo "ty fixture cleanup failed -- aborting before it poisons the real run"; exit 1; }

echo "--- shellcheck fixture ---"
cat "$SCRATCH_DIR/shellcheck-fixture.log"
echo "--- ty fixture ---"
cat "$SCRATCH_DIR/ty-fixture.log"

# Assert the hook RAN before judging what it found: a prek install failure or
# an unreachable hook repo also produces "no SC2155", and reporting that as a
# dead lint gate would misdiagnose an outage.
grep -qE '^shellcheck\.+(Failed|Passed)' "$SCRATCH_DIR/shellcheck-fixture.log" ||
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

grep -qE '^ty check\.+(Failed|Passed)' "$SCRATCH_DIR/ty-fixture.log" ||
  { echo "prek never ran the ty hook -- install failure?"; exit 1; }
test "$ty_status" -ne 0 ||
  { echo "ty passed a known-bad annotation -- the type gate is dead"; exit 1; }
grep -q 'invalid-assignment' "$SCRATCH_DIR/ty-fixture.log" || { echo "no invalid-assignment -- the type gate is dead"; exit 1; }
grep -q '_ty_gate_fixture' "$SCRATCH_DIR/ty-fixture.log" || { echo "ty never saw the fixture -- the type gate is dead"; exit 1; }

# scripts/ci-lint-run.sh's zero-match grep rests on an assumption -- that prek
# reports a hook matching no files as `Skipped` with this exact phrase and
# exit 0 -- that nothing above has exercised. Prove it against real prek
# output, the same way the two fixtures above prove the `Failed|Passed`
# format. README.md is never shell, so shellcheck matches nothing -- but
# confirm it actually exists first: prek reports the identical
# `(no files to check)Skipped` line and exit 0 for a *missing* path too
# (with an extra, unchecked warning line), so an unasserted input would let
# this fixture silently start proving the wrong thing.
test -f README.md || { echo "zero-match fixture input (README.md) is gone -- pick another always-present non-shell file"; exit 1; }
set +e
uv run --project portal --group dev prek run shellcheck \
  --files README.md >"$SCRATCH_DIR/zero-match-fixture.log" 2>&1
zm_status=$?
set -e
echo "--- zero-match fixture ---"
cat "$SCRATCH_DIR/zero-match-fixture.log"
test "$zm_status" -eq 0 ||
  { echo "prek exited nonzero on a hook matching no files -- the zero-match assumption is already wrong"; exit 1; }
grep -qE '^shellcheck\.+\(no files to check\)Skipped$' "$SCRATCH_DIR/zero-match-fixture.log" ||
  { echo "prek's zero-match output no longer matches the grep in ci-lint-run.sh -- update it"; exit 1; }

# The shellcheck hook's OWN matcher config -- types/exclude_types/stages --
# is pinned by prek.toml's `rev =`, not written there, so it is invisible to
# portal/tests/test_ci_lint_job.py, which only ever reads prek.toml's own
# text. Ask prek directly whether it still reaches every real first-party
# shell script instead of inferring from static config. NUL-delimited on both
# ends -- git ls-files -z (this oracle's own source, in
# portal/tests/test_ci_lint_job.py) is NUL-safe specifically so a tracked
# filename containing a literal newline round-trips intact; joining on '\n'
# here would silently reintroduce that exact class of corruption.
uv run --project portal --group dev python -c "
import sys
sys.path.insert(0, 'portal/tests')
from test_ci_lint_job import _first_party_shell_scripts
sys.stdout.write('\0'.join(_first_party_shell_scripts()))
" >"$SCRATCH_DIR/shell-scripts.nul"
test -s "$SCRATCH_DIR/shell-scripts.nul" || { echo "no first-party shell scripts found -- the oracle broke"; exit 1; }
while IFS= read -r -d '' path; do
  set +e
  uv run --project portal --group dev prek run shellcheck --files "$path" >"$SCRATCH_DIR/reach.log" 2>&1
  reach_status=$?
  set -e
  # Same "assert the hook ran before judging what it found" rule as the two
  # fixtures above: an infra failure (hook-env install, a network blip
  # fetching the shellcheck repo) also yields a nonzero status with no
  # "Skipped" line, and must not be reported as a real finding in $path.
  grep -qE '^shellcheck\.+(Failed|Passed)' "$SCRATCH_DIR/reach.log" ||
    { echo "prek never ran the shellcheck hook for $path -- install/clone failure?"; cat "$SCRATCH_DIR/reach.log"; exit 1; }
  if grep -q '(no files to check)Skipped' "$SCRATCH_DIR/reach.log"; then
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
