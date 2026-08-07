#!/usr/bin/env bash
# Fixture self-test for the `lint` job in .github/workflows/test.yaml. Proves
# the shellcheck and ty hooks still catch a known-bad file, that prek's
# zero-match reporting still matches the phrase the next step greps for, and
# that shellcheck's own hook manifest (pinned upstream by prek.toml's `rev =`,
# not written there) still reaches every first-party shell script. Run from
# the repo root.
set -euo pipefail
shopt -s inherit_errexit

# Isolation from the real run (scripts/ci-lint-run.sh) is the `rm` lines, NOT
# the `--files` argument. The shellcheck fixture is untracked and
# `--all-files` enumerates via `git ls-files`, so that one is doubly safe --
# but the ty hook sets `pass_filenames = false`, so prek passes it no
# filenames at all and `ty` scans the whole portal project off the
# filesystem. A ty fixture left on disk would poison the real run and be
# misread as a genuine type error. Hence plain `rm` plus an explicit
# gone-check, not `rm -f`.
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
  --files .prek-gate-fixture.sh >shellcheck-fixture.log 2>&1
sc_status=$?
set -e
rm .prek-gate-fixture.sh

printf 'x: int = "not an int"\n' >portal/src/postern/_ty_gate_fixture.py
test -s portal/src/postern/_ty_gate_fixture.py ||
  { echo "could not write the ty fixture -- setup failure"; exit 1; }

set +e
uv run --project portal --group dev prek run ty --all-files >ty-fixture.log 2>&1
ty_status=$?
set -e
rm portal/src/postern/_ty_gate_fixture.py
test ! -e portal/src/postern/_ty_gate_fixture.py ||
  { echo "ty fixture cleanup failed -- aborting before it poisons the real run"; exit 1; }

echo "--- shellcheck fixture ---"
cat shellcheck-fixture.log
echo "--- ty fixture ---"
cat ty-fixture.log

# Assert the hook RAN before judging what it found: a prek install failure or
# an unreachable hook repo also produces "no SC2155", and reporting that as a
# dead lint gate would misdiagnose an outage.
grep -qE '^shellcheck\.+(Failed|Passed)' shellcheck-fixture.log ||
  { echo "prek never ran the shellcheck hook -- install/clone failure?"; exit 1; }
test "$sc_status" -ne 0 ||
  { echo "shellcheck passed a known-bad script -- the shell gate is dead"; exit 1; }
grep -q SC2155 shellcheck-fixture.log || { echo "no SC2155 finding -- the shell gate is dead"; exit 1; }
grep -q SC2086 shellcheck-fixture.log || { echo "no SC2086 finding -- the shell gate is dead"; exit 1; }
# SC2310 only fires with the optional check-set-e-suppressed enabled
# (prek.toml's `args` on this hook) -- proves that arg still reaches the
# linter, not just that the hook runs at all.
grep -q SC2310 shellcheck-fixture.log ||
  { echo "no SC2310 finding -- check-set-e-suppressed is not reaching shellcheck"; exit 1; }

grep -qE '^ty check\.+(Failed|Passed)' ty-fixture.log ||
  { echo "prek never ran the ty hook -- install failure?"; exit 1; }
test "$ty_status" -ne 0 ||
  { echo "ty passed a known-bad annotation -- the type gate is dead"; exit 1; }
grep -q 'invalid-assignment' ty-fixture.log || { echo "no invalid-assignment -- the type gate is dead"; exit 1; }
grep -q '_ty_gate_fixture' ty-fixture.log || { echo "ty never saw the fixture -- the type gate is dead"; exit 1; }

# scripts/ci-lint-run.sh's zero-match grep rests on an assumption -- that prek
# reports a hook matching no files as `Skipped` with this exact phrase and
# exit 0 -- that nothing above has exercised. Prove it against real prek
# output, the same way the two fixtures above prove the `Failed|Passed`
# format. README.md always exists and is never shell, so shellcheck matches
# nothing.
set +e
uv run --project portal --group dev prek run shellcheck \
  --files README.md >zero-match-fixture.log 2>&1
zm_status=$?
set -e
echo "--- zero-match fixture ---"
cat zero-match-fixture.log
test "$zm_status" -eq 0 ||
  { echo "prek exited nonzero on a hook matching no files -- the zero-match assumption is already wrong"; exit 1; }
grep -qE '^shellcheck\.+\(no files to check\)Skipped$' zero-match-fixture.log ||
  { echo "prek's zero-match output no longer matches the grep in ci-lint-run.sh -- update it"; exit 1; }

# The shellcheck hook's OWN matcher config -- types/exclude_types/stages --
# is pinned by prek.toml's `rev =`, not written there, so it is invisible to
# portal/tests/test_ci_lint_job.py, which only ever reads prek.toml's own
# text. Ask prek directly whether it still reaches every real first-party
# shell script instead of inferring from static config.
uv run --project portal --group dev python -c "
import sys
sys.path.insert(0, 'portal/tests')
from test_ci_lint_job import _first_party_shell_scripts
print('\n'.join(_first_party_shell_scripts()))
" >shell-scripts.txt
test -s shell-scripts.txt || { echo "no first-party shell scripts found -- the oracle broke"; exit 1; }
while IFS= read -r path; do
  set +e
  uv run --project portal --group dev prek run shellcheck --files "$path" >reach.log 2>&1
  reach_status=$?
  set -e
  if grep -q '(no files to check)Skipped' reach.log; then
    echo "shellcheck skipped $path -- its upstream hook manifest narrowed to exclude it:"
    cat reach.log
    exit 1
  fi
  if [ "$reach_status" -ne 0 ]; then
    echo "shellcheck found a real issue in $path -- fix it, this is not a coverage gap:"
    cat reach.log
    exit 1
  fi
done <shell-scripts.txt

rm -f shellcheck-fixture.log ty-fixture.log zero-match-fixture.log shell-scripts.txt reach.log
