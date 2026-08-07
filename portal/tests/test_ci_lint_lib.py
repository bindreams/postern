"""Unit tests for scripts/ci_lint_lib.py's dry-run-log parser and coverage-gap check.

These exercise `parse_dry_run_hook_files` / `find_dry_run_coverage_gaps` against
canned `prek run --dry-run --all-files -vv` transcripts, not a live prek
invocation -- prek's actual output format is exercised for real by
scripts/ci-lint-run.sh in the CI job itself. A change to prek's `-vv` text
format that breaks the regexes below is exactly the kind of blind spot this
file exists to close: without it, the parser is exercised only by a live CI
run, where a format shift shows up as an opaque exception or a silently wrong
file list rather than a clear assertion failure.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from ci_lint_lib import find_dry_run_coverage_gaps  # noqa: E402
from ci_lint_lib import parse_dry_run_hook_files  # noqa: E402

# A trimmed but structurally real transcript covering every entry in
# `PER_HOOK_CHECKS` plus the two hooks it deliberately excludes: two ordinary
# hooks, a `pass_filenames = false` hook (ty, no file list at all), and the
# two same-id mdformat entries told apart only by their display name. Tracked
# files are a.py/b.py (python), README.md (non-docs markdown), and
# docs/index.md (docs markdown) -- none carry the `executable` tag, so
# `check that executables have shebangs` and `Check .editorconfig rules`
# (which excludes python/markdown) correctly match nothing here.
SAMPLE_LOG = """\
format section comments.................................................Dry Run
- hook id: format-section-comments
- duration: 0.00s

  `format-section-comments` would be run on 2 files:
  - a.py
  - b.py
ty check................................................................Dry Run
- hook id: ty
- duration: 0.00s
check that executables have shebangs....................................Dry Run
- hook id: check-executables-have-shebangs
- duration: 0.00s
check that scripts with shebangs are executable.........................Dry Run
- hook id: check-shebang-scripts-are-executable
- duration: 0.00s

  `check-shebang-scripts-are-executable` would be run on 4 files:
  - a.py
  - b.py
  - README.md
  - docs/index.md
mixed line ending.......................................................Dry Run
- hook id: mixed-line-ending
- duration: 0.00s

  `mixed-line-ending` would be run on 4 files:
  - a.py
  - b.py
  - README.md
  - docs/index.md
Check .editorconfig rules...............................................Dry Run
- hook id: editorconfig-checker
- duration: 0.00s
yapf....................................................................Dry Run
- hook id: yapf
- duration: 0.00s

  `yapf` would be run on 2 files:
  - a.py
  - b.py
mdformat................................................................Dry Run
- hook id: mdformat
- duration: 0.00s

  `mdformat` would be run on 1 files:
  - README.md
mdformat (myst).........................................................Dry Run
- hook id: mdformat
- duration: 0.00s

  `mdformat (myst)` would be run on 1 files:
  - docs/index.md
"""


def test_parse_dry_run_hook_files_keys_on_display_name_not_hook_id():
    parsed = parse_dry_run_hook_files(SAMPLE_LOG)

    assert parsed["format section comments"] == ["a.py", "b.py"]
    assert parsed["yapf"] == ["a.py", "b.py"]
    # Both mdformat entries share `hook id: mdformat`; only the display name
    # distinguishes them, so a key collision here would silently merge or
    # overwrite one hook's file list with the other's.
    assert parsed["mdformat"] == ["README.md"]
    assert parsed["mdformat (myst)"] == ["docs/index.md"]


def test_parse_dry_run_hook_files_handles_pass_filenames_false_hook():
    parsed = parse_dry_run_hook_files(SAMPLE_LOG)

    assert parsed["ty check"] == []


def test_parse_dry_run_hook_files_on_empty_log_returns_empty_dict():
    assert parse_dry_run_hook_files("") == {}


# Fake tag lookup so these tests need no real files on disk. Keys are the
# fictional paths used in SAMPLE_LOG above.
FAKE_TAGS = {
    "a.py": frozenset({"text", "python"}),
    "b.py": frozenset({"text", "python"}),
    "README.md": frozenset({"text", "markdown"}),
    "docs/index.md": frozenset({"text", "markdown"}),
    "orphan.md": frozenset({"text", "markdown"}),
}


def test_find_dry_run_coverage_gaps_clean_log_reports_nothing():
    tracked = ["a.py", "b.py", "README.md", "docs/index.md"]
    assert find_dry_run_coverage_gaps(SAMPLE_LOG, tracked, FAKE_TAGS.get) == []


def test_find_dry_run_coverage_gaps_flags_a_file_no_hook_claims():
    tracked = ["a.py", "b.py", "README.md", "docs/index.md", "orphan.md"]
    problems = find_dry_run_coverage_gaps(SAMPLE_LOG, tracked, FAKE_TAGS.get)

    assert any("orphan.md" in problem for problem in problems)


def test_find_dry_run_coverage_gaps_flags_per_hook_narrowing_masked_by_union():
    """A file yapf silently dropped, while another hook still covers it in the union."""
    log_with_narrowed_yapf = SAMPLE_LOG.replace(
        "  `yapf` would be run on 2 files:\n  - a.py\n  - b.py\n",
        "  `yapf` would be run on 1 files:\n  - a.py\n",
    )
    # b.py is still claimed by format-section-comments, so the union check
    # alone would report this log as clean -- only the per-hook yapf check
    # catches the narrowing.
    tracked = ["a.py", "b.py", "README.md", "docs/index.md"]
    problems = find_dry_run_coverage_gaps(log_with_narrowed_yapf, tracked, FAKE_TAGS.get)

    assert any("yapf" in problem and "b.py" in problem for problem in problems)


def test_find_dry_run_coverage_gaps_on_no_hooks_at_all_reports_install_failure():
    assert find_dry_run_coverage_gaps("", ["a.py"]) == [
        "prek --dry-run reported no hooks at all -- install/clone failure?"
    ]
