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

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import ci_lint_lib  # noqa: E402
from ci_lint_lib import assert_no_newline_paths  # noqa: E402
from ci_lint_lib import find_dry_run_coverage_gaps  # noqa: E402
from ci_lint_lib import is_vendored  # noqa: E402
from ci_lint_lib import parse_dry_run_hook_files  # noqa: E402
from ci_lint_lib import tags_for_first_party_file  # noqa: E402

# A trimmed but structurally real transcript covering every entry in
# `PER_HOOK_CHECKS`, plus `ty check` and `shellcheck` -- the two hooks
# `PER_HOOK_CHECKS` deliberately excludes (see that constant's own header
# comment for why: `pass_filenames = false` makes ty's own `types`
# restriction irrelevant, and shellcheck has its own live per-file
# reachability check in scripts/ci-lint-selftest.sh instead) -- and the two
# same-id mdformat entries told apart only by their display name. Tracked
# files are a.py/b.py (python), README.md (non-docs markdown), docs/index.md
# (docs markdown), run.sh (text+executable+shell, so it also exercises `check
# that executables have shebangs` and `shellcheck`, whose predicates every
# OTHER fixture file here fails), and config.yaml (text, not
# rust/markdown/python, so it also exercises `Check .editorconfig rules`'s
# predicate).
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

  `check-executables-have-shebangs` would be run on 1 files:
  - run.sh
check that scripts with shebangs are executable.........................Dry Run
- hook id: check-shebang-scripts-are-executable
- duration: 0.00s

  `check-shebang-scripts-are-executable` would be run on 6 files:
  - a.py
  - b.py
  - README.md
  - docs/index.md
  - run.sh
  - config.yaml
mixed line ending.......................................................Dry Run
- hook id: mixed-line-ending
- duration: 0.00s

  `mixed-line-ending` would be run on 6 files:
  - a.py
  - b.py
  - README.md
  - docs/index.md
  - run.sh
  - config.yaml
shellcheck...............................................................Dry Run
- hook id: shellcheck
- duration: 0.00s

  `shellcheck` would be run on 1 files:
  - run.sh
Check .editorconfig rules...............................................Dry Run
- hook id: editorconfig-checker
- duration: 0.00s

  `editorconfig-checker` would be run on 2 files:
  - run.sh
  - config.yaml
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

  `mdformat` would be run on 1 files:
  - docs/index.md
"""
# The `mdformat (myst)` section's "would be run on" line above reads
# `` `mdformat` would be run on ... `` -- the bare hook id, matching real prek
# output verbatim (verified against a live `prek run --dry-run --all-files -vv`
# on this repo) -- NOT `` `mdformat (myst)` ``. Both mdformat entries print the
# identical bare-id backtick line; only the status line ("mdformat
# (myst)....Dry Run") carries the distinguishing suffix, which is exactly why
# `parse_dry_run_hook_files` keys on that line instead. See
# test_parse_dry_run_hook_files_ignores_the_backtick_line below.


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


def test_parse_dry_run_hook_files_raises_on_duplicate_display_name():
    """prek.toml does not enforce display-name uniqueness (`name =` is optional).

    Two hooks sharing a display name -- e.g. a third `mdformat`-family entry
    added without a distinguishing `name =` -- must fail loudly instead of
    silently merging into one `by_name` key, which would validate the union of
    both hooks' files against `PER_HOOK_CHECKS` instead of each hook's own list.
    """
    duplicated_log = SAMPLE_LOG.replace(
        "mdformat (myst).........................................................Dry Run\n"
        "- hook id: mdformat\n- duration: 0.00s\n\n  `mdformat` would be run on 1 files:\n  - docs/index.md\n",
        "mdformat................................................................Dry Run\n"
        "- hook id: mdformat\n- duration: 0.00s\n\n  `mdformat` would be run on 1 files:\n  - docs/index.md\n",
    )
    with pytest.raises(ValueError, match="mdformat"):
        parse_dry_run_hook_files(duplicated_log)


def test_find_dry_run_coverage_gaps_reports_duplicate_display_name_instead_of_raising():
    duplicated_log = SAMPLE_LOG.replace(
        "mdformat (myst).........................................................Dry Run\n"
        "- hook id: mdformat\n- duration: 0.00s\n\n  `mdformat` would be run on 1 files:\n  - docs/index.md\n",
        "mdformat................................................................Dry Run\n"
        "- hook id: mdformat\n- duration: 0.00s\n\n  `mdformat` would be run on 1 files:\n  - docs/index.md\n",
    )
    problems = find_dry_run_coverage_gaps(duplicated_log, SAMPLE_TRACKED, FAKE_TAGS.get)

    assert any("mdformat" in problem for problem in problems)


def test_parse_dry_run_hook_files_ignores_the_backtick_line():
    """Both mdformat sections' backtick lines say `` `mdformat` `` -- real prek never
    distinguishes them there. Corrupting that line must not change the parse: it proves
    the parser is keyed on the status line, matching its own docstring's stated design.
    """
    corrupted = SAMPLE_LOG.replace(
        "  `mdformat` would be run on 1 files:\n  - docs/index.md",
        "  `something-else-entirely` would be run on 1 files:\n  - docs/index.md",
    )
    assert parse_dry_run_hook_files(corrupted)["mdformat (myst)"] == ["docs/index.md"]


# Fake tag lookup so these tests need no real files on disk. Keys are the
# fictional paths used in SAMPLE_LOG above.
FAKE_TAGS = {
    "a.py": frozenset({"text", "python"}),
    "b.py": frozenset({"text", "python"}),
    "README.md": frozenset({"text", "markdown"}),
    "docs/index.md": frozenset({"text", "markdown"}),
    "orphan.md": frozenset({"text", "markdown"}),
    "run.sh": frozenset({"text", "executable", "shell"}),
    "config.yaml": frozenset({"text", "yaml"}),
}

SAMPLE_TRACKED = ["a.py", "b.py", "README.md", "docs/index.md", "run.sh", "config.yaml"]


def test_find_dry_run_coverage_gaps_clean_log_reports_nothing():
    assert find_dry_run_coverage_gaps(SAMPLE_LOG, SAMPLE_TRACKED, FAKE_TAGS.get) == []


def test_find_dry_run_coverage_gaps_flags_a_file_no_hook_claims():
    tracked = [*SAMPLE_TRACKED, "orphan.md"]
    problems = find_dry_run_coverage_gaps(SAMPLE_LOG, tracked, FAKE_TAGS.get)

    assert any("orphan.md" in problem for problem in problems)


def test_find_dry_run_coverage_gaps_flags_executable_shebang_narrowing():
    """run.sh is the only fixture matching `check that executables have shebangs`'s
    {"text", "executable"} predicate -- confirm the check actually fires on it,
    not just on files no fixture here exercises.
    """
    log_with_narrowed_hook = SAMPLE_LOG.replace(
        "\n  `check-executables-have-shebangs` would be run on 1 files:\n  - run.sh\n",
        "\n",
    )
    problems = find_dry_run_coverage_gaps(log_with_narrowed_hook, SAMPLE_TRACKED, FAKE_TAGS.get)

    assert any("check that executables have shebangs" in problem and "run.sh" in problem for problem in problems)


def test_find_dry_run_coverage_gaps_flags_editorconfig_narrowing():
    """run.sh and config.yaml are the only fixtures matching `Check .editorconfig
    rules`'s text-but-not-{rust,markdown,python} predicate -- confirm the check
    actually fires on them, not just on files no fixture here exercises.
    """
    log_with_narrowed_hook = SAMPLE_LOG.replace(
        "\n  `editorconfig-checker` would be run on 2 files:\n  - run.sh\n  - config.yaml\n",
        "\n",
    )
    problems = find_dry_run_coverage_gaps(log_with_narrowed_hook, SAMPLE_TRACKED, FAKE_TAGS.get)

    assert any(
        "Check .editorconfig rules" in problem and "run.sh" in problem and "config.yaml" in problem
        for problem in problems
    )


def test_find_dry_run_coverage_gaps_flags_format_section_comments_narrowing():
    """b.py is still claimed by yapf, so the union check alone would report this log
    as clean -- only the per-hook `format section comments` check catches the
    narrowing.
    """
    log_with_narrowed_hook = SAMPLE_LOG.replace(
        "\n  `format-section-comments` would be run on 2 files:\n  - a.py\n  - b.py\n",
        "\n  `format-section-comments` would be run on 1 files:\n  - a.py\n",
    )
    problems = find_dry_run_coverage_gaps(log_with_narrowed_hook, SAMPLE_TRACKED, FAKE_TAGS.get)

    assert any("format section comments" in problem and "b.py" in problem for problem in problems)


def test_find_dry_run_coverage_gaps_flags_check_shebang_scripts_are_executable_narrowing():
    """config.yaml is still claimed by mixed-line-ending and editorconfig-checker, so
    the union check alone would report this log as clean -- only the per-hook
    `check that scripts with shebangs are executable` check catches the narrowing.
    """
    log_with_narrowed_hook = SAMPLE_LOG.replace(
        "  `check-shebang-scripts-are-executable` would be run on 6 files:\n"
        "  - a.py\n  - b.py\n  - README.md\n  - docs/index.md\n  - run.sh\n  - config.yaml\n",
        "  `check-shebang-scripts-are-executable` would be run on 5 files:\n"
        "  - a.py\n  - b.py\n  - README.md\n  - docs/index.md\n  - run.sh\n",
    )
    problems = find_dry_run_coverage_gaps(log_with_narrowed_hook, SAMPLE_TRACKED, FAKE_TAGS.get)

    assert any(
        "check that scripts with shebangs are executable" in problem and "config.yaml" in problem
        for problem in problems
    )


def test_find_dry_run_coverage_gaps_flags_mixed_line_ending_narrowing():
    """run.sh is still claimed by check-executables-have-shebangs, check-shebang-scripts-
    are-executable, and shellcheck, so the union check alone would report this log as
    clean -- only the per-hook `mixed line ending` check catches the narrowing.
    """
    log_with_narrowed_hook = SAMPLE_LOG.replace(
        "  `mixed-line-ending` would be run on 6 files:\n"
        "  - a.py\n  - b.py\n  - README.md\n  - docs/index.md\n  - run.sh\n  - config.yaml\n",
        "  `mixed-line-ending` would be run on 5 files:\n"
        "  - a.py\n  - b.py\n  - README.md\n  - docs/index.md\n  - config.yaml\n",
    )
    problems = find_dry_run_coverage_gaps(log_with_narrowed_hook, SAMPLE_TRACKED, FAKE_TAGS.get)

    assert any("mixed line ending" in problem and "run.sh" in problem for problem in problems)


def test_find_dry_run_coverage_gaps_flags_mdformat_narrowing():
    """README.md is the only fixture in the non-docs mdformat hook's scope -- confirm
    the per-hook check actually fires on it.
    """
    log_with_narrowed_hook = SAMPLE_LOG.replace(
        "\n  `mdformat` would be run on 1 files:\n  - README.md\n",
        "\n",
    )
    problems = find_dry_run_coverage_gaps(log_with_narrowed_hook, SAMPLE_TRACKED, FAKE_TAGS.get)

    assert any("mdformat" in problem and "README.md" in problem for problem in problems)


def test_find_dry_run_coverage_gaps_flags_mdformat_myst_narrowing():
    """docs/index.md is the only fixture in the docs mdformat (myst) hook's scope --
    confirm the per-hook check actually fires on it.
    """
    log_with_narrowed_hook = SAMPLE_LOG.replace(
        "\n  `mdformat` would be run on 1 files:\n  - docs/index.md\n",
        "\n",
    )
    problems = find_dry_run_coverage_gaps(log_with_narrowed_hook, SAMPLE_TRACKED, FAKE_TAGS.get)

    assert any("mdformat (myst)" in problem and "docs/index.md" in problem for problem in problems)


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


def test_find_dry_run_coverage_gaps_reports_newline_paths_instead_of_raising():
    problems = find_dry_run_coverage_gaps(SAMPLE_LOG, ["a.py", "b\nc.py"], FAKE_TAGS.get)
    assert any("newline" in problem for problem in problems)


# is_vendored ==========================================================================================================


def test_is_vendored_reads_prek_tomls_real_exclude_pattern():
    """Against the real, tracked prek.toml (not injected) -- confirms this is a live
    derivation, not a hardcoded prefix that could silently drift from prek.toml's
    actual `exclude`.
    """
    assert is_vendored("external/shadowsocks-rust/Cargo.toml")
    assert not is_vendored("scripts/ci_lint_lib.py")


# tags_for_first_party_file ============================================================================================


def test_tags_for_first_party_file_returns_tags_for_a_real_file():
    # This test file itself is guaranteed to exist and be tracked.
    tags = tags_for_first_party_file("portal/tests/test_ci_lint_lib.py")
    assert tags is not None
    assert "python" in tags


def test_tags_for_first_party_file_returns_none_for_vendored_path():
    assert tags_for_first_party_file("external/shadowsocks-rust/anything.rs") is None


def test_tags_for_first_party_file_returns_none_for_a_missing_path():
    assert tags_for_first_party_file("this/path/does/not/exist.py") is None


def test_tags_for_first_party_file_returns_none_on_a_bare_file_not_found_error(monkeypatch):
    """identify's `tags_from_path` normally wraps an `os.lstat` miss as `ValueError`, but
    for a file it cannot classify from its filename alone, it falls through to a content
    sniff with its own separate `open()` call -- a deletion racing strictly after
    `tags_from_path`'s own initial lstat check raises a bare `FileNotFoundError` there,
    unwrapped, from that second call. That must be treated the same as any other
    "missing" disposition: skipped, not left to propagate and crash the caller.

    The re-stat inside the except block must ALSO see the file as gone here (unlike
    test_tags_for_first_party_file_propagates_non_missing_lstat_errors, where it
    doesn't): a real content-sniff race means the file really is gone by the time
    the disambiguation re-stat runs.
    """

    def _raise_bare_file_not_found(path):
        raise FileNotFoundError("simulated content-sniff race")

    def _also_missing(self):
        raise FileNotFoundError("really gone by the re-stat too")

    monkeypatch.setattr(ci_lint_lib, "tags_from_path", _raise_bare_file_not_found)
    monkeypatch.setattr(Path, "lstat", _also_missing)
    assert tags_for_first_party_file("portal/tests/test_ci_lint_lib.py") is None


def test_tags_for_first_party_file_propagates_non_missing_lstat_errors(monkeypatch):
    """A permission error (or any lstat failure other than "missing") must not be
    silently swallowed into `None` -- that would drop a real, present file out of
    every coverage check this module backs.

    Simulates identify's real failure mode (`tags_from_path` re-raising an
    `os.lstat` failure as `ValueError`) so the `except ValueError` disambiguation
    branch actually runs, then makes the re-stat inside it hit a non-missing error.
    """

    def _raise_value_error(path):
        raise ValueError("identify's generic re-raise")

    def _permission_denied(self):
        raise PermissionError("permission denied")

    monkeypatch.setattr(ci_lint_lib, "tags_from_path", _raise_value_error)
    monkeypatch.setattr(Path, "lstat", _permission_denied)
    with pytest.raises(PermissionError):
        tags_for_first_party_file("portal/tests/test_ci_lint_lib.py")


# assert_no_newline_paths ==============================================================================================


def test_assert_no_newline_paths_accepts_ordinary_paths():
    assert_no_newline_paths(["a.py", "dir/b.py"])  # must not raise


def test_assert_no_newline_paths_rejects_a_literal_newline():
    with pytest.raises(ValueError, match="newline"):
        assert_no_newline_paths(["a.py", "weird\nname.py"])
