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

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import ci_lint_lib  # noqa: E402
from ci_lint_lib import assert_no_newline_paths  # noqa: E402
from ci_lint_lib import find_dry_run_coverage_gaps  # noqa: E402
from ci_lint_lib import find_ty_coverage_gaps  # noqa: E402
from ci_lint_lib import is_vendored  # noqa: E402
from ci_lint_lib import parse_dry_run_hook_files  # noqa: E402
from ci_lint_lib import parse_ty_verbose_checked_files  # noqa: E402
from ci_lint_lib import tags_for_first_party_file  # noqa: E402
from ci_lint_lib import tracked_files  # noqa: E402

# A trimmed but structurally real transcript covering every entry in
# `PER_HOOK_CHECKS` (which includes `shellcheck` -- see that constant's own
# header comment for why it isn't exempted despite also having a live
# per-file reachability check in scripts/ci-lint-selftest.sh), plus `ty
# check` -- the one hook `PER_HOOK_CHECKS` genuinely can't cover, since
# `pass_filenames = false` decouples what it scans from prek's own file
# matcher entirely (ty's coverage is pinned separately, in
# portal/tests/test_ci_lint_job.py's `test_every_first_party_python_file_is_a_ty_check_target`)
# -- and the two same-id mdformat entries told apart only by their display
# name. Tracked files are a.py/b.py (python), README.md (non-docs markdown),
# docs/index.md (docs markdown), run.sh (text+executable+shell, so it also
# exercises `check that executables have shebangs` and `shellcheck`, whose
# predicates every OTHER fixture file here fails), and config.yaml (text,
# not rust/markdown/python, so it also exercises `Check .editorconfig
# rules`'s predicate).
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
# output verbatim -- NOT `` `mdformat (myst)` ``. Both mdformat entries print
# the identical bare-id backtick line; only the status line ("mdformat
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
    # No "text" tag -- a real tracked binary asset, e.g.
    # portal/src/postern/static/fonts/FiraCode-Regular.woff2, identify-tagged
    # {"non-executable", "file", "woff2", "binary"}. No hook in SAMPLE_LOG
    # claims this path; it must NOT be reported as uncovered, since the union
    # and per-hook checks both gate on "text" in tags before ever reporting
    # anything missing.
    "image.png": frozenset({"non-executable", "file", "png", "binary"}),
}

SAMPLE_TRACKED = ["a.py", "b.py", "README.md", "docs/index.md", "run.sh", "config.yaml"]


def test_find_dry_run_coverage_gaps_clean_log_reports_nothing():
    assert find_dry_run_coverage_gaps(SAMPLE_LOG, SAMPLE_TRACKED, FAKE_TAGS.get) == []


def test_find_dry_run_coverage_gaps_does_not_flag_a_binary_file_no_hook_claims():
    """A tracked binary asset (no "text" tag) that no hook claims is correct, not a
    gap: no prek hook in this repo targets binary files, so the union/per-hook
    checks both gate on "text" in tags before reporting anything missing. A
    regression that dropped or inverted that guard would report every binary
    asset in the tree as "uncovered" -- nothing else in this file would catch it.
    """
    tracked = [*SAMPLE_TRACKED, "image.png"]
    problems = find_dry_run_coverage_gaps(SAMPLE_LOG, tracked, FAKE_TAGS.get)

    assert not any("image.png" in problem for problem in problems)


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


def test_find_dry_run_coverage_gaps_flags_shellcheck_narrowing():
    """run.sh is the only fixture matching shellcheck's "shell" predicate -- confirm
    the check actually fires on it. shellcheck also has its own live per-file
    reachability loop in scripts/ci-lint-selftest.sh, but that's defense-in-depth
    for the language this whole gate exists to enforce, not a substitute for this
    cheap, uniform check -- see PER_HOOK_CHECKS's own comment.
    """
    log_with_narrowed_hook = SAMPLE_LOG.replace(
        "\n  `shellcheck` would be run on 1 files:\n  - run.sh\n",
        "\n",
    )
    problems = find_dry_run_coverage_gaps(log_with_narrowed_hook, SAMPLE_TRACKED, FAKE_TAGS.get)

    assert any("shellcheck" in problem and "run.sh" in problem for problem in problems)


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


# parse_ty_verbose_checked_files / find_ty_coverage_gaps ===============================================================

# A trimmed but structurally real `ty check ... -vv` transcript (see
# ci_lint_lib.run_ty_verbose's docstring for why `-vv` and not prek's own
# `--dry-run`): noise lines (timestamps, `Adding new file root`, `Invalid
# __all__ in ...`, `Module X not found`, the `INFO Checking file ... took more
# than 100ms` slow-file variant, which uses backticks rather than the single
# quotes this parser keys on) interleaved with real `DEBUG Checking file
# '<path>'` lines, exactly as ty 0.0.31 emits them on stderr. Absolute paths
# are rooted at REPO_ROOT so `.resolve().relative_to(REPO_ROOT)` succeeds the
# same way it would against a real invocation.
TY_VV_LOG = f"""\
2026-08-08 04:55:12.601901049 DEBUG Version: 0.0.31
2026-08-08 04:55:12.603604405 DEBUG Adding new file root '{REPO_ROOT}/portal' of kind Project
2026-08-08 04:55:12.607923313 INFO Indexed 116 file(s) in 0.004s
2026-08-08 04:55:12.608450249 DEBUG Checking file '{REPO_ROOT}/portal/src/postern/mta/dkim.py'
2026-08-08 04:55:12.608489722 DEBUG Checking file '{REPO_ROOT}/portal/tests/test_repo_hygiene.py'
2026-08-08 04:55:12.626537629 DEBUG Module `__builtins__` not found in search paths
2026-08-08 04:55:12.879279345 DEBUG Invalid `__all__` in `{REPO_ROOT}/portal/.venv/lib/python3.14/site-packages/yaml/scanner.py`
2026-08-08 04:55:12.591327803 INFO Checking file `{REPO_ROOT}/portal/src/postern/cli.py` took more than 100ms (267ms)
2026-08-08 04:55:12.869009156 DEBUG Checking file '{REPO_ROOT}/scripts/format-section-comments.py'
2026-08-08 04:55:12.913866978 DEBUG Checking file '{REPO_ROOT}/docs/conf.py'
2026-08-08 04:55:12.926317375 DEBUG Checking all files took 0.318s
2026-08-08 04:55:12.926395871 DEBUG Exiting main loop
"""

TY_VV_TRACKED = [
    "portal/src/postern/mta/dkim.py",
    "portal/tests/test_repo_hygiene.py",
    "scripts/format-section-comments.py",
    "docs/conf.py",
]


def test_parse_ty_verbose_checked_files_extracts_repo_relative_paths():
    assert parse_ty_verbose_checked_files(TY_VV_LOG) == TY_VV_TRACKED


def test_parse_ty_verbose_checked_files_ignores_the_slow_file_backtick_line():
    """The `INFO ... took more than 100ms` line uses backticks, not single quotes, for
    portal/src/postern/cli.py -- confirm it is never counted (it isn't in TY_VV_TRACKED
    above), so a future format where the two variants collide can't double-count or
    silently swap which quoting style this parser keys on.
    """
    assert "portal/src/postern/cli.py" not in parse_ty_verbose_checked_files(TY_VV_LOG)


def test_parse_ty_verbose_checked_files_on_empty_log_returns_empty_list():
    assert parse_ty_verbose_checked_files("") == []


def test_find_ty_coverage_gaps_clean_log_reports_nothing():
    assert find_ty_coverage_gaps(TY_VV_LOG, TY_VV_TRACKED) == []


def test_find_ty_coverage_gaps_flags_a_file_ty_never_reported_checking():
    """The narrowing vector this function exists for: a file ty silently excluded
    (a `[tool.ty.src] exclude`, or one of ty's own built-in default excludes) never
    gets a `Checking file` line, even though it's tracked and not vendored.
    """
    tracked = [*TY_VV_TRACKED, "portal/src/postern/routes/dashboard.py"]
    problems = find_ty_coverage_gaps(TY_VV_LOG, tracked)

    assert any("portal/src/postern/routes/dashboard.py" in problem for problem in problems)


def test_find_ty_coverage_gaps_does_not_flag_a_vendored_file():
    tracked = [*TY_VV_TRACKED, "external/shadowsocks-rust/setup.py"]
    problems = find_ty_coverage_gaps(TY_VV_LOG, tracked)

    assert not any("external/" in problem for problem in problems)


def test_find_ty_coverage_gaps_does_not_flag_a_known_uncovered_file():
    """mta/entrypoint.py and provisioner/entrypoint.py are deliberately outside every ty
    check root (issue #220) -- ci_lint_lib.TY_UNCOVERED_PYTHON_FILES is the allowlist,
    not a bug this check should report.
    """
    tracked = [*TY_VV_TRACKED, "mta/entrypoint.py", "provisioner/entrypoint.py"]
    problems = find_ty_coverage_gaps(TY_VV_LOG, tracked)

    assert problems == []


def test_find_ty_coverage_gaps_does_not_flag_a_non_python_file():
    tracked = [*TY_VV_TRACKED, "README.md"]
    problems = find_ty_coverage_gaps(TY_VV_LOG, tracked)

    assert not any("README.md" in problem for problem in problems)


def test_find_ty_coverage_gaps_on_empty_log_reports_invocation_failure():
    assert find_ty_coverage_gaps("", TY_VV_TRACKED) == [
        "ty -vv reported checking no files at all -- install/invocation failure?"
    ]


# is_vendored ==========================================================================================================


def test_is_vendored_reads_prek_tomls_real_exclude_pattern():
    """Against the real, tracked prek.toml (not injected) -- confirms this is a live
    derivation, not a hardcoded prefix that could silently drift from prek.toml's
    actual `exclude`.
    """
    assert is_vendored("external/shadowsocks-rust/Cargo.toml")
    assert not is_vendored("scripts/ci_lint_lib.py")


def test_pattern_excludes_treats_an_empty_pattern_as_excluding_nothing():
    """`re.compile("").search(x)` always matches -- an absent/empty prek.toml `exclude`
    (which can't happen against the real, tracked prek.toml, since it always sets one)
    must not make ci_lint_lib._pattern_excludes -- and therefore is_vendored -- treat
    every path as vendored.
    """
    assert not ci_lint_lib._pattern_excludes(re.compile(""), "any/path/at/all.py")


def test_pattern_excludes_applies_a_real_pattern():
    pattern = re.compile("^external/")
    assert ci_lint_lib._pattern_excludes(pattern, "external/shadowsocks-rust/Cargo.toml")
    assert not ci_lint_lib._pattern_excludes(pattern, "scripts/ci_lint_lib.py")


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


def test_tags_for_first_party_file_propagates_original_error_when_file_still_exists(monkeypatch):
    """The one branch the two tests above don't reach: `tags_from_path` raises, but the
    disambiguation re-stat SUCCEEDS (the file is genuinely still there) -- neither
    `except FileNotFoundError: return None` fires (lstat didn't raise) nor does lstat's
    own exception propagate in its place (there isn't one); control falls through to
    the bare `raise`, re-raising the ORIGINAL error from `tags_from_path`. A regression
    collapsing that `raise` into `return None` would silently drop a stable, present,
    merely-unclassifiable-by-identify file from every coverage check in this module,
    and the two existing tests (one all-missing, one lstat-also-fails) wouldn't notice.
    """

    def _raise_value_error(path):
        raise ValueError("identify's generic re-raise, but the file is genuinely still there")

    monkeypatch.setattr(ci_lint_lib, "tags_from_path", _raise_value_error)
    # Path.lstat is deliberately left real: portal/tests/test_ci_lint_lib.py exists,
    # so the re-stat inside the except block succeeds and falls through to the raise.
    with pytest.raises(ValueError, match="identify's generic re-raise"):
        tags_for_first_party_file("portal/tests/test_ci_lint_lib.py")


# tracked_files ========================================================================================================


def test_tracked_files_returns_real_tracked_paths():
    # Against the real repo -- this test file itself is guaranteed tracked.
    files = tracked_files()
    assert "portal/tests/test_ci_lint_lib.py" in files
    assert all(path for path in files)  # no empty-string entries from a trailing NUL


def test_tracked_files_raises_runtime_error_with_decoded_stderr_on_git_failure(monkeypatch):
    """`capture_output=True` buffers git's own stderr onto the exception instead of
    letting it reach the caller directly -- confirm the decode-and-reraise actually
    surfaces it, rather than a bare `CalledProcessError` whose default traceback
    shows only the exit code and discards git's real diagnostic.
    """

    def _fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            128, ["git", "ls-files", "-z"], output=b"", stderr=b"fatal: not a git repository"
        )

    monkeypatch.setattr(ci_lint_lib.subprocess, "run", _fake_run)
    with pytest.raises(RuntimeError, match="fatal: not a git repository"):
        tracked_files()


# assert_no_newline_paths ==============================================================================================


def test_assert_no_newline_paths_accepts_ordinary_paths():
    assert_no_newline_paths(["a.py", "dir/b.py"])  # must not raise


def test_assert_no_newline_paths_rejects_a_literal_newline():
    with pytest.raises(ValueError, match="newline"):
        assert_no_newline_paths(["a.py", "weird\nname.py"])
