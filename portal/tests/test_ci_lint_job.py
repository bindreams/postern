"""Every first-party file must actually reach the prek hook that lints its language.

prek reports a hook whose matcher lost some of its files as `Passed`, not as a
failure, and prints no per-hook file count -- so narrowing `prek.toml`'s matcher
config can drop files out of the lint gate without anything going red. The CI
job's own `(no files to check)` grep only fires when a hook matches *nothing*.
Shell scripts get the most scrutiny (a dedicated exclusion check, plus a live
per-file shellcheck run in scripts/ci-lint-selftest.sh), since that is this
issue's subject; every other linted language gets the same `exclude` check.

The expected sets are derived from `identify`, the library whose tags
(`shell`, `python`, `markdown`, ...) the hooks' `types`/`types_or` selectors
name, rather than from a pinned list or a hand-rolled suffix heuristic.

One assumption: `prek` matches `exclude` with Rust's `regex` crate and this
compares with Python's `re`. Today's patterns are simple enough to be
dialect-agnostic; a future pattern using lookaround or Unicode classes could
behave differently here than in prek.
"""

import os
import re
import subprocess
import tomllib
from pathlib import Path

from identify.identify import tags_from_path

REPO_ROOT = Path(__file__).resolve().parents[2]
PREK_CONFIG = REPO_ROOT / "prek.toml"
VENDORED = "external/"

# Keys on a hook table that narrow which files -- or which runs -- it
# participates in. Anything else (`name`, `args`, `verbose`, ...) leaves the
# matcher alone. `stages` belongs here even though it is not a file matcher:
# a hook confined to a stage that `--all-files` doesn't run at is dropped
# from the whole-tree run entirely -- confirmed empirically, adding
# `stages = ["manual"]` to the shellcheck hook makes it vanish from
# `--all-files` output with exit 0 and no `Skipped` line, so the CI job's
# zero-match grep never fires either.
NARROWING_KEYS = frozenset({"files", "exclude", "types", "types_or", "exclude_types", "stages"})

# Top-level config keys that narrow every hook at once. `default_stages` is
# `files`'s equally global sibling: setting it to a stage no hook opts out of
# (e.g. `["manual"]`) drops all but the two hooks that pin their own `stages`
# upstream -- confirmed empirically, exit 0, no diagnostic.
TOP_LEVEL_NARROWING_KEYS = frozenset({"files", "default_stages"})

# The complete hook roster, keyed the same way as `test_no_hook_narrows_its_own_file_set_unexpectedly`'s
# `narrowing` set. Every check above is a subset assertion over keys *present*
# in prek.toml, so all of them are blind to a hook being deleted outright --
# confirmed empirically, dropping yapf's `hooks = [...]` entry to `[]` still
# passes every narrowing check and leaves `--all-files` exiting 0 with no
# `Skipped` line. Pinning the exact roster here is what catches that.
EXPECTED_HOOKS = frozenset({
    "format section comments",
    "ty check",
    "check-executables-have-shebangs",
    "check-shebang-scripts-are-executable",
    "mixed-line-ending",
    "shellcheck",
    "editorconfig-checker",
    "yapf",
    "mdformat",
    "mdformat (myst)",
})

# Every language tag a local, first-party hook selects on: `shell` for
# shellcheck, `python` for ty and yapf, `markdown` for the mdformat hooks, and
# the rest for format-section-comments' `types_or`. The top-level `exclude`
# is the most global narrowing key of all -- it silently drops a matching
# file from every hook whose language tag it carries, not just shell scripts.
LINTED_LANGUAGE_TAGS = frozenset({
    "shell", "python", "rust", "toml", "javascript", "ts", "jsx", "tsx", "dockerfile", "markdown"
})


def _config() -> dict:
    return tomllib.loads(PREK_CONFIG.read_text(encoding="utf-8"))


def _hooks() -> list[dict]:
    return [hook for repo in _config()["repos"] for hook in repo.get("hooks", [])]


def _tracked_files() -> list[str]:
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True)
    return [path for path in listing.stdout.decode().split("\0") if path]


def _tags_for_first_party_file(path: str) -> frozenset[str] | None:
    """identify's tags for a tracked, non-vendored file, or `None` if it should be skipped."""
    if path.startswith(VENDORED):
        return None
    full_path = REPO_ROOT / path
    try:
        return frozenset(tags_from_path(full_path))
    except ValueError:
        # `identify.tags_from_path` re-raises every `os.lstat` failure -- not
        # just a missing file -- as this same generic `ValueError`. Re-stat
        # directly (not `Path.exists()`, which also swallows `PermissionError`
        # into `False`) to recover the real errno: `FileNotFoundError` is
        # "indexed but missing from the working tree" -- an ordinary transient
        # state during a staged deletion or sparse checkout -- and is skipped;
        # anything else (permission, ELOOP, stale mount, ...) propagates
        # instead of being silently dropped from the set this module exists
        # to defend. A residual race between the two stats is accepted: it
        # can only misclassify a file that changed state during this single
        # check, not hide a stable unreadable one.
        try:
            os.lstat(full_path)
        except FileNotFoundError:
            return None
        raise


def _first_party_shell_scripts() -> list[str]:
    """Tracked, non-vendored files identify tags as shell."""
    return [path for path in _tracked_files() if (tags := _tags_for_first_party_file(path)) and "shell" in tags]


def _first_party_linted_files() -> list[str]:
    """Tracked, non-vendored files identify tags with a language some local hook lints."""
    return [
        path for path in _tracked_files() if (tags := _tags_for_first_party_file(path)) and LINTED_LANGUAGE_TAGS & tags
    ]


def test_first_party_shell_scripts_exist_to_be_linted():
    """Guard against the coverage test below passing vacuously."""
    assert _first_party_shell_scripts()


def test_first_party_linted_files_exist_to_be_linted():
    """Guard against the coverage test below passing vacuously."""
    assert _first_party_linted_files()


def test_no_first_party_shell_script_is_excluded_from_the_lint_gate():
    config = _config()
    exclude = config.get("exclude", "")
    dropped = [path for path in _first_party_shell_scripts() if exclude and re.search(exclude, path)]

    assert not dropped, (f"prek.toml's `exclude` drops these first-party shell scripts out of the lint gate: {dropped}")


def test_no_first_party_linted_file_is_excluded_from_the_lint_gate():
    """The shell-only check above can't see `exclude` dropping, say, python or markdown files instead."""
    config = _config()
    exclude = config.get("exclude", "")
    dropped = [path for path in _first_party_linted_files() if exclude and re.search(exclude, path)]

    assert not dropped, (f"prek.toml's `exclude` drops these first-party linted files out of the lint gate: {dropped}")


def test_prek_has_exactly_the_expected_hooks():
    """Deleting a hook (or a whole [[repos]] block) passes every subset-based check above silently -- pin the roster."""
    actual = {hook.get("name", hook.get("id")) for hook in _hooks()}
    assert actual == EXPECTED_HOOKS, (
        f"prek.toml's hook roster changed: missing {sorted(EXPECTED_HOOKS - actual)}, "
        f"added {sorted(actual - EXPECTED_HOOKS)}. If a hook was deliberately added or removed, update "
        "EXPECTED_HOOKS (and, for a removed shellcheck/ty, scripts/ci-lint-selftest.sh's fixtures)"
    )


def test_prek_has_no_top_level_narrowing_key():
    """A top-level `files` or `default_stages` narrows every hook at once, invisibly to the checks above."""
    present = TOP_LEVEL_NARROWING_KEYS & _config().keys()
    assert not present, (
        f"prek.toml grew a top-level narrowing key: {sorted(present)}. Each narrows every hook's matcher or "
        "stage participation at once, so fold its effect into the other checks in this file before adding it"
    )


def test_no_hook_narrows_its_own_file_set_unexpectedly():
    """Per-hook matcher overrides bypass the top-level checks, so each one must be deliberate.

    Every entry allow-listed here is a language restriction that is the point of
    the hook: the section-comment formatter and ty handle only the languages
    they parse, editorconfig-checker defers to the dedicated formatters, and the
    two mdformat hooks split `docs/` from everything else because MyST and GFM
    need separate plugin environments. `shellcheck` is deliberately absent -- it
    must keep matching every shell file in the tree.

    Keyed on `name` (falling back to `id`), not `id` alone: prek.toml's two
    mdformat hooks share `id = "mdformat"` and are told apart only by the
    `name` on the second one, so an `id`-only key would let either hook's
    narrowing key stand in for the other's -- e.g. an `exclude` newly added to
    the myst hook would pass unnoticed under the entry meant for the gfm hook.
    """
    allowed = {
        ("format section comments", "types_or"),
        ("ty check", "types"),
        ("editorconfig-checker", "exclude_types"),
        ("mdformat", "exclude"),
        ("mdformat (myst)", "files"),
    }
    narrowing = {(hook.get("name", hook.get("id")), key) for hook in _hooks() for key in hook if key in NARROWING_KEYS}

    assert narrowing <= allowed, (
        f"these hooks narrow their own file matcher: {sorted(narrowing - allowed)}. prek reports a narrowed "
        "hook as `Passed` with no file count, so add the entry here only after checking it does not drop "
        "files the gate is supposed to cover"
    )
