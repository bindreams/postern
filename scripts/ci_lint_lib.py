"""Shared helpers for the CI `lint` job (.github/workflows/test.yaml) and its
coverage test (portal/tests/test_ci_lint_job.py).

Lives outside portal/tests/ on purpose. scripts/ci-lint-run.sh and
scripts/ci-lint-selftest.sh both import from this module at CI runtime; if
they instead reached into portal/tests/test_ci_lint_job.py's private helpers,
a test-readability rename or refactor there could silently break the CI job
with nothing in the offline `pytest` run catching it -- exactly the class of
silent-gap failure this job exists to close for prek's own hooks.
`portal/tests/test_ci_lint_job.py` imports this module the same way the shell
scripts do, rather than owning its own private copies.

Not part of the `postern` package: it has nothing to do with the runtime
portal and needs `identify`, a dev-only dependency declared alongside `prek`
in portal/pyproject.toml.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from pathlib import Path

from identify.identify import tags_from_path

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDORED = "external/"


def tracked_files() -> list[str]:
    """NUL-terminated (trailing NUL after every path, not just between paths) both so a tracked
    filename containing a literal newline round-trips intact, and so a caller reading this list
    line-delimited (any hand-rolled parse of `prek run --dry-run` output, for one) must reject
    such a path instead of silently mis-splitting it -- see `assert_no_newline_paths`.
    """
    try:
        listing = subprocess.run(["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True)
    except subprocess.CalledProcessError as exc:
        # `capture_output=True` buffers git's own stderr onto the exception instead of letting it
        # reach the caller's terminal/log; the default traceback then shows only the exit code,
        # discarding git's actual diagnostic (e.g. "fatal: not a git repository") right when it's
        # needed most -- this function is the ground-truth oracle every guard in this module
        # depends on.
        raise RuntimeError(f"git ls-files failed: {exc.stderr.decode(errors='replace')}") from exc
    return [path for path in listing.stdout.decode().split("\0") if path]


def assert_no_newline_paths(paths: list[str]) -> None:
    """Raise if any path contains a literal newline.

    `parse_dry_run_hook_files` parses `prek run --dry-run -vv`'s plain-text
    output line-by-line (prek's own dry-run output has no NUL-safe mode), so a
    tracked path containing a literal newline would corrupt that parse --
    silently mis-splitting into multiple bogus paths rather than failing
    loudly. Callers that feed `tracked_files()`'s output into that parser
    should call this first.
    """
    newline_paths = [path for path in paths if "\n" in path]
    if newline_paths:
        raise ValueError(f"tracked paths containing a literal newline break the dry-run parse: {newline_paths}")


def tags_for_first_party_file(path: str) -> frozenset[str] | None:
    """identify's tags for a tracked, non-vendored file, or `None` if it should be skipped.

    A read error other than "missing" is left to propagate: git guarantees
    tracked files are readable, so an unreadable one is a broken checkout,
    not a file this module should silently drop from its coverage checks.
    """
    if path.startswith(VENDORED):
        return None
    full_path = REPO_ROOT / path
    try:
        return frozenset(tags_from_path(full_path))
    except ValueError:
        # identify.tags_from_path re-raises every os.lstat failure -- not just
        # a missing file -- as this same generic ValueError. Re-stat directly
        # (not Path.exists(), which also swallows PermissionError into False)
        # to recover the real errno: FileNotFoundError is "indexed but missing
        # from the working tree" -- an ordinary transient state during a
        # staged deletion or sparse checkout -- and is skipped; anything else
        # propagates instead of being silently dropped from the set this
        # module exists to defend. A residual race between the two stats is
        # accepted: it can only misclassify a file that changed state during
        # this single check, not hide a stable unreadable one.
        try:
            full_path.lstat()
        except FileNotFoundError:
            return None
        raise


def first_party_shell_scripts() -> list[str]:
    """Tracked, non-vendored files identify tags as shell."""
    return [path for path in tracked_files() if (tags := tags_for_first_party_file(path)) and "shell" in tags]


# Per-hook dry-run coverage checks =====================================================================================

# Each entry is (dry-run display name, "is this file the hook's language"
# tag predicate, "is this file in the hook's path scope" predicate). Every
# hook listed here has a base file matcher that lives entirely or partly
# upstream -- pinned by a `rev =` in prek.toml, not written there -- so it is
# invisible to portal/tests/test_ci_lint_job.py's static reads of prek.toml,
# and a routine dependency bump could narrow it with nothing else noticing.
# Predicates are read off each hook's own upstream `.pre-commit-hooks.yaml`
# `types`/`types_or` (AND semantics for `types`).
#
# `ty check` is deliberately absent: `pass_filenames = false` makes it scan
# the whole portal project regardless of its `types = ["python"]` restriction,
# so no matcher narrowing can reduce what it actually checks. Every other
# hook -- INCLUDING `format-section-comments`, despite `types_or` already
# being a key written in prek.toml -- needs its own entry here:
# `test_no_hook_narrows_its_own_file_set_unexpectedly` only asserts a
# narrowing KEY is present and allow-listed, never the key's VALUE, so
# narrowing an already-allow-listed `types_or`/`exclude_types`/etc. in place
# (e.g. trimming `format-section-comments`'s `types_or` list) is invisible to it.
PER_HOOK_CHECKS: list[tuple[str, Callable[[frozenset[str]], bool], Callable[[str], bool]]] = [
    (
        "format section comments",
        # OR semantics (types_or), matching prek.toml's format-section-comments hook.
        lambda tags: bool({"rust", "python", "toml", "javascript", "ts", "jsx", "tsx", "dockerfile"} & tags),
        lambda path: True,
    ),
    (
        "check that executables have shebangs",
        lambda tags: {"text", "executable"} <= tags,
        lambda path: True,
    ),
    (
        "check that scripts with shebangs are executable",
        lambda tags: "text" in tags,
        lambda path: True,
    ),
    (
        "mixed line ending",
        lambda tags: "text" in tags,
        lambda path: True,
    ),
    (
        "Check .editorconfig rules",
        lambda tags: "text" in tags and not ({"rust", "markdown", "python"} & tags),
        lambda path: True,
    ),
    (
        "yapf",
        lambda tags: "python" in tags,
        lambda path: True,
    ),
    (
        "mdformat",
        lambda tags: "markdown" in tags,
        lambda path: not path.startswith("docs/"),
    ),
    (
        "mdformat (myst)",
        lambda tags: "markdown" in tags,
        lambda path: path.startswith("docs/"),
    ),
]


def parse_dry_run_hook_files(log: str) -> dict[str, list[str]]:
    """Parse `prek run --dry-run --all-files -vv` output into {hook display name: [file, ...]}.

    Keyed on the display-name status line (e.g. `mdformat (myst)....Dry Run`),
    NOT `- hook id: <id>` or the backtick-quoted name in `would be run on` --
    both of those repeat the bare hook id `mdformat` for both same-id mdformat
    entries, while only the status line carries the distinguishing `(myst)`
    suffix. A hook with `pass_filenames = false` (`ty check`) contributes an
    empty file list, which is correct: nothing should expect ty to appear in
    a per-file coverage check.

    Raises `ValueError` if two hooks share a display name: prek.toml does not
    enforce display-name uniqueness (`name =` is optional; the bare `id` is
    the fallback), and silently merging two hooks' file lists into one key
    would validate their UNION against `PER_HOOK_CHECKS` instead of each
    hook's own list -- defeating the one guard built to catch a single hook
    losing a subset of its files.
    """
    sections = re.split(r"(?=^\S.*\.+Dry Run$)", log, flags=re.MULTILINE)
    by_name: dict[str, list[str]] = {}
    duplicated: set[str] = set()
    for section in sections:
        match = re.match(r"(\S.*?)\.+Dry Run$", section, re.MULTILINE)
        if not match:
            continue
        hook_name = match.group(1)
        files = re.findall(r"^  - (.+)$", section, re.MULTILINE)
        if hook_name in by_name:
            duplicated.add(hook_name)
        by_name.setdefault(hook_name, []).extend(files)
    if duplicated:
        raise ValueError(
            f"prek's dry-run output has more than one hook section named {sorted(duplicated)} -- "
            "two hooks in prek.toml resolve to the same display name (either the same `id` with no "
            "distinguishing `name =`, or two different `id`s whose upstream manifests both default to "
            "this name), which would silently merge their per-hook coverage checks. Give one a unique `name =`."
        )
    return by_name


def find_dry_run_coverage_gaps(
    dry_run_log: str,
    tracked: list[str],
    tag_lookup: Callable[[str], frozenset[str] | None] = tags_for_first_party_file,
) -> list[str]:
    """Compare a dry-run's resolved per-hook file lists against the tracked tree.

    Returns a list of human-readable problem descriptions; empty means clean.
    Two kinds of check, ground-truthed against prek's own dry-run output
    rather than a re-implementation of its matcher rules (dodging the Python
    `re`-vs-Rust-`regex` dialect gap):

    - union coverage: every first-party tracked TEXT file must be claimed by
      at least one hook. Catches `exclude`/`files`/`default_stages` narrowing,
      which drops a file from every hook at once -- including the
      file/executable-wide hooks (`mixed-line-ending`, the two shebang hooks)
      that would otherwise dominate the union and mask any other single hook
      narrowing on its own.
    - per-hook coverage, for every hook in `PER_HOOK_CHECKS`: every in-scope,
      correctly-tagged first-party file must appear in THAT hook's own list.
      Catches a hook's own upstream-only matcher narrowing, which the union
      check cannot see when a same-language sibling hook still covers the
      file (e.g. `editorconfig-checker` losing files while `yapf`/`mdformat`
      still claim them).

    `tag_lookup` defaults to `tags_for_first_party_file` (real filesystem +
    identify lookups); tests inject a fake mapping instead of requiring real
    files on disk.
    """
    try:
        assert_no_newline_paths(tracked)
    except ValueError as exc:
        return [str(exc)]
    try:
        by_name = parse_dry_run_hook_files(dry_run_log)
    except ValueError as exc:
        return [str(exc)]
    if not by_name:
        return ["prek --dry-run reported no hooks at all -- install/clone failure?"]

    problems = []

    covered = {path for files in by_name.values() for path in files}
    uncovered = [
        path for path in tracked if path not in covered and (tags := tag_lookup(path)) is not None and "text" in tags
    ]
    if uncovered:
        problems.append(f"no prek hook would run on these first-party tracked text files: {uncovered}")

    for hook_name, tag_matches, in_scope in PER_HOOK_CHECKS:
        hook_files = set(by_name.get(hook_name, []))
        missing = [
            path for path in tracked if in_scope(path) and (tags := tag_lookup(path)) is not None and tag_matches(tags)
            and path not in hook_files
        ]
        if missing:
            problems.append(
                f"{hook_name} would not run on these in-scope first-party files -- its upstream matcher narrowed: {missing}"
            )

    return problems
