"""Every first-party shell script must actually reach prek's shellcheck hook.

prek reports a hook whose matcher lost some of its files as `Passed`, not as a
failure, and prints no per-hook file count -- so narrowing `prek.toml`'s matcher
config can drop scripts out of the lint gate without anything going red. The CI
job's own `(no files to check)` grep only fires when a hook matches *nothing*.

Coverage for every OTHER linted language is checked differently, in
scripts/ci-lint-run.sh via `ci_lint_lib.find_dry_run_coverage_gaps` (see that
function's docstring for the mechanism): a hand-enumerated language-tag set
would miss hooks with no explicit `types` restriction (editorconfig-checker,
mixed-line-ending, the two shebang hooks -- which between them match nearly
every tracked file), and shelling out to prek from every offline `pytest` run
would also slow down the fast unit suite for a check that belongs in the lint
job that already pays for a live prek invocation. Shell gets its own
Python-side check here, and a live per-file reachability check in
scripts/ci-lint-selftest.sh, since shell is the language this gate exists to
enforce. `test_ci_lint_lib.py` unit-tests the dry-run-log parser itself
against canned transcripts.

The expected set is derived from `identify`, the library whose `shell` tag the
shellcheck hook's `types: [shell]` selector names, rather than from a pinned
list or a hand-rolled suffix/shebang heuristic.

One assumption: `prek` matches `exclude` with Rust's `regex` crate and this
compares with Python's `re`. Today's patterns are simple enough to be
dialect-agnostic; a future pattern using lookaround or Unicode classes could
behave differently here than in prek.

The tracked-file / identify-tag helpers live in scripts/ci_lint_lib.py, not
here -- see that module's docstring for why.
"""

import sys
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
PREK_CONFIG = REPO_ROOT / "prek.toml"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from ci_lint_lib import PER_HOOK_CHECKS  # noqa: E402
from ci_lint_lib import first_party_shell_scripts  # noqa: E402
from ci_lint_lib import is_vendored  # noqa: E402
from ci_lint_lib import tracked_files  # noqa: E402

# Hardcoded expectations, NOT derived from prek.toml. `ci_lint_lib.is_vendored`,
# `_FORMAT_SECTION_COMMENTS_TAGS` and `_EDITORCONFIG_EXCLUDE_TAGS` all derive their
# filtering/predicate logic from these same three prek.toml fields -- which is right
# for FILTERING (it keeps the derived logic in sync with prek's real matcher), but
# wrong as the sole oracle for whether the field's VALUE itself has drifted: a
# self-referential check that reads the field it's supposed to be validating can
# never detect that field being narrowed or widened, since the check silently moves
# with it. These three constants are the independent second source that makes the
# corresponding value-pinning test below non-vacuous.
EXPECTED_EXCLUDE = "^external/"
EXPECTED_FORMAT_SECTION_COMMENTS_TYPES_OR = ["rust", "python", "toml", "javascript", "ts", "jsx", "tsx", "dockerfile"]
EXPECTED_EDITORCONFIG_EXCLUDE_TYPES = ["rust", "markdown", "python"]

# `ty check` is the one hook that legitimately needs no `ci_lint_lib.PER_HOOK_CHECKS`
# entry: `pass_filenames = false` decouples what it scans from prek's file matcher
# entirely, so there is no per-file tag predicate to write -- its coverage is instead
# pinned directly by `test_every_first_party_python_file_is_a_ty_check_target` below.
# `shellcheck` DOES have a PER_HOOK_CHECKS entry (see that constant's own comment for
# why it isn't exempted just because it also has a live per-file check).
HOOKS_EXEMPT_FROM_PER_HOOK_CHECKS = frozenset({"ty check"})

# prek.toml's `id`/`name` (what `_hooks()` below reads) does not always match
# `PER_HOOK_CHECKS`'s key, which is prek's own dry-run *display* name pulled
# from each hook's upstream `.pre-commit-hooks.yaml`. Every hook needs an
# explicit entry here, not just the four whose prek.toml identity happens to
# differ from their real display name: `test_hook_id_to_dry_run_name_map_is_complete`
# asserts every hook in `_hooks()` is a key, so a newly added hook with no
# entry fails loudly there, by name, instead of silently falling back to
# itself in every consumer (`test_no_two_hooks_share_a_dry_run_display_name`,
# `test_every_hook_has_a_dry_run_coverage_check`) and defeating whichever one
# depended on it actually resolving to the hook's true display name.
HOOK_ID_TO_DRY_RUN_NAME = {
    "format section comments": "format section comments",
    "ty check": "ty check",
    "check-executables-have-shebangs": "check that executables have shebangs",
    "check-shebang-scripts-are-executable": "check that scripts with shebangs are executable",
    "mixed-line-ending": "mixed line ending",
    "shellcheck": "shellcheck",
    "editorconfig-checker": "Check .editorconfig rules",
    "yapf": "yapf",
    "mdformat": "mdformat",
    "mdformat (myst)": "mdformat (myst)",
}

# Keys on a hook table that narrow which files -- or which runs -- it
# participates in. Anything else (`name`, `args`, `verbose`, ...) leaves the
# matcher alone. `stages` belongs here even though it is not a file matcher:
# a hook confined to a stage that `--all-files` doesn't run at is dropped
# from the whole-tree run entirely, silently passing both the zero-match
# grep and this test.
NARROWING_KEYS = frozenset({"files", "exclude", "types", "types_or", "exclude_types", "stages"})

# Top-level config keys that narrow every hook at once. `default_stages` is
# `files`'s equally global sibling: setting it to a stage no hook opts out of
# (e.g. `["manual"]`) drops all but the two hooks that pin their own `stages`
# upstream, exiting 0 with no diagnostic.
TOP_LEVEL_NARROWING_KEYS = frozenset({"files", "default_stages"})

# The complete hook roster, keyed the same way as `test_no_hook_narrows_its_own_file_set_unexpectedly`'s
# `narrowing` set. Every check above is a subset assertion over keys *present*
# in prek.toml, so all of them are blind to a hook being deleted outright
# (e.g. dropping yapf's `hooks = [...]` to `[]` passes every narrowing check
# and exits `--all-files` 0 with no `Skipped` line). Pinning the exact roster
# here is what catches that.
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


def _config() -> dict:
    return tomllib.loads(PREK_CONFIG.read_text(encoding="utf-8"))


def _hooks() -> list[dict]:
    return [hook for repo in _config()["repos"] for hook in repo.get("hooks", [])]


def _hook_field(hook_id: str, field: str) -> Any:
    """The value of `field` on the prek.toml hook with this `id` -- a `list[str]` for
    `types_or`/`exclude_types`, a `str` for `entry`; `Any` because this one small
    helper serves both callers rather than needing a type-narrowed variant each.

    A small, deliberate duplicate of ci_lint_lib._hook_field rather than an
    import of it: that helper is a private (underscore-prefixed) production
    detail, and this file's own established boundary is to read prek.toml
    independently (via _config()/_hooks() above) rather than reach into
    ci_lint_lib's internals -- the same reason ci_lint_lib.py itself never
    imports from this test file.
    """
    for hook in _hooks():
        if hook.get("id") == hook_id:
            return hook[field]
    raise KeyError(f"no hook with id {hook_id!r} in prek.toml")


def test_hook_id_to_dry_run_name_map_is_complete():
    """Every hook in prek.toml needs an explicit `HOOK_ID_TO_DRY_RUN_NAME` entry.

    `test_no_two_hooks_share_a_dry_run_display_name` and
    `test_every_hook_has_a_dry_run_coverage_check` both resolve through
    `HOOK_ID_TO_DRY_RUN_NAME.get(name, name)` -- a graceful-looking fallback that
    is actually a silent hole: a newly added hook absent from the map falls back
    to its own prek.toml identity, which can coincidentally collide with (or fail
    to collide with) another hook's real display name, with neither downstream
    test able to tell the difference. This test makes that fallback unreachable
    for any hook actually in prek.toml, by requiring every one of them to have a
    real, explicitly recorded entry.
    """
    actual = {hook.get("name", hook.get("id")) for hook in _hooks()}
    missing = actual - HOOK_ID_TO_DRY_RUN_NAME.keys()

    assert not missing, (
        f"these hooks have no entry in HOOK_ID_TO_DRY_RUN_NAME: {sorted(missing)}. Look up each one's real prek "
        "dry-run display name (run `prek run --dry-run --all-files -vv` and find its status line) and add an "
        "explicit entry -- don't assume the prek.toml `name`/`id` text is already correct"
    )


def test_no_two_hooks_share_a_dry_run_display_name():
    """The identity that actually matters -- prek's dry-run *display* name, via
    `HOOK_ID_TO_DRY_RUN_NAME` -- not prek.toml's own `name`/`id` text.

    `test_prek_has_exactly_the_expected_hooks`'s set comparison,
    `test_no_hook_narrows_its_own_file_set_unexpectedly`'s `(name, key)` pairs, and
    `test_every_hook_has_a_dry_run_coverage_check`'s roster diff all key on the
    dry-run name (the last two through `HOOK_ID_TO_DRY_RUN_NAME`) and all silently
    collapse two hooks sharing THAT name into one entry (a `set` dedupes, so a
    duplicate changes neither side of an equality check) -- even when the two
    hooks' prek.toml `id`s differ, e.g. `editorconfig-checker` and a hypothetical
    `editorconfig-checker-system` both resolve to the upstream display name `Check
    .editorconfig rules`. Keying this guard on prek.toml's own `name`/`id` instead
    of the mapped dry-run name would miss exactly that case. prek.toml does not
    enforce dry-run-name uniqueness itself -- `name =` is optional, falling back to
    `id`, and even an explicit `name =` can coincide with another hook's upstream
    name -- so this is the one guard that makes every other check's name-keying
    safe to rely on; enforce it once here rather than converting every downstream
    check to a counted/ordered comparison.
    """
    dry_run_names = [
        HOOK_ID_TO_DRY_RUN_NAME.get(hook.get("name", hook.get("id")), hook.get("name", hook.get("id")))
        for hook in _hooks()
    ]
    duplicates = {name for name in dry_run_names if dry_run_names.count(name) > 1}

    assert not duplicates, (
        f"these hooks share a dry-run display name with another hook: {sorted(duplicates)}. Every hook needs a "
        "dry-run display name unique among the whole roster -- prek.toml's two mdformat entries do this via an "
        "explicit `name =` on the second one; a duplicate silently collapses in every name-keyed check in this file"
    )


def test_first_party_shell_scripts_exist_to_be_linted():
    """Guard against `first_party_shell_scripts()` passing every other check here vacuously."""
    assert first_party_shell_scripts()


def test_prek_exclude_is_exactly_the_vendored_prefix():
    """Pin `exclude`'s VALUE, not just assert it exists -- `ci_lint_lib.is_vendored`
    (which `first_party_shell_scripts()` and every other coverage check in this module
    filters through) derives its vendored-path pattern from this same prek.toml field, so
    a widened `exclude` (e.g. covering `scripts/` too) would drop matching first-party
    files from `first_party_shell_scripts()`'s OWN output before any check here ever sees
    them -- silently, since there is no longer an independent second source to compare
    against. This is that second source: a hardcoded expected value, not derived from
    prek.toml at all, so it cannot inherit the same blind spot.

    Widening `exclude` is real project risk, not a hypothetical: it drops matching files
    from every prek hook at once (the same mechanism `test_prek_has_no_top_level_narrowing_key`
    guards for `files`/`default_stages`), including `scripts/deploy.sh` and this repo's own
    lint-gate scripts.
    """
    exclude = _config().get("exclude", "")
    assert exclude == EXPECTED_EXCLUDE, (
        f"prek.toml's top-level `exclude` changed from {EXPECTED_EXCLUDE!r} to {exclude!r}. This drops matching "
        "files from every hook at once, invisibly to every other check in this file (they all filter through "
        "the same value via ci_lint_lib.is_vendored) -- confirm the new pattern still covers only external/, "
        "then update EXPECTED_EXCLUDE"
    )


def test_format_section_comments_types_or_is_pinned():
    """Same self-reference risk as `test_prek_exclude_is_exactly_the_vendored_prefix`,
    one hook down: `ci_lint_lib._FORMAT_SECTION_COMMENTS_TAGS` derives its predicate
    from this same prek.toml `types_or` field, so narrowing it (e.g. dropping `python`)
    moves the hook's real coverage and the check's oracle in lockstep -- the drift
    would never be reported by anything that only reads the derived value.
    """
    actual = _hook_field("format-section-comments", "types_or")
    assert actual == EXPECTED_FORMAT_SECTION_COMMENTS_TYPES_OR, (
        f"prek.toml's format-section-comments `types_or` changed from "
        f"{EXPECTED_FORMAT_SECTION_COMMENTS_TYPES_OR!r} to {actual!r}. ci_lint_lib.PER_HOOK_CHECKS derives its "
        "coverage predicate for this hook from the same field, so this drift is invisible to every other check "
        "-- confirm the narrowing is deliberate, then update EXPECTED_FORMAT_SECTION_COMMENTS_TYPES_OR"
    )


def test_editorconfig_checker_exclude_types_is_pinned():
    """Same self-reference risk as `test_format_section_comments_types_or_is_pinned`,
    for `ci_lint_lib._EDITORCONFIG_EXCLUDE_TAGS`, derived from this `exclude_types`.
    """
    actual = _hook_field("editorconfig-checker", "exclude_types")
    assert actual == EXPECTED_EDITORCONFIG_EXCLUDE_TYPES, (
        f"prek.toml's editorconfig-checker `exclude_types` changed from "
        f"{EXPECTED_EDITORCONFIG_EXCLUDE_TYPES!r} to {actual!r}. ci_lint_lib.PER_HOOK_CHECKS derives its coverage "
        "predicate for this hook from the same field, so this drift is invisible to every other check -- confirm "
        "the change is deliberate, then update EXPECTED_EDITORCONFIG_EXCLUDE_TYPES"
    )


# Tracked first-party Python files outside every ty check root, deliberately
# left uncovered -- tracked as issue #220, not fixed here, because closing
# the gap means fixing pre-existing, unrelated bugs first (a module-scope-
# unresolved name in mta/entrypoint.py; provisioner/entrypoint.py importing
# `postern_mta`, which only exists as `portal/src/postern/mta` COPYed at
# Docker build time, not as an importable path in the source tree).
TY_UNCOVERED_PYTHON_FILES = frozenset({"mta/entrypoint.py", "provisioner/entrypoint.py"})


def _ty_check_roots() -> list[str]:
    """Repo-root-relative directory prefixes ty actually scans, parsed from the `ty`
    hook's `entry` in prek.toml -- not a hand-copied second list, so a root added or
    removed there is exactly what `test_every_first_party_python_file_is_a_ty_check_target`
    verifies against, with nothing to keep in sync by hand.

    The entry's positional (non-flag) arguments after `check` are the roots; parsed with
    a plain `.split()` since prek.toml's `entry` strings are simple space-separated
    commands with no quoting. They resolve relative to the entry's own CWD (`portal/`,
    from `--directory portal`), not the repo root.
    """
    entry: str = _hook_field("ty", "entry")
    tokens = entry.split()
    check_index = tokens.index("check")
    positional = [token for token in tokens[check_index + 1:] if not token.startswith("-")]
    roots = []
    for token in positional:
        resolved = (REPO_ROOT / "portal" / token).resolve()
        rel = resolved.relative_to(REPO_ROOT).as_posix()
        roots.append(rel + "/" if rel else "")
    return roots


def test_every_first_party_python_file_is_a_ty_check_target():
    """`ty check`'s `pass_filenames = false` decouples what it scans from prek's own
    file matcher entirely, so nothing else here -- and nothing in
    `ci_lint_lib.find_dry_run_coverage_gaps`'s union check, satisfied by every OTHER
    hook matching text files regardless of language -- can see a first-party Python
    file falling outside every root the `ty` hook's `entry` actually names. Verified
    live: a tracked `tools/x.py` with a real type error passed the entire lint gate
    green before this test existed.
    """
    roots = _ty_check_roots()
    tracked_python = [path for path in tracked_files() if path.endswith(".py") and not is_vendored(path)]
    uncovered = [
        path for path in tracked_python
        if path not in TY_UNCOVERED_PYTHON_FILES and not any(path.startswith(root) for root in roots)
    ]
    assert not uncovered, (
        f"these first-party Python files fall outside every ty check root ({roots}): {uncovered}. Either widen "
        "the `ty` hook's `entry` in prek.toml to cover them, or add them to TY_UNCOVERED_PYTHON_FILES here with "
        "an issue reference if closing the gap requires fixing unrelated pre-existing bugs first"
    )


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


def test_every_hook_has_a_dry_run_coverage_check():
    """Every hook in prek.toml, except the documented exemptions, needs a `ci_lint_lib.PER_HOOK_CHECKS` entry.

    Adding a hook to `prek.toml` only fails `test_prek_has_exactly_the_expected_hooks`,
    whose message tells the author to update `EXPECTED_HOOKS` and says nothing about
    `PER_HOOK_CHECKS`. Following just that instruction leaves the new hook's matcher
    -- including one pinned upstream by a `rev =`, invisible to prek.toml's own text
    -- with no per-hook narrowing check: it can be narrowed to a subset of its files
    with every other guard staying green (`Passed`, no file count; the union check in
    `ci_lint_lib.find_dry_run_coverage_gaps` is dominated by the file/executable-wide
    hooks that claim nearly every tracked file regardless).
    """
    checked_hooks = {name for name, _tag_matches, _in_scope in PER_HOOK_CHECKS}
    actual = {hook.get("name", hook.get("id")) for hook in _hooks()}
    actual_dry_run_names = {HOOK_ID_TO_DRY_RUN_NAME.get(name, name) for name in actual}
    missing = actual_dry_run_names - checked_hooks - HOOKS_EXEMPT_FROM_PER_HOOK_CHECKS

    assert not missing, (
        f"these hooks have no ci_lint_lib.PER_HOOK_CHECKS entry: {sorted(missing)}. Add one (see "
        "PER_HOOK_CHECKS's own header comment for the predicate shape), or add the hook to "
        "HOOKS_EXEMPT_FROM_PER_HOOK_CHECKS here with a reason if it genuinely needs none"
    )
