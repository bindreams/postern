"""Every first-party shell script must actually reach prek's shellcheck hook.

prek reports a hook whose matcher lost some of its files as `Passed`, not as a
failure, and prints no per-hook file count -- so narrowing `prek.toml`'s matcher
config can drop scripts out of the lint gate without anything going red. The CI
job's own `(no files to check)` grep only fires when a hook matches *nothing*.

The expected set is derived from `identify`, the library whose `shell` tag the
shellcheck hook's `types: [shell]` selector names, rather than from a pinned
list or a hand-rolled suffix/shebang heuristic.

One assumption: `prek` matches `exclude` with Rust's `regex` crate and this
compares with Python's `re`. Today's patterns are simple enough to be
dialect-agnostic; a future pattern using lookaround or Unicode classes could
behave differently here than in prek.
"""

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


def _config() -> dict:
    return tomllib.loads(PREK_CONFIG.read_text(encoding="utf-8"))


def _tracked_files() -> list[str]:
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True)
    return [path for path in listing.stdout.decode().split("\0") if path]


def _is_first_party_shell_script(path: str) -> bool:
    if path.startswith(VENDORED):
        return False
    try:
        tags = tags_from_path(REPO_ROOT / path)
    except ValueError:
        # Indexed but missing from the working tree (staged deletion, sparse
        # checkout) -- an ordinary transient state, not a broken checkout.
        # Any other error is left to propagate: git guarantees a present,
        # tracked file is readable, so an unreadable one really is a broken
        # checkout, and swallowing that would drop the path from the set this
        # module exists to defend.
        return False
    return "shell" in tags


def _first_party_shell_scripts() -> list[str]:
    """Tracked, non-vendored files identify tags as shell."""
    return [path for path in _tracked_files() if _is_first_party_shell_script(path)]


def test_first_party_shell_scripts_exist_to_be_linted():
    """Guard against the coverage test below passing vacuously."""
    assert _first_party_shell_scripts()


def test_no_first_party_shell_script_is_excluded_from_the_lint_gate():
    config = _config()
    exclude = config.get("exclude", "")
    dropped = [path for path in _first_party_shell_scripts() if exclude and re.search(exclude, path)]

    assert not dropped, (f"prek.toml's `exclude` drops these first-party shell scripts out of the lint gate: {dropped}")


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
    narrowing = {(hook.get("name", hook.get("id")), key)
                 for repo in _config()["repos"]
                 for hook in repo.get("hooks", [])
                 for key in hook if key in NARROWING_KEYS}

    assert narrowing <= allowed, (
        f"these hooks narrow their own file matcher: {sorted(narrowing - allowed)}. prek reports a narrowed "
        "hook as `Passed` with no file count, so add the entry here only after checking it does not drop "
        "files the gate is supposed to cover"
    )
