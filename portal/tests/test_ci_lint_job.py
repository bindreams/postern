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

# Keys on a hook table that narrow which files it runs against. Anything else
# (`name`, `args`, `stages`, `verbose`, ...) leaves the matcher alone.
NARROWING_KEYS = frozenset({"files", "exclude", "types", "types_or", "exclude_types"})


def _config() -> dict:
    return tomllib.loads(PREK_CONFIG.read_text(encoding="utf-8"))


def _tracked_files() -> list[str]:
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True)
    return [path for path in listing.stdout.decode().split("\0") if path]


def _first_party_shell_scripts() -> list[str]:
    """Tracked, non-vendored files identify tags as shell.

    A read error is left to propagate: git guarantees tracked files are
    readable, so an unreadable one is a broken checkout, not a non-shell file.
    Swallowing it would drop the path from the set this module exists to defend.
    """
    return [
        path for path in _tracked_files()
        if not path.startswith(VENDORED) and "shell" in tags_from_path(REPO_ROOT / path)
    ]


def test_first_party_shell_scripts_exist_to_be_linted():
    """Guard against the coverage test below passing vacuously."""
    assert _first_party_shell_scripts()


def test_no_first_party_shell_script_is_excluded_from_the_lint_gate():
    config = _config()
    exclude = config.get("exclude", "")
    dropped = [path for path in _first_party_shell_scripts() if exclude and re.search(exclude, path)]

    assert not dropped, (f"prek.toml's `exclude` drops these first-party shell scripts out of the lint gate: {dropped}")


def test_prek_has_no_top_level_files_include():
    """A top-level `files` include-regex narrows every hook, invisibly to the check above."""
    assert "files" not in _config(), (
        "prek.toml grew a top-level `files` include-regex; it narrows every hook's matcher, so fold it "
        "into test_no_first_party_shell_script_is_excluded_from_the_lint_gate before adding it"
    )


def test_no_hook_narrows_its_own_file_set_unexpectedly():
    """Per-hook matcher overrides bypass the top-level checks, so each one must be deliberate.

    Every entry allow-listed here is a language restriction that is the point of
    the hook: the section-comment formatter and ty handle only the languages
    they parse, editorconfig-checker defers to the dedicated formatters, and the
    two mdformat hooks split `docs/` from everything else because MyST and GFM
    need separate plugin environments. `shellcheck` is deliberately absent -- it
    must keep matching every shell file in the tree.
    """
    allowed = {
        ("format-section-comments", "types_or"),
        ("ty", "types"),
        ("editorconfig-checker", "exclude_types"),
        ("mdformat", "exclude"),
        ("mdformat", "files"),
    }
    narrowing = {(hook.get("id"), key)
                 for repo in _config()["repos"]
                 for hook in repo.get("hooks", [])
                 for key in hook if key in NARROWING_KEYS}

    assert narrowing <= allowed, (
        f"these hooks narrow their own file matcher: {sorted(narrowing - allowed)}. prek reports a narrowed "
        "hook as `Passed` with no file count, so add the entry here only after checking it does not drop "
        "files the gate is supposed to cover"
    )
