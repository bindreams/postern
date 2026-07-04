"""Guard tests for the <old-name> → example.env rename (issue #156).

These tests run without Docker and pin three invariants:
  (a) example.env exists and the old <old-name> does not;
  (b) .gitignore contains a .tmp/ entry;
  (c) no tracked file still references the old name.

The old-name literal is assembled at runtime so this file never self-matches the
git-grep.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

# portal/tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Assembled at runtime so git grep never matches *this* file.
OLD_NAME = ".env" + ".example"
NEW_NAME = "example.env"


def test_example_env_exists_and_old_name_does_not():
    assert (REPO_ROOT / NEW_NAME).is_file(), (f"{NEW_NAME} not found at repo root; rename has not been applied.")
    assert not (REPO_ROOT / OLD_NAME).exists(), (f"{OLD_NAME} still exists at repo root; rename is incomplete.")


def test_gitignore_contains_tmp():
    gitignore = (REPO_ROOT / ".gitignore").read_text()
    assert ".tmp/" in gitignore, (
        ".gitignore must contain a .tmp/ entry (CLAUDE.md mandates .tmp/claude as the "
        "per-worktree scratch dir)."
    )


def test_no_tracked_file_references_old_name():
    """git grep across all tracked content must find zero hits for the old name."""
    result = subprocess.run(
        ["git", "grep", "-lF", OLD_NAME],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    # git grep exits 0 when matches are found, 1 when none, >1 on error.
    if result.returncode > 1:
        raise RuntimeError(f"git grep failed: {result.stderr.strip()}")
    hits = [line for line in result.stdout.splitlines() if line]
    assert not hits, (
        f"The following tracked files still reference {OLD_NAME!r}; update them:\n" + "\n".join(f"  {h}" for h in hits)
    )
