"""Renovate bumps only `branch =` in `.gitrepo`; subrepo-pull.yaml pulls the source in a later commit. This fails a bump
whose pull never landed.

Offline, the vendored Cargo.toml version stands in for the tag: an upstream release whose version differs from its tag
fails here even when the pull landed, and needs this test extended.
"""

import configparser
import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GITREPOS = sorted((REPO_ROOT / "external").glob("*/.gitrepo"))


def _declared_tag(gitrepo: Path) -> str:
    parser = configparser.ConfigParser()
    parser.read_string(gitrepo.read_text(encoding="utf-8"))
    return parser["subrepo"]["branch"]


def _vendored_version(subrepo: Path) -> str | None:
    cargo = subrepo / "Cargo.toml"
    if not cargo.is_file():
        return None
    version = tomllib.loads(cargo.read_text(encoding="utf-8")).get("package", {}).get("version")
    return version if isinstance(version, str) else None


@pytest.mark.parametrize("gitrepo", GITREPOS, ids=lambda p: p.parent.name)
def test_vendored_source_is_at_the_declared_tag(gitrepo):
    version = _vendored_version(gitrepo.parent)
    assert version is not None, f"cannot read {gitrepo.parent.name}'s version from Cargo.toml [package]; extend this test"
    tag = _declared_tag(gitrepo)
    assert re.fullmatch(r"v?" + re.escape(version), tag), (
        f"{gitrepo.relative_to(REPO_ROOT)} declares {tag} but the vendored source is {version}: "
        "the subrepo pull did not land (see .github/workflows/subrepo-pull.yaml)"
    )


def test_there_is_a_subrepo_to_check():
    assert GITREPOS
