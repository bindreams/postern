"""Every vendored subrepo holds the source its .gitrepo declares.

Renovate bumps only `branch =` in `.gitrepo`; subrepo-pull.yaml pulls the source in a later commit. This check is what
keeps a bump whose pull never landed from merging.
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


@pytest.mark.parametrize("gitrepo", GITREPOS, ids=lambda p: p.parent.name)
def test_vendored_source_is_at_the_declared_tag(gitrepo):
    cargo = gitrepo.parent / "Cargo.toml"
    assert cargo.is_file(), f"no way to read the vendored version of {gitrepo.parent.name}; extend this test"
    version = tomllib.loads(cargo.read_text(encoding="utf-8"))["package"]["version"]
    tag = _declared_tag(gitrepo)
    assert re.fullmatch(r"v?" + re.escape(version), tag), (
        f"{gitrepo.relative_to(REPO_ROOT)} declares {tag} but the vendored source is {version}: "
        "the subrepo pull did not land (see .github/workflows/subrepo-pull.yaml)"
    )


def test_there_is_a_subrepo_to_check():
    assert GITREPOS
