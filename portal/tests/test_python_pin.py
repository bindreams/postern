"""The mta and provisioner images pin one Python minor, equal to the portal's.

Each Dockerfile declares `PYTHON_MINOR` once and derives both the apk pin and the
site-packages COPY target from it, so an unpinned `python3` cannot drift from the
py3-* packages.
"""
import re
import shlex
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGES = ("mta/Dockerfile", "provisioner/Dockerfile")


def _text(rel: str) -> str:
    return (REPO_ROOT / rel).read_text()


def _portal_minor() -> str:
    minors = set(re.findall(r"^FROM dhi\.io/python:(\d+\.\d+)-", _text("portal/Dockerfile"), re.MULTILINE))
    assert minors, "portal/Dockerfile no longer FROMs dhi.io/python:<minor>-..."
    assert len(minors) == 1, f"portal/Dockerfile stages disagree on the Python minor: {sorted(minors)}"
    return minors.pop()


@pytest.mark.parametrize("rel", IMAGES)
def test_python_minor_matches_portal(rel):
    m = re.search(r"^ARG PYTHON_MINOR=(\S+)$", _text(rel), re.MULTILINE)
    assert m, f"{rel} must declare `ARG PYTHON_MINOR=<minor>`"
    assert m.group(1) == _portal_minor()


def _apk_add_python_tokens(code: str) -> list[str]:
    """Every `python3*` word in every `apk add` list, quotes resolved and backslash continuations joined."""
    tokens = []
    for line in code.replace("\\\n", " ").splitlines():
        for add in re.findall(r"\bapk add\b([^;&|]*)", line):
            tokens += [t for t in shlex.split(add) if t.startswith("python3")]
    return tokens


@pytest.mark.parametrize("rel", IMAGES)
def test_apk_python_is_pinned_to_the_minor(rel):
    code = "\n".join(line for line in _text(rel).splitlines() if not line.lstrip().startswith("#"))
    tokens = _apk_add_python_tokens(code)
    assert tokens, f"{rel} installs no python3 with apk add"
    # Anything but the exact pinned form (bare, `python3>=3.14`, `python3=3.15`, ...) is unpinned.
    assert set(tokens) == {"python3~${PYTHON_MINOR}"}, tokens


@pytest.mark.parametrize("rel", (*IMAGES, "mta/entrypoint.py", "provisioner/entrypoint.py"))
def test_no_hardcoded_python_minor_path(rel):
    assert not re.search(r"python3\.\d+", _text(rel)), f"{rel} hardcodes a Python minor; use ${{PYTHON_MINOR}}"


def _code_lines(rel: str) -> list[str]:
    """Dockerfile lines without comments, backslash continuations joined."""
    lines = _text(rel).replace("\\\n", " ").splitlines()
    return [line for line in lines if not line.lstrip().startswith("#")]


def _copy_destinations(rel: str) -> set[str]:
    """Destination of every COPY into a site-packages dir: the last token, `--flag` tokens dropped."""
    dests = set()
    for line in _code_lines(rel):
        tokens = shlex.split(line)
        if tokens[:1] == ["COPY"]:
            args = [t for t in tokens[1:] if not t.startswith("--")]
            if "site-packages" in args[-1]:
                dests.add(args[-1])
    return dests


SITE_PACKAGES = "/usr/lib/python${PYTHON_MINOR}/site-packages"
EXPECTED_COPIES = {
    "mta/Dockerfile": {"postern_mta"},
    "provisioner/Dockerfile": {"postern_mta", "postern", "postern_provisioner"},
}


@pytest.mark.parametrize("rel", IMAGES)
def test_site_packages_copies_use_the_pinned_minor(rel):
    expected = {f"{SITE_PACKAGES}/{name}" for name in EXPECTED_COPIES[rel]}
    assert _copy_destinations(rel) == expected


@pytest.mark.parametrize("rel", IMAGES)
def test_every_stage_using_the_minor_redeclares_the_arg(rel):
    """A global ARG is not visible inside a stage until the stage redeclares it."""
    stage_lines: list[str] = []
    stages = [stage_lines]
    for line in _code_lines(rel):
        if line.startswith("FROM "):
            stage_lines = []
            stages.append(stage_lines)
        else:
            stage_lines.append(line)
    for lines in stages:
        use = next((n for n, line in enumerate(lines) if "PYTHON_MINOR}" in line and not line.startswith("ARG ")), None)
        if use is not None:
            assert any(re.fullmatch(r"ARG PYTHON_MINOR(=\S+)?", line.strip()) for line in lines[:use]), lines[use]
