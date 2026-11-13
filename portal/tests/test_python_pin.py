"""The mta and provisioner images pin one Python minor (issue #266).

Alpine's live apk index can offer two Python minors at once; an unpinned
`apk add python3` then either fails to solve or installs a minor that the
`py3-*` packages (built for another minor) do not match. Each Dockerfile
declares `PYTHON_MINOR` once and derives both the apk pin and the
site-packages COPY target from it, so they cannot drift apart. The pin
follows the portal's Python.
"""
import re
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


@pytest.mark.parametrize("rel", IMAGES)
def test_apk_python_is_pinned_to_the_minor(rel):
    code = "\n".join(line for line in _text(rel).splitlines() if not line.lstrip().startswith("#"))
    assert "python3~${PYTHON_MINOR}" in code
    # A whitespace-delimited bare `python3` in an apk add list is the unpinned form.
    for add in re.findall(r"apk add.*(?:\\\n.*)*", code):
        assert not re.search(r"(?<=\s)python3(?=\s|$)", add), add


@pytest.mark.parametrize("rel", (*IMAGES, "mta/entrypoint.py", "provisioner/entrypoint.py"))
def test_no_hardcoded_python_minor_path(rel):
    assert not re.search(r"python3\.\d+", _text(rel)), f"{rel} hardcodes a Python minor; use ${{PYTHON_MINOR}}"


@pytest.mark.parametrize("rel", IMAGES)
def test_site_packages_copies_use_the_pinned_minor(rel):
    text = _text(rel)
    copies = re.findall(r"^COPY \S+ (\S*site-packages\S*)$", text, re.MULTILINE)
    assert copies
    for dest in copies:
        assert dest.startswith("/usr/lib/python${PYTHON_MINOR}/site-packages/"), dest
