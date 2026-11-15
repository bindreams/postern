"""Every Python pin site carries one minor, and one Renovate manager bumps them all.

The sites are `ARG PYTHON_MINOR=<minor>` in the portal, mta and provisioner Dockerfiles and
`portal/.python-version`. The mta and provisioner derive both the apk pin and the
site-packages COPY target from the ARG, so an unpinned `python3` cannot drift from the
py3-* packages; the portal derives its `dhi.io/python` tag from it.
"""
import json
import re
import shlex
from fnmatch import fnmatch
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGES = ("mta/Dockerfile", "provisioner/Dockerfile")
PIN_DOCKERFILES = ("portal/Dockerfile", *IMAGES)
PYTHON_VERSION_FILE = "portal/.python-version"
PIN_SITES = (*PIN_DOCKERFILES, PYTHON_VERSION_FILE)


def _text(rel: str) -> str:
    return (REPO_ROOT / rel).read_text()


def _pin(rel: str) -> str:
    """The Python minor a pin site declares."""
    if rel == PYTHON_VERSION_FILE:
        return _text(rel).strip()
    m = re.search(r"^ARG PYTHON_MINOR=(\S+)$", _text(rel), re.MULTILINE)
    assert m, f"{rel} must declare `ARG PYTHON_MINOR=<minor>`"
    return m.group(1)


def test_every_pin_site_declares_the_same_minor():
    minors = {rel: _pin(rel) for rel in PIN_SITES}
    assert len(set(minors.values())) == 1, minors


def _python_froms() -> list[tuple[str, str]]:
    """(image, stage name or "") of every `FROM dhi.io/python:...` in the portal Dockerfile; FROM flags allowed."""
    pattern = r"^FROM (?:--\S+\s+)*(dhi\.io/python:\S+)(?:\s+AS\s+(\S+))?\s*$"
    return re.findall(pattern, _text("portal/Dockerfile"), re.MULTILINE)


def test_portal_python_image_tag_comes_from_the_arg():
    froms = _python_froms()
    assert len(froms) == 2, froms  # build and runtime stage
    assert all(image.startswith("dhi.io/python:${PYTHON_MINOR}-") for image, _ in froms), froms


def _renovate() -> dict:
    return json.loads(_text(".github/renovate.json"))


def _regex_managers_matching(rel: str) -> list[dict]:
    """Custom regex managers that track the `python` dependency and whose file patterns select `rel`.

    Renovate wraps a file pattern in `/.../`. Other managers also select the Dockerfiles (Lego, for one).
    """
    return [
        m for m in _renovate()["customManagers"] if m["customType"] == "regex" and m.get("depNameTemplate") == "python"
        and any(re.search(pattern.strip("/"), rel) for pattern in m["managerFilePatterns"])
    ]


def _js_regex(pattern: str) -> re.Pattern[str]:
    """A Renovate (JS) regex as a Python one: named groups `(?<n>` become `(?P<n>`; lookbehinds `(?<=`/`(?<!` stay."""
    return re.compile(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", pattern))


def _manager_for(rel: str) -> dict:
    (manager, ) = _regex_managers_matching(rel)
    return manager


def test_one_renovate_manager_bumps_every_pin_site():
    managers = [_regex_managers_matching(rel) for rel in PIN_SITES]
    assert all(len(found) == 1 for found in managers), managers
    assert all(found[0] == managers[0][0] for found in managers), "pin sites are bumped by different managers"


@pytest.mark.parametrize("rel", PIN_SITES)
def test_renovate_manager_reads_the_pin_site(rel):
    found = [
        m.group("currentValue") for pattern in _manager_for(rel)["matchStrings"]
        for m in _js_regex(pattern).finditer(_text(rel))
    ]
    assert found == [_pin(rel)], found


def test_renovate_dockerfile_manager_leaves_the_python_image_to_the_pin():
    """It would resolve the portal's `${PYTHON_MINOR}` tag into a second, unreplaceable update."""
    assert any(
        rule.get("matchManagers") == ["dockerfile"] and rule.get("matchPackageNames") == ["dhi.io/python"]
        and rule.get("enabled") is False for rule in _renovate()["packageRules"]
    )


def test_renovate_only_offers_minors_published_in_the_variant_the_portal_pulls():
    """The bare `3.16` tag (Debian) can appear before `3.16-alpine3.23-dev`; the build stage's tag is the one offered."""
    (build_tag, ) = [image for image, stage in _python_froms() if stage == "build"]
    suffix = build_tag.removeprefix("dhi.io/python:${PYTHON_MINOR}")
    extract = _js_regex(_manager_for("portal/Dockerfile")["extractVersionTemplate"])

    def tag_to_version(tag: str) -> str | None:
        m = extract.search(tag)
        return m.group("version") if m else None

    assert tag_to_version(f"3.16{suffix}") == "3.16"
    for tag in ("3.16", "3.16.1", f"3.16.1{suffix}", "3.16-alpine3.23", "3.16-debian13-dev", "3.16-alpine3.99-dev"):
        assert tag_to_version(tag) is None, tag


def _final_automerge(rel: str) -> bool:
    """`automerge` for the python dependency at `rel` after every packageRule, in order: a later match wins."""
    dep = {
        "matchManagers": "custom.regex",
        "matchDepNames": "python",
        "matchPackageNames": "dhi.io/python",
    }
    config = _renovate()
    automerge = config["automerge"]
    for rule in config["packageRules"]:
        matched = all(dep[key] in rule[key] for key in dep if key in rule)
        if "matchFileNames" in rule:
            matched = matched and any(fnmatch(rel, glob) for glob in rule["matchFileNames"])
        if matched and "automerge" in rule:
            automerge = rule["automerge"]
    return automerge


def test_renovate_python_bump_is_not_automerged():
    """The lockfile and the apk set trail a new minor, so a person looks at every bump."""
    assert [_final_automerge(rel) for rel in PIN_SITES] == [False] * len(PIN_SITES)


def test_renovate_pyenv_manager_is_off():
    """It would bump `.python-version` on its own, in a PR the Dockerfiles do not follow."""
    assert _renovate().get("pyenv") == {"enabled": False}


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


@pytest.mark.parametrize("rel", (*PIN_DOCKERFILES, "mta/entrypoint.py", "provisioner/entrypoint.py"))
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


@pytest.mark.parametrize("rel", PIN_DOCKERFILES)
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
