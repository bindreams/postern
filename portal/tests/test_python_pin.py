"""Every Python pin site carries one minor, and one Renovate manager bumps them all.

The sites are `ARG PYTHON_MINOR=<minor>` in the portal, mta and provisioner Dockerfiles and
`portal/.python-version`. The mta and provisioner derive both the apk pin and the
site-packages COPY target from the ARG, so an unpinned `python3` cannot drift from the
py3-* packages; the portal derives its `dhi.io/python` tag from it.
"""
import json
import re
import shlex
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
    assert len(froms) == 2, froms
    assert all(image.startswith("dhi.io/python:${PYTHON_MINOR}-") for image, _ in froms), froms


def _renovate() -> dict:
    return json.loads(_text(".github/renovate.json"))


def _regex_managers_matching(rel: str) -> list[dict]:
    """Custom regex managers that track the `python` dependency and whose file patterns select `rel`.

    Renovate wraps a file pattern in `/.../`.
    """
    return [
        m for m in _renovate()["customManagers"] if m["customType"] == "regex" and m.get("depNameTemplate") == "python"
        and any(re.search(pattern.strip("/"), rel) for pattern in m["managerFilePatterns"])
    ]


def _js_regex(pattern: str) -> re.Pattern[str]:
    """A Renovate (JS, flags `gm`) regex as a Python one: named groups `(?<n>` become `(?P<n>`; lookbehinds stay."""
    return re.compile(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", pattern), re.MULTILINE)


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


# Renovate packageRules ------------------------------------------------------------------------------------------------
# Rules are evaluated in order and a later match wins. The evaluator decides a rule only through
# matchers it models exactly: exact entries of the keys below. A rule that sets the checked key
# through anything else (a glob, `/regex/`, `!negation`, another match* key) fails the test
# instead of being guessed at.
MODELLED_MATCHERS = {
    "matchManagers": "manager",
    "matchDatasources": "datasource",
    "matchDepNames": "dep_name",
    "matchPackageNames": "package_name",
    "matchFileNames": "file",
}
PATTERN_CHARS = r"[*?\[\]{}()!|\\]"


def _entry_matches(key: str, entry: str, dep: dict[str, str]) -> bool | None:
    """Whether one matcher entry matches `dep`; None when it is a pattern the evaluator cannot decide."""
    value = dep[MODELLED_MATCHERS[key]]
    if not re.search(PATTERN_CHARS, entry) and not (entry.startswith("/") and entry.endswith("/")):
        return entry == value
    # A file glob can only match a path that starts with its literal prefix.
    prefix = re.split(PATTERN_CHARS, entry)[0]
    if key == "matchFileNames" and prefix and not value.startswith(prefix):
        return False
    return None


def _rule_matches(rule: dict, dep: dict[str, str]) -> bool | None:
    """True/False when decided; None when an undecidable matcher could still change the answer.

    Matchers are ANDed, so one that definitely fails decides the rule whatever the others are.
    """
    verdicts = []
    for key, entries in rule.items():
        if not key.startswith("match"):
            continue
        if key not in MODELLED_MATCHERS:
            verdicts.append(None)
            continue
        results = [_entry_matches(key, entry, dep) for entry in entries]
        verdicts.append(True if True in results else None if None in results else False)
    if False in verdicts:
        return False
    return None if None in verdicts else True


def _final_setting(key: str, dep: dict[str, str]):
    """`key` for `dep` after every packageRule, in order; fails on a rule that sets it and cannot be decided."""
    config = _renovate()
    value = config.get(key)
    for rule in config["packageRules"]:
        if key not in rule:
            continue
        verdict = _rule_matches(rule, dep)
        if verdict is None:
            pytest.fail(
                f"cannot prove whether the packageRule {rule.get('description', rule)[:60]!r} sets {key} for {dep}; "
                "check by hand or extend the evaluator"
            )
        if verdict:
            value = rule[key]
    return value


def _python_dep(manager: str, rel: str) -> dict[str, str]:
    return {
        "manager": manager, "datasource": "docker", "dep_name": "python", "package_name": "dhi.io/python", "file": rel
    }


@pytest.mark.parametrize("rel", PIN_SITES)
def test_renovate_python_bump_is_not_automerged(rel):
    """The lockfile and the apk set trail a new minor, so a person looks at every bump."""
    assert _final_setting("automerge", _python_dep("custom.regex", rel)) is False


# Docker-datasource updates --------------------------------------------------------------------------------------------
# One representative dependency per manager that yields docker-datasource updates here. The
# docker-compose and github-actions managers have no registry image today (compose.yaml builds
# `local/` tags only); their entries keep a later one covered.
DOCKER_DEPS = [
    ("dockerfile", "dhi.io/alpine-base", "mta/Dockerfile"),
    ("dockerfile", "ghcr.io/astral-sh/uv", "portal/Dockerfile"),
    ("docker-compose", "ghcr.io/linuxserver/socket-proxy", "compose.yaml"),
    ("github-actions", "ghcr.io/linuxserver/socket-proxy", ".github/workflows/test.yaml"),
]


@pytest.mark.parametrize(("manager", "image", "rel"), DOCKER_DEPS)
def test_renovate_docker_updates_open_without_a_release_timestamp(manager, image, rel):
    """Docker Hub is the only registry with release timestamps, so any other image needs `timestamp-optional` to be
    raised under the cooldown; the evaluator fails on any rule it cannot decide."""
    dep = {"manager": manager, "datasource": "docker", "dep_name": image, "package_name": image, "file": rel}
    assert _final_setting("minimumReleaseAgeBehaviour", dep) == "timestamp-optional"


@pytest.mark.parametrize("rel", PIN_SITES)
def test_renovate_python_bump_is_raised_without_a_release_timestamp(rel):
    """The `custom.regex` manager's python pin is a docker-datasource dep on `dhi.io/python`."""
    assert _final_setting("minimumReleaseAgeBehaviour", _python_dep("custom.regex", rel)) == "timestamp-optional"


def test_renovate_keeps_the_release_age_cooldown_for_other_datasources():
    """GitHub tags carry timestamps, so the cooldown applies to them as written."""
    dep = {
        "manager": "custom.regex", "datasource": "github-tags", "dep_name": "bindreams/hole-ex-ray",
        "package_name": "bindreams/hole", "file": "shadowsocks/Dockerfile"
    }
    assert _final_setting("minimumReleaseAgeBehaviour", dep) is None
    assert _renovate()["minimumReleaseAge"] == "7 days"


def test_renovate_dockerfile_manager_leaves_the_python_image_to_the_pin():
    """It would resolve the portal's `${PYTHON_MINOR}` tag into a second, unreplaceable update."""
    dep = {
        "manager": "dockerfile", "datasource": "docker", "dep_name": "dhi.io/python", "package_name": "dhi.io/python",
        "file": "portal/Dockerfile"
    }
    assert _final_setting("enabled", dep) is False


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


# Alpine releases and licence versions look like a Python minor but are not one.
NOT_A_PYTHON_MINOR = re.compile(r"(?i)\b(?:alpine-base:|alpine|AGPL-)\s?\d+\.\d+")
HARDCODED_MINOR = (r"python3\.\d+", r"py3\.\d+-", r"cp3\d+", r"\b3\.\d+\b")


@pytest.mark.parametrize("rel", (*PIN_DOCKERFILES, "mta/entrypoint.py", "provisioner/entrypoint.py"))
def test_no_hardcoded_python_minor(rel):
    hits = []
    for number, line in enumerate(_text(rel).splitlines(), 1):
        if line.startswith("ARG PYTHON_MINOR="):
            continue
        line = NOT_A_PYTHON_MINOR.sub("", line)
        hits += [f"{rel}:{number}: {line.strip()}" for pattern in HARDCODED_MINOR if re.search(pattern, line)]
    assert not hits, "hardcodes a Python minor; use ${PYTHON_MINOR}:\n" + "\n".join(hits)


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
