"""uv.lock honours every version floor pyproject.toml declares.

Packages raised for security advisories carry their floor in pyproject.toml, not just
in whatever uv.lock happens to pin: a hand-edited or re-resolved lock that slips below
it fails here. Transitive packages are floored through `[tool.uv] constraint-dependencies`
(the lock alone says nothing about them to a later resolution); direct ones in
`[project] dependencies`. The numbers live in pyproject.toml.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

PORTAL = Path(__file__).resolve().parent.parent

# Advisory fix versions; pyproject.toml must not loosen below these.
ADVISORY_FLOORS = {
    "anyio": Version("4.14.2"),
    "urllib3": Version("2.8.0"),
    "starlette": Version("1.3.1"),
    "h2": Version("4.4.1"),
    "idna": Version("3.15"),
    "dnspython": Version("2.9.2"),
}
ADVISORY_TRANSITIVES = ADVISORY_FLOORS.keys() - {"dnspython"}


def _pyproject() -> dict:
    return tomllib.loads((PORTAL / "pyproject.toml").read_text())


def _lower_bounds(specs: list[str]) -> dict[str, Version]:
    """Package -> the `>=` bound each requirement string declares."""
    bounds = {}
    for spec in specs:
        req = Requirement(spec)
        lowers = [Version(s.version) for s in req.specifier if s.operator == ">="]
        if lowers:
            bounds[canonicalize_name(req.name)] = max(lowers)
    return bounds


def _declared_floors() -> dict[str, Version]:
    """Package -> the highest floor declared across dependencies and constraint-dependencies."""
    pyproject = _pyproject()
    floors: dict[str, Version] = {}
    for bounds in (
        _lower_bounds(pyproject["project"]["dependencies"]),
        _lower_bounds(pyproject["tool"]["uv"].get("constraint-dependencies", [])),
    ):
        for name, version in bounds.items():
            floors[name] = max(version, floors.get(name, version))
    return floors


def _locked_versions() -> dict[str, list[Version]]:
    """Package -> every version uv.lock holds for it (a lock may hold several)."""
    lock = tomllib.loads((PORTAL / "uv.lock").read_text())
    locked: dict[str, list[Version]] = {}
    for pkg in lock["package"]:
        locked.setdefault(canonicalize_name(pkg["name"]), []).append(Version(pkg["version"]))
    return locked


def test_advisory_transitives_are_floored_by_uv_constraints():
    constraints = _lower_bounds(_pyproject()["tool"]["uv"].get("constraint-dependencies", []))
    assert ADVISORY_TRANSITIVES <= constraints.keys()


@pytest.mark.parametrize("package,floor", sorted(ADVISORY_FLOORS.items()))
def test_advisory_floor_is_not_loosened(package, floor):
    assert _declared_floors()[package] >= floor


@pytest.mark.parametrize("package,floor", sorted(_declared_floors().items()))
def test_lock_meets_declared_floor(package, floor):
    assert min(_locked_versions()[package]) >= floor
