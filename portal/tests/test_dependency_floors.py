"""uv.lock honours every version floor pyproject.toml declares.

Packages raised for security advisories carry their floor in pyproject.toml, not just
in whatever uv.lock happens to pin: a hand-edited or re-resolved lock that slips below
it fails here. Transitive packages are floored through `[tool.uv] constraint-dependencies`
(the lock alone says nothing about them to a later resolution); direct ones in
`[project] dependencies`. The numbers live in pyproject.toml; ADVISORY_FLOORS pins the
advisory ones so a floor cannot be loosened there.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

PORTAL = Path(__file__).resolve().parent.parent

# Packages raised for advisories, at the versions that fixed them: pyproject.toml must not
# loosen a floor below these (a lock bump alone would otherwise be the only guard).
ADVISORY_FLOORS = {
    "anyio": Version("4.14.2"),
    "urllib3": Version("2.8.0"),
    "starlette": Version("1.3.1"),
    "h2": Version("4.4.1"),
    "idna": Version("3.15"),
    "dnspython": Version("2.9.2"),
}
# Of those, the ones that are transitive: floored through `constraint-dependencies`.
ADVISORY_TRANSITIVES = {"anyio", "urllib3", "starlette", "h2", "idna"}


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
    pyproject = _pyproject()
    return {
        **_lower_bounds(pyproject["project"]["dependencies"]),
        **_lower_bounds(pyproject["tool"]["uv"].get("constraint-dependencies", [])),
    }


def _locked_versions() -> dict[str, Version]:
    lock = tomllib.loads((PORTAL / "uv.lock").read_text())
    return {pkg["name"]: Version(pkg["version"]) for pkg in lock["package"]}


def test_advisory_transitives_are_floored_by_uv_constraints():
    constraints = _lower_bounds(_pyproject()["tool"]["uv"].get("constraint-dependencies", []))
    assert ADVISORY_TRANSITIVES <= constraints.keys()


@pytest.mark.parametrize("package,floor", sorted(ADVISORY_FLOORS.items()))
def test_advisory_floor_is_not_loosened(package, floor):
    assert _declared_floors()[package] >= floor


@pytest.mark.parametrize("package,floor", sorted(_declared_floors().items()))
def test_lock_meets_declared_floor(package, floor):
    assert _locked_versions()[package] >= floor
