"""The patched dependency versions are floors in pyproject.toml, not just what uv.lock happens to pin.

A lockfile alone is undone by the next `uv lock --upgrade`-less resolution that a
looser spec permits, and says nothing about the transitive packages. Each floor is the
first release without the advisory the package was raised for.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

PORTAL = Path(__file__).resolve().parent.parent

# Transitive packages: floored through [tool.uv] constraint-dependencies.
TRANSITIVE_FLOORS = {
    "anyio": Version("4.14.2"),
    "urllib3": Version("2.8.0"),
    "starlette": Version("1.3.1"),
    "h2": Version("4.4.1"),
    "idna": Version("3.15"),
}
# Direct dependency: floored in [project] dependencies. 2.9.2 is the release the DoH
# ech= front check is written and tested against.
DIRECT_FLOORS = {"dnspython": Version("2.9.2")}


def _pyproject() -> dict:
    return tomllib.loads((PORTAL / "pyproject.toml").read_text())


def _locked_versions() -> dict[str, Version]:
    lock = tomllib.loads((PORTAL / "uv.lock").read_text())
    return {pkg["name"]: Version(pkg["version"]) for pkg in lock["package"]}


def _lower_bounds(specs: list[str]) -> dict[str, Version]:
    """Package -> the `>=` bound each requirement string declares."""
    bounds = {}
    for spec in specs:
        req = Requirement(spec)
        lowers = [Version(s.version) for s in req.specifier if s.operator == ">="]
        if lowers:
            bounds[req.name] = max(lowers)
    return bounds


def test_transitive_floors_are_declared_as_uv_constraints():
    declared = _lower_bounds(_pyproject()["tool"]["uv"].get("constraint-dependencies", []))
    for package, floor in TRANSITIVE_FLOORS.items():
        assert declared.get(package, Version("0")) >= floor, package


def test_direct_floors_are_declared_in_project_dependencies():
    declared = _lower_bounds(_pyproject()["project"]["dependencies"])
    for package, floor in DIRECT_FLOORS.items():
        assert declared.get(package, Version("0")) >= floor, package


@pytest.mark.parametrize("package,floor", {**TRANSITIVE_FLOORS, **DIRECT_FLOORS}.items())
def test_lock_meets_floor(package, floor):
    assert _locked_versions()[package] >= floor
