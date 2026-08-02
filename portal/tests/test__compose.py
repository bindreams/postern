"""Unit tests for the shared !reset-tolerant compose YAML loader."""
from __future__ import annotations

from pathlib import Path

from ._compose import load_compose

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_load_compose_tolerates_reset_tag():
    compose = load_compose(REPO_ROOT / "compose.gateway.yaml")
    assert compose["services"]["nginx"]["ports"] is None


def test_load_compose_returns_dict_for_ordinary_file():
    compose = load_compose(REPO_ROOT / "compose.yaml")
    assert isinstance(compose, dict)
    assert "services" in compose
