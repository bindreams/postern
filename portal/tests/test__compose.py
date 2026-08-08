"""Unit tests for the shared !reset-tolerant compose YAML loader."""
from __future__ import annotations

from pathlib import Path

import yaml

from ._compose import ComposeLoader, load_compose

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_load_compose_tolerates_reset_tag():
    compose = load_compose(REPO_ROOT / "compose.gateway.yaml")
    assert compose["services"]["nginx"]["ports"] is None


def test_load_compose_returns_dict_for_ordinary_file():
    compose = load_compose(REPO_ROOT / "compose.yaml")
    assert isinstance(compose, dict)
    assert "services" in compose


def test_load_compose_reads_unquoted_low_numbered_ports_as_strings():
    """PyYAML's stock int resolver follows YAML 1.1's sexagesimal rule: an
    unquoted `25:25` would otherwise parse as the int 1525 (25*60+25), not the
    string Docker Compose itself reads. Every compose file in this repo
    quotes its `ports:` entries today, so this never fires in practice --
    tested directly against the loader so a future unquoted low port doesn't
    silently misparse."""
    data = yaml.load("ports:\n  - 25:25\n  - 53:53\n  - 42\n", Loader=ComposeLoader)
    assert data["ports"] == ["25:25", "53:53", 42]
