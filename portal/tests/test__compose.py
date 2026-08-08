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
    """See ComposeLoader's YAML-1.2 int-resolver comment in _compose.py for why
    an unquoted low-numbered port would otherwise misparse."""
    data = yaml.load("ports:\n  - 25:25\n  - 53:53\n  - 8080:53\n  - 42\n", Loader=ComposeLoader)
    assert data["ports"] == ["25:25", "53:53", "8080:53", 42]


def test_load_compose_reads_unquoted_sexagesimal_shaped_floats_as_strings():
    """See ComposeLoader's YAML-1.2 float-resolver comment in _compose.py for
    why an unquoted colon-shaped decimal would otherwise misparse."""
    data = yaml.load("a: 5:30.5\nb: 0.5\nc: -0.5\nd: 1.5\n", Loader=ComposeLoader)
    assert data == {"a": "5:30.5", "b": 0.5, "c": -0.5, "d": 1.5}


def test_load_compose_reads_legacy_bool_spellings_as_booleans():
    """See ComposeLoader's bool-resolver comment in _compose.py for why this
    one is deliberately NOT narrowed to YAML 1.2's true/false-only set."""
    data = yaml.load(
        "a: yes\nb: no\nc: on\nd: off\ne: true\nf: True\ng: TRUE\nh: false\ni: False\nj: FALSE\n",
        Loader=ComposeLoader,
    )
    assert data == {
        "a": True,
        "b": False,
        "c": True,
        "d": False,
        "e": True,
        "f": True,
        "g": True,
        "h": False,
        "i": False,
        "j": False,
    }
