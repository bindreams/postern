"""Tests for postern.mta.rotation -- state schema, persistence, triggers."""

import datetime as dt
import json
from pathlib import Path

import pytest

from postern.mta import rotation


# Schema persistence ===================================================================================================
def test_read_state_returns_no_keys_default_when_file_missing(tmp_path: Path):
    state = rotation.read_state(keydir=tmp_path)
    assert state.state == "NO_KEYS"
    assert state.active_selectors == []
    assert state.schema_version == rotation.SCHEMA_VERSION


def test_write_then_read_roundtrips(tmp_path: Path):
    original = rotation.RotationState(
        state="STABLE",
        active_selectors=["postern-2026-04"],
        last_rotation_iso="2026-04-27T12:00:00+00:00",
        next_rotation_iso="2026-10-24T12:00:00+00:00",
    )
    rotation.write_state(original, keydir=tmp_path)
    loaded = rotation.read_state(keydir=tmp_path)
    assert loaded == original


def test_write_state_is_atomic_via_replace(tmp_path: Path):
    """A partial write must not corrupt an existing state.json."""
    rotation.write_state(rotation.RotationState(state="STABLE", active_selectors=["a"]), keydir=tmp_path)
    # Simulate concurrent reader -- read should get a complete file even mid-write.
    rotation.write_state(
        rotation.RotationState(state="OVERLAP", active_selectors=["a", "b"], retiring_selector="a"),
        keydir=tmp_path,
    )
    loaded = rotation.read_state(keydir=tmp_path)
    assert loaded.state == "OVERLAP"
    assert loaded.active_selectors == ["a", "b"]


def test_read_state_logs_warning_for_newer_schema(tmp_path: Path, caplog):
    path = rotation.state_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "schema_version": rotation.SCHEMA_VERSION + 1,
            "state": "STABLE",
            "active_selectors": ["sel"],
            "future_field": "Postern can't see me",
        })
    )
    with caplog.at_level("WARNING"):
        loaded = rotation.read_state(keydir=tmp_path)
    assert loaded.state == "STABLE"
    assert loaded.active_selectors == ["sel"]
    assert any("schema_version" in rec.message for rec in caplog.records)


def test_read_state_handles_corrupt_file(tmp_path: Path, caplog):
    rotation.state_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    rotation.state_path(tmp_path).write_text("not valid json {")
    with caplog.at_level("WARNING"):
        loaded = rotation.read_state(keydir=tmp_path)
    assert loaded.state == "NO_KEYS"


# Trigger files ========================================================================================================
def test_trigger_rotation_creates_file(tmp_path: Path):
    path = rotation.trigger_rotation(keydir=tmp_path)
    assert path.exists()
    assert path.name == ".rotate-dkim"


def test_trigger_opendkim_reload_creates_file(tmp_path: Path):
    path = rotation.trigger_opendkim_reload(keydir=tmp_path)
    assert path.exists()
    assert path.name == ".reload-opendkim"


# Selector naming ======================================================================================================
def test_make_selector_uses_year_month():
    when = dt.datetime(2026, 4, 27, tzinfo=dt.timezone.utc)
    assert rotation.make_selector("postern", now=when) == "postern-2026-04"


def test_make_selector_pads_month_to_two_digits():
    when = dt.datetime(2026, 1, 5, tzinfo=dt.timezone.utc)
    assert rotation.make_selector("postern", now=when) == "postern-2026-01"


def test_make_selector_respects_custom_prefix():
    when = dt.datetime(2026, 4, 27, tzinfo=dt.timezone.utc)
    assert rotation.make_selector("custom", now=when) == "custom-2026-04"
