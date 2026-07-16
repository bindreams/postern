"""Tests for the provisioner zone-ECH reconciler + state."""
from __future__ import annotations

import datetime as dt
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from postern_provisioner import ech

_NOW = dt.datetime(2026, 7, 14, tzinfo=dt.timezone.utc)


@dataclass
class FakeRunner:
    fail: bool = False
    stderr: str = ""
    calls: list[str] = field(default_factory=list)

    def set_on(self, domain: str) -> None:
        self.calls.append(domain)
        if self.fail:
            raise subprocess.CalledProcessError(1, ["postern-dns", "ech-set", domain, "on"], stderr=self.stderr)


def _settings():
    return ech.EchZoneSettings(domain="postern.test", ech_doh_url="https://doh.test/dns-query")


def test_reconcile_records_success_and_serving(caplog):
    caplog.set_level(logging.INFO, logger="postern_provisioner.ech")
    runner = FakeRunner()
    new = ech.reconcile_zone_ech(
        ech.EchZoneState(), settings=_settings(), runner=runner,
        serving_check=lambda d, u: "present", now=_NOW,
    )
    assert runner.calls == ["postern.test"]
    assert new.last_enabled_ok_iso == _NOW.isoformat()
    assert new.consecutive_failures == 0
    assert new.last_serving is True
    assert "zone ECH enabled" in caplog.text  # first-success transition logged by the reconciler


def test_reconcile_steady_state_is_a_noop(caplog):
    # Already enabled + serving: reconcile must return a state EQUAL to the input,
    # so _try_advance_ech skips write_state (no churn, no nginx reload regardless of dir).
    caplog.set_level(logging.INFO, logger="postern_provisioner.ech")
    prior = ech.EchZoneState(last_enabled_ok_iso="2026-01-01T00:00:00+00:00", last_serving=True)
    runner = FakeRunner()
    new = ech.reconcile_zone_ech(
        prior, settings=_settings(), runner=runner,
        serving_check=lambda d, u: "present", now=_NOW,
    )
    assert new == prior  # identical -> caller writes nothing
    assert "zone ECH enabled" not in caplog.text  # no transition log on steady state


def test_reconcile_warns_when_not_serving_but_stays_enabled(caplog):
    caplog.set_level(logging.WARNING, logger="postern_provisioner.ech")
    runner = FakeRunner()
    new = ech.reconcile_zone_ech(
        ech.EchZoneState(), settings=_settings(), runner=runner,
        serving_check=lambda d, u: "absent", now=_NOW,
    )
    assert new.last_enabled_ok_iso == _NOW.isoformat()  # PATCH succeeded -> health fact set
    assert new.last_serving is False
    assert "not serving ech=" in caplog.text


def test_reconcile_serving_check_exception_keeps_enablement(caplog):
    # A serving_check raise must NOT discard the earned enablement fact nor propagate.
    caplog.set_level(logging.DEBUG, logger="postern_provisioner.ech")

    def boom(d, u):
        raise RuntimeError("doh blew up")

    new = ech.reconcile_zone_ech(
        ech.EchZoneState(), settings=_settings(), runner=FakeRunner(),
        serving_check=boom, now=_NOW,
    )
    assert new.last_enabled_ok_iso == _NOW.isoformat()  # enablement fact preserved
    assert new.last_serving is None  # unchanged (unknown), not flipped


def test_reconcile_counts_failures_and_preserves_prior_ok():
    prior = ech.EchZoneState(last_enabled_ok_iso="2026-01-01T00:00:00+00:00")
    runner = FakeRunner(fail=True, stderr="ECH is not available on this plan")
    new = ech.reconcile_zone_ech(
        prior, settings=_settings(), runner=runner,
        serving_check=lambda d, u: "present", now=_NOW,
    )
    assert new.consecutive_failures == 1
    assert new.last_enabled_ok_iso == "2026-01-01T00:00:00+00:00"  # unchanged on failure
    assert "ECH is not available on this plan" in new.last_error


def test_reconcile_accumulates_consecutive_failures():
    # The failure counter must accumulate across ticks, not reset each tick.
    prior = ech.EchZoneState(consecutive_failures=2)
    new = ech.reconcile_zone_ech(
        prior, settings=_settings(), runner=FakeRunner(fail=True, stderr="boom"),
        serving_check=lambda d, u: "present", now=_NOW,
    )
    assert new.consecutive_failures == 3


def test_reconcile_recovery_restamps_enabled_ok():
    # After a failure, the next success re-stamps last_enabled_ok_iso and clears failures.
    prior = ech.EchZoneState(last_enabled_ok_iso="2026-01-01T00:00:00+00:00", consecutive_failures=1)
    new = ech.reconcile_zone_ech(
        prior, settings=_settings(), runner=FakeRunner(),
        serving_check=lambda d, u: "present", now=_NOW,
    )
    assert new.last_enabled_ok_iso == _NOW.isoformat()
    assert new.consecutive_failures == 0


def test_reconcile_inconclusive_leaves_serving_unchanged_no_warn(caplog):
    # A transient DoH blip (inconclusive) must NOT flip last_serving to False nor warn
    # "not serving" -- that would churn state and misattribute a query-side failure.
    caplog.set_level(logging.WARNING, logger="postern_provisioner.ech")
    prior = ech.EchZoneState(last_enabled_ok_iso="2026-01-01T00:00:00+00:00", last_serving=True)
    new = ech.reconcile_zone_ech(
        prior, settings=_settings(), runner=FakeRunner(),
        serving_check=lambda d, u: "inconclusive", now=_NOW,
    )
    assert new.last_serving is True          # unchanged
    assert new == prior                       # no state change -> caller writes nothing
    assert "not serving ech=" not in caplog.text


def test_reconcile_records_launch_failure_in_state(caplog):
    # A non-CalledProcessError from set_on (e.g. missing binary -> FileNotFoundError, an
    # OSError) must still be recorded into consecutive_failures/last_error, not escape.
    caplog.set_level(logging.ERROR, logger="postern_provisioner.ech")

    class MissingBinaryRunner:
        def set_on(self, domain):
            raise FileNotFoundError(2, "No such file or directory", "/usr/local/bin/postern-dns")

    new = ech.reconcile_zone_ech(
        ech.EchZoneState(), settings=_settings(), runner=MissingBinaryRunner(),
        serving_check=lambda d, u: "present", now=_NOW,
    )
    assert new.consecutive_failures == 1
    assert new.last_enabled_ok_iso is None
    assert "postern-dns" in new.last_error


def test_reconcile_and_persist_writes_only_on_change(tmp_path: Path, monkeypatch):
    writes: list = []
    real_write = ech.write_state
    monkeypatch.setattr(ech, "write_state", lambda st, **k: (writes.append(st), real_write(st, **k))[-1])
    s = _settings()
    ech.reconcile_and_persist(settings=s, runner=FakeRunner(), serving_check=lambda d, u: "present", state_dir=tmp_path, now=_NOW)
    assert len(writes) == 1  # first success -> write
    ech.reconcile_and_persist(settings=s, runner=FakeRunner(), serving_check=lambda d, u: "present", state_dir=tmp_path, now=_NOW)
    assert len(writes) == 1  # steady state -> no second write


def test_state_roundtrip(tmp_path: Path):
    st = ech.EchZoneState(
        last_enabled_ok_iso="2026-07-14T00:00:00+00:00", consecutive_failures=2,
        last_error="x", last_serving=False,
    )
    ech.write_state(st, state_dir=tmp_path)
    assert ech.read_state(state_dir=tmp_path) == st


def test_read_state_missing_is_empty(tmp_path: Path):
    assert ech.read_state(state_dir=tmp_path) == ech.EchZoneState()


def test_read_state_corrupt_json_is_empty(tmp_path: Path):
    # The healthcheck calls read_state uncaught -- a torn/corrupt file must degrade
    # to empty state, not raise (which would wedge first-boot gating).
    (tmp_path / ech.STATE_FILENAME).write_text("{not valid json", encoding="utf-8")
    assert ech.read_state(state_dir=tmp_path) == ech.EchZoneState()


def test_write_state_cleans_up_tmp_on_replace_failure(tmp_path: Path, monkeypatch):
    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(ech.os, "replace", boom)
    with pytest.raises(OSError):
        ech.write_state(ech.EchZoneState(last_enabled_ok_iso="x"), state_dir=tmp_path)
    assert not list(tmp_path.glob(".ech_zone_state.*.tmp"))  # no leaked temp file
