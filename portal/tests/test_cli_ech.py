"""Tests for the `postern ech` CLI (DoH front verification)."""
from __future__ import annotations

from typer.testing import CliRunner

from postern.cli import app

runner = CliRunner()


def _env(monkeypatch, **kw):
    monkeypatch.setenv("SECRET_KEY", "x" * 64)
    monkeypatch.setenv("DOMAIN", "postern.test")
    for k, v in kw.items():
        monkeypatch.setenv(k, v)


def test_ech_verify_passes_when_present(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setattr("postern.ech.check_apex_ech", lambda *a, **k: "present")
    result = runner.invoke(app, ["ech", "verify"])
    assert result.exit_code == 0
    assert "ech OK" in result.stdout


def test_ech_verify_fails_when_absent(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setattr("postern.ech.check_apex_ech", lambda *a, **k: "absent")
    result = runner.invoke(app, ["ech", "verify"])
    assert result.exit_code == 1


def test_ech_verify_inconclusive_exit_2(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setattr("postern.ech.check_apex_ech", lambda *a, **k: "inconclusive")
    result = runner.invoke(app, ["ech", "verify"])
    assert result.exit_code == 2


def test_ech_show_prints_status_and_state(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setattr("postern.ech.check_apex_ech", lambda *a, **k: "present")
    # Surface a captured Cloudflare error from the provisioner state file.
    from postern_provisioner import ech as ech_state
    monkeypatch.setattr(
        ech_state,
        "read_state",
        lambda *a, **k: ech_state.EchZoneState(consecutive_failures=3, last_error="ECH is not available on this plan"),
    )
    result = runner.invoke(app, ["ech", "show"])
    assert result.exit_code == 0
    assert "front serving ech= :     present" in result.stdout
    assert "ECH is not available on this plan" in result.stdout
