"""Smoke tests for the `postern doctor` subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from postern import doctor
from postern.cli import app

runner = CliRunner()


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "x" * 64)
    monkeypatch.setenv("DOMAIN", "hole.example")
    monkeypatch.setenv("PUBLIC_IPV4", "203.0.113.42")
    monkeypatch.setenv("MTA_ADMIN_EMAIL", "ops@example.com")


def _build_passing_report() -> doctor.DoctorReport:
    return doctor.DoctorReport(
        results=[
            doctor.CheckResult(section=doctor.EXTERNAL, label="DS hole.example", status="ok", detail="-> ok"),
            doctor.CheckResult(section=doctor.CONNECTIVITY, label=":443/tcp hole.example", status="ok"),
        ]
    )


def _build_failing_report() -> doctor.DoctorReport:
    return doctor.DoctorReport(
        results=[
            doctor.CheckResult(
                section=doctor.EXTERNAL,
                label="PTR 203.0.113.42",
                status="fail",
                detail="no PTR record",
                fix="set rDNS at VPS provider",
            ),
        ]
    )


def test_doctor_exits_zero_when_all_checks_pass(env):
    with patch.object(doctor, "run_doctor", return_value=_build_passing_report()):
        result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "All 2 checks passed" in result.output


def test_doctor_exits_nonzero_on_any_fail(env):
    with patch.object(doctor, "run_doctor", return_value=_build_failing_report()):
        result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "[FAIL]" in result.output
    assert "Fix: set rDNS at VPS provider" in result.output


def test_doctor_json_flag_emits_structured_output(env):
    with patch.object(doctor, "run_doctor", return_value=_build_failing_report()):
        result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 1
    decoded = json.loads(result.output)
    assert decoded["exit_code"] == 1
    assert decoded["results"][0]["status"] == "fail"


def test_doctor_external_only_restricts_sections(env):
    captured: dict = {}

    def fake_run_doctor(_settings, *, sections, **kwargs):
        captured["sections"] = sections
        return _build_passing_report()

    with patch.object(doctor, "run_doctor", side_effect=fake_run_doctor):
        result = runner.invoke(app, ["doctor", "--external-only"])
    assert result.exit_code == 0
    assert captured["sections"] == (doctor.EXTERNAL, )


def test_doctor_postern_only_restricts_sections(env):
    captured: dict = {}

    def fake_run_doctor(_settings, *, sections, **kwargs):
        captured["sections"] = sections
        return _build_passing_report()

    with patch.object(doctor, "run_doctor", side_effect=fake_run_doctor):
        result = runner.invoke(app, ["doctor", "--postern-only"])
    assert result.exit_code == 0
    assert captured["sections"] == (doctor.POSTERN_MANAGED, )


def test_doctor_connectivity_only_restricts_sections(env):
    captured: dict = {}

    def fake_run_doctor(_settings, *, sections, **kwargs):
        captured["sections"] = sections
        return _build_passing_report()

    with patch.object(doctor, "run_doctor", side_effect=fake_run_doctor):
        result = runner.invoke(app, ["doctor", "--connectivity-only"])
    assert result.exit_code == 0
    assert captured["sections"] == (doctor.CONNECTIVITY, )


def test_doctor_rejects_multiple_only_flags(env):
    result = runner.invoke(app, ["doctor", "--external-only", "--postern-only"])
    assert result.exit_code == 2
    assert "at most one of" in (result.stderr or result.output)


def test_doctor_settings_passed_through(env, tmp_path: Path):
    """Smoke: the typer wrapper composes a DoctorSettings from the env."""
    captured: dict = {}

    def fake_run_doctor(settings, **kwargs):
        captured["settings"] = settings
        return _build_passing_report()

    with patch.object(doctor, "run_doctor", side_effect=fake_run_doctor):
        result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    s = captured["settings"]
    assert s.domain == "hole.example"
    assert s.public_ipv4 == "203.0.113.42"
    assert s.admin_email == "ops@example.com"
    # No cert on disk in this test -> tlsa_cert_hex is None.
    assert s.tlsa_cert_hex is None
