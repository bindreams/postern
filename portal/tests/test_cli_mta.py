"""Tests for `postern mta` CLI subcommands."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from postern.cli import app
from postern.mta import dkim as mta_dkim
from postern.mta import rotation


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Provide a fresh keydir + the env vars Settings needs to instantiate."""
    monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
    monkeypatch.setenv("DOMAIN", "postern.test")
    monkeypatch.setenv("MTA_ADMIN_EMAIL", "admin@elsewhere.example")
    monkeypatch.setenv("MTA_REQUIRE_DNSSEC", "false")
    keydir = tmp_path / "opendkim"
    keydir.mkdir()
    monkeypatch.setattr(mta_dkim, "DEFAULT_KEYDIR", keydir)
    monkeypatch.setattr(rotation, "DEFAULT_KEYDIR", keydir)
    return keydir


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# show-dns =============================================================================================================
def test_show_dns_renders_records_with_no_keys(env: Path, runner: CliRunner):
    result = runner.invoke(app, ["mta", "show-dns"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "MX" in out
    assert "SPF" in out
    assert "DMARC" in out
    assert "MTA-STS" in out
    assert "DKIM" in out
    assert "postern.test" in out
    assert "admin@elsewhere.example" in out


def test_show_dns_includes_dkim_pubkey_when_keys_present(env: Path, runner: CliRunner):
    selector = "postern-2026-04"
    (env / f"{selector}.txt").write_text(f'{selector}._domainkey IN TXT ( "v=DKIM1; k=rsa; " "p=ABC123XYZ" )')
    (env / f"{selector}.private").write_text("dummy")
    rotation.write_state(rotation.RotationState(state="STABLE", active_selectors=[selector]), keydir=env)

    result = runner.invoke(app, ["mta", "show-dns"])
    assert result.exit_code == 0, result.output
    assert "ABC123XYZ" in result.output
    assert f"{selector}._domainkey" in result.output


# verify-dns ===========================================================================================================
def test_verify_dns_fails_when_no_keys_yet(env: Path, runner: CliRunner):
    result = runner.invoke(app, ["mta", "verify-dns"])
    assert result.exit_code == 1
    assert "no DKIM keys yet" in result.output or "no DKIM keys yet" in result.stderr


# rotate-dkim ==========================================================================================================
def test_rotate_dkim_writes_trigger_file(env: Path, runner: CliRunner):
    result = runner.invoke(app, ["mta", "rotate-dkim"])
    assert result.exit_code == 0, result.output
    assert (env / ".rotate-dkim").exists()


# rotation-status ======================================================================================================
def test_rotation_status_shows_no_keys_default(env: Path, runner: CliRunner):
    result = runner.invoke(app, ["mta", "rotation-status"])
    assert result.exit_code == 0, result.output
    assert "NO_KEYS" in result.output
    assert "(none)" in result.output


def test_rotation_status_renders_active_selectors(env: Path, runner: CliRunner):
    rotation.write_state(
        rotation.RotationState(
            state="OVERLAP",
            active_selectors=["postern-2026-04", "postern-2026-10"],
            retiring_selector="postern-2026-04",
            last_rotation_iso="2026-04-27T12:00:00+00:00",
            next_rotation_iso="2026-10-24T12:00:00+00:00",
        ),
        keydir=env,
    )
    result = runner.invoke(app, ["mta", "rotation-status"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "OVERLAP" in out
    assert "postern-2026-04" in out
    assert "postern-2026-10" in out
    assert "Retiring selector" in out
    assert "2026-10-24" in out


# dnssec-status ========================================================================================================
def test_dnssec_status_passes_when_check_returns_no_failures(env: Path, runner: CliRunner):
    with patch("postern.mta.dnssec.check", return_value=[]):
        result = runner.invoke(app, ["mta", "dnssec-status"])
    assert result.exit_code == 0, result.output
    assert "signed and validating" in result.output


def test_dnssec_status_exits_1_on_failures(env: Path, runner: CliRunner):
    with patch("postern.mta.dnssec.check", return_value=["DNSSEC postern.test: AD bit not set"]):
        result = runner.invoke(app, ["mta", "dnssec-status"])
    assert result.exit_code == 1
    combined = result.output + (result.stderr or "")
    assert "AD bit not set" in combined
