"""Tests for postern.cert.state -- state schema, persistence, triggers."""

import dataclasses
import json
from pathlib import Path

from postern.cert import state as cert_state


# Schema persistence ===================================================================================================
def test_read_state_returns_no_cert_default_when_file_missing(tmp_path: Path):
    state = cert_state.read_state(certdir=tmp_path)
    assert state.state == "NO_CERT"
    assert state.sans == []
    assert state.consecutive_failures == 0
    assert state.schema_version == cert_state.SCHEMA_VERSION


def test_write_then_read_roundtrips(tmp_path: Path):
    original = cert_state.CertState(
        state="INSTALLED",
        not_after_iso="2026-07-26T12:00:00+00:00",
        sans=["postern.example.com", "*.postern.example.com"],
        last_issued_iso="2026-04-27T12:00:00+00:00",
        last_attempt_iso="2026-04-27T12:00:00+00:00",
        consecutive_failures=0,
        acme_directory="https://acme-v02.api.letsencrypt.org/directory",
    )
    cert_state.write_state(original, certdir=tmp_path)
    loaded = cert_state.read_state(certdir=tmp_path)
    assert loaded == original


def test_write_state_is_atomic_via_replace(tmp_path: Path):
    """A partial write must not corrupt an existing state.json."""
    cert_state.write_state(cert_state.CertState(state="ISSUING"), certdir=tmp_path)
    cert_state.write_state(
        cert_state.CertState(
            state="INSTALLED",
            sans=["postern.example.com", "*.postern.example.com"],
            not_after_iso="2026-07-26T12:00:00+00:00",
        ),
        certdir=tmp_path,
    )
    loaded = cert_state.read_state(certdir=tmp_path)
    assert loaded.state == "INSTALLED"
    assert loaded.sans == ["postern.example.com", "*.postern.example.com"]


def test_read_state_logs_warning_for_newer_schema(tmp_path: Path, caplog):
    path = cert_state.state_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "schema_version": cert_state.SCHEMA_VERSION + 1,
            "state": "INSTALLED",
            "sans": ["postern.example.com", "*.postern.example.com"],
            "future_field": "Postern can't see me",
        })
    )
    with caplog.at_level("WARNING"):
        loaded = cert_state.read_state(certdir=tmp_path)
    assert loaded.state == "INSTALLED"
    assert loaded.sans == ["postern.example.com", "*.postern.example.com"]
    assert any("schema_version" in rec.message for rec in caplog.records)


def test_read_state_handles_corrupt_file(tmp_path: Path, caplog):
    cert_state.state_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    cert_state.state_path(tmp_path).write_text("not valid json {")
    with caplog.at_level("WARNING"):
        loaded = cert_state.read_state(certdir=tmp_path)
    assert loaded.state == "NO_CERT"


def test_read_state_non_object_top_level_degrades_to_default(tmp_path: Path, caplog):
    """JSON-valid but non-object content must degrade to the default-state
    warning path, not raise -- the provisioner healthcheck calls read_state
    uncaught, and an AttributeError would wedge first-boot gating of nginx/mta
    under compose.cert.yaml."""
    cert_state.state_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    cert_state.state_path(tmp_path).write_text(json.dumps(["not", "an", "object"]))
    with caplog.at_level("WARNING"):
        loaded = cert_state.read_state(certdir=tmp_path)
    assert loaded == cert_state.CertState()
    assert any("treating as NO_CERT" in rec.getMessage() for rec in caplog.records)


def test_read_state_malformed_field_shape_degrades_to_default(tmp_path: Path, caplog):
    """schema_version not comparable to an int must degrade, not raise TypeError."""
    cert_state.state_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    cert_state.state_path(tmp_path).write_text(json.dumps({"schema_version": "two", "state": "INSTALLED"}))
    with caplog.at_level("WARNING"):
        loaded = cert_state.read_state(certdir=tmp_path)
    assert loaded == cert_state.CertState()
    assert any("treating as NO_CERT" in rec.getMessage() for rec in caplog.records)


def test_read_state_accepts_per_directory_times(tmp_path: Path):
    original = cert_state.CertState(
        state="INSTALLED",
        last_issued_by_directory={"https://acme.example/directory": "2026-11-01T00:00:00+00:00"},
        pending_acme_directory="https://acme.example/directory",
    )
    cert_state.write_state(original, certdir=tmp_path)
    assert cert_state.read_state(certdir=tmp_path) == original


def test_latest_issued_iso_prefers_the_per_directory_times():
    state = cert_state.CertState(
        last_issued_iso="2026-01-01T00:00:00+00:00",
        last_issued_by_directory={"a": "2026-11-01T00:00:00+00:00", "b": "2026-11-02T00:00:00+00:00"},
    )
    assert state.latest_issued_iso == "2026-11-02T00:00:00+00:00"


def test_latest_issued_iso_is_none_without_per_directory_times():
    assert cert_state.CertState().latest_issued_iso is None
    assert cert_state.CertState(last_issued_iso="2026-01-01T00:00:00+00:00").latest_issued_iso is None


def test_read_state_accepts_failed_with_a_last_failed_state(tmp_path: Path):
    original = cert_state.CertState(state="FAILED", last_failed_state="RENEWING", consecutive_failures=6)
    cert_state.write_state(original, certdir=tmp_path)
    assert cert_state.read_state(certdir=tmp_path) == original


# Pre-upgrade state ====================================================================================================
PROD = "https://acme-v02.api.letsencrypt.org/directory"
STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


def _write_legacy(tmp_path: Path, **fields) -> None:
    """state.json as the code before `last_issued_by_directory` wrote it."""
    path = cert_state.state_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 1, **fields}))


def test_legacy_state_seeds_the_per_directory_time_from_last_issued_iso(tmp_path: Path):
    _write_legacy(tmp_path, state="INSTALLED", acme_directory=STAGING, last_issued_iso="2026-11-01T00:00:00+00:00")
    loaded = cert_state.read_state(certdir=tmp_path)
    assert loaded.last_issued_by_directory == {STAGING: "2026-11-01T00:00:00+00:00"}
    assert loaded.latest_issued_iso == "2026-11-01T00:00:00+00:00"
    assert loaded.acme_directory == STAGING


def test_legacy_state_without_any_lego_run_is_untouched(tmp_path: Path):
    """An adopted BYO cert: nothing to seed."""
    _write_legacy(tmp_path, state="INSTALLED", sans=["postern.example.com", "*.postern.example.com"])
    loaded = cert_state.read_state(certdir=tmp_path)
    assert loaded.acme_directory == ""
    assert loaded.last_issued_by_directory == {}


def test_legacy_migration_is_one_shot(tmp_path: Path):
    """Once the state is written with the per-directory map, reading it again changes nothing."""
    _write_legacy(tmp_path, state="INSTALLED", acme_directory=PROD, last_issued_iso="2026-11-01T00:00:00+00:00")
    migrated = cert_state.read_state(certdir=tmp_path)
    cert_state.write_state(dataclasses.replace(migrated, last_issued_by_directory={}), certdir=tmp_path)
    assert cert_state.read_state(certdir=tmp_path).last_issued_by_directory == {}


def test_state_written_by_current_code_is_not_migrated(tmp_path: Path):
    original = cert_state.CertState(state="INSTALLED", acme_directory=PROD, last_issued_iso="2026-11-01T00:00:00+00:00")
    cert_state.write_state(original, certdir=tmp_path)
    assert cert_state.read_state(certdir=tmp_path) == original


def test_pending_cert_paths_round_trips(tmp_path: Path):
    original = cert_state.CertState(
        state="ISSUED_PENDING_INSTALL",
        pending_cert_paths={
            "fullchain": "/etc/letsencrypt/lego/certificates/postern.example.com.crt",
            "privkey": "/etc/letsencrypt/lego/certificates/postern.example.com.key",
            "chain": "/etc/letsencrypt/lego/certificates/postern.example.com.issuer.crt",
        },
    )
    cert_state.write_state(original, certdir=tmp_path)
    loaded = cert_state.read_state(certdir=tmp_path)
    assert loaded == original


# Trigger files ========================================================================================================
def test_trigger_renewal_creates_file(tmp_path: Path):
    path = cert_state.trigger_renewal(certdir=tmp_path)
    assert path.exists()
    assert path.name == ".renew-cert"


def test_trigger_mta_tls_reload_creates_file(tmp_path: Path):
    """The mta-tls reload trigger lives on postern-mta-data, NOT on the cert volume.

    Mirrors the .reload-opendkim pattern: provisioner -> mta via the shared
    postern-mta-data volume, since the cert volume is not mounted on mta in BYO mode.
    """
    path = cert_state.trigger_mta_tls_reload(keydir=tmp_path)
    assert path.exists()
    assert path.name == ".reload-mta-tls"


# Path helpers =========================================================================================================
def test_state_path_uses_default_certdir(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cert_state, "DEFAULT_CERTDIR", tmp_path)
    assert cert_state.state_path() == tmp_path / "state.json"


def test_trigger_path_uses_default_certdir(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cert_state, "DEFAULT_CERTDIR", tmp_path)
    assert cert_state.trigger_path() == tmp_path / ".renew-cert"
