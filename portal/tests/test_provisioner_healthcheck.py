"""Tests for the provisioner healthcheck script."""

import json
from pathlib import Path

import pytest

from postern_provisioner import healthcheck


@pytest.fixture(autouse=True)
def _patch_paths(monkeypatch, tmp_path: Path):
    keydir = tmp_path / "opendkim"
    certdir = tmp_path / "letsencrypt"
    keydir.mkdir()
    certdir.mkdir()
    monkeypatch.setattr(healthcheck.rotation, "DEFAULT_KEYDIR", keydir)
    monkeypatch.setattr(healthcheck.cert_state, "DEFAULT_CERTDIR", certdir)
    return keydir, certdir


def test_healthy_when_both_disabled(monkeypatch):
    monkeypatch.setenv("CERT_RENEWAL", "false")
    monkeypatch.setenv("DNS_PROVIDER", "none")
    # No state.json files exist anywhere.
    assert healthcheck.main() == 0


def test_unhealthy_when_dkim_state_says_no_keys(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "NO_KEYS"}))
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "false")
    assert healthcheck.main() == 1


def test_healthy_when_dkim_initialised(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE", "active_selectors": ["postern-2026-04"]}))
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "false")
    assert healthcheck.main() == 0


def test_unhealthy_when_cert_renewal_on_but_no_cert(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "true")
    # No cert state -> defaults to NO_CERT.
    assert healthcheck.main() == 1


def test_healthy_when_cert_renewal_on_and_cert_installed(monkeypatch, _patch_paths):
    keydir, certdir = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    (certdir / "state.json").write_text(json.dumps({"state": "INSTALLED"}))
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "true")
    assert healthcheck.main() == 0
