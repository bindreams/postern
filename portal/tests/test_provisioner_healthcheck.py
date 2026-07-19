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
    monkeypatch.setattr(healthcheck.dns_records_state, "DEFAULT_CERTDIR", certdir)
    monkeypatch.setattr(healthcheck.mta_records_state, "DEFAULT_KEYDIR", keydir)
    monkeypatch.setattr(healthcheck.ech_state, "DEFAULT_STATE_DIR", keydir)
    monkeypatch.setattr(healthcheck.ssl_mode_state, "DEFAULT_STATE_DIR", keydir)
    # Clean baseline so a test that relies on "MTA not deployed" isn't polluted by
    # an ambient COMPOSE_PROFILES/EDGE_PROFILE. Tests opt in explicitly.
    monkeypatch.delenv("COMPOSE_PROFILES", raising=False)
    monkeypatch.delenv("EDGE_PROFILE", raising=False)
    return keydir, certdir


def _seed_mta_records_reconciled(keydir: Path) -> None:
    """Convenience: write a minimal mta_records_state.json marking reconciled.
    Most tests need this once the new (#118) MTA-records healthcheck half lands."""
    (keydir / "mta_records_state.json").write_text(json.dumps({
        "last_reconciled_iso": "2026-05-11T00:00:00+00:00",
    }))


def _seed_ssl_set_ok(keydir: Path) -> None:
    """Mark the ssl-mode as set so the SSL healthcheck half passes; needed by any
    cloudflare-edge test that expects health (the half is active under EDGE_PROFILE=cloudflare)."""
    (keydir / "ssl_mode_state.json").write_text(json.dumps({"last_set_ok_iso": "2026-07-18T00:00:00+00:00"}))


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
    _seed_mta_records_reconciled(keydir)
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "false")
    monkeypatch.setenv("COMPOSE_PROFILES", "with-mta")
    assert healthcheck.main() == 0


def test_unhealthy_when_mta_records_not_reconciled(monkeypatch, _patch_paths):
    """MTA is deployed (with-mta) and DKIM is initialised, but the MTA-records
    reconciler hasn't completed yet (#118)."""
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    # No mta_records_state.json -> read_state returns default (last_reconciled_iso=None).
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "false")
    monkeypatch.setenv("COMPOSE_PROFILES", "with-mta")
    assert healthcheck.main() == 1


def test_healthy_when_provider_set_but_mta_not_deployed(monkeypatch, _patch_paths):
    """Cert-only / edge-only: DNS_PROVIDER is set (edge and cert both require it)
    but the with-mta profile is absent, so the mta_records tick never runs. The
    healthcheck must NOT wait on mta_records here, or `service_healthy` would
    deadlock forever (last_reconciled_iso stays null)."""
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    # No mta_records_state.json on purpose -- nothing publishes it without with-mta.
    _seed_ssl_set_ok(keydir)
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "false")
    monkeypatch.setenv("EDGE_PROFILE", "cloudflare")
    monkeypatch.setenv("COMPOSE_PROFILES", "with-edge")  # NO with-mta
    assert healthcheck.main() == 0


def test_unhealthy_when_cert_renewal_on_but_no_cert(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "true")
    # No cert state -> defaults to NO_CERT.
    assert healthcheck.main() == 1


def test_healthy_when_cert_renewal_on_and_cert_installed(monkeypatch, _patch_paths):
    """All halves green: DKIM STABLE, cert INSTALLED, apex-DNS + MTA-DNS records reconciled."""
    keydir, certdir = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    (certdir / "state.json").write_text(json.dumps({"state": "INSTALLED"}))
    (certdir / "dns_records_state.json").write_text(
        json.dumps({
            "last_published_ipv4": "1.2.3.4",
            "last_reconciled_iso": "2026-05-11T00:00:00+00:00",
        })
    )
    _seed_mta_records_reconciled(keydir)
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "true")
    monkeypatch.setenv("COMPOSE_PROFILES", "with-mta,with-cert-renewal")
    assert healthcheck.main() == 0


def test_unhealthy_when_cert_renewal_on_but_dns_not_reconciled(monkeypatch, _patch_paths):
    """Cert is INSTALLED but the DNS reconciler hasn't completed a tick yet."""
    keydir, certdir = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    (certdir / "state.json").write_text(json.dumps({"state": "INSTALLED"}))
    # No dns_records_state.json -> read_state returns default (last_reconciled_iso=None).
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "true")
    assert healthcheck.main() == 1


# ECH half =============================================================================================================
def _managed_ech_env(monkeypatch):
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "false")
    monkeypatch.setenv("EDGE_PROFILE", "cloudflare")
    monkeypatch.setenv("COMPOSE_PROFILES", "with-edge")  # no with-mta
    monkeypatch.setenv("EDGE_CF_MANAGE_ZONE_ECH", "true")


def test_unhealthy_when_ech_managed_but_not_enabled(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    _managed_ech_env(monkeypatch)
    # No ech_zone_state.json -> last_enabled_ok_iso is None -> red.
    assert healthcheck.main() == 1


def test_healthy_when_ech_zone_ok(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    (keydir / "ech_zone_state.json").write_text(json.dumps({"last_enabled_ok_iso": "2026-07-14T00:00:00+00:00"}))
    _seed_ssl_set_ok(keydir)
    _managed_ech_env(monkeypatch)
    assert healthcheck.main() == 0


def test_unhealthy_when_ech_enablement_regresses_after_first_success(monkeypatch, _patch_paths):
    # Enabled once, but the latest ticks are failing -> the container must go unhealthy
    # again (the signal tracks current reality, not "ever worked once").
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    (keydir / "ech_zone_state.json").write_text(
        json.dumps({
            "last_enabled_ok_iso": "2026-07-14T00:00:00+00:00",
            "consecutive_failures": 3,
            "last_error": "ECH is not available on this plan",
        })
    )
    _managed_ech_env(monkeypatch)
    assert healthcheck.main() == 1


def test_ech_half_absent_when_manage_flag_off(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    _seed_ssl_set_ok(keydir)
    _managed_ech_env(monkeypatch)
    monkeypatch.setenv("EDGE_CF_MANAGE_ZONE_ECH", "false")  # ech_zone_enabled False -> half skipped
    assert healthcheck.main() == 0


def test_ech_half_absent_when_manage_flag_unset(monkeypatch, _patch_paths):
    """EDGE_CF_MANAGE_ZONE_ECH unset -> False (MANAGE_ZONE_ECH_DEFAULT): the healthcheck
    must NOT gate on zone-ECH state. Pins healthcheck.py's env default to the opt-in."""
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    _seed_ssl_set_ok(keydir)  # SSL half is default-on under a cloudflare edge; seed it so only ECH is under test
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "false")
    monkeypatch.setenv("EDGE_PROFILE", "cloudflare")
    monkeypatch.setenv("COMPOSE_PROFILES", "with-edge")
    monkeypatch.delenv("EDGE_CF_MANAGE_ZONE_ECH", raising=False)
    # No ech_zone_state.json -- would make main() return 1 IF the ECH half were active.
    assert healthcheck.main() == 0


# SSL/TLS-mode half ====================================================================================================
def _managed_ssl_env(monkeypatch):
    # cloudflare edge with SSL management on (default) -> SSL half active. ECH half stays
    # inactive: EDGE_CF_MANAGE_ZONE_ECH defaults off (opt-in) and is left unset here.
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_RENEWAL", "false")
    monkeypatch.setenv("EDGE_PROFILE", "cloudflare")
    monkeypatch.setenv("COMPOSE_PROFILES", "with-edge")


def test_unhealthy_when_ssl_managed_but_not_set(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    _managed_ssl_env(monkeypatch)
    assert healthcheck.main() == 1


def test_healthy_when_ssl_set_ok(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    _seed_ssl_set_ok(keydir)
    _managed_ssl_env(monkeypatch)
    assert healthcheck.main() == 0


def test_unhealthy_when_ssl_regresses_after_first_success(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    (keydir / "ssl_mode_state.json").write_text(
        json.dumps({
            "last_set_ok_iso": "2026-07-18T00:00:00+00:00",
            "consecutive_failures": 2,
            "last_error": "SSL/TLS mode not available on this plan",
        })
    )
    _managed_ssl_env(monkeypatch)
    assert healthcheck.main() == 1


def test_ssl_half_absent_when_manage_flag_off(monkeypatch, _patch_paths):
    keydir, _ = _patch_paths
    (keydir / "state.json").write_text(json.dumps({"state": "STABLE"}))
    _managed_ssl_env(monkeypatch)
    monkeypatch.setenv("EDGE_CF_MANAGE_SSL_MODE", "false")
    assert healthcheck.main() == 0
