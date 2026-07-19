"""Tests for the `postern edge` CLI (SSL/TLS-mode status)."""
from __future__ import annotations

import re

from typer.testing import CliRunner

from postern.cli import app

runner = CliRunner()


def _env(monkeypatch, **kw):
    monkeypatch.setenv("SECRET_KEY", "x" * 64)
    monkeypatch.setenv("DOMAIN", "postern.test")
    for k, v in kw.items():
        monkeypatch.setenv(k, v)


def test_ssl_status_prints_settings_and_state(monkeypatch):
    _env(
        monkeypatch,
        EDGE_PROFILE="cloudflare",
        DNS_PROVIDER="cloudflare",
        PUBLIC_IPV4="203.0.113.10",
        EDGE_CF_SSL_MODE="full",
    )
    from postern_provisioner import ssl_mode as ssl_state
    monkeypatch.setattr(
        ssl_state,
        "read_state",
        lambda *a, **k: ssl_state.SslModeState(
            last_set_ok_iso="2026-07-18T00:00:00+00:00",
            consecutive_failures=2,
            last_error="SSL/TLS mode not available on this plan",
            last_observed_mode="full",
        ),
    )
    result = runner.invoke(app, ["edge", "ssl-status"])
    assert result.exit_code == 0
    # Pin value-on-the-right-line (a bare `"full" in stdout` would pass on any line).
    assert re.search(r"^edge_cf_ssl_mode:\s+full$", result.stdout, re.M)  # configured target
    assert re.search(r"^zone_ssl_current_mode:\s+full$", result.stdout, re.M)  # actual mode CF reported
    assert re.search(r"^zone_ssl_failures:\s+2$", result.stdout, re.M)
    assert re.search(r"^zone_ssl_last_error:\s+SSL/TLS mode not available on this plan$", result.stdout, re.M)


def test_ssl_status_surfaces_target_vs_actual_drift(monkeypatch):
    # The honesty case: configured target strict but CF left the zone at full (raise-only).
    # ssl-status must show BOTH so the operator can see strict was never reached.
    _env(monkeypatch, EDGE_PROFILE="cloudflare", DNS_PROVIDER="cloudflare", PUBLIC_IPV4="203.0.113.10")
    from postern_provisioner import ssl_mode as ssl_state
    monkeypatch.setattr(
        ssl_state,
        "read_state",
        lambda *a, **k: ssl_state.SslModeState(last_set_ok_iso="2026-07-18T00:00:00+00:00", last_observed_mode="full"),
    )
    result = runner.invoke(app, ["edge", "ssl-status"])
    assert result.exit_code == 0
    assert re.search(r"^edge_cf_ssl_mode:\s+strict$", result.stdout, re.M)  # target
    assert re.search(r"^zone_ssl_current_mode:\s+full$", result.stdout, re.M)  # actual != target


def test_ssl_status_defaults_on_plain_deployment(monkeypatch):
    _env(monkeypatch)  # edge_profile=none
    # Isolate from ambient filesystem state: force an empty state rather than reading the
    # real /var/lib/opendkim path (which could exist with prior state on the test host).
    from postern_provisioner import ssl_mode as ssl_state
    monkeypatch.setattr(ssl_state, "read_state", lambda *a, **k: ssl_state.SslModeState())
    result = runner.invoke(app, ["edge", "ssl-status"])
    assert result.exit_code == 0
    assert re.search(r"^edge_profile:\s+none$", result.stdout, re.M)
    assert re.search(r"^zone_ssl_set_at:\s+\(never\)$", result.stdout, re.M)
    assert re.search(r"^zone_ssl_current_mode:\s+\(unknown\)$", result.stdout, re.M)
