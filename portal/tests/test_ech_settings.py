"""Tests for the ECH (client SNI concealment) settings + validators."""

import pytest
from pydantic import ValidationError

from postern.settings import Settings


def _settings(**overrides) -> Settings:
    return Settings(
        secret_key="x" * 64,
        domain="postern.test",
        **overrides,
    )


# Defaults =============================================================================================================
def test_ech_defaults_off():
    s = _settings()
    assert s.ech_enabled is False
    assert s.ech_doh_url == "https://cloudflare-dns.com/dns-query"


# URL syntax is validated unconditionally (independent of ech_enabled) =================================================
def test_ech_disabled_valid_url_passes():
    s = _settings(ech_enabled=False, ech_doh_url="https://dns.example/dns-query")
    assert s.ech_doh_url == "https://dns.example/dns-query"


def test_ech_disabled_malformed_url_rejected():
    # A malformed URL is a syntax error whether or not the feature is on -- catch it
    # at config load, not later when someone flips ECH_ENABLED=true.
    with pytest.raises(ValidationError, match="ECH_DOH_URL"):
        _settings(ech_enabled=False, ech_doh_url="not-a-url")


def test_ech_non_https_url_rejected():
    with pytest.raises(ValidationError, match="https://"):
        _settings(ech_doh_url="http://insecure.example/dns-query")


def test_ech_url_empty_host_rejected():
    with pytest.raises(ValidationError, match="https://"):
        _settings(ech_doh_url="https://")


def test_ech_url_semicolon_rejected():
    with pytest.raises(ValidationError, match="SIP003"):
        _settings(ech_doh_url="https://ex.test/dns;query")


def test_ech_url_backslash_rejected():
    with pytest.raises(ValidationError, match="SIP003"):
        _settings(ech_doh_url="https://ex.test/dns\\query")


def test_ech_url_whitespace_rejected():
    with pytest.raises(ValidationError, match="SIP003"):
        _settings(ech_doh_url="https://ex.test/dns query")


def test_ech_url_hostless_userinfo_rejected():
    with pytest.raises(ValidationError, match="host"):
        _settings(ech_doh_url="https://@/dns-query")


def test_ech_url_hostless_port_only_rejected():
    with pytest.raises(ValidationError, match="host"):
        _settings(ech_doh_url="https://:443/dns-query")


def test_ech_url_percent_encoded_semicolon_rejected():
    with pytest.raises(ValidationError, match="SIP003"):
        _settings(ech_doh_url="https://doh.example/dns%3Bquery")


# Presence required only when enabled ==================================================================================
def test_ech_enabled_with_default_doh_is_valid():
    s = _settings(ech_enabled=True)
    assert s.ech_enabled is True
    assert s.ech_doh_url == "https://cloudflare-dns.com/dns-query"


def test_ech_enabled_empty_doh_rejected():
    with pytest.raises(ValidationError, match="requires ECH_DOH_URL"):
        _settings(ech_enabled=True, ech_doh_url="")


# Environment-variable parsing =========================================================================================
class TestEchFromEnv:

    def test_ech_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
        monkeypatch.setenv("ECH_ENABLED", "true")
        monkeypatch.setenv("ECH_DOH_URL", "https://dns.example/dns-query")
        s = Settings()
        assert s.ech_enabled is True
        assert s.ech_doh_url == "https://dns.example/dns-query"
