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
def test_ech_doh_url_default():
    s = _settings()
    assert s.ech_doh_url == "https://cloudflare-dns.com/dns-query"


# URL syntax is always validated when a value is present ================================================================
def test_ech_doh_url_valid_passes():
    s = _settings(ech_doh_url="https://dns.example/dns-query")
    assert s.ech_doh_url == "https://dns.example/dns-query"


def test_ech_doh_url_malformed_rejected():
    with pytest.raises(ValidationError, match="ECH_DOH_URL"):
        _settings(ech_doh_url="not-a-url")


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


# Environment-variable parsing =========================================================================================
class TestEchFromEnv:

    def test_ech_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
        monkeypatch.setenv("ECH_DOH_URL", "https://dns.example/dns-query")
        s = Settings()
        assert s.ech_doh_url == "https://dns.example/dns-query"
