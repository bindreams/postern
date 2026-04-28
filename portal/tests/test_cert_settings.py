"""Tests for the cert renewal settings validator."""

import pytest
from pydantic import ValidationError

from postern.settings import Settings


def _settings(**overrides) -> Settings:
    return Settings(
        secret_key="x" * 64,
        domain="postern.test",
        **overrides,
    )


def test_cert_renewal_off_works_with_no_provider():
    s = _settings(cert_renewal=False)
    assert s.dns_provider == "none"
    assert s.cert_renewal is False


def test_cert_renewal_on_requires_dns_provider():
    with pytest.raises(ValidationError, match="DNS_PROVIDER"):
        _settings(cert_renewal=True, dns_provider="none", cert_acme_email="ops@postern.test")


def test_cert_renewal_on_requires_acme_email():
    with pytest.raises(ValidationError, match="CERT_ACME_EMAIL"):
        _settings(cert_renewal=True, dns_provider="cloudflare", cert_acme_email="")


def test_cert_renewal_rejects_example_email():
    with pytest.raises(ValidationError, match="example"):
        _settings(cert_renewal=True, dns_provider="cloudflare", cert_acme_email="ops@example.com")


def test_cert_renewal_days_before_expiry_minimum():
    with pytest.raises(ValidationError, match="DAYS_BEFORE_EXPIRY"):
        _settings(cert_renewal_days_before_expiry=0)


def test_cert_renewal_full_config_valid():
    s = _settings(
        cert_renewal=True,
        dns_provider="cloudflare",
        cert_acme_email="ops@postern.test",
        cert_acme_directory="https://acme-staging-v02.api.letsencrypt.org/directory",
        cert_renewal_days_before_expiry=14,
    )
    assert s.cert_renewal is True
    assert s.dns_provider == "cloudflare"
    assert s.cert_renewal_days_before_expiry == 14
