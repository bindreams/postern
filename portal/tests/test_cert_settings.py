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
        public_ipv4="1.2.3.4",  # required when cert_renewal=true (PR #115)
    )
    assert s.cert_renewal is True
    assert s.dns_provider == "cloudflare"
    assert s.cert_renewal_days_before_expiry == 14
    assert s.public_ipv4 == "1.2.3.4"


@pytest.mark.parametrize("days", [0, -1])
def test_provisioner_cert_settings_reject_a_renewal_threshold_below_one(days):
    """lego treats 0 as one third of the lifetime and a negative number as always renew."""
    from postern_provisioner.cert import CertSettings
    with pytest.raises(ValueError, match="CERT_RENEWAL_DAYS_BEFORE_EXPIRY must be >= 1"):
        CertSettings(
            domain="postern.test",
            dns_provider="cloudflare",
            cert_acme_email="ops@postern.test",
            cert_renewal_days_before_expiry=days,
        )


def test_provisioner_cert_settings_accept_a_threshold_of_one():
    from postern_provisioner.cert import CertSettings
    settings = CertSettings(
        domain="postern.test",
        dns_provider="cloudflare",
        cert_acme_email="ops@postern.test",
        cert_renewal_days_before_expiry=1,
    )
    assert settings.cert_renewal_days_before_expiry == 1
