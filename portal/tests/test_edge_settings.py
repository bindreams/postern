"""Tests for the edge (CDN / reverse-proxy) settings validator."""

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from postern.settings import Settings

REPO_ROOT = Path(__file__).parents[2]


def _settings(**overrides) -> Settings:
    return Settings(
        secret_key="x" * 64,
        domain="postern.test",
        **overrides,
    )


# Defaults =============================================================================================================
def test_edge_defaults_are_none_profile():
    s = _settings()
    assert s.edge_profile == "none"
    assert s.edge_trusted_cidrs == ""
    assert s.edge_realip_header == ""
    assert s.edge_cf_authenticated_origin_pull is True


def test_edge_profile_none_ignores_edge_fields():
    # "none" imposes no requirements even with the edge knobs left unset.
    s = _settings(edge_profile="none")
    assert s.edge_profile == "none"


# cloudflare profile ===================================================================================================
def test_cloudflare_requires_dns_provider_cloudflare():
    with pytest.raises(ValidationError, match="DNS_PROVIDER=cloudflare"):
        _settings(edge_profile="cloudflare", dns_provider="none", public_ipv4="1.2.3.4")


def test_cloudflare_requires_public_ipv4():
    with pytest.raises(ValidationError, match="PUBLIC_IPV4"):
        _settings(edge_profile="cloudflare", dns_provider="cloudflare", public_ipv4="")


def test_cloudflare_rejects_whitespace_public_ipv4():
    with pytest.raises(ValidationError, match="PUBLIC_IPV4"):
        _settings(edge_profile="cloudflare", dns_provider="cloudflare", public_ipv4="   ")


def test_cloudflare_full_config_valid():
    s = _settings(edge_profile="cloudflare", dns_provider="cloudflare", public_ipv4="1.2.3.4")
    assert s.edge_profile == "cloudflare"
    assert s.dns_provider == "cloudflare"
    assert s.public_ipv4 == "1.2.3.4"
    assert s.edge_cf_authenticated_origin_pull is True


def test_cloudflare_accepts_aop_disabled():
    # Positive test (panel #20): cloudflare + AOP=False is a valid, accepted config
    # -- the operator is opting out of Authenticated Origin Pull deliberately.
    s = _settings(
        edge_profile="cloudflare",
        dns_provider="cloudflare",
        public_ipv4="1.2.3.4",
        edge_cf_authenticated_origin_pull=False,
    )
    assert s.edge_cf_authenticated_origin_pull is False


# generic profile ======================================================================================================
def test_generic_requires_trusted_cidrs():
    with pytest.raises(ValidationError, match="EDGE_TRUSTED_CIDRS"):
        _settings(edge_profile="generic", edge_trusted_cidrs="", edge_realip_header="X-Real-IP")


def test_generic_rejects_whitespace_trusted_cidrs():
    # Panel #5: strip-before-emptiness -- a whitespace-only CIDR list must NOT pass.
    with pytest.raises(ValidationError, match="EDGE_TRUSTED_CIDRS"):
        _settings(edge_profile="generic", edge_trusted_cidrs="   ", edge_realip_header="X-Real-IP")


def test_generic_requires_realip_header():
    with pytest.raises(ValidationError, match="EDGE_REALIP_HEADER"):
        _settings(edge_profile="generic", edge_trusted_cidrs="10.0.0.0/8", edge_realip_header="")


def test_generic_rejects_whitespace_realip_header():
    with pytest.raises(ValidationError, match="EDGE_REALIP_HEADER"):
        _settings(edge_profile="generic", edge_trusted_cidrs="10.0.0.0/8", edge_realip_header="  ")


def test_generic_full_config_valid():
    s = _settings(
        edge_profile="generic",
        edge_trusted_cidrs="10.0.0.0/8, 172.16.0.0/12",
        edge_realip_header="X-Real-IP",
    )
    assert s.edge_profile == "generic"
    assert s.edge_trusted_cidrs == "10.0.0.0/8, 172.16.0.0/12"
    assert s.edge_realip_header == "X-Real-IP"


# edge_cf_authenticated_origin_pull is cloudflare-only =================================================================
def test_aop_explicit_under_none_rejected():
    with pytest.raises(ValidationError, match="only meaningful under EDGE_PROFILE=cloudflare"):
        _settings(edge_profile="none", edge_cf_authenticated_origin_pull=False)


def test_aop_explicit_under_generic_rejected():
    with pytest.raises(ValidationError, match="only meaningful under EDGE_PROFILE=cloudflare"):
        _settings(
            edge_profile="generic",
            edge_trusted_cidrs="10.0.0.0/8",
            edge_realip_header="X-Real-IP",
            edge_cf_authenticated_origin_pull=True,
        )


# Environment-variable parsing =========================================================================================
class TestEdgeFromEnv:

    def test_whitespace_trusted_cidrs_from_env_rejected(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
        monkeypatch.setenv("EDGE_PROFILE", "generic")
        monkeypatch.setenv("EDGE_TRUSTED_CIDRS", "   ")
        monkeypatch.setenv("EDGE_REALIP_HEADER", "X-Real-IP")
        with pytest.raises(ValidationError, match="EDGE_TRUSTED_CIDRS"):
            Settings()

    def test_cloudflare_from_env_valid(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
        monkeypatch.setenv("EDGE_PROFILE", "cloudflare")
        monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
        monkeypatch.setenv("PUBLIC_IPV4", "1.2.3.4")
        s = Settings()
        assert s.edge_profile == "cloudflare"
        assert s.edge_cf_authenticated_origin_pull is True


# zone-ECH management flag =============================================================================================
def test_manage_zone_ech_defaults_true():
    assert _settings().edge_cf_manage_zone_ech is True


def test_manage_zone_ech_ok_under_cloudflare():
    s = _settings(
        edge_profile="cloudflare",
        dns_provider="cloudflare",
        public_ipv4="1.2.3.4",
        edge_cf_manage_zone_ech=False,
    )
    assert s.edge_cf_manage_zone_ech is False


def test_manage_zone_ech_explicit_under_non_cloudflare_rejected():
    with pytest.raises(ValidationError, match="EDGE_CF_MANAGE_ZONE_ECH"):
        _settings(edge_profile="none", edge_cf_manage_zone_ech=True)


# edge_cf_manage_ssl_mode / edge_cf_ssl_mode are cloudflare-only =======================================================
def test_ssl_mode_defaults():
    s = _settings()
    assert s.edge_cf_manage_ssl_mode is True
    assert s.edge_cf_ssl_mode == "strict"


def test_ssl_mode_accepts_full_under_cloudflare():
    s = _settings(edge_profile="cloudflare", dns_provider="cloudflare", public_ipv4="1.2.3.4", edge_cf_ssl_mode="full")
    assert s.edge_cf_ssl_mode == "full"


def test_ssl_mode_rejects_unknown_value():
    with pytest.raises(ValidationError):
        _settings(edge_profile="cloudflare", dns_provider="cloudflare", public_ipv4="1.2.3.4", edge_cf_ssl_mode="off")


def test_manage_ssl_mode_explicit_under_none_rejected():
    with pytest.raises(ValidationError):
        _settings(edge_profile="none", edge_cf_manage_ssl_mode=False)


def test_ssl_mode_explicit_default_value_under_none_still_rejected():
    # The guard keys on model_fields_set (was it PASSED), not on the value -- so even
    # passing the field's OWN default explicitly under a non-cloudflare profile is
    # rejected. Pins that semantics so a value-vs-default "simplification" can't slip
    # `EDGE_CF_MANAGE_SSL_MODE=true` / `EDGE_CF_SSL_MODE=strict` through under EDGE_PROFILE=none.
    with pytest.raises(ValidationError):
        _settings(edge_profile="none", edge_cf_manage_ssl_mode=True)  # True is the default
    with pytest.raises(ValidationError):
        _settings(
            edge_profile="generic", edge_trusted_cidrs="10.0.0.0/8", edge_realip_header="X-Real-IP",
            edge_cf_ssl_mode="strict",  # "strict" is the default
        )


def test_ssl_mode_explicit_under_generic_rejected():
    with pytest.raises(ValidationError):
        _settings(
            edge_profile="generic",
            edge_trusted_cidrs="10.0.0.0/8",
            edge_realip_header="X-Real-IP",
            edge_cf_ssl_mode="full",
        )


# Cross-container agreement: the portal Literal and the provisioner's parse_ssl_target
# both read the same EDGE_CF_SSL_MODE env var (separate containers, no shared validator),
# so they MUST accept/reject the identical set -- else a stray value splits the stack
# (one boots, one dies). Pinned here so a future normalization change to either side
# that reintroduces the divergence fails loudly.
@pytest.mark.parametrize("value", ["full", "strict"])
def test_ssl_mode_valid_value_accepted_by_both(value):
    from postern_provisioner.ssl_mode import parse_ssl_target
    s = _settings(edge_profile="cloudflare", dns_provider="cloudflare", public_ipv4="1.2.3.4", edge_cf_ssl_mode=value)
    assert s.edge_cf_ssl_mode == value
    assert parse_ssl_target(value) == value


@pytest.mark.parametrize("variant", ["Full", "STRICT", " strict ", "flexible", "off", ""])
def test_ssl_mode_bad_value_rejected_by_both_when_managing(variant):
    # With management ON (default), a bad value is rejected by BOTH sides.
    from postern_provisioner.ssl_mode import parse_ssl_target
    with pytest.raises(ValidationError):
        _settings(
            edge_profile="cloudflare", dns_provider="cloudflare", public_ipv4="1.2.3.4", edge_cf_ssl_mode=variant
        )
    with pytest.raises(ValueError):
        parse_ssl_target(variant)


@pytest.mark.parametrize("variant", ["flexible", "off", "Strict", ""])
def test_ssl_mode_bad_value_tolerated_when_management_off(variant):
    # With management OFF, EDGE_CF_SSL_MODE is inert -> BOTH sides tolerate it (portal
    # does not crash on the value; the provisioner never reads it because ssl_mode_enabled
    # is False), so a stray value can't split the stack.
    from postern_provisioner.enablement import compute_enablement
    s = _settings(
        edge_profile="cloudflare", dns_provider="cloudflare", public_ipv4="1.2.3.4",
        edge_cf_manage_ssl_mode=False, edge_cf_ssl_mode=variant,
    )
    assert s.edge_cf_ssl_mode == variant  # portal tolerates the inert value
    assert not compute_enablement(
        dns_provider="cloudflare", cert_renewal=False, edge_profile="cloudflare", mta_deployed=False,
        manage_ssl_mode=False,
    ).ssl_mode_enabled  # provisioner won't read/validate it


# example.env ships a bootable default config ==========================================================================
# Regression guard (issue #170): the cloudflare-only edge knobs that fail loud when
# explicitly set under a non-cloudflare EDGE_PROFILE -- EDGE_CF_AUTHENTICATED_ORIGIN_PULL
# and EDGE_CF_MANAGE_ZONE_ECH -- must be OFFERED COMMENTED-OUT in example.env, since the
# default EDGE_PROFILE is "none". Shipping either as an active assignment makes the
# canonical "cp example.env .env" bring-up trip _check_edge_settings and refuse to boot.
def _example_env_active_settings() -> dict[str, str]:
    """example.env's uncommented KEY=VALUE assignments, restricted to Settings
    fields (compose-only vars like COMPOSE_PROFILES are dropped). Commented
    lines start with '#' and never match the leading-uppercase key pattern."""
    text = (REPO_ROOT / "example.env").read_text(encoding="utf-8")
    fields = set(Settings.model_fields)
    active = {}
    for key, value in re.findall(r"^\s*([A-Z][A-Z0-9_]+)=(.*)$", text, flags=re.M):
        name = key.lower()
        if name in fields:
            active[name] = value
    return active


def test_example_env_default_config_boots(monkeypatch: pytest.MonkeyPatch):
    # The shipped example.env, with only the required SECRET_KEY / DOMAIN placeholders
    # supplied, must construct a valid Settings -- the canonical "cp example.env .env"
    # bring-up. This RED-flags any active assignment of a cloudflare-only edge knob
    # under the default EDGE_PROFILE=none (issue #170).
    for field in Settings.model_fields:
        monkeypatch.delenv(field.upper(), raising=False)
    overrides = _example_env_active_settings()
    overrides["secret_key"] = "x" * 64
    overrides["domain"] = "postern.test"
    Settings(**overrides)  # must not raise
