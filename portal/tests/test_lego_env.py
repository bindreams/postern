"""Tests for postern_provisioner.lego_env -- env-var mapping table."""

import pytest

from postern_provisioner import lego_env


def test_cloudflare_translates_token():
    cfg = lego_env.lego_config("cloudflare", {"CLOUDFLARE_API_TOKEN": "abc"})
    assert cfg.dns_slug == "cloudflare"
    assert cfg.env == {"CLOUDFLARE_DNS_API_TOKEN": "abc"}


def test_route53_passes_aws_vars_through():
    cfg = lego_env.lego_config(
        "route53", {
            "AWS_REGION": "us-east-1",
            "AWS_ACCESS_KEY_ID": "AKIA",
            "AWS_SECRET_ACCESS_KEY": "secret",
        }
    )
    assert cfg.dns_slug == "route53"
    assert cfg.env == {
        "AWS_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "AKIA",
        "AWS_SECRET_ACCESS_KEY": "secret",
    }


def test_gandi_renames_to_gandiv5():
    cfg = lego_env.lego_config("gandi", {"GANDI_API_TOKEN": "tok"})
    assert cfg.dns_slug == "gandiv5"
    assert cfg.env == {"GANDIV5_PERSONAL_ACCESS_TOKEN": "tok"}


def test_digitalocean_pass_through():
    cfg = lego_env.lego_config("digitalocean", {"DO_AUTH_TOKEN": "tok"})
    assert cfg.dns_slug == "digitalocean"
    assert cfg.env == {"DO_AUTH_TOKEN": "tok"}


def test_ovh_passes_four_vars():
    env = {
        "OVH_ENDPOINT": "ovh-eu",
        "OVH_APPLICATION_KEY": "ak",
        "OVH_APPLICATION_SECRET": "as",
        "OVH_CONSUMER_KEY": "ck",
    }
    cfg = lego_env.lego_config("ovh", env)
    assert cfg.dns_slug == "ovh"
    assert cfg.env == env


def test_hetzner_renames_token():
    cfg = lego_env.lego_config("hetzner", {"HETZNER_API_TOKEN": "tok"})
    assert cfg.dns_slug == "hetzner"
    assert cfg.env == {"HETZNER_API_KEY": "tok"}


def test_linode_pass_through():
    cfg = lego_env.lego_config("linode", {"LINODE_TOKEN": "tok"})
    assert cfg.dns_slug == "linodev4"
    assert cfg.env == {"LINODE_TOKEN": "tok"}


def test_namecheap_passes_three_vars():
    env = {
        "NAMECHEAP_API_KEY": "ak",
        "NAMECHEAP_API_USER": "user",
        "NAMECHEAP_CLIENT_IP": "1.2.3.4",
    }
    cfg = lego_env.lego_config("namecheap", env)
    assert cfg.dns_slug == "namecheap"
    assert cfg.env == env


def test_pebble_uses_exec_with_default_hook_path():
    cfg = lego_env.lego_config("pebble", {})
    assert cfg.dns_slug == "exec"
    assert cfg.env == {"EXEC_PATH": "/usr/local/bin/lego-pebble-hook.sh"}


def test_pebble_respects_lego_exec_path_override():
    cfg = lego_env.lego_config("pebble", {"LEGO_EXEC_PATH": "/tmp/hook.sh"})
    assert cfg.env == {"EXEC_PATH": "/tmp/hook.sh"}


def test_unknown_provider_raises():
    with pytest.raises(ValueError, match="unknown DNS_PROVIDER"):
        lego_env.lego_config("notreal", {})


def test_supported_providers_excludes_pebble():
    providers = lego_env.supported_providers()
    assert "pebble" not in providers
    assert "cloudflare" in providers


def test_provider_name_is_case_insensitive():
    cfg_lower = lego_env.lego_config("cloudflare", {"CLOUDFLARE_API_TOKEN": "x"})
    cfg_upper = lego_env.lego_config("CLOUDFLARE", {"CLOUDFLARE_API_TOKEN": "x"})
    assert cfg_lower == cfg_upper


def test_missing_credentials_yields_empty_env():
    """We don't pre-validate; let Lego surface its own error message."""
    cfg = lego_env.lego_config("cloudflare", {})
    assert cfg.dns_slug == "cloudflare"
    assert cfg.env == {}
