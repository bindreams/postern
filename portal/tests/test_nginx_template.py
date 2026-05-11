"""Regression tests pinning the load-bearing strings in nginx/etc/*.tmpl.

These are the surfaces PR-B (#111) introduced as templates rendered at container
start. The path-token regex in particular is one third of a cross-component chain
(see CLAUDE.md "Path-token chain"); a stray rewrite of that string silently
breaks routing.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NGINX_ETC = REPO_ROOT / "nginx" / "etc"


# nginx.conf.tmpl =======================================================================================================
def test_path_token_regex_byte_identical_in_template():
    """The `^/t/([a-f0-9]{24})$` literal must stay byte-identical in nginx.conf.tmpl.

    The same regex is referenced in cli.py (`secrets.token_hex(12)` -> 24 hex chars)
    and reconciler.py (`ss-{path_token}`). A stray edit here silently breaks
    container DNS lookup of the per-connection tunnel."""
    body = (NGINX_ETC / "nginx.conf.tmpl").read_text()
    assert "^/t/([a-f0-9]{24})$" in body, (
        "Path-token regex missing or rewritten in nginx.conf.tmpl. "
        "It must stay byte-identical; cli.py and reconciler.py depend on it.")


def test_auth_zone_limit_rate_unchanged():
    """Production auth rate-limit zone is `rate=10r/m, burst=5` per CLAUDE.md.
    The e2e overlay diverges intentionally (600r/m, burst=20); this pins the
    production side so an accidental tightening doesn't lock real users out."""
    body = (NGINX_ETC / "nginx.conf.tmpl").read_text()
    assert "rate=10r/m" in body
    assert "burst=5" in body


def test_main_server_name_uses_domain_placeholder():
    """The main server's `server_name` must reference ${DOMAIN}, not a literal."""
    body = (NGINX_ETC / "nginx.conf.tmpl").read_text()
    assert "server_name ${DOMAIN};" in body
    # The literal placeholder domain `postern.example.com` should be absent from
    # the template now -- it's only the default value of settings.domain, not a
    # source string.
    assert "postern.example.com" not in body


def test_cert_include_uses_fixed_filename():
    """nginx.conf includes a fixed `conf.d/cert.conf` (rendered from cert.conf.tmpl),
    not a `conf.d/certs/<domain>.conf` path."""
    body = (NGINX_ETC / "nginx.conf.tmpl").read_text()
    assert "include conf.d/cert.conf;" in body
    assert "conf.d/certs/" not in body


# cert.conf.tmpl ========================================================================================================
def test_cert_paths_use_domain_placeholder():
    """The three cert paths (fullchain, privkey, chain) all reference ${DOMAIN}."""
    body = (NGINX_ETC / "conf.d" / "cert.conf.tmpl").read_text()
    assert "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" in body
    assert "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" in body
    assert "/etc/letsencrypt/live/${DOMAIN}/chain.pem" in body


# mta-sts.conf.tmpl + policy.txt.tmpl ===================================================================================
def test_mta_sts_server_name_uses_domain_placeholder():
    body = (NGINX_ETC / "conf.d" / "mta-sts.conf.tmpl").read_text()
    assert "server_name mta-sts.${DOMAIN};" in body


def test_mta_sts_policy_mx_uses_domain_placeholder():
    body = (NGINX_ETC / "conf.d" / "mta-sts" / "policy.txt.tmpl").read_text()
    assert "mx: mail.${DOMAIN}" in body
