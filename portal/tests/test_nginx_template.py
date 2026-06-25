"""Regression tests pinning the load-bearing strings in nginx/etc/*.tmpl.

These are the surfaces PR-B (#111) introduced as templates rendered at container
start. The path-token regex in particular is one third of a cross-component chain
(see CLAUDE.md "Path-token chain"); a stray rewrite of that string silently
breaks routing.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NGINX_ETC = REPO_ROOT / "nginx" / "etc"


# nginx.conf.tmpl ======================================================================================================
def test_path_token_regex_byte_identical_in_template():
    """The `^/t/([a-f0-9]{24})$` literal must stay byte-identical in nginx.conf.tmpl.

    The same regex is referenced in cli.py (`secrets.token_hex(12)` -> 24 hex chars)
    and reconciler.py (`ss-{path_token}`). A stray edit here silently breaks
    container DNS lookup of the per-connection tunnel."""
    body = (NGINX_ETC / "nginx.conf.tmpl").read_text()
    assert "^/t/([a-f0-9]{24})$" in body, (
        "Path-token regex missing or rewritten in nginx.conf.tmpl. "
        "It must stay byte-identical; cli.py and reconciler.py depend on it."
    )


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


# cert.conf.tmpl =======================================================================================================
def test_cert_paths_use_domain_placeholder():
    """The three cert paths (fullchain, privkey, chain) all reference ${DOMAIN}."""
    body = (NGINX_ETC / "conf.d" / "cert.conf.tmpl").read_text()
    assert "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" in body
    assert "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" in body
    assert "/etc/letsencrypt/live/${DOMAIN}/chain.pem" in body


# mta-sts.conf.tmpl + policy.txt.tmpl ==================================================================================
def test_mta_sts_server_name_uses_domain_placeholder():
    body = (NGINX_ETC / "conf.d" / "mta-sts.conf.tmpl").read_text()
    assert "server_name mta-sts.${DOMAIN};" in body


def test_mta_sts_policy_mx_uses_domain_placeholder():
    body = (NGINX_ETC / "conf.d" / "mta-sts" / "policy.txt.tmpl").read_text()
    assert "mx: mail.${DOMAIN}" in body


# /t/ response uniformity ==============================================================================================
E2E_NGINX_CONF = REPO_ROOT / "portal" / "tests" / "e2e" / "nginx.conf"


def test_tunnel_misses_reroute_to_at_miss_in_both_nginx_configs():
    """Every non-live-token /t/ request must fall through to @miss so the tunnel
    route is indistinguishable from a generic 404. Must hold in both the production
    template and the static e2e config (bind-mounted, not rendered), which stay in
    sync."""
    for path in ((NGINX_ETC / "nginx.conf.tmpl"), E2E_NGINX_CONF):
        body = path.read_text()
        assert "error_page 418 502 503 504 = @miss;" in body, f"error_page reroute missing in {path}"
        assert "location @miss {" in body, f"@miss named location missing in {path}"
        assert "return 418;" in body, f"non-WS 418 sentinel missing in {path}"


def _location_block_body(config_text: str, location_re: str) -> list[str]:
    """Non-comment directive lines inside a flat `location <X> { ... }` block
    (no nested braces, which holds for `@miss` and `location /`)."""
    m = re.search(location_re + r"\s*\{([^}]*)\}", config_text)
    assert m, f"location block {location_re!r} not found"
    return [ln.strip() for ln in m.group(1).splitlines() if ln.strip() and not ln.strip().startswith("#")]


def test_at_miss_body_identical_to_location_root_in_both_configs():
    """The /t/ obfuscation requires @miss to produce a byte-identical response to
    `location /`; pin that they carry the same proxy_pass + proxy_set_header set in
    both the production template and the static e2e config, so divergence fails at
    unit time, not only in the e2e stack."""
    for path in ((NGINX_ETC / "nginx.conf.tmpl"), E2E_NGINX_CONF):
        body = path.read_text()
        assert _location_block_body(body, r"location @miss") == _location_block_body(body, r"location /"), \
            f"@miss and location / diverged in {path}; a /t/ miss is no longer indistinguishable"
