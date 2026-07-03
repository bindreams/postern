"""Unit tests for nginx/render.sh template rendering (issue #98).

render.sh substitutes ${DOMAIN} and ${PROXY_PROTOCOL_LISTEN} into *.tmpl files
and generates conf.d/real_ip.conf. The PROXY-protocol directives must appear
only when PROXY_PROTOCOL_FROM is set, and be absent otherwise (no regression for
direct deployments).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RENDER_SH = _REPO_ROOT / "nginx" / "render.sh"
_NGINX_ETC = _REPO_ROOT / "nginx" / "etc"


def _render(
    tmp_path: Path,
    *,
    domain: str = "example.com",
    proxy_from: str | None = None,
    edge_profile: str | None = None,
    edge_trusted_cidrs: str | None = None,
    edge_realip_header: str | None = None,
    edge_cf_aop: str | None = None,
) -> Path:
    """Run render.sh against a temp copy of nginx/etc/; return the output dir."""
    templates = tmp_path / "templates"
    shutil.copytree(_NGINX_ETC, templates)
    out = tmp_path / "out"
    out.mkdir()
    env = dict(os.environ)
    env.update(TEMPLATE_DIR=str(templates), TARGET_DIR=str(out), DOMAIN=domain)
    if proxy_from is None:
        env.pop("PROXY_PROTOCOL_FROM", None)
    else:
        env["PROXY_PROTOCOL_FROM"] = proxy_from
    # Edge env is read raw by render.sh (pydantic does not gate the nginx
    # container). Pop when unset so an inherited value can't leak into a case
    # that expects it absent.
    for key, val in (
        ("EDGE_PROFILE", edge_profile),
        ("EDGE_TRUSTED_CIDRS", edge_trusted_cidrs),
        ("EDGE_REALIP_HEADER", edge_realip_header),
        ("EDGE_CF_AUTHENTICATED_ORIGIN_PULL", edge_cf_aop),
    ):
        if val is None:
            env.pop(key, None)
        else:
            env[key] = val
    subprocess.run(
        ["sh", "-c", f'set -eu; . "{_RENDER_SH}"; render_templates'],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return out


def test_render_without_proxy_protocol_is_unchanged(tmp_path):
    out = _render(tmp_path)
    conf = (out / "nginx.conf").read_text()
    assert "proxy_protocol" not in conf
    assert "${PROXY_PROTOCOL_LISTEN}" not in conf
    assert "listen 443 ssl fastopen=256 so_keepalive=on;" in conf
    assert (out / "conf.d" / "real_ip.conf").read_text().strip() == ""


def test_render_with_proxy_protocol_emits_directives(tmp_path):
    out = _render(tmp_path, proxy_from="172.20.0.0/16")
    conf = (out / "nginx.conf").read_text()
    assert "listen 443 ssl fastopen=256 so_keepalive=on proxy_protocol;" in conf
    real_ip = (out / "conf.d" / "real_ip.conf").read_text()
    assert "real_ip_header proxy_protocol;" in real_ip
    assert "real_ip_recursive on;" in real_ip
    assert "set_real_ip_from 172.20.0.0/16;" in real_ip


def test_render_with_multiple_cidrs(tmp_path):
    out = _render(tmp_path, proxy_from="10.0.0.0/8,172.16.0.0/12 192.168.0.0/16,fc00::/7")
    real_ip = (out / "conf.d" / "real_ip.conf").read_text()
    assert "set_real_ip_from 10.0.0.0/8;" in real_ip
    assert "set_real_ip_from 172.16.0.0/12;" in real_ip
    assert "set_real_ip_from 192.168.0.0/16;" in real_ip
    assert "set_real_ip_from fc00::/7;" in real_ip


def test_render_substitutes_domain(tmp_path):
    out = _render(tmp_path, domain="vpn.example.org")
    conf = (out / "nginx.conf").read_text()
    assert "vpn.example.org" in conf
    assert "${DOMAIN}" not in conf


def test_render_fails_loudly_on_unwritable_conf_dir(tmp_path):
    """A genuine render failure must be fatal, not silently skipped.

    Pre-creating conf.d as a regular FILE makes every conf.d write hit ENOTDIR --
    which even root cannot bypass -- so render_templates must return non-zero and
    print FATAL. (The read-only-mv tolerance for the e2e bind mount is covered by
    the e2e suite, which bind-mounts nginx.conf read-only and must still boot.)
    """
    templates = tmp_path / "templates"
    shutil.copytree(_NGINX_ETC, templates)
    out = tmp_path / "out"
    out.mkdir()
    (out / "conf.d").write_text("not a directory")  # forces conf.d writes to ENOTDIR
    env = dict(os.environ)
    env.update(TEMPLATE_DIR=str(templates), TARGET_DIR=str(out), DOMAIN="example.com")
    env.pop("PROXY_PROTOCOL_FROM", None)
    result = subprocess.run(
        ["sh", "-c", f'. "{_RENDER_SH}"; render_templates'],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, f"expected non-zero; stderr:\n{result.stderr}"
    assert "FATAL" in result.stderr


def test_render_tolerates_trailing_separator(tmp_path):
    """A trailing comma/space in PROXY_PROTOCOL_FROM must not abort the render."""
    out = _render(tmp_path, proxy_from="172.20.0.0/16, ")
    real_ip = (out / "conf.d" / "real_ip.conf").read_text()
    assert real_ip.count("set_real_ip_from") == 1
    assert "set_real_ip_from 172.20.0.0/16;" in real_ip


# Edge profiles (Cloudflare / generic reverse proxy) =====

def test_render_edge_none_generates_empty_edge_conf(tmp_path):
    """No EDGE_PROFILE -> edge.conf exists but is empty (the include always resolves)."""
    out = _render(tmp_path)
    assert (out / "conf.d" / "edge.conf").read_text().strip() == ""


def test_render_edge_conf_included_in_both_443_blocks(tmp_path):
    out = _render(tmp_path)
    conf = (out / "nginx.conf").read_text()
    # Present in the portal :443 server AND the catch-all :443 default_server,
    # so CF Authenticated-Origin-Pull mTLS covers every TLS handshake on 443;
    # absent from the port-80 redirect block (no TLS there).
    assert conf.count("include conf.d/edge.conf;") == 2


def test_render_edge_generic_emits_header_and_cidrs(tmp_path):
    out = _render(
        tmp_path,
        edge_profile="generic",
        edge_realip_header="X-Forwarded-For",
        edge_trusted_cidrs="10.0.0.0/8,192.168.0.0/16",
    )
    edge = (out / "conf.d" / "edge.conf").read_text()
    assert "real_ip_header X-Forwarded-For;" in edge
    assert "real_ip_recursive on;" in edge
    assert "set_real_ip_from 10.0.0.0/8;" in edge
    assert "set_real_ip_from 192.168.0.0/16;" in edge
    # generic must not smuggle in the CF header or the mTLS directives.
    assert "CF-Connecting-IP" not in edge
    assert "ssl_verify_client" not in edge


def test_render_edge_generic_tab_and_newline_separators(tmp_path):
    out = _render(
        tmp_path,
        edge_profile="generic",
        edge_realip_header="X-Real-IP",
        edge_trusted_cidrs="10.0.0.0/8\t172.16.0.0/12\n192.168.0.0/16",
    )
    edge = (out / "conf.d" / "edge.conf").read_text()
    assert "set_real_ip_from 10.0.0.0/8;" in edge
    assert "set_real_ip_from 172.16.0.0/12;" in edge
    assert "set_real_ip_from 192.168.0.0/16;" in edge


def test_render_edge_cloudflare_uses_cf_header_and_glob_include(tmp_path):
    out = _render(tmp_path, edge_profile="cloudflare")
    edge = (out / "conf.d" / "edge.conf").read_text()
    assert "real_ip_header CF-Connecting-IP;" in edge
    assert "real_ip_recursive on;" in edge
    assert "include /var/lib/postern-edge/*.conf;" in edge


def test_render_edge_cloudflare_aop_on_by_default_emits_mtls_once(tmp_path):
    out = _render(tmp_path, edge_profile="cloudflare")
    edge = (out / "conf.d" / "edge.conf").read_text()
    assert "ssl_client_certificate /etc/nginx/cloudflare-origin-pull-ca.pem;" in edge
    assert edge.count("ssl_verify_client on;") == 1


def test_render_edge_cloudflare_aop_off_omits_mtls(tmp_path):
    out = _render(tmp_path, edge_profile="cloudflare", edge_cf_aop="false")
    edge = (out / "conf.d" / "edge.conf").read_text()
    assert "ssl_verify_client" not in edge
    assert "ssl_client_certificate" not in edge
    # Real-IP recovery stays active regardless of the AOP toggle.
    assert "real_ip_header CF-Connecting-IP;" in edge


def test_render_edge_cloudflare_aop_unrecognized_is_fatal(tmp_path):
    """A typo'd AOP toggle must fail the render, never silently disable origin auth."""
    templates = tmp_path / "templates"
    shutil.copytree(_NGINX_ETC, templates)
    out = tmp_path / "out"
    out.mkdir()
    env = dict(os.environ)
    env.update(
        TEMPLATE_DIR=str(templates),
        TARGET_DIR=str(out),
        DOMAIN="example.com",
        EDGE_PROFILE="cloudflare",
        EDGE_CF_AUTHENTICATED_ORIGIN_PULL="flase",
    )
    result = subprocess.run(
        ["sh", "-c", f'. "{_RENDER_SH}"; render_templates'],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, f"expected non-zero; stderr:\n{result.stderr}"
    assert "FATAL" in result.stderr
    assert "EDGE_CF_AUTHENTICATED_ORIGIN_PULL" in result.stderr
