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


def _render(tmp_path: Path, *, domain: str = "example.com", proxy_from: str | None = None) -> Path:
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
