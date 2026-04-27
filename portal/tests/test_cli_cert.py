"""Smoke tests for the `postern cert` subcommands."""

import os
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from postern.cert import state as cert_state
from postern.cli import app

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cert_state, "DEFAULT_CERTDIR", tmp_path)
    monkeypatch.setenv("SECRET_KEY", "x" * 64)
    monkeypatch.setenv("DOMAIN", "postern.test")
    return tmp_path


def test_show_no_cert(env):
    result = runner.invoke(app, ["cert", "show"])
    assert result.exit_code == 1
    assert "no cert installed" in (result.stderr or result.output)


def test_renewal_status_default_state(env):
    result = runner.invoke(app, ["cert", "renewal-status"])
    assert result.exit_code == 0
    assert "NO_CERT" in result.output


def test_renew_errors_when_renewal_disabled(env, monkeypatch):
    monkeypatch.setenv("CERT_RENEWAL", "false")
    result = runner.invoke(app, ["cert", "renew"])
    assert result.exit_code == 1
    assert "auto-renewal is not enabled" in (result.stderr or result.output)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics required")
def test_show_with_existing_cert(env, tmp_path):
    from postern_provisioner import install
    from tests.e2e._certs import generate_test_pki
    scratch = tmp_path / "scratch"
    generate_test_pki(scratch, hostname="postern.test")
    (env / "live").mkdir()
    setattr(install.os, "chown", lambda *a, **k: None)
    install.install_cert_triple(
        fullchain_src=scratch / "fullchain.pem",
        privkey_src=scratch / "privkey.pem",
        chain_src=scratch / "chain.pem",
        live_dir=env / "live",
        domain="postern.test",
    )
    result = runner.invoke(app, ["cert", "show"])
    assert result.exit_code == 0
    assert "postern.test" in result.output
    assert "*.postern.test" in result.output
