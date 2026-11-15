"""Tests for postern_provisioner.lego_env -- env-var mapping table."""

import pytest

from postern_provisioner import cert, lego_env


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


def test_hetzner_pass_through():
    """lego's hetzner provider reads HETZNER_API_TOKEN (a Hetzner Cloud token, as postern-dns does);
    HETZNER_API_KEY is its deprecated legacy-DNS-API variable, which a Cloud token cannot satisfy."""
    cfg = lego_env.lego_config("hetzner", {"HETZNER_API_TOKEN": "tok"})
    assert cfg.dns_slug == "hetzner"
    assert cfg.env == {"HETZNER_API_TOKEN": "tok"}


def test_linode_pass_through():
    cfg = lego_env.lego_config("linode", {"LINODE_TOKEN": "tok"})
    assert cfg.dns_slug == "linode"
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


def test_lego_subprocess_receives_the_route53_session_token(monkeypatch):
    """lego reads AWS_SESSION_TOKEN natively; the runner hands it the whole environment, so a
    session token delivered to the provisioner reaches the process that signs the request."""
    seen = {}
    monkeypatch.setattr(cert, "_run_lego", lambda cmd, env: seen.update(env=env))
    settings = cert.CertSettings(domain="postern.test", dns_provider="route53", cert_acme_email="a@postern.test")
    runner = cert.LegoRunner(env={"AWS_ACCESS_KEY_ID": "AKIA", "AWS_SESSION_TOKEN": "session-sentinel"})
    runner.issue_or_renew(settings=settings, force=True)
    assert seen["env"]["AWS_SESSION_TOKEN"] == "session-sentinel"


def _runner_argv(monkeypatch, *, force: bool = True, renew_days: int = 30) -> list[str]:
    seen = {}
    monkeypatch.setattr(cert, "_run_lego", lambda cmd, env: seen.update(cmd=cmd))
    settings = cert.CertSettings(
        domain="postern.test",
        dns_provider="cloudflare",
        cert_acme_email="a@postern.test",
        cert_renewal_days_before_expiry=renew_days,
    )
    cert.LegoRunner(env={}).issue_or_renew(settings=settings, force=force)
    return seen["cmd"]


def test_runner_uses_the_v5_run_command(monkeypatch):
    """v5 takes its flags after the command; v4's global-flag layout is rejected."""
    argv = _runner_argv(monkeypatch)
    assert argv[:2] == ["lego", "run"]
    assert "renew" not in argv
    assert "--days" not in argv
    assert argv[argv.index("--path") + 1] == str(cert.LEGO_PATH)
    assert argv[argv.index("--email") + 1] == "a@postern.test"
    domains = [argv[i + 1] for i, a in enumerate(argv) if a == "--domains"]
    assert domains == ["postern.test", "*.postern.test"]
    assert argv[argv.index("--dns") + 1] == "cloudflare"
    assert argv[argv.index("--server") + 1] == "https://acme-v02.api.letsencrypt.org/directory"
    assert argv[argv.index("--key-type") + 1] == "rsa2048"
    assert "--accept-tos" in argv


def _child(code: str) -> list[str]:
    import sys
    return [sys.executable, "-c", code]


def test_run_lego_streams_both_streams_to_stdout_as_they_arrive(capfd):
    cert._run_lego(_child("import sys; print('out'); print('err', file=sys.stderr)"), {})
    captured = capfd.readouterr()
    assert "out" in captured.out and "err" in captured.out


def test_run_lego_failure_carries_what_lego_printed(capfd):
    """lego logs its error to stdout; the state machine reads it to tell a lost ACME account from other failures."""
    code = "import sys; print('ERROR accountDoesNotExist'); sys.exit(3)"
    with pytest.raises(cert.subprocess.CalledProcessError) as raised:
        cert._run_lego(_child(code), {})
    assert raised.value.returncode == 3
    assert "accountDoesNotExist" in raised.value.output
    assert "accountDoesNotExist" in capfd.readouterr().out


def test_runner_logs_the_timing_flag_it_passes(monkeypatch, caplog):
    caplog.set_level("INFO", logger=cert.logger.name)
    _runner_argv(monkeypatch, force=True)
    assert "invoking run --renew-force" in caplog.text
    caplog.clear()
    _runner_argv(monkeypatch, force=False, renew_days=21)
    assert "invoking run --renew-days 21" in caplog.text
    assert "--renew-force" not in caplog.text


def test_forced_run_passes_renew_force_and_no_renew_days(monkeypatch):
    """Without --renew-force an existing, not-yet-due cert makes `lego run` exit 0 and write nothing."""
    argv = _runner_argv(monkeypatch, force=True)
    assert "--renew-force" in argv
    assert "--renew-days" not in argv


def test_unforced_run_passes_postern_threshold_and_no_renew_force(monkeypatch):
    """The threshold is Postern's own, so lego no-ops only on a cert newer than the live one (lego v5.6.0 getDueDate)."""
    argv = _runner_argv(monkeypatch, force=False, renew_days=21)
    assert "--renew-force" not in argv
    assert argv[argv.index("--renew-days") + 1] == "21"


@pytest.mark.parametrize("force", [True, False])
def test_every_run_keeps_domains_exact_and_hands_lego_no_timing_decision(monkeypatch, force):
    argv = _runner_argv(monkeypatch, force=force)
    for flag in ("--force-cert-domains", "--ari-disable", "--no-random-sleep"):
        assert flag in argv
