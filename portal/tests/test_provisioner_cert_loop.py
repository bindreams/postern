"""Tests for postern_provisioner.cert -- the cert renewal state machine.

The driver is a pure function over (state, settings, lego, time). We mock
LegoRunner and exercise every transition.
"""

import datetime as dt
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from postern.cert import state as cert_state
from postern_provisioner import cert as cert_driver
from postern_provisioner.cert import CertSettings, LegoOutput

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics required (install path uses symlinks)")


@pytest.fixture
def settings() -> CertSettings:
    return CertSettings(
        domain="postern.test",
        dns_provider="cloudflare",
        cert_acme_email="ops@postern.test",
        cert_acme_directory="https://acme-staging-v02.api.letsencrypt.org/directory",
        cert_renewal_days_before_expiry=30,
    )


@pytest.fixture
def now() -> dt.datetime:
    # Real wall-clock time so the test cert's validity window (generate_test_pki
    # uses datetime.now() - 5min) overlaps with the test's `now`. A hardcoded
    # date breaks the in-validity adoption check.
    return dt.datetime.now(tz=dt.timezone.utc)


@pytest.fixture
def cert_dir(tmp_path: Path) -> Path:
    """A clean cert volume layout."""
    (tmp_path / "live").mkdir()
    (tmp_path / "lego" / "certificates").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def lego_mock(cert_dir: Path, settings: CertSettings) -> MagicMock:
    """Returns a LegoRunner mock that, when invoked, writes a fake cert triple."""
    from tests.e2e._certs import generate_test_pki
    pki_dir = cert_dir / "lego" / "certificates"
    runner = MagicMock(spec=cert_driver.LegoRunner)

    def _fake_issue(*, settings, action):
        # Reuse the existing wildcard-PKI helper to produce a real x.509 cert
        # with the right SANs, so the post-install adoption check passes.
        scratch = pki_dir / ".scratch"
        scratch.mkdir(exist_ok=True)
        generate_test_pki(scratch, hostname=settings.domain)
        fc = pki_dir / f"{settings.domain}.crt"
        pk = pki_dir / f"{settings.domain}.key"
        ch = pki_dir / f"{settings.domain}.issuer.crt"
        fc.write_bytes((scratch / "fullchain.pem").read_bytes())
        pk.write_bytes((scratch / "privkey.pem").read_bytes())
        ch.write_bytes((scratch / "chain.pem").read_bytes())
        return LegoOutput(fullchain=fc, privkey=pk, chain=ch)

    runner.issue_or_renew.side_effect = _fake_issue
    return runner


@pytest.fixture(autouse=True)
def _patch_paths(monkeypatch, cert_dir: Path):
    """Redirect production paths to the per-test cert_dir."""
    monkeypatch.setattr(cert_driver, "CERT_DIR", cert_dir)
    monkeypatch.setattr(cert_driver, "LEGO_PATH", cert_dir / "lego")
    monkeypatch.setattr(cert_driver, "LIVE_DIR", cert_dir / "live")
    monkeypatch.setattr(cert_state, "DEFAULT_CERTDIR", cert_dir)
    # Suppress mta-tls reload trigger writing into a non-existent /var/lib/opendkim.
    monkeypatch.setattr(cert_state, "DEFAULT_KEYDIR", cert_dir / "keydir")


# Happy path ===========================================================================================================
def test_no_cert_to_issuing(settings, lego_mock, now):
    state = cert_state.CertState()
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "ISSUING"
    assert next_state.acme_directory == settings.cert_acme_directory
    lego_mock.issue_or_renew.assert_not_called()


def test_issuing_runs_lego_then_pending_install(settings, lego_mock, now):
    state = cert_state.CertState(state="ISSUING", last_attempt_iso=now.isoformat())
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    assert next_state.last_issued_iso == now.isoformat()
    assert "fullchain" in next_state.pending_cert_paths
    lego_mock.issue_or_renew.assert_called_once()


def test_pending_install_writes_cert_files_and_transitions_to_installed(settings, lego_mock, now):
    # Simulate a successful Lego run by populating the pending_cert_paths.
    state = cert_state.CertState(state="ISSUING")
    after_issue = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    after_install = cert_driver.advance_cert_state(
        after_issue,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert after_install.state == "INSTALLED"
    assert (cert_driver.CERT_DIR / "live" / settings.domain / "fullchain.pem").exists()
    assert set(after_install.sans) == {settings.domain, f"*.{settings.domain}"}


def test_no_cert_adopts_existing_valid_cert(settings, lego_mock, now, cert_dir):
    """An on-disk cert with valid SANs + in-validity adopts to INSTALLED without Lego."""
    from postern_provisioner import install as install_mod
    from tests.e2e._certs import generate_test_pki
    scratch = cert_dir / "scratch"
    generate_test_pki(scratch, hostname=settings.domain)
    install_mod.install_cert_triple(
        fullchain_src=scratch / "fullchain.pem",
        privkey_src=scratch / "privkey.pem",
        chain_src=scratch / "chain.pem",
        live_dir=cert_dir / "live",
        domain=settings.domain,
    )
    next_state = cert_driver.advance_cert_state(
        cert_state.CertState(),
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "INSTALLED"
    lego_mock.issue_or_renew.assert_not_called()


# Renewal triggers =====================================================================================================
def test_installed_renews_when_expiry_close(settings, lego_mock, now, cert_dir):
    from postern_provisioner import install as install_mod
    from tests.e2e._certs import generate_test_pki
    scratch = cert_dir / "scratch"
    generate_test_pki(scratch, hostname=settings.domain)
    install_mod.install_cert_triple(
        fullchain_src=scratch / "fullchain.pem",
        privkey_src=scratch / "privkey.pem",
        chain_src=scratch / "chain.pem",
        live_dir=cert_dir / "live",
        domain=settings.domain,
    )
    state = cert_state.CertState(
        state="INSTALLED",
        sans=[settings.domain, f"*.{settings.domain}"],
        acme_directory=settings.cert_acme_directory,
    )
    # Time-travel to just before expiry (test cert is 30 days; threshold is 30).
    near_expiry = now + dt.timedelta(days=29, hours=12)
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=near_expiry,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "RENEWING"


def test_installed_renews_on_explicit_trigger(settings, lego_mock, now, cert_dir):
    from postern_provisioner import install as install_mod
    from tests.e2e._certs import generate_test_pki
    scratch = cert_dir / "scratch"
    generate_test_pki(scratch, hostname=settings.domain)
    install_mod.install_cert_triple(
        fullchain_src=scratch / "fullchain.pem",
        privkey_src=scratch / "privkey.pem",
        chain_src=scratch / "chain.pem",
        live_dir=cert_dir / "live",
        domain=settings.domain,
    )
    state = cert_state.CertState(
        state="INSTALLED",
        sans=[settings.domain, f"*.{settings.domain}"],
        acme_directory=settings.cert_acme_directory,
    )
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=True,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "RENEWING"


def test_installed_renews_on_acme_directory_drift(settings, lego_mock, now, cert_dir):
    from postern_provisioner import install as install_mod
    from tests.e2e._certs import generate_test_pki
    scratch = cert_dir / "scratch"
    generate_test_pki(scratch, hostname=settings.domain)
    install_mod.install_cert_triple(
        fullchain_src=scratch / "fullchain.pem",
        privkey_src=scratch / "privkey.pem",
        chain_src=scratch / "chain.pem",
        live_dir=cert_dir / "live",
        domain=settings.domain,
    )
    state = cert_state.CertState(
        state="INSTALLED",
        sans=[settings.domain, f"*.{settings.domain}"],
        acme_directory="https://acme-v02.api.letsencrypt.org/directory",  # production
    )
    # settings has staging
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "RENEWING"


# Rate-limit guards ====================================================================================================
def test_24h_rate_limit_blocks_reissue(settings, lego_mock, now):
    state = cert_state.CertState(
        state="RENEWING",
        last_issued_iso=(now - dt.timedelta(hours=12)).isoformat(),
        acme_directory=settings.cert_acme_directory,
    )
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "INSTALLED"
    lego_mock.issue_or_renew.assert_not_called()


def test_force_reissue_bypasses_rate_limit(settings, lego_mock, now):
    settings.cert_force_reissue = True
    state = cert_state.CertState(
        state="RENEWING",
        last_issued_iso=(now - dt.timedelta(hours=12)).isoformat(),
        acme_directory=settings.cert_acme_directory,
    )
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    lego_mock.issue_or_renew.assert_called_once()


# FAILED state and retry ===============================================================================================
def test_six_failures_transitions_to_failed(settings, lego_mock, now):
    import subprocess
    lego_mock.issue_or_renew.side_effect = subprocess.CalledProcessError(1, "lego")
    state = cert_state.CertState(
        state="ISSUING",
        consecutive_failures=5,
        last_attempt_iso=now.isoformat(),
        acme_directory=settings.cert_acme_directory,
    )
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "FAILED"
    assert next_state.last_failed_state == "ISSUING"


def test_failed_holdoff_then_retry(settings, lego_mock, now):
    state = cert_state.CertState(
        state="FAILED",
        last_failed_state="RENEWING",
        last_attempt_iso=(now - dt.timedelta(hours=2)).isoformat(),
        consecutive_failures=6,
    )
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "RENEWING"
    assert next_state.consecutive_failures == 0


def test_failed_holdoff_not_yet_elapsed_stays(settings, lego_mock, now):
    state = cert_state.CertState(
        state="FAILED",
        last_failed_state="RENEWING",
        last_attempt_iso=(now - dt.timedelta(minutes=30)).isoformat(),
        consecutive_failures=6,
    )
    next_state = cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert next_state.state == "FAILED"


# ACME account email change ============================================================================================
def test_email_change_resets_lego_account_dir(settings, lego_mock, now, cert_dir):
    accounts = cert_dir / "lego" / "accounts" / "old"
    accounts.mkdir(parents=True)
    (accounts / "account.json").write_text("{}")
    state = cert_state.CertState(
        state="ISSUING",
        acme_account_email="previous@old.example",
        last_attempt_iso=now.isoformat(),
        acme_directory=settings.cert_acme_directory,
    )
    cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego_mock,
        trigger_present=False,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )
    assert not (cert_dir / "lego" / "accounts").exists() or not accounts.exists()
