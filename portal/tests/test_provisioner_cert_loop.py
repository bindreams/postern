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

PROD = "https://acme-v02.api.letsencrypt.org/directory"
STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


@pytest.fixture
def settings() -> CertSettings:
    return CertSettings(
        domain="postern.test",
        dns_provider="cloudflare",
        cert_acme_email="ops@postern.test",
        cert_acme_directory=STAGING,
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


def test_installed_reissues_on_acme_directory_drift(settings, lego_mock, now, cert_dir):
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
        acme_directory=PROD,
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
    # ISSUING (lego `run`), not RENEWING: `renew` needs an account registered under the new directory.
    assert next_state.state == "ISSUING"
    # The old directory stays recorded until lego succeeds, so a failed attempt cannot hide the drift.
    assert next_state.acme_directory == PROD


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


# ACME directory switch (staging -> production) ========================================================================
@pytest.fixture
def prod_settings(settings: CertSettings) -> CertSettings:
    """Operator removed CERT_ACME_DIRECTORY after testing on staging."""
    return CertSettings(
        domain=settings.domain,
        dns_provider=settings.dns_provider,
        cert_acme_email=settings.cert_acme_email,
        cert_acme_directory=PROD,
    )


def _advance(state, settings, lego, now, *, trigger_present=False):
    return cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego,
        trigger_present=trigger_present,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )


def _staging_account(cert_dir: Path) -> Path:
    account = cert_dir / "lego" / "accounts" / "acme-staging-v02.api.letsencrypt.org" / "ops@postern.test"
    account.mkdir(parents=True)
    (account / "account.json").write_text("{}")
    return account


def _staging_issued(now: dt.datetime, **overrides) -> cert_state.CertState:
    """A staging issuance made an hour ago, with the switch to production not yet attempted."""
    fields = dict(
        state="ISSUING",
        last_issued_iso=(now - dt.timedelta(hours=1)).isoformat(),
        last_issued_directory=STAGING,
        acme_directory=STAGING,
        acme_account_email="ops@postern.test",
    )
    fields.update(overrides)
    return cert_state.CertState(**fields)


@pytest.mark.parametrize("state_name", ["ISSUING", "RENEWING"])
def test_directory_switch_runs_lego_run_not_renew(prod_settings, lego_mock, now, state_name):
    state = _staging_issued(now, state=state_name)
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "run"
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    assert next_state.acme_directory == PROD
    assert next_state.last_issued_directory == PROD


def test_directory_switch_resets_lego_account_dir(prod_settings, lego_mock, now, cert_dir):
    account = _staging_account(cert_dir)
    _advance(_staging_issued(now), prod_settings, lego_mock, now)
    assert not account.exists()


def test_directory_switch_ignores_24h_guard_of_the_old_directory(prod_settings, lego_mock, now):
    """Let's Encrypt limits are per directory: a staging issuance an hour ago must not delay production."""
    next_state = _advance(_staging_issued(now), prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_called_once()
    assert next_state.state == "ISSUED_PENDING_INSTALL"


def test_directory_switch_ignores_24h_guard_for_pre_upgrade_state(prod_settings, lego_mock, now):
    """State written before last_issued_directory existed: acme_directory scopes the guard."""
    state = _staging_issued(now, last_issued_directory="")
    _advance(state, prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_called_once()


def test_24h_guard_still_applies_to_attempts_under_the_new_directory(prod_settings, lego_mock, now):
    """A failed production attempt an hour ago still guards production."""
    state = _staging_issued(now, last_issued_directory=PROD)  # acme_directory stays staging until success
    next_state = _advance(state, prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_not_called()
    assert next_state.state == "INSTALLED"
    assert next_state.acme_directory == STAGING  # drift survives the deferral


def test_force_reissue_still_bypasses_guard_for_the_new_directory(prod_settings, lego_mock, now):
    prod_settings.cert_force_reissue = True
    state = _staging_issued(now, last_issued_directory=PROD)
    _advance(state, prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_called_once()


def test_failed_switch_attempt_keeps_run_action_and_does_not_reset_account_again(
    prod_settings, lego_mock, now, cert_dir
):
    import subprocess
    lego_mock.issue_or_renew.side_effect = subprocess.CalledProcessError(1, "lego")
    failed = _advance(_staging_issued(now, state="RENEWING"), prod_settings, lego_mock, now)
    assert failed.state == "RENEWING"
    assert failed.acme_directory == STAGING  # on-disk cert is still the staging one
    assert failed.last_issued_directory == PROD

    # Next attempt (guard bypassed): still `run`, and the registration made by the failed attempt survives.
    prod_settings.cert_force_reissue = True
    account = cert_dir / "lego" / "accounts" / "acme-v02.api.letsencrypt.org" / "ops@postern.test"
    account.mkdir(parents=True)
    lego_mock.issue_or_renew.side_effect = None
    lego_mock.issue_or_renew.reset_mock()
    _advance(failed, prod_settings, lego_mock, now + dt.timedelta(hours=1))
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "run"
    assert account.exists()


def test_failed_state_does_not_hold_off_directory_switch(prod_settings, lego_mock, now):
    state = _staging_issued(
        now,
        state="FAILED",
        last_failed_state="RENEWING",
        consecutive_failures=6,
        last_attempt_iso=(now - dt.timedelta(minutes=5)).isoformat(),
    )
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == "ISSUING"
    assert next_state.consecutive_failures == 0


def test_failed_state_holds_off_after_an_attempt_under_the_new_directory(prod_settings, lego_mock, now):
    state = _staging_issued(
        now,
        state="FAILED",
        last_failed_state="RENEWING",
        consecutive_failures=6,
        last_issued_directory=PROD,
        last_attempt_iso=(now - dt.timedelta(minutes=5)).isoformat(),
    )
    assert _advance(state, prod_settings, lego_mock, now).state == "FAILED"


def test_installed_directory_drift_takes_priority_over_san_mismatch(prod_settings, lego_mock, now):
    """No cert on disk (SAN check fails) and drift together must still choose `run`."""
    state = _staging_issued(now, state="INSTALLED")
    assert _advance(state, prod_settings, lego_mock, now).state == "ISSUING"


def test_full_staging_to_production_switch(settings, prod_settings, lego_mock, now, cert_dir):
    """Staging issuance, then CERT_ACME_DIRECTORY removed: ends INSTALLED under production via `run`."""
    state = cert_state.CertState(state="ISSUING", last_attempt_iso=now.isoformat())
    for _ in range(2):
        state = _advance(state, settings, lego_mock, now)
    assert state.state == "INSTALLED"
    assert state.acme_directory == STAGING
    account = _staging_account(cert_dir)

    t = now + dt.timedelta(hours=1)  # well inside the 24h guard
    lego_mock.issue_or_renew.reset_mock()
    for _ in range(3):
        state = _advance(state, prod_settings, lego_mock, t)
        t += dt.timedelta(minutes=1)
    assert state.state == "INSTALLED"
    assert state.acme_directory == PROD
    lego_mock.issue_or_renew.assert_called_once()
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "run"
    assert not account.exists()
