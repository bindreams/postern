"""Tests for postern_provisioner.cert -- the cert renewal state machine.

The driver is a pure function over (state, settings, lego, time). We mock
LegoRunner and exercise every transition.
"""

import dataclasses
import datetime as dt
import json
import os
import subprocess
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


def _register_account(cert_dir: Path, directory: str, email: str) -> Path:
    """What lego leaves behind: accounts/<host>/<email>/account.json."""
    from urllib.parse import urlparse
    account = cert_dir / "lego" / "accounts" / urlparse(directory).netloc / email
    account.mkdir(parents=True, exist_ok=True)
    (account / "account.json").write_text("{}")
    return account


def _advance(state, settings, lego, now, *, trigger_present=False):
    return cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego,
        trigger_present=trigger_present,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
    )


def _install_live_cert(cert_dir: Path, settings: CertSettings) -> None:
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


def _lego_cert(cert_dir: Path, settings: CertSettings) -> None:
    """The certificate file lego leaves under its --path after any issuance."""
    (cert_dir / "lego" / "certificates" / f"{settings.domain}.crt").write_text("x")


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
        _register_account(cert_dir, settings.cert_acme_directory, settings.cert_acme_email)
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
    assert next_state.last_issued_by_directory == {settings.cert_acme_directory: now.isoformat()}
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
    # ISSUING (`lego run`): `lego renew --days N` is a no-op on a cert that is not yet due.
    assert next_state.state == "ISSUING"


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
    # The old directory stays recorded until the install succeeds, so a failed attempt cannot hide the drift.
    assert next_state.acme_directory == PROD


# Rate-limit guards ====================================================================================================
def test_24h_rate_limit_blocks_reissue(settings, lego_mock, now, cert_dir):
    _install_live_cert(cert_dir, settings)
    state = cert_state.CertState(
        state="RENEWING",
        last_issued_by_directory={settings.cert_acme_directory: (now - dt.timedelta(hours=12)).isoformat()},
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


def test_24h_rate_limit_without_an_installed_cert_stays_put(settings, lego_mock, now):
    """INSTALLED with nothing to serve would open the healthcheck gate under compose.cert.yaml."""
    state = cert_state.CertState(
        state="ISSUING",
        last_issued_by_directory={settings.cert_acme_directory: (now - dt.timedelta(hours=12)).isoformat()},
    )
    next_state = _advance(state, settings, lego_mock, now)
    assert next_state.state == "ISSUING"
    lego_mock.issue_or_renew.assert_not_called()


def test_force_reissue_bypasses_rate_limit(settings, lego_mock, now):
    settings.cert_force_reissue = True
    state = cert_state.CertState(
        state="RENEWING",
        last_issued_by_directory={settings.cert_acme_directory: (now - dt.timedelta(hours=12)).isoformat()},
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


# ACME directory switch (staging -> production) ========================================================================
@pytest.fixture
def prod_settings(settings: CertSettings) -> CertSettings:
    """Operator removed CERT_ACME_DIRECTORY after testing on staging."""
    return CertSettings(
        domain=settings.domain,
        dns_provider=settings.dns_provider,
        cert_acme_email=settings.cert_acme_email,
        cert_acme_directory=PROD,
        cert_renewal_days_before_expiry=10,  # the 30-day test cert is not due
    )


def _staging_issued(now: dt.datetime, **overrides) -> cert_state.CertState:
    """A staging issuance made an hour ago, with the switch to production not yet attempted."""
    issued = (now - dt.timedelta(hours=1)).isoformat()
    fields = dict(
        state="ISSUING",
        last_issued_by_directory={STAGING: issued},
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
    assert next_state.last_issued_by_directory[PROD] == now.isoformat()
    # The staging cert is still what is installed.
    assert next_state.acme_directory == STAGING


def test_directory_switch_discards_the_other_directorys_account(prod_settings, lego_mock, now, cert_dir):
    """Changing the directory discards every account, so Lego registers afresh under the new one."""
    staging_account = _register_account(cert_dir, STAGING, "ops@postern.test")
    registered_at_run = _record_account_presence_at_run(lego_mock, staging_account)
    _advance(_staging_issued(now), prod_settings, lego_mock, now)
    assert registered_at_run == [False]
    assert not staging_account.exists()  # the account Lego registered under the new directory is all that remains


def test_directory_switch_ignores_24h_guard_of_the_old_directory(prod_settings, lego_mock, now):
    """Let's Encrypt limits are per directory: a staging issuance an hour ago must not delay production."""
    next_state = _advance(_staging_issued(now), prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_called_once()
    assert next_state.state == "ISSUED_PENDING_INSTALL"


def test_24h_guard_still_applies_to_attempts_under_the_new_directory(prod_settings, lego_mock, now, cert_dir):
    """A failed production attempt an hour ago still guards production."""
    _install_live_cert(cert_dir, prod_settings)
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = _staging_issued(now, last_issued_by_directory={PROD: issued})
    next_state = _advance(state, prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_not_called()
    assert next_state.state == "INSTALLED"
    assert next_state.acme_directory == STAGING  # drift survives the deferral


def test_24h_guard_remembers_production_across_a_staging_detour(prod_settings, lego_mock, now, cert_dir):
    """prod -> staging -> prod must not buy an extra production issuance."""
    _install_live_cert(cert_dir, prod_settings)
    prod_at = (now - dt.timedelta(hours=3)).isoformat()
    staging_at = (now - dt.timedelta(hours=1)).isoformat()
    state = _staging_issued(now, last_issued_by_directory={PROD: prod_at, STAGING: staging_at})
    next_state = _advance(state, prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_not_called()
    assert next_state.state == "INSTALLED"


def test_force_reissue_still_bypasses_guard_for_the_new_directory(prod_settings, lego_mock, now):
    prod_settings.cert_force_reissue = True
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = _staging_issued(now, last_issued_by_directory={PROD: issued})
    _advance(state, prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_called_once()


def test_failed_switch_attempt_keeps_run_action(prod_settings, lego_mock, now, cert_dir):
    """Even with an account and a Lego cert (so `renew` would be possible), the drift still forces `run`."""
    import subprocess
    _lego_cert(cert_dir, prod_settings)
    lego_mock.issue_or_renew.side_effect = subprocess.CalledProcessError(1, "lego")
    failed = _advance(_staging_issued(now, state="RENEWING"), prod_settings, lego_mock, now)
    assert failed.state == "RENEWING"
    assert failed.acme_directory == STAGING  # on-disk cert is still the staging one

    # Next attempt (guard bypassed): still `run`, even though the failed attempt may have registered an account.
    prod_settings.cert_force_reissue = True
    _register_account(cert_dir, PROD, "ops@postern.test")
    lego_mock.issue_or_renew.side_effect = None
    lego_mock.issue_or_renew.reset_mock()
    _advance(failed, prod_settings, lego_mock, now + dt.timedelta(hours=1))
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "run"


def test_failures_under_the_old_directory_do_not_count_toward_the_new_one(prod_settings, lego_mock, now):
    import subprocess
    lego_mock.issue_or_renew.side_effect = subprocess.CalledProcessError(1, "lego")
    state = _staging_issued(now, consecutive_failures=5)
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == "ISSUING"  # not FAILED
    assert next_state.consecutive_failures == 1


def test_failed_state_does_not_hold_off_directory_switch(prod_settings, lego_mock, now, cert_dir):
    _install_live_cert(cert_dir, prod_settings)
    state = _staging_issued(
        now,
        state="FAILED",
        last_failed_state="RENEWING",
        consecutive_failures=6,
        last_attempt_iso=(now - dt.timedelta(minutes=5)).isoformat(),
    )
    next_state = _advance(state, prod_settings, lego_mock, now)
    # Re-evaluated from INSTALLED, where drift picks ISSUING.
    assert next_state.state == "INSTALLED"
    assert next_state.consecutive_failures == 0
    assert _advance(next_state, prod_settings, lego_mock, now).state == "ISSUING"


def test_failed_under_another_directory_without_an_installed_cert_issues_instead_of_installed(
    prod_settings, lego_mock, now
):
    """INSTALLED with no cert would open the healthcheck gate under compose.cert.yaml with nothing to serve."""
    state = _staging_issued(
        now,
        state="FAILED",
        last_failed_state="ISSUING",
        consecutive_failures=6,
        last_attempt_iso=(now - dt.timedelta(minutes=5)).isoformat(),
    )
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == "ISSUING"
    assert next_state.consecutive_failures == 0


def test_failed_state_holds_off_after_an_attempt_under_the_new_directory(prod_settings, lego_mock, now):
    old = (now - dt.timedelta(hours=1)).isoformat()
    recent = (now - dt.timedelta(minutes=5)).isoformat()
    state = _staging_issued(
        now,
        state="FAILED",
        last_failed_state="RENEWING",
        consecutive_failures=6,
        last_issued_by_directory={STAGING: old, PROD: recent},
        last_attempt_iso=recent,
    )
    assert _advance(state, prod_settings, lego_mock, now).state == "FAILED"


def test_installed_directory_drift_takes_priority_over_san_mismatch(prod_settings, lego_mock, now):
    """No cert on disk (SAN check fails) and drift together still choose ISSUING."""
    state = _staging_issued(now, state="INSTALLED")
    assert _advance(state, prod_settings, lego_mock, now).state == "ISSUING"


def test_installed_drift_logs_that_it_serves_a_pending_renew_trigger(prod_settings, lego_mock, now, caplog):
    caplog.set_level("INFO", logger=cert_driver.logger.name)
    _advance(_staging_issued(now, state="INSTALLED"), prod_settings, lego_mock, now, trigger_present=True)
    assert ".renew-cert trigger" in caplog.text


# Directory drift under an active guard ================================================================================
def test_drift_under_an_active_guard_stays_installed_instead_of_flapping(
    prod_settings, lego_mock, now, cert_dir, caplog
):
    """INSTALLED -> ISSUING -> INSTALLED every tick would flap the healthcheck for the whole 24h."""
    caplog.set_level("INFO", logger=cert_driver.logger.name)
    _install_live_cert(cert_dir, prod_settings)
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = _staging_issued(now, state="INSTALLED", last_issued_by_directory={PROD: issued})
    for tick in range(3):
        state = _advance(state, prod_settings, lego_mock, now + dt.timedelta(minutes=tick))
        assert state.state == "INSTALLED"
    lego_mock.issue_or_renew.assert_not_called()
    assert "guard active" in caplog.text


def test_drift_is_served_once_the_guard_clears(prod_settings, lego_mock, now, cert_dir):
    _install_live_cert(cert_dir, prod_settings)
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = _staging_issued(now, state="INSTALLED", last_issued_by_directory={PROD: issued})
    assert _advance(state, prod_settings, lego_mock, now).state == "INSTALLED"
    assert _advance(state, prod_settings, lego_mock, now + dt.timedelta(hours=24)).state == "ISSUING"


def test_installed_without_a_cert_on_disk_under_an_active_guard_goes_to_issuing(
    prod_settings, lego_mock, now, cert_dir
):
    """A deferral reports INSTALLED only while a cert is on disk: INSTALLED with none would open the healthcheck gate."""
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = _staging_issued(now, state="INSTALLED", last_issued_by_directory={PROD: issued})
    state = _advance(state, prod_settings, lego_mock, now)
    assert state.state == "ISSUING"
    assert _advance(state, prod_settings, lego_mock, now).state == "ISSUING"
    lego_mock.issue_or_renew.assert_not_called()


def test_dropped_renew_trigger_under_an_active_guard_is_logged(settings, lego_mock, now, cert_dir, caplog):
    _install_live_cert(cert_dir, settings)
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = cert_state.CertState(
        state="INSTALLED",
        sans=[settings.domain, f"*.{settings.domain}"],
        acme_directory=STAGING,
        last_issued_by_directory={STAGING: issued},
    )
    _advance(state, settings, lego_mock, now, trigger_present=True)
    assert ".renew-cert request was dropped" in caplog.text
    assert "CERT_FORCE_REISSUE" in caplog.text


def test_no_cert_with_a_trigger_under_an_active_guard_does_not_claim_it_stayed_or_dropped(
    prod_settings, lego_mock, now, caplog
):
    """With no cert on disk the state goes to ISSUING, whose own deferral logs; INSTALLED did not stay."""
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = _staging_issued(now, state="INSTALLED", last_issued_by_directory={PROD: issued})
    state = _advance(state, prod_settings, lego_mock, now, trigger_present=True)
    assert state.state == "ISSUING"
    assert "request was dropped" not in caplog.text
    assert "staying INSTALLED" not in caplog.text


def test_drift_with_a_trigger_under_an_active_guard_logs_one_accurate_line(
    prod_settings, lego_mock, now, cert_dir, caplog
):
    caplog.set_level("INFO", logger=cert_driver.logger.name)
    _install_live_cert(cert_dir, prod_settings)
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = _staging_issued(now, state="INSTALLED", last_issued_by_directory={PROD: issued})
    _advance(state, prod_settings, lego_mock, now, trigger_present=True)
    assert ".renew-cert request was dropped" in caplog.text
    assert "served" not in caplog.text


def test_san_mismatch_under_an_active_guard_stays_installed(settings, lego_mock, now, cert_dir):
    _install_live_cert(cert_dir, settings)
    settings.expected_sans = {"other.test"}
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = cert_state.CertState(state="INSTALLED", acme_directory=STAGING, last_issued_by_directory={STAGING: issued})
    assert _advance(state, settings, lego_mock, now).state == "INSTALLED"


def test_explicit_trigger_under_an_active_guard_stays_installed(settings, lego_mock, now, cert_dir):
    _install_live_cert(cert_dir, settings)
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = cert_state.CertState(
        state="INSTALLED",
        sans=[settings.domain, f"*.{settings.domain}"],
        acme_directory=STAGING,
        last_issued_by_directory={STAGING: issued},
    )
    assert _advance(state, settings, lego_mock, now, trigger_present=True).state == "INSTALLED"


def test_force_reissue_leaves_installed_despite_the_guard(prod_settings, lego_mock, now, cert_dir):
    prod_settings.cert_force_reissue = True
    _install_live_cert(cert_dir, prod_settings)
    issued = (now - dt.timedelta(hours=1)).isoformat()
    state = _staging_issued(now, state="INSTALLED", last_issued_by_directory={PROD: issued})
    assert _advance(state, prod_settings, lego_mock, now).state == "ISSUING"


# Forced reissue and renewal ===========================================================================================
def test_san_mismatch_reissues_with_run(settings, lego_mock, now, cert_dir):
    """`lego renew` would no-op on the (still fresh) cert."""
    _install_live_cert(cert_dir, settings)
    _register_account(cert_dir, STAGING, "ops@postern.test")
    settings.expected_sans = {"other.test"}
    state = cert_state.CertState(state="INSTALLED", acme_directory=STAGING)
    state = _advance(state, settings, lego_mock, now)
    assert state.state == "ISSUING"
    _advance(state, settings, lego_mock, now)
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "run"


def test_renewing_without_a_registered_account_runs(settings, lego_mock, now):
    """e.g. an adopted BYO cert reaching expiry: lego has no account to renew with."""
    state = cert_state.CertState(state="RENEWING", acme_directory=STAGING)
    _advance(state, settings, lego_mock, now)
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "run"


def test_renewing_with_an_account_but_no_lego_cert_runs(settings, lego_mock, now, cert_dir):
    """An adopted BYO cert plus an earlier failed lego run leaves an account but nothing for `renew` to renew."""
    _register_account(cert_dir, STAGING, "ops@postern.test")
    state = cert_state.CertState(state="RENEWING", acme_directory=STAGING)
    _advance(state, settings, lego_mock, now)
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "run"


def test_renewing_with_a_registered_account_renews(settings, lego_mock, now, cert_dir):
    _register_account(cert_dir, STAGING, "ops@postern.test")
    _lego_cert(cert_dir, settings)
    state = cert_state.CertState(state="RENEWING", acme_directory=STAGING)
    _advance(state, settings, lego_mock, now)
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "renew"


# acme_directory moves with the install ================================================================================
def test_failed_install_keeps_the_directory_drift(prod_settings, lego_mock, now):
    state = _staging_issued(now, state="ISSUED_PENDING_INSTALL", pending_cert_paths={})  # KeyError in install
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    assert next_state.acme_directory == STAGING


def test_install_records_the_directory_the_cert_was_issued_under(settings, prod_settings, lego_mock, now):
    """The configured directory may have changed between the Lego run and the install."""
    state = _advance(cert_state.CertState(state="ISSUING"), settings, lego_mock, now)
    assert state.state == "ISSUED_PENDING_INSTALL"
    state = _advance(state, prod_settings, lego_mock, now)
    assert state.state == "INSTALLED"
    assert state.acme_directory == STAGING


def test_full_staging_to_production_switch(settings, prod_settings, lego_mock, now, cert_dir):
    """Staging issuance, then CERT_ACME_DIRECTORY removed: ends INSTALLED under production via `run`."""
    state = cert_state.CertState(state="ISSUING", last_attempt_iso=now.isoformat())
    for _ in range(2):
        state = _advance(state, settings, lego_mock, now)
    assert state.state == "INSTALLED"
    assert state.acme_directory == STAGING
    staging_account = _register_account(cert_dir, STAGING, "ops@postern.test")

    t = now + dt.timedelta(hours=1)  # well inside the 24h guard
    lego_mock.issue_or_renew.reset_mock()
    for _ in range(3):
        state = _advance(state, prod_settings, lego_mock, t)
        t += dt.timedelta(minutes=1)
    assert state.state == "INSTALLED"
    assert state.acme_directory == PROD
    lego_mock.issue_or_renew.assert_called_once()
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "run"
    assert not staging_account.exists()  # the switch discarded it


# Install under the directory lego ran with ============================================================================
def test_issuing_records_the_directory_it_ran_under_with_the_pending_paths(settings, lego_mock, now):
    state = _advance(cert_state.CertState(state="ISSUING"), settings, lego_mock, now)
    assert state.pending_acme_directory == STAGING


def test_install_uses_the_recorded_directory_not_the_latest_clock_entry(prod_settings, lego_mock, now):
    """A clock step can make another directory's entry the newest; the install must not guess from timestamps."""
    state = _advance(_staging_issued(now, last_issued_by_directory={}), prod_settings, lego_mock, now)
    assert state.state == "ISSUED_PENDING_INSTALL"
    assert state.pending_acme_directory == PROD
    stepped = dataclasses.replace(
        state,
        last_issued_by_directory={PROD: now.isoformat(), STAGING: (now + dt.timedelta(days=30)).isoformat()},
    )
    installed = _advance(stepped, prod_settings, lego_mock, now)
    assert installed.state == "INSTALLED"
    assert installed.acme_directory == PROD
    assert installed.pending_acme_directory == ""


def test_adopted_cert_without_any_lego_state_is_left_alone(prod_settings, lego_mock, now, cert_dir):
    _install_live_cert(cert_dir, prod_settings)
    state = cert_state.CertState(state="INSTALLED", sans=[prod_settings.domain, f"*.{prod_settings.domain}"])
    assert _advance(state, prod_settings, lego_mock, now).state == "INSTALLED"


# Lego's account directory =============================================================================================
def test_account_path_of_a_host_with_a_port_replaces_the_colon(prod_settings, lego_mock, now, cert_dir):
    """Lego writes `accounts/<host>_<port>/<email>`; looking under `<host>:<port>` would never find it."""
    prod_settings.cert_acme_directory = "https://ca.internal:9000/acme/dir"
    account = cert_dir / "lego" / "accounts" / "ca.internal_9000" / "ops@postern.test"
    account.mkdir(parents=True)
    (account / "account.json").write_text("{}")
    _lego_cert(cert_dir, prod_settings)
    state = cert_state.CertState(state="RENEWING", acme_directory=prod_settings.cert_acme_directory)
    _advance(state, prod_settings, lego_mock, now)
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "renew"


STEP_CA_OLD = "https://ca.internal/acme/old/directory"
STEP_CA_NEW = "https://ca.internal/acme/new/directory"


def _record_account_presence_at_run(lego_mock: MagicMock, account: Path, *, fail: bool = False) -> list[bool]:
    """Record whether `account` exists when Lego runs; with `fail`, Lego registers its account and then fails."""
    present: list[bool] = []
    if not hasattr(lego_mock, "base_issue"):
        lego_mock.base_issue = lego_mock.issue_or_renew.side_effect
    real_issue = lego_mock.base_issue

    def run(*, settings, action):
        present.append(account.exists())
        output = real_issue(settings=settings, action=action)
        if fail:
            raise subprocess.CalledProcessError(1, "lego")
        return output

    lego_mock.issue_or_renew.side_effect = run
    return present


def _step_ca_switch(prod_settings: CertSettings, now: dt.datetime) -> cert_state.CertState:
    prod_settings.cert_acme_directory = STEP_CA_NEW
    issued = (now - dt.timedelta(days=3)).isoformat()
    return cert_state.CertState(
        state="ISSUING",
        acme_directory=STEP_CA_OLD,
        acme_account_email="ops@postern.test",
        last_issued_by_directory={STEP_CA_OLD: issued},
    )


def test_switch_between_directories_on_one_host_discards_the_old_account(prod_settings, lego_mock, now, cert_dir):
    """Lego keys accounts by host alone, so the old directory's account would be reused for the new one."""
    old_account = _register_account(cert_dir, STEP_CA_OLD, "ops@postern.test")
    registered_at_run = _record_account_presence_at_run(lego_mock, old_account)
    _advance(_step_ca_switch(prod_settings, now), prod_settings, lego_mock, now)
    assert registered_at_run == [False]  # gone before Lego ran, so it registers afresh


def test_retry_after_a_failed_switch_attempt_keeps_the_account_the_attempt_registered(
    prod_settings, lego_mock, now, cert_dir
):
    """The failed attempt already registered an account under the new directory; discarding it again is waste."""
    state = _step_ca_switch(prod_settings, now)
    state = dataclasses.replace(
        state,
        last_issued_by_directory={
            **state.last_issued_by_directory, STEP_CA_NEW: (now - dt.timedelta(days=2)).isoformat()
        },
    )
    account = _register_account(cert_dir, STEP_CA_NEW, "ops@postern.test")
    _advance(state, prod_settings, lego_mock, now)
    assert (account / "account.json").exists()


def test_reissue_without_a_switch_leaves_the_account_alone(settings, lego_mock, now, cert_dir):
    account = _register_account(cert_dir, STAGING, "ops@postern.test")
    state = cert_state.CertState(state="ISSUING", acme_directory=STAGING, acme_account_email="ops@postern.test")
    _advance(state, settings, lego_mock, now)
    assert (account / "account.json").exists()


def test_switch_through_a_failing_directory_discards_the_account_at_both_steps(prod_settings, lego_mock, now, cert_dir):
    """A -> S (fails after registering) -> B on one host: S's registration is not B's, so B starts clean too."""
    account = _register_account(cert_dir, STEP_CA_OLD, "ops@postern.test")
    state = _step_ca_switch(prod_settings, now)
    prod_settings.cert_acme_directory = STAGING
    first = _record_account_presence_at_run(lego_mock, account, fail=True)
    state = _advance(state, prod_settings, lego_mock, now)
    assert first == [False]
    assert state.consecutive_failures == 1
    account = _register_account(cert_dir, STAGING, "ops@postern.test")  # what S's failed run left behind

    prod_settings.cert_acme_directory = STEP_CA_NEW
    second = _record_account_presence_at_run(lego_mock, account)
    _advance(state, prod_settings, lego_mock, now + dt.timedelta(minutes=5))
    assert second == [False]


def test_failed_switch_then_revert_does_not_reuse_the_account_the_failed_attempt_registered(
    prod_settings, lego_mock, now, cert_dir
):
    """A -> B (same host, Lego registers B's account, then fails) -> config back to A: B's account is not A's."""
    account = _register_account(cert_dir, STEP_CA_OLD, "ops@postern.test")
    state = _step_ca_switch(prod_settings, now)
    first = _record_account_presence_at_run(lego_mock, account, fail=True)
    state = _advance(state, prod_settings, lego_mock, now)  # configured STEP_CA_NEW
    assert first == [False]
    assert state.consecutive_failures == 1
    account = _register_account(cert_dir, STEP_CA_NEW, "ops@postern.test")  # what B's failed run left behind

    prod_settings.cert_acme_directory = STEP_CA_OLD
    present = _record_account_presence_at_run(lego_mock, account)
    state = dataclasses.replace(state, state="ISSUING")
    _advance(state, prod_settings, lego_mock, now + dt.timedelta(days=2))
    assert present == [False]


def test_account_reset_log_names_the_directory(prod_settings, lego_mock, now, cert_dir, caplog):
    caplog.set_level("INFO", logger=cert_driver.logger.name)
    _register_account(cert_dir, STEP_CA_OLD, "ops@postern.test")
    _advance(_step_ca_switch(prod_settings, now), prod_settings, lego_mock, now)
    assert "ACME directory changed; resetting lego account dir" in caplog.text


def test_account_path_ignores_userinfo_in_the_directory_url(prod_settings, lego_mock, now, cert_dir):
    """Lego names the account directory by the URL's host and port, without `user:pass@`."""
    prod_settings.cert_acme_directory = "https://user:pass@ca.internal:9000/acme/dir"
    account = cert_dir / "lego" / "accounts" / "ca.internal_9000" / "ops@postern.test"
    account.mkdir(parents=True)
    (account / "account.json").write_text("{}")
    _lego_cert(cert_dir, prod_settings)
    state = cert_state.CertState(state="RENEWING", acme_directory=prod_settings.cert_acme_directory)
    _advance(state, prod_settings, lego_mock, now)
    assert lego_mock.issue_or_renew.call_args.kwargs["action"] == "renew"


# ACME account email change ============================================================================================
def test_email_change_log_names_the_email(settings, lego_mock, now, cert_dir, caplog):
    caplog.set_level("INFO", logger=cert_driver.logger.name)
    _register_account(cert_dir, STAGING, "previous@old.example")
    state = cert_state.CertState(state="ISSUING", acme_account_email="previous@old.example", acme_directory=STAGING)
    _advance(state, settings, lego_mock, now)
    assert "ACME account email changed; resetting lego account dir" in caplog.text


def test_email_change_resets_lego_account_dir(settings, lego_mock, now, cert_dir):
    old_account = _register_account(cert_dir, STAGING, "previous@old.example")
    state = cert_state.CertState(
        state="ISSUING",
        acme_account_email="previous@old.example",
        acme_directory=STAGING,
    )
    next_state = _advance(state, settings, lego_mock, now)
    assert not old_account.exists()
    assert next_state.acme_account_email == settings.cert_acme_email


def test_unchanged_email_keeps_lego_account_dir(settings, lego_mock, now, cert_dir):
    account = _register_account(cert_dir, STAGING, "ops@postern.test")
    state = cert_state.CertState(state="ISSUING", acme_account_email="ops@postern.test", acme_directory=STAGING)
    _advance(state, settings, lego_mock, now)
    assert (account / "account.json").exists()


# last_issued_iso is legacy ============================================================================================
def test_attempt_records_only_the_per_directory_time(settings, lego_mock, now):
    legacy = "2026-01-01T00:00:00+00:00"
    state = cert_state.CertState(state="ISSUING", last_issued_iso=legacy)
    state = _advance(state, settings, lego_mock, now)
    assert state.last_issued_by_directory == {STAGING: now.isoformat()}
    assert state.last_issued_iso == legacy


# State written before the per-directory attempt times =================================================================
def _legacy_state(settings: CertSettings, **fields) -> cert_state.CertState:
    """Write state.json the way the pre-upgrade code did, then read it back as the provisioner does."""
    path = cert_state.state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 1, **fields}))
    return cert_state.read_state()


def test_legacy_adopted_cert_is_left_alone(prod_settings, lego_mock, now, cert_dir):
    _install_live_cert(cert_dir, prod_settings)
    state = _legacy_state(prod_settings, state="INSTALLED", sans=[prod_settings.domain, f"*.{prod_settings.domain}"])
    assert _advance(state, prod_settings, lego_mock, now).state == "INSTALLED"
    lego_mock.issue_or_renew.assert_not_called()


def test_legacy_staging_attempt_does_not_guard_production(prod_settings, lego_mock, now):
    state = _legacy_state(
        prod_settings,
        state="ISSUING",
        acme_directory=STAGING,
        last_issued_iso=(now - dt.timedelta(hours=1)).isoformat(),
    )
    assert _advance(state, prod_settings, lego_mock, now).state == "ISSUED_PENDING_INSTALL"


def test_legacy_failed_under_the_configured_directory_still_holds_off(prod_settings, lego_mock, now):
    recent = (now - dt.timedelta(minutes=5)).isoformat()
    state = _legacy_state(
        prod_settings,
        state="FAILED",
        last_failed_state="RENEWING",
        consecutive_failures=6,
        acme_directory=PROD,
        last_issued_iso=recent,
        last_attempt_iso=recent,
    )
    assert _advance(state, prod_settings, lego_mock, now).state == "FAILED"


def test_legacy_failed_under_another_directory_skips_the_hold_off(prod_settings, lego_mock, now):
    recent = (now - dt.timedelta(minutes=5)).isoformat()
    state = _legacy_state(
        prod_settings,
        state="FAILED",
        last_failed_state="RENEWING",
        consecutive_failures=6,
        acme_directory=STAGING,
        last_issued_iso=recent,
        last_attempt_iso=recent,
    )
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == "ISSUING"
    assert next_state.consecutive_failures == 0


def test_legacy_pending_install_completes_under_the_configured_directory(prod_settings, lego_mock, now):
    state = _advance(cert_state.CertState(state="ISSUING"), prod_settings, lego_mock, now)
    legacy = _legacy_state(
        prod_settings,
        state="ISSUED_PENDING_INSTALL",
        acme_directory=PROD,
        last_issued_iso=now.isoformat(),
        pending_cert_paths=state.pending_cert_paths,
    )
    assert _advance(legacy, prod_settings, lego_mock, now).acme_directory == PROD
