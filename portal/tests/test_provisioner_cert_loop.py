"""Tests for postern_provisioner.cert -- the cert renewal state machine.

The driver is a pure function over (state, settings, lego, time). We mock
LegoRunner and exercise every transition.
"""

import dataclasses
import datetime as dt
import json
import os
import shutil
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


# lego v5 `account.json`: `registration` is an acme.ExtendedAccount, whose `status` is a top-level field.
REGISTERED_ACCOUNT = json.dumps({"registration": {"status": "valid", "accountURL": "https://ca.test/acct/1"}})


def _generate_account_key() -> bytes:
    """A PEM key as lego writes it: one lego can load."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )


ACCOUNT_KEY = _generate_account_key()


def _register_account(cert_dir: Path, directory: str, email: str) -> Path:
    """What lego leaves behind: accounts/<host>/<email>/account.json."""
    from urllib.parse import urlparse
    account = cert_dir / "lego" / "accounts" / urlparse(directory).netloc / email
    account.mkdir(parents=True, exist_ok=True)
    (account / "account.json").write_text(REGISTERED_ACCOUNT)
    return account


def _advance(state, settings, lego, now, *, trigger_present=False, clock=None):
    extra = {} if clock is None else {"clock": clock}
    return cert_driver.advance_cert_state(
        state,
        settings=settings,
        lego=lego,
        trigger_present=trigger_present,
        now=now,
        cert_dir=cert_driver.CERT_DIR,
        **extra,
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


@pytest.fixture
def lego_mock(cert_dir: Path, settings: CertSettings) -> MagicMock:
    """Returns a LegoRunner mock that, when invoked, writes a fake cert triple."""
    from tests.e2e._certs import generate_test_pki
    pki_dir = cert_dir / "lego" / "certificates"
    runner = MagicMock(spec=cert_driver.LegoRunner)

    def _fake_issue(*, settings, force):
        # Reuse the existing wildcard-PKI helper to produce a real x.509 cert
        # with the right SANs, so the post-install adoption check passes.
        scratch = pki_dir / ".scratch"
        scratch.mkdir(exist_ok=True)
        # A 90-day leaf, like Let's Encrypt's: one that is already due under the 30-day threshold is not installable.
        generate_test_pki(
            scratch,
            hostname=settings.domain,
            leaf_not_after=dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(days=90)
        )
        fc = pki_dir / f"{settings.domain}.crt"
        pk = pki_dir / f"{settings.domain}.key"
        ch = pki_dir / f"{settings.domain}.issuer.crt"
        # lego's resource file, written last
        (pki_dir /
         f"{settings.domain}.json").write_text(json.dumps({"id": settings.domain, "domains": [settings.domain]}))
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
    # ISSUING, which forces the run: `lego run` without `--renew-force` writes nothing for a cert that is not yet due.
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
    # ISSUING, not RENEWING: a cert from the old directory is not due, and lego's own copy may be from it too.
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
        last_attempt_directory=STAGING,
        acme_directory=STAGING,
        acme_account_email="ops@postern.test",
    )
    fields.update(overrides)
    return cert_state.CertState(**fields)


@pytest.mark.parametrize("state_name", ["ISSUING", "RENEWING"])
def test_directory_switch_issues_from_either_state(prod_settings, lego_mock, now, state_name):
    state = _staging_issued(now, state=state_name)
    next_state = _advance(state, prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_called_once()
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


def test_failures_under_the_old_directory_do_not_count_toward_the_new_one(prod_settings, lego_mock, now):
    import subprocess
    lego_mock.issue_or_renew.side_effect = subprocess.CalledProcessError(1, "lego")
    state = _staging_issued(now, consecutive_failures=5)
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == "ISSUING"  # not FAILED
    assert next_state.consecutive_failures == 1


def test_an_attempt_records_the_directory_it_ran_under(prod_settings, lego_mock, now):
    assert _advance(_staging_issued(now), prod_settings, lego_mock, now).last_attempt_directory == PROD


def test_a_discarded_account_keeps_the_guard_clear_but_records_the_directory_attempted(prod_settings, lego_mock, now):
    _fail_lego(lego_mock)
    failed = _advance(_staging_issued(now), prod_settings, lego_mock, now)
    assert failed.last_issued_by_directory == _staging_issued(now).last_issued_by_directory
    assert failed.last_attempt_directory == PROD


def test_a_directory_switch_whose_every_run_discards_the_account_still_reaches_failed(prod_settings, lego_mock, now):
    """Failures count toward FAILED from the first attempt under the new directory, not from each tick afresh."""
    _fail_lego(lego_mock)
    state = _staging_issued(now)
    for _ in range(cert_driver.MAX_CONSECUTIVE_FAILURES):
        state = _advance(state, prod_settings, lego_mock, now)
    assert state.state == "FAILED"


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
        last_attempt_directory=PROD,
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
def test_san_mismatch_reissues(settings, lego_mock, now, cert_dir):
    """The (still fresh) cert is replaced: lego is called once."""
    _install_live_cert(cert_dir, settings)
    _register_account(cert_dir, STAGING, "ops@postern.test")
    settings.expected_sans = {"other.test"}
    state = cert_state.CertState(state="INSTALLED", acme_directory=STAGING)
    state = _advance(state, settings, lego_mock, now)
    assert state.state == "ISSUING"
    _advance(state, settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_called_once()


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


# Validating lego's output =============================================================================================
def _lego_writes(lego_mock: MagicMock, mutate) -> None:
    """Have the fake lego run `mutate(output)` on the files it wrote, as a crash or a no-op leaves them."""
    real_issue = lego_mock.issue_or_renew.side_effect

    def run(*, settings, force):
        output = real_issue(settings=settings, force=force)
        mutate(output)
        return output

    lego_mock.issue_or_renew.side_effect = run


def _replace_with_pki(output: LegoOutput, scratch: Path, *, key: bool = True, cert: bool = True, **pki) -> None:
    """Overwrite the cert and/or key lego wrote with those of a freshly generated PKI."""
    from tests.e2e._certs import generate_test_pki
    generate_test_pki(scratch, **pki)
    if cert:
        output.fullchain.write_bytes((scratch / "fullchain.pem").read_bytes())
        output.chain.write_bytes((scratch / "chain.pem").read_bytes())
    if key:
        output.privkey.write_bytes((scratch / "privkey.pem").read_bytes())


def _days_from_now(days: float) -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(days=days)


# Each flaw with the problem the log must name.
def _generate_other_pki(output: LegoOutput, scratch: Path) -> None:
    """Replace the issuer certificate with that of a different CA."""
    from tests.e2e._certs import generate_test_pki
    generate_test_pki(scratch / "other")
    output.chain.write_bytes((scratch / "other" / "chain.pem").read_bytes())


BAD_LEGO_OUTPUT = {
    # A crash between lego's writes of the .crt and the .key leaves a new certificate with the old key.
    "mismatched-key": (lambda out, tmp: _replace_with_pki(out, tmp, cert=False), "is not the key of"),
    "wrong-sans": (lambda out, tmp: _replace_with_pki(out, tmp, hostname="other.test"), "its names"),
    "expired": (
        lambda out, tmp:
        _replace_with_pki(out, tmp, leaf_not_before=_days_from_now(-10), leaf_not_after=_days_from_now(-1)), "expired"
    ),
    "not-yet-valid": (
        lambda out, tmp:
        _replace_with_pki(out, tmp, leaf_not_before=_days_from_now(0.05), leaf_not_after=_days_from_now(90)),
        "not valid until"
    ),
    "unparseable-cert": (lambda out, tmp: out.fullchain.write_text("not a certificate"), "cannot read"),
    "unparseable-key": (lambda out, tmp: out.privkey.write_text("not a key"), "cannot read"),
    # The issuer certificate is another CA's (same name, other key), unparseable, or missing.
    "wrong-issuer": (_generate_other_pki, "did not issue"),
    "unparseable-issuer": (lambda out, tmp: out.chain.write_text("not a certificate"), "cannot read"),
    "missing-issuer": (lambda out, tmp: out.chain.unlink(), "cannot read"),
}


@pytest.mark.parametrize("state_name", ["ISSUING", "RENEWING"])
@pytest.mark.parametrize("flaw", BAD_LEGO_OUTPUT)
def test_a_lego_output_that_is_not_installable_is_never_installed(
    prod_settings, lego_mock, now, cert_dir, tmp_path, caplog, flaw, state_name
):
    mutate, problem = BAD_LEGO_OUTPUT[flaw]
    _lego_writes(lego_mock, lambda out: mutate(out, tmp_path / "bad"))
    state = dataclasses.replace(
        _issuing(prod_settings, state_name), last_issued_by_directory={PROD: "2000-01-01T00:00:00+00:00"}
    )
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == state_name
    assert next_state.pending_cert_paths == {}
    assert next_state.consecutive_failures == 1
    assert "not installable" in caplog.text
    assert problem in caplog.text
    # An order was placed, so the 24h guard is armed.
    assert next_state.last_issued_by_directory == {PROD: now.isoformat()}
    # lego's resource file is what makes `lego run` renew instead of obtain; without it the next run is a fresh
    # issuance whatever flag Postern passes, and none of the bad files stays around to be trusted.
    assert sorted(p.name for p in (cert_dir / "lego" / "certificates").glob(f"{prod_settings.domain}*")) == []


@pytest.mark.parametrize("state_name", ["ISSUING", "RENEWING"])
def test_a_valid_lego_output_is_accepted(prod_settings, lego_mock, now, state_name):
    state = dataclasses.replace(
        _issuing(prod_settings, state_name), last_issued_by_directory={PROD: "2000-01-01T00:00:00+00:00"}
    )
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    assert set(next_state.pending_cert_paths) == {"fullchain", "privkey", "chain"}


def test_a_leaf_that_became_valid_after_the_tick_began_is_accepted(prod_settings, lego_mock, now, tmp_path):
    """A CA that does not backdate (Pebble) sets notBefore to the issuance time, which is after the tick's `now`."""
    returned = now + dt.timedelta(minutes=2)
    _lego_writes(
        lego_mock, lambda out: _replace_with_pki(
            out,
            tmp_path / "late",
            leaf_not_before=now + dt.timedelta(minutes=1),
            leaf_not_after=now + dt.timedelta(days=90)
        )
    )
    next_state = _advance(_issuing(prod_settings), prod_settings, lego_mock, now, clock=lambda: returned)
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    assert next_state.last_attempt_iso == now.isoformat()


def test_the_validity_check_reads_the_injected_clock_not_the_wall_clock(prod_settings, lego_mock, now, caplog):
    """The 90-day leaf is valid by the wall clock, but lego returned (by the injected clock) after it had expired."""
    returned = now + dt.timedelta(days=200)
    next_state = _advance(_issuing(prod_settings), prod_settings, lego_mock, now, clock=lambda: returned)
    assert next_state.state == "ISSUING"
    assert "expired" in caplog.text


def test_a_transition_without_a_given_time_reads_the_clock_once_for_the_tick(prod_settings, lego_mock, now):
    ticks = iter([now, now + dt.timedelta(minutes=2)])
    next_state = cert_driver.advance_cert_state(
        _issuing(prod_settings),
        settings=prod_settings,
        lego=lego_mock,
        trigger_present=False,
        cert_dir=cert_driver.CERT_DIR,
        clock=lambda: next(ticks),
    )
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    assert next_state.last_attempt_iso == now.isoformat()
    assert next(ticks, None) is None  # the tick's start and the post-lego time were the clock's only two readings


def test_a_failed_cleanup_of_rejected_lego_output_is_logged_not_raised(
    prod_settings, lego_mock, now, tmp_path, monkeypatch, caplog
):
    _lego_writes(lego_mock, lambda out: BAD_LEGO_OUTPUT["mismatched-key"][0](out, tmp_path / "bad"))

    def boom(self, *args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(Path, "unlink", boom)
    next_state = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert next_state.state == "ISSUING"
    assert next_state.consecutive_failures == 1
    assert "read-only file system" in caplog.text


def test_cleanup_of_rejected_lego_output_removes_the_resource_file_first_and_stops_at_the_first_failure(
    prod_settings, lego_mock, now, cert_dir, tmp_path, monkeypatch
):
    """lego holding a resource file with no certificate beside it cannot run, so the resource file goes first."""
    _lego_writes(lego_mock, lambda out: BAD_LEGO_OUTPUT["mismatched-key"][0](out, tmp_path / "bad"))
    real_unlink = Path.unlink
    calls: list[str] = []

    def fail_the_second(self, *args, **kwargs):
        calls.append(self.name)
        if len(calls) == 2:
            raise OSError("read-only file system")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_the_second)
    _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    domain = prod_settings.domain
    assert calls == [f"{domain}.json", f"{domain}.crt"]
    remaining = sorted(p.name for p in _lego_certificates(cert_dir).glob(f"{domain}*"))
    assert remaining == [f"{domain}.crt", f"{domain}.issuer.crt", f"{domain}.key"]


# Whether a lego run is forced =========================================================================================
def _forced(lego_mock: MagicMock) -> bool:
    lego_mock.issue_or_renew.assert_called_once()
    return lego_mock.issue_or_renew.call_args.kwargs["force"]


def test_issuing_forces_the_run(prod_settings, lego_mock, now):
    _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert _forced(lego_mock) is True


def _renewing_after_an_attempt(settings: CertSettings, now: dt.datetime) -> cert_state.CertState:
    """RENEWING with a Lego attempt on record under the configured directory, which proves lego's certificate is its own."""
    return dataclasses.replace(
        _issuing(settings, "RENEWING"),
        last_issued_by_directory={settings.cert_acme_directory: (now - dt.timedelta(days=60)).isoformat()},
    )


def test_renewing_with_nothing_changed_lets_lego_apply_postern_threshold(prod_settings, lego_mock, now):
    """A tick is RENEWING because the live cert is due; lego no-ops only on a cert a crashed tick left newer."""
    _advance(_renewing_after_an_attempt(prod_settings, now), prod_settings, lego_mock, now)
    assert _forced(lego_mock) is False


def test_renewing_with_no_attempt_on_record_for_the_directory_forces_the_run(prod_settings, lego_mock, now):
    """An adopted cert, or a state.json that was lost or unreadable, leaves nothing to say that the certificate lego
    holds is from this directory (it may be a staging one that is not due)."""
    _advance(_issuing(prod_settings, "RENEWING"), prod_settings, lego_mock, now)
    assert _forced(lego_mock) is True


def test_renewing_under_a_changed_directory_forces_the_run(prod_settings, lego_mock, now):
    """lego's own cert may be from the old directory, so a not-due check on it proves nothing."""
    state = dataclasses.replace(
        _issuing(prod_settings, "RENEWING"),
        last_issued_by_directory={STAGING: (now - dt.timedelta(days=3)).isoformat()}
    )
    _advance(state, prod_settings, lego_mock, now)
    assert _forced(lego_mock) is True


def test_renewing_under_a_changed_email_forces_the_run(prod_settings, lego_mock, now):
    state = dataclasses.replace(_issuing(prod_settings, "RENEWING"), acme_account_email="old@postern.test")
    _advance(state, prod_settings, lego_mock, now)
    assert _forced(lego_mock) is True


# A lego run that writes nothing =======================================================================================
def _lego_declines(lego_mock: MagicMock, output: LegoOutput) -> None:
    """lego exits 0 without placing an order and hands back the set it already holds."""
    lego_mock.issue_or_renew.side_effect = lambda *, settings, force: output


def _unforced_renewing(settings: CertSettings, now: dt.datetime) -> cert_state.CertState:
    return _renewing_after_an_attempt(settings, now)


def test_lego_declining_a_certificate_that_is_not_due_installs_it(prod_settings, lego_mock, now, cert_dir):
    """The recovery of a tick that crashed after lego issued: lego now sees its own newer certificate as not due."""
    stored = _stored_lego_set(cert_dir, prod_settings.domain, leaf_not_after=_days_from_now(90))
    _lego_declines(lego_mock, stored)
    next_state = _advance(_unforced_renewing(prod_settings, now), prod_settings, lego_mock, now)
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    assert next_state.pending_cert_paths["fullchain"] == str(stored.fullchain)


def test_lego_declining_a_certificate_that_is_due_is_rejected_and_places_no_order(
    prod_settings, lego_mock, now, cert_dir, caplog
):
    stored = _stored_lego_set(
        cert_dir, prod_settings.domain, leaf_not_before=_days_from_now(-85), leaf_not_after=_days_from_now(5)
    )
    _lego_declines(lego_mock, stored)
    state = _unforced_renewing(prod_settings, now)
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == "RENEWING"
    assert next_state.pending_cert_paths == {}
    assert next_state.consecutive_failures == 1
    assert "declined" in caplog.text
    # No order was placed, so the 24h guard is as it was; and lego's set is gone, so the next run obtains afresh.
    assert next_state.last_issued_by_directory == state.last_issued_by_directory
    assert list(_lego_certificates(cert_dir).glob(f"{prod_settings.domain}*")) == []


@pytest.mark.parametrize("state_name", ["ISSUING", "RENEWING"])
def test_a_new_certificate_is_not_held_to_the_due_check(prod_settings, lego_mock, now, tmp_path, state_name):
    """Forced runs never get it, and an unforced run that wrote a new certificate placed an order for it."""
    _lego_writes(
        lego_mock, lambda out:
        _replace_with_pki(out, tmp_path / "due", leaf_not_before=_days_from_now(-85), leaf_not_after=_days_from_now(5))
    )
    state = dataclasses.replace(
        _issuing(prod_settings, state_name), last_issued_by_directory={PROD: "2000-01-01T00:00:00+00:00"}
    )
    assert _advance(state, prod_settings, lego_mock, now).state == "ISSUED_PENDING_INSTALL"


def _stored_set_with_flaw(cert_dir: Path, tmp_path: Path, domain: str, flaw: str) -> LegoOutput:
    """lego's stored set with a flaw that leaves its leaf (and so its serial) as it was."""
    if flaw == "expired":
        return _stored_lego_set(
            cert_dir, domain, leaf_not_before=_days_from_now(-10), leaf_not_after=_days_from_now(-1)
        )
    if flaw == "not-yet-valid":
        return _stored_lego_set(
            cert_dir, domain, leaf_not_before=_days_from_now(0.05), leaf_not_after=_days_from_now(90)
        )
    stored = _stored_lego_set(cert_dir, domain, leaf_not_after=_days_from_now(90))
    if flaw == "mismatched-key":
        _replace_with_pki(stored, tmp_path / "other", cert=False)
    else:
        _generate_other_pki(stored, tmp_path / "other")  # wrong-issuer
    return stored


@pytest.mark.parametrize("flaw", ["mismatched-key", "wrong-issuer", "expired", "not-yet-valid"])
def test_a_set_that_lego_declined_to_renew_places_no_order_whatever_is_wrong_with_it(
    prod_settings, lego_mock, now, cert_dir, tmp_path, flaw
):
    """The serial is unchanged, so the CA was not asked: the 24h guard stays as it was for every rejection."""
    _lego_declines(lego_mock, _stored_set_with_flaw(cert_dir, tmp_path, prod_settings.domain, flaw))
    state = _unforced_renewing(prod_settings, now)
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert _forced(lego_mock) is False
    assert next_state.state == "RENEWING"
    assert next_state.consecutive_failures == 1
    assert next_state.last_issued_by_directory == state.last_issued_by_directory
    assert list(_lego_certificates(cert_dir).glob(f"{prod_settings.domain}*")) == []


def test_a_forced_run_is_not_compared_with_the_stored_certificate(prod_settings, lego_mock, now, cert_dir):
    stored = _stored_lego_set(
        cert_dir, prod_settings.domain, leaf_not_before=_days_from_now(-85), leaf_not_after=_days_from_now(5)
    )
    _lego_declines(lego_mock, stored)
    next_state = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert next_state.state == "ISSUED_PENDING_INSTALL"


@pytest.mark.parametrize(("at_offset", "problem"), [(dt.timedelta(0), False), (dt.timedelta(seconds=1), True)])
def test_a_certificate_is_due_when_it_has_less_than_the_threshold_left(
    prod_settings, cert_dir, tmp_path, at_offset, problem
):
    """Postern's rule is `days_left < threshold`; lego's own `<=` would call the boundary due."""
    from postern.cert import inspect as cert_inspect
    stored = _stored_lego_set(
        cert_dir, prod_settings.domain, leaf_not_before=_days_from_now(-85), leaf_not_after=_days_from_now(5)
    )
    leaf = cert_inspect.read_cert(stored.fullchain)
    at = leaf.not_after - dt.timedelta(days=prod_settings.cert_renewal_days_before_expiry) + at_offset
    rejection = cert_driver._reject_lego_output(
        stored, {prod_settings.domain, f"*.{prod_settings.domain}"},
        prod_settings,
        forced=False,
        prior_serial=leaf.serial,
        at=at
    )
    assert (rejection is not None) is problem


@pytest.mark.parametrize("state_name", ["ISSUING", "RENEWING"])
@pytest.mark.parametrize(("extra", "logged"), [(dt.timedelta(0), True), (dt.timedelta(seconds=1), False)])
def test_a_renewal_threshold_that_is_not_shorter_than_the_lifetime_installs_the_certificate_and_logs_an_error(
    prod_settings, lego_mock, now, tmp_path, caplog, state_name, extra, logged
):
    """Rejecting the valid certificate would leave the live one to expire, so it is installed and the operator told."""
    start = now - dt.timedelta(days=1)
    lifetime = dt.timedelta(days=prod_settings.cert_renewal_days_before_expiry) + extra
    _lego_writes(
        lego_mock,
        lambda out: _replace_with_pki(out, tmp_path / "short", leaf_not_before=start, leaf_not_after=start + lifetime)
    )
    state = dataclasses.replace(
        _issuing(prod_settings, state_name), last_issued_by_directory={PROD: "2000-01-01T00:00:00+00:00"}
    )
    next_state = _advance(state, prod_settings, lego_mock, now)
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    if not logged:
        assert errors == []
        return
    assert len(errors) == 1
    assert "CERT_RENEWAL_DAYS_BEFORE_EXPIRY=10" in errors[0]
    assert "10.0-day" in errors[0]


# Lego's account directory =============================================================================================
def _unregistered_account(cert_dir: Path, host: str, email: str = "ops@postern.test", body: str | None = None) -> Path:
    """What a v5 lego run leaves when it fails after saving its key but before registering."""
    account = cert_dir / "lego" / "accounts" / host / email
    account.mkdir(parents=True)
    (account / "account.json").write_text(body if body is not None else json.dumps({"registration": None}))
    (account / f"{email}.key").write_bytes(ACCOUNT_KEY)
    return account


def _issuing(settings: CertSettings, state: str = "ISSUING") -> cert_state.CertState:
    return cert_state.CertState(state=state, acme_directory=settings.cert_acme_directory)


# lego's stdout when the CA does not know the account key.
ACCOUNT_DOES_NOT_EXIST = (
    'ERROR Error error="registration: resolve account by key: unable to communicate with the API server: '
    "acme: error: 400 :: urn:ietf:params:acme:error:accountDoesNotExist :: unable to find existing account for "
    'only-return-existing request"'
)
RATE_LIMITED = (
    'ERROR Error error="obtain certificate: acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many '
    'certificates (5) already issued"'
)


def _fail_lego(lego_mock: MagicMock, output: str = ACCOUNT_DOES_NOT_EXIST) -> None:
    lego_mock.issue_or_renew.side_effect = subprocess.CalledProcessError(1, "lego", output=output)


@pytest.mark.parametrize("state_name", ["ISSUING", "RENEWING"])
def test_unregistered_lego_account_is_kept_for_lego_to_recover(prod_settings, lego_mock, now, cert_dir, state_name):
    """lego v5 recovers a key-only account from the CA (ResolveAccountByKey), so it is not discarded up front."""
    account = _unregistered_account(cert_dir, "acme-v02.api.letsencrypt.org")
    present = _record_account_presence_at_run(lego_mock, account)
    _advance(_issuing(prod_settings, state_name), prod_settings, lego_mock, now)
    assert present == [True]


@pytest.mark.parametrize("state_name", ["ISSUING", "RENEWING"])
def test_lego_account_is_discarded_after_a_run_that_says_the_account_does_not_exist(
    prod_settings, lego_mock, now, cert_dir, state_name
):
    """The CA has no such account (RFC 8555 accountDoesNotExist), so the next tick must register afresh."""
    account = _unregistered_account(cert_dir, "acme-v02.api.letsencrypt.org")
    _fail_lego(lego_mock)
    next_state = _advance(_issuing(prod_settings, state_name), prod_settings, lego_mock, now)
    assert not account.exists()
    assert next_state.consecutive_failures == 1


def test_registered_lego_account_the_ca_has_lost_is_discarded(prod_settings, lego_mock, now, cert_dir):
    account = _register_account(cert_dir, PROD, "ops@postern.test")
    _fail_lego(lego_mock)
    _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert not account.exists()


@pytest.mark.parametrize("output", [RATE_LIMITED, "", 'ERROR Error error="registration: dial tcp: i/o timeout"'])
def test_unregistered_lego_account_is_kept_after_any_other_failure(prod_settings, lego_mock, now, cert_dir, output):
    """lego may still recover the account by its key; only the CA's own answer says it cannot."""
    account = _unregistered_account(cert_dir, "acme-v02.api.letsencrypt.org")
    _fail_lego(lego_mock, output)
    _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert account.exists()


def test_unreadable_lego_account_file_is_discarded_after_any_failed_run(prod_settings, lego_mock, now, cert_dir):
    """lego cannot load it at all, so no run can recover it."""
    account = _unregistered_account(cert_dir, "acme-v02.api.letsencrypt.org", body='{"id": "ops@po')
    _fail_lego(lego_mock, RATE_LIMITED)
    _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert not account.exists()


def test_unloadable_lego_account_key_discards_the_account_after_any_failed_run(prod_settings, lego_mock, now, cert_dir):
    """A truncated `<email>.key` beside a readable `account.json` makes lego fail before it reaches the CA."""
    account = _register_account(cert_dir, PROD, "ops@postern.test")
    (account / "ops@postern.test.key").write_text("-----BEGIN RSA PRIVATE KEY-----" + chr(10) + "AAAA")
    _fail_lego(lego_mock, RATE_LIMITED)
    _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert not account.exists()


def test_an_account_file_that_cannot_be_read_is_discarded_and_the_failure_recorded(
    prod_settings, lego_mock, now, cert_dir
):
    """Any OSError, not only a missing file: the attempt is recorded and nothing escapes the tick."""
    account = cert_dir / "lego" / "accounts" / "acme-v02.api.letsencrypt.org" / "ops@postern.test"
    (account / "account.json").mkdir(parents=True)
    _fail_lego(lego_mock, RATE_LIMITED)
    next_state = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert next_state.consecutive_failures == 1
    assert not account.exists()


def test_a_run_that_discards_the_account_does_not_arm_the_24h_guard(prod_settings, lego_mock, now, cert_dir):
    """An account the CA never had cannot have placed an order, so the next tick retries at once."""
    _unregistered_account(cert_dir, "acme-v02.api.letsencrypt.org")
    working_lego = lego_mock.issue_or_renew.side_effect
    _fail_lego(lego_mock)
    state = _issuing(prod_settings)
    failed = _advance(state, prod_settings, lego_mock, now)
    assert failed.last_issued_by_directory == {}
    lego_mock.issue_or_renew.reset_mock()
    lego_mock.issue_or_renew.side_effect = working_lego
    _advance(failed, prod_settings, lego_mock, now + dt.timedelta(hours=1))
    lego_mock.issue_or_renew.assert_called_once()


def test_a_failed_run_that_keeps_the_account_arms_the_24h_guard(prod_settings, lego_mock, now, cert_dir):
    _register_account(cert_dir, PROD, "ops@postern.test")
    _fail_lego(lego_mock, RATE_LIMITED)
    failed = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert failed.last_issued_by_directory == {PROD: now.isoformat()}


def test_registered_lego_account_is_kept_after_a_failed_run(prod_settings, lego_mock, now, cert_dir):
    """A failure at the CA (rate limit, DNS-01) says nothing about an account that is registered."""
    account = _register_account(cert_dir, PROD, "ops@postern.test")
    (account / "ops@postern.test.key").write_bytes(ACCOUNT_KEY)
    present = _record_account_presence_at_run(lego_mock, account, fail=True)
    _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert present == [True]
    assert (account / "ops@postern.test.key").read_bytes() == ACCOUNT_KEY


def test_unregistered_lego_account_is_kept_after_a_successful_run(prod_settings, lego_mock, now, cert_dir):
    account = _unregistered_account(cert_dir, "acme-v02.api.letsencrypt.org")
    real_issue = lego_mock.issue_or_renew.side_effect

    def run(*, settings, force):
        output = real_issue(settings=settings, force=force)
        (account / "account.json").write_text(json.dumps({"registration": None}))
        return output

    lego_mock.issue_or_renew.side_effect = run
    next_state = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert next_state.state == "ISSUED_PENDING_INSTALL"
    assert account.exists()


def test_missing_lego_account_is_a_no_op(prod_settings, lego_mock, now):
    _fail_lego(lego_mock)
    next_state = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    lego_mock.issue_or_renew.assert_called_once()
    assert next_state.consecutive_failures == 1


def test_account_path_of_a_host_with_a_port_replaces_the_colon(prod_settings, lego_mock, now, cert_dir):
    """Lego writes `accounts/<host>_<port>/<email>`; looking under `<host>:<port>` would never find it."""
    prod_settings.cert_acme_directory = "https://ca.internal:9000/acme/dir"
    account = _unregistered_account(cert_dir, "ca.internal_9000")
    _fail_lego(lego_mock)
    _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert not account.exists()


def test_account_path_ignores_userinfo_in_the_directory_url(prod_settings, lego_mock, now, cert_dir):
    """Lego names the account directory by the URL's host and port, without `user:pass@`."""
    prod_settings.cert_acme_directory = "https://user:pass@ca.internal:9000/acme/dir"
    account = _unregistered_account(cert_dir, "ca.internal_9000")
    _fail_lego(lego_mock)
    _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert not account.exists()


def test_cleanup_failure_does_not_abort_the_tick(prod_settings, lego_mock, now, cert_dir, monkeypatch, caplog):
    _unregistered_account(cert_dir, "acme-v02.api.letsencrypt.org")
    _fail_lego(lego_mock)

    def boom(path, *args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(cert_driver.shutil, "rmtree", boom)
    next_state = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert next_state.consecutive_failures == 1
    assert "read-only file system" in caplog.text


STEP_CA_OLD = "https://ca.internal/acme/old/directory"
STEP_CA_NEW = "https://ca.internal/acme/new/directory"


def _record_account_presence_at_run(lego_mock: MagicMock, account: Path, *, fail: bool = False) -> list[bool]:
    """Record whether `account` exists when Lego runs; with `fail`, Lego registers its account and then fails."""
    present: list[bool] = []
    if not hasattr(lego_mock, "base_issue"):
        lego_mock.base_issue = lego_mock.issue_or_renew.side_effect
    real_issue = lego_mock.base_issue

    def run(*, settings, force):
        present.append(account.exists())
        output = real_issue(settings=settings, force=force)
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
        last_attempt_directory=STEP_CA_OLD,
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
        last_attempt_directory=STEP_CA_NEW,
    )
    account = _register_account(cert_dir, STEP_CA_NEW, "ops@postern.test")
    present = _record_account_presence_at_run(lego_mock, account)
    _advance(state, prod_settings, lego_mock, now)
    assert present == [True]


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


def test_failed_account_reset_aborts_the_tick_and_is_retried(prod_settings, lego_mock, now, cert_dir, monkeypatch):
    """A reset that fails must not record the attempt under the new directory, or the next tick would skip the reset."""
    account = _register_account(cert_dir, STEP_CA_OLD, "ops@postern.test")
    state = _step_ca_switch(prod_settings, now)
    real_rmtree = shutil.rmtree

    def broken(*args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(cert_driver.shutil, "rmtree", broken)
    after = _advance(state, prod_settings, lego_mock, now)
    assert after == state
    lego_mock.issue_or_renew.assert_not_called()

    monkeypatch.setattr(cert_driver.shutil, "rmtree", real_rmtree)
    registered_at_run = _record_account_presence_at_run(lego_mock, account)
    _advance(after, prod_settings, lego_mock, now + dt.timedelta(minutes=1))
    assert registered_at_run == [False]


def test_account_reset_log_names_the_directory(prod_settings, lego_mock, now, cert_dir, caplog):
    caplog.set_level("INFO", logger=cert_driver.logger.name)
    _register_account(cert_dir, STEP_CA_OLD, "ops@postern.test")
    _advance(_step_ca_switch(prod_settings, now), prod_settings, lego_mock, now)
    assert "ACME directory changed; resetting lego account dir" in caplog.text


# Lego's stored certificate ============================================================================================
def _lego_certificates(cert_dir: Path) -> Path:
    return cert_dir / "lego" / "certificates"


def _stored_lego_set(cert_dir: Path, domain: str, *, resource: str | None = None, **pki) -> LegoOutput:
    """lego's certificate directory as an earlier run left it: a loadable set, with the given resource file."""
    from tests.e2e._certs import generate_test_pki
    certs = _lego_certificates(cert_dir)
    generate_test_pki(cert_dir / "stored-pki", hostname=domain, **pki)
    output = LegoOutput(
        fullchain=certs / f"{domain}.crt", privkey=certs / f"{domain}.key", chain=certs / f"{domain}.issuer.crt"
    )
    for target, name in ((output.fullchain, "fullchain.pem"), (output.privkey, "privkey.pem"),
                         (output.chain, "chain.pem")):
        target.write_bytes((cert_dir / "stored-pki" / name).read_bytes())
    (certs /
     f"{domain}.json").write_text(json.dumps({"id": domain, "domains": [domain]}) if resource is None else resource)
    return output


@pytest.mark.parametrize("state_name", ["ISSUING", "RENEWING"])
def test_an_unloadable_stored_certificate_is_discarded_after_a_failed_run_and_the_guard_stays_clear(
    prod_settings, lego_mock, now, cert_dir, state_name
):
    """A truncated resource file fails every `lego run`, forced or not, and fails it before any order is placed."""
    _stored_lego_set(cert_dir, prod_settings.domain, resource='{"id": "postern.test", "domains": ["postern.te')
    _fail_lego(lego_mock, RATE_LIMITED)
    state = dataclasses.replace(
        _issuing(prod_settings, state_name), last_issued_by_directory={PROD: "2000-01-01T00:00:00+00:00"}
    )
    failed = _advance(state, prod_settings, lego_mock, now)
    assert list(_lego_certificates(cert_dir).glob(f"{prod_settings.domain}*")) == []
    assert failed.consecutive_failures == 1
    assert failed.last_issued_by_directory == {PROD: "2000-01-01T00:00:00+00:00"}


def test_a_loadable_stored_certificate_is_kept_after_a_failed_run(prod_settings, lego_mock, now, cert_dir):
    _stored_lego_set(cert_dir, prod_settings.domain, resource='{"id": "postern.test"}')
    _fail_lego(lego_mock, RATE_LIMITED)
    failed = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert len(list(_lego_certificates(cert_dir).glob(f"{prod_settings.domain}*"))) == 4
    assert failed.last_issued_by_directory == {PROD: now.isoformat()}


def test_an_unparseable_stored_certificate_is_discarded_even_when_the_account_is_too(
    prod_settings, lego_mock, now, cert_dir
):
    _stored_lego_set(cert_dir, prod_settings.domain, resource='{"id": "postern.test"}')
    (_lego_certificates(cert_dir) /
     f"{prod_settings.domain}.crt").write_text("-----BEGIN CERTIFICATE-----" + chr(10) + "AAAA")
    account = _unregistered_account(cert_dir, "acme-v02.api.letsencrypt.org")
    _fail_lego(lego_mock)
    failed = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert list(_lego_certificates(cert_dir).glob(f"{prod_settings.domain}*")) == []
    assert not account.exists()
    assert failed.last_issued_by_directory == {}


def _lego_breaks_then_fails(lego_mock: MagicMock, breaks) -> None:
    """A lego run that the CA answered (it issued), whose save then left a file lego cannot load, and that fails."""

    def run(*, settings, force):
        breaks()
        raise subprocess.CalledProcessError(1, "lego", output=RATE_LIMITED)

    lego_mock.issue_or_renew.side_effect = run


def test_an_account_a_run_broke_is_discarded_but_the_run_still_arms_the_24h_guard(
    prod_settings, lego_mock, now, cert_dir
):
    """The account loaded when the run began, so the CA may have issued before the save broke it."""
    account = _register_account(cert_dir, PROD, "ops@postern.test")
    (account / "ops@postern.test.key").write_bytes(ACCOUNT_KEY)
    _lego_breaks_then_fails(lego_mock, lambda: (account / "account.json").write_text('{"id": "ops@po'))
    failed = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert not account.exists()
    assert failed.last_issued_by_directory == {PROD: now.isoformat()}


def test_a_certificate_a_run_broke_is_discarded_but_the_run_still_arms_the_24h_guard(
    prod_settings, lego_mock, now, cert_dir
):
    _stored_lego_set(cert_dir, prod_settings.domain)
    resource = _lego_certificates(cert_dir) / f"{prod_settings.domain}.json"
    _lego_breaks_then_fails(lego_mock, lambda: resource.write_text('{"id": "postern.test", "domains": ["postern.te'))
    failed = _advance(_issuing(prod_settings), prod_settings, lego_mock, now)
    assert list(_lego_certificates(cert_dir).glob(f"{prod_settings.domain}*")) == []
    assert failed.last_issued_by_directory == {PROD: now.isoformat()}


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
