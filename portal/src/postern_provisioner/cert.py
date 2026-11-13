"""Cert renewal state-machine driver -- ACME DNS-01 via Lego.

Symmetric with `provisioner/entrypoint.py`'s DKIM rotation loop. Public API:

    advance_cert_state(state, *, settings, lego, now) -> CertState
    run_cert_loop(domain, settings) -> NoReturn

Transitions are specified in postern.cert.state. The driver itself is a pure
function over (state, env, time) that returns the next state; the caller
persists it. This makes the state machine fully unit-testable with no real
filesystem or subprocess.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from postern.cert import inspect as cert_inspect
from postern.cert import state as cert_state

from . import install, lego_env

logger = logging.getLogger(__name__)

CERT_DIR = Path("/etc/letsencrypt")
LEGO_PATH = CERT_DIR / "lego"
LIVE_DIR = CERT_DIR / "live"
RATE_LIMIT_GUARD_SECONDS = 24 * 3600
MAX_CONSECUTIVE_FAILURES = 6
FAILED_HOLDOFF_SECONDS = 60 * 60  # 1 hour, matches TICK_SECONDS


# Settings shape (subset of portal settings; injected so this module
# does not import from postern.settings -- the provisioner image does
# not load the portal app config). =====================================================================================
@dataclass
class CertSettings:
    domain: str
    dns_provider: str
    cert_acme_email: str
    cert_acme_directory: str = "https://acme-v02.api.letsencrypt.org/directory"
    cert_renewal_days_before_expiry: int = 30
    cert_force_reissue: bool = False
    expected_sans: set[str] = field(default_factory=set)


def expected_sans_for(domain: str) -> set[str]:
    """Wildcard SAN list: <domain> + *.<domain>. The wildcard hides subdomain
    enumeration in Certificate Transparency logs -- adding more SANs would
    leak names and is rejected by `postern cert verify`."""
    return {domain, f"*.{domain}"}


# Lego invocation ======================================================================================================
@dataclass
class LegoOutput:
    """What Lego writes for a successful issuance."""
    fullchain: Path
    privkey: Path
    chain: Path


class LegoRunner:
    """subprocess.run wrapper, swappable in tests."""

    def __init__(self, *, env: dict[str, str] | None = None) -> None:
        self.env = env if env is not None else dict(os.environ)

    def issue_or_renew(self, *, settings: CertSettings, action: str) -> LegoOutput:
        """Run `lego ... run` (action='run') or `lego ... renew` (action='renew')."""
        cfg = lego_env.lego_config(settings.dns_provider, self.env)
        run_env = dict(self.env)
        run_env.update(cfg.env)
        cmd = [
            "lego",
            "--path",
            str(LEGO_PATH),
            "--email",
            settings.cert_acme_email,
            "--domains",
            settings.domain,
            "--domains",
            f"*.{settings.domain}",
            "--dns",
            cfg.dns_slug,
            "--server",
            settings.cert_acme_directory,
            "--key-type",
            "rsa2048",
            "--accept-tos",
        ]
        if action == "renew":
            cmd.extend(["renew", "--days", str(settings.cert_renewal_days_before_expiry)])
        else:
            cmd.append("run")
        logger.info("lego: invoking %s", action)
        subprocess.run(cmd, env=run_env, check=True)

        cert_dir = LEGO_PATH / "certificates"
        return LegoOutput(
            fullchain=cert_dir / f"{settings.domain}.crt",
            privkey=cert_dir / f"{settings.domain}.key",
            chain=cert_dir / f"{settings.domain}.issuer.crt",
        )


# State machine ========================================================================================================
def advance_cert_state(
    state: cert_state.CertState,
    *,
    settings: CertSettings,
    lego: LegoRunner,
    trigger_present: bool,
    now: dt.datetime | None = None,
    cert_dir: Path = CERT_DIR,
) -> cert_state.CertState:
    """One transition. Idempotent enough to retry on failure.

    Pure with respect to fs+subprocess: takes everything as parameters or
    via the injected `lego` runner. Easy to unit-test by patching `lego`.
    """
    if now is None:
        now = dt.datetime.now(tz=dt.timezone.utc)
    expected = settings.expected_sans or expected_sans_for(settings.domain)

    # FAILED handling: after the hold-off, retry the prior state -------------------------------------------------------
    if state.state == "FAILED":
        # The failures were under the old directory, so the hold-off protects nothing under the new one.
        switching = _directory_switch_pending(state, settings)
        if not switching:
            if state.last_attempt_iso is None:
                return state
            last = dt.datetime.fromisoformat(state.last_attempt_iso)
            if (now - last).total_seconds() < FAILED_HOLDOFF_SECONDS:
                return state
        retry_to = "ISSUING" if switching else (state.last_failed_state or "ISSUING")
        logger.info(
            "cert: FAILED hold-off %s; retrying %s", "skipped (ACME directory changed)" if switching else "elapsed",
            retry_to
        )
        return cert_state.CertState(
            **{
                **_state_dict(state),
                "state": retry_to,
                "consecutive_failures": 0,
                "last_failed_state": None,
            }
        )

    # acme_directory is where the on-disk cert came from; it only moves once Lego succeeds under the new directory.
    directory_drift = _directory_drift(state, settings)

    # NO_CERT: adopt existing valid cert OR begin issuance -------------------------------------------------------------
    if state.state == "NO_CERT":
        adopted = _try_adopt_existing(cert_dir, settings.domain, expected, now)
        if adopted is not None:
            logger.info("cert: adopting existing on-disk cert (no state.json)")
            return adopted
        return _begin_issuance(state, settings, "ISSUING", now)

    # INSTALLED: check whether to renew --------------------------------------------------------------------------------
    if state.state == "INSTALLED":
        # Checked first: `renew` needs an account registered under the new directory, so a switch must be `run`.
        if directory_drift:
            logger.info("cert: ACME directory changed; transitioning to ISSUING")
            return _begin_issuance(state, settings, "ISSUING", now)
        # SAN list invariant: defends CT-leak hygiene.
        on_disk = _read_cert_or_none(cert_dir / "live" / settings.domain / "fullchain.pem")
        if on_disk is None or not on_disk.sans_match(expected):
            logger.info("cert: SAN mismatch or missing on-disk cert; transitioning to RENEWING")
            return _begin_issuance(state, settings, "RENEWING", now)
        if trigger_present:
            logger.info("cert: .renew-cert trigger present; transitioning to RENEWING")
            return _begin_issuance(state, settings, "RENEWING", now)
        days_left = on_disk.days_until_expiry(now=now)
        if days_left < settings.cert_renewal_days_before_expiry:
            logger.info("cert: %.1f days to expiry < threshold; transitioning to RENEWING", days_left)
            return _begin_issuance(state, settings, "RENEWING", now)
        return state

    # ISSUING / RENEWING: actually call Lego, then transition to PENDING_INSTALL.
    if state.state in ("ISSUING", "RENEWING"):
        if not _rate_limit_guard_clear(state, settings, now):
            logger.warning(
                "cert: 24h rate-limit guard active; deferring %s. Set CERT_FORCE_REISSUE=true to override.",
                state.state,
            )
            return cert_state.CertState(**{**_state_dict(state), "state": "INSTALLED"})

        # Account-email mismatch or first attempt under a new ACME directory: clear Lego account dir before issuing
        # fresh. Later attempts under the new directory keep the registration the first one made.
        email_changed = bool(state.acme_account_email) and state.acme_account_email != settings.cert_acme_email
        if email_changed or _directory_switch_pending(state, settings):
            _reset_lego_account_dir()

        # While the on-disk cert predates the directory switch, `renew` would fail (no account) or no-op (cert still
        # fresh), so keep using `run` across retries.
        action = "run" if state.state == "ISSUING" or directory_drift else "renew"
        # Record last_issued_iso BEFORE Lego: defends rate limits even on
        # post-issuance failures (rename, etc.).
        attempt_state = cert_state.CertState(
            **{
                **_state_dict(state),
                "last_issued_iso": now.isoformat(),
                "last_attempt_iso": now.isoformat(),
                "last_issued_directory": settings.cert_acme_directory,
                "acme_account_email": settings.cert_acme_email,
            }
        )
        try:
            output = lego.issue_or_renew(settings=settings, action=action)
        except subprocess.CalledProcessError as e:
            logger.error("cert: lego failed: %s", e)
            return _failed_or_increment(attempt_state, settings, now)

        return cert_state.CertState(
            **{
                **_state_dict(attempt_state),
                "acme_directory": settings.cert_acme_directory,
                "state": "ISSUED_PENDING_INSTALL",
                "consecutive_failures": 0,
                "pending_cert_paths": {
                    "fullchain": str(output.fullchain),
                    "privkey": str(output.privkey),
                    "chain": str(output.chain),
                },
            }
        )

    # ISSUED_PENDING_INSTALL: copy via symlink-flip into live/<domain>/
    if state.state == "ISSUED_PENDING_INSTALL":
        try:
            paths = state.pending_cert_paths
            install.install_cert_triple(
                fullchain_src=Path(paths["fullchain"]),
                privkey_src=Path(paths["privkey"]),
                chain_src=Path(paths["chain"]),
                live_dir=cert_dir / "live",
                domain=settings.domain,
                now=now,
            )
            cert_state.trigger_mta_tls_reload()
        except (OSError, KeyError) as e:
            logger.error("cert: install step failed: %s", e)
            return _failed_or_increment(state, settings, now)

        installed_cert = _read_cert_or_none(cert_dir / "live" / settings.domain / "fullchain.pem")
        return cert_state.CertState(
            **{
                **_state_dict(state),
                "state": "INSTALLED",
                "consecutive_failures": 0,
                "pending_cert_paths": {},
                "not_after_iso": installed_cert.not_after.isoformat() if installed_cert else None,
                "sans": list(installed_cert.sans) if installed_cert else [],
            }
        )

    return state


# Helpers ==============================================================================================================
def _state_dict(s: cert_state.CertState) -> dict:
    """Shallow copy of CertState fields for use in {**dict, ...} updates."""
    return {f: getattr(s, f) for f in cert_state.CertState.__dataclass_fields__}


def _read_cert_or_none(path: Path) -> cert_inspect.CertInfo | None:
    if not path.exists():
        return None
    try:
        return cert_inspect.read_cert(path)
    except (OSError, ValueError) as e:
        logger.warning("cert: could not parse %s: %s", path, e)
        return None


def _try_adopt_existing(
    cert_dir: Path, domain: str, expected: set[str], now: dt.datetime
) -> cert_state.CertState | None:
    """If an on-disk cert exists with valid SANs and is currently in-validity,
    adopt to INSTALLED without calling Lego. Defends against accidental volume
    re-creation triggering wasteful re-issuance."""
    info = _read_cert_or_none(cert_dir / "live" / domain / "fullchain.pem")
    if info is None or not info.sans_match(expected):
        return None
    if not (info.not_before <= now <= info.not_after):
        return None
    return cert_state.CertState(
        state="INSTALLED",
        not_after_iso=info.not_after.isoformat(),
        sans=list(info.sans),
    )


def _directory_drift(state: cert_state.CertState, settings: CertSettings) -> bool:
    """The on-disk cert was issued under a different ACME directory than the one configured."""
    return bool(state.acme_directory) and state.acme_directory != settings.cert_acme_directory


def _last_issued_elsewhere(state: cert_state.CertState, settings: CertSettings) -> bool:
    """The most recent Lego attempt was under another ACME directory. Pre-upgrade state has no
    `last_issued_directory`; `acme_directory` was then recorded at the same moment and stands in."""
    scope = state.last_issued_directory or state.acme_directory
    return bool(scope) and scope != settings.cert_acme_directory


def _directory_switch_pending(state: cert_state.CertState, settings: CertSettings) -> bool:
    """The directory changed and Lego has not been tried under the new one yet."""
    return _directory_drift(state, settings) and _last_issued_elsewhere(state, settings)


def _rate_limit_guard_clear(state: cert_state.CertState, settings: CertSettings, now: dt.datetime) -> bool:
    if settings.cert_force_reissue:
        return True
    if state.last_issued_iso is None:
        return True
    # Let's Encrypt limits are per directory: an issuance under another one (staging) does not count here.
    if _last_issued_elsewhere(state, settings):
        return True
    last = dt.datetime.fromisoformat(state.last_issued_iso)
    return (now - last).total_seconds() >= RATE_LIMIT_GUARD_SECONDS


def _begin_issuance(
    state: cert_state.CertState,
    settings: CertSettings,
    target_state: str,
    now: dt.datetime,
) -> cert_state.CertState:
    return cert_state.CertState(**{
        **_state_dict(state),
        "state": target_state,
        "last_attempt_iso": now.isoformat(),
    })


def _failed_or_increment(state: cert_state.CertState, settings: CertSettings, now: dt.datetime) -> cert_state.CertState:
    failures = state.consecutive_failures + 1
    if failures >= MAX_CONSECUTIVE_FAILURES:
        logger.error("cert: %d consecutive failures; transitioning to FAILED", failures)
        return cert_state.CertState(
            **{
                **_state_dict(state),
                "state": "FAILED",
                "consecutive_failures": failures,
                "last_failed_state": state.state,
                "last_attempt_iso": now.isoformat(),
            }
        )
    return cert_state.CertState(
        **{
            **_state_dict(state),
            "consecutive_failures": failures,
            "last_attempt_iso": now.isoformat(),
        }
    )


def _reset_lego_account_dir() -> None:
    accounts = LEGO_PATH / "accounts"
    if accounts.exists():
        logger.info("cert: ACME email or directory changed; resetting lego account dir")
        try:
            shutil.rmtree(accounts)
        except OSError as e:
            logger.warning("could not remove %s: %s", accounts, e)
