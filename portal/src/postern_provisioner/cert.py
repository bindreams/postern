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
from urllib.parse import urlparse

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
        return _advance_failed(state, settings, now)

    # acme_directory is where the installed cert came from; it only moves once the install under the new directory completes.
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
        # Every path but expiry takes ISSUING (`lego run`): `renew` is fatal without an account registered under the
        # configured directory, and a no-op on a cert that is not yet due. Drift is checked first.
        if directory_drift or _stuck_without_account(settings):
            logger.info("cert: ACME directory changed or has no Lego account; transitioning to ISSUING")
            if trigger_present:
                logger.info("cert: .renew-cert trigger is served by this reissue")
            return _begin_issuance(state, settings, "ISSUING", now)
        # SAN list invariant: defends CT-leak hygiene.
        on_disk = _read_cert_or_none(cert_dir / "live" / settings.domain / "fullchain.pem")
        if on_disk is None or not on_disk.sans_match(expected):
            logger.info("cert: SAN mismatch or missing on-disk cert; transitioning to ISSUING")
            return _begin_issuance(state, settings, "ISSUING", now)
        if trigger_present:
            logger.info("cert: .renew-cert trigger present; transitioning to ISSUING")
            return _begin_issuance(state, settings, "ISSUING", now)
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

        # Lego keys accounts by directory host and email, so a directory switch needs no reset: `run` registers the
        # new one. An email change is the only reset; it lands in the unregistered case below.
        if bool(state.acme_account_email) and state.acme_account_email != settings.cert_acme_email:
            _reset_lego_account_dir()

        # `renew` is a no-op on a fresh cert and fatal without a registered account, so it is only for a due cert.
        action = "run" if state.state == "ISSUING" or directory_drift or not _lego_account_registered(
            settings
        ) else "renew"
        # Failures counted under another directory say nothing about this one.
        under_new_directory = _latest_attempt_directory(state) not in ("", settings.cert_acme_directory)
        # Record last_issued_iso BEFORE Lego: defends rate limits even on
        # post-issuance failures (rename, etc.).
        attempt_state = cert_state.CertState(
            **{
                **_state_dict(state),
                "last_issued_iso": now.isoformat(),
                "last_attempt_iso": now.isoformat(),
                "last_issued_by_directory": {
                    **state.last_issued_by_directory, settings.cert_acme_directory: now.isoformat()
                },
                "consecutive_failures": 0 if under_new_directory else state.consecutive_failures,
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
                # The directory the cert was issued under, which a config change since may no longer be.
                "acme_directory": _latest_attempt_directory(state) or settings.cert_acme_directory,
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


def _issued_at(state: cert_state.CertState, directory: str) -> dt.datetime | None:
    """Time of the last Lego attempt under `directory`. Pre-upgrade state has only `last_issued_iso`;
    `acme_directory` was recorded with it and says which directory it was (empty: assume this one)."""
    if state.last_issued_by_directory:
        iso = state.last_issued_by_directory.get(directory)
    elif state.last_issued_iso and (state.acme_directory or directory) == directory:
        iso = state.last_issued_iso
    else:
        iso = None
    return dt.datetime.fromisoformat(iso) if iso else None


def _latest_attempt_directory(state: cert_state.CertState) -> str:
    """Directory of the most recent Lego attempt ('' if none)."""
    by_directory = state.last_issued_by_directory
    if not by_directory:
        return state.acme_directory
    return max(by_directory, key=lambda d: dt.datetime.fromisoformat(by_directory[d]))


def _lego_server_dir(settings: CertSettings) -> Path:
    """Lego keeps accounts at `<path>/accounts/<server host, ':' -> '_'>/<email>/account.json`."""
    host = urlparse(settings.cert_acme_directory).netloc.replace(":", "_")
    return LEGO_PATH / "accounts" / host


def _lego_account_registered(settings: CertSettings) -> bool:
    return (_lego_server_dir(settings) / settings.cert_acme_email / "account.json").exists()


def _stuck_without_account(settings: CertSettings) -> bool:
    """Lego issued a cert here but never registered with the configured directory (under any email): the
    installed cert predates the directory, whatever `acme_directory` says. A deployment stranded by the
    earlier `renew`-on-switch bug looks like this. A BYO cert adopted without ever running Lego does not."""
    if not (LEGO_PATH / "certificates" / f"{settings.domain}.crt").exists():
        return False
    return not any(_lego_server_dir(settings).glob("*/account.json"))


def _rate_limit_guard_clear(state: cert_state.CertState, settings: CertSettings, now: dt.datetime) -> bool:
    if settings.cert_force_reissue:
        return True
    # Let's Encrypt limits are per directory: an issuance under another one (staging) does not count here.
    last = _issued_at(state, settings.cert_acme_directory)
    return last is None or (now - last).total_seconds() >= RATE_LIMIT_GUARD_SECONDS


def _advance_failed(state: cert_state.CertState, settings: CertSettings, now: dt.datetime) -> cert_state.CertState:
    """After the hold-off, retry the prior state. When the failures were under another directory than the configured
    one, the hold-off protects nothing: re-evaluate from INSTALLED (drift, SAN and expiry checks decide)."""
    attempted = _latest_attempt_directory(state)
    if attempted not in ("", settings.cert_acme_directory):
        logger.info("cert: FAILED under another ACME directory; skipping hold-off")
        return _with(state, state="INSTALLED", consecutive_failures=0, last_failed_state=None)
    if state.last_attempt_iso is None:
        return state
    last = dt.datetime.fromisoformat(state.last_attempt_iso)
    if (now - last).total_seconds() < FAILED_HOLDOFF_SECONDS:
        return state
    logger.info("cert: FAILED hold-off elapsed; retrying %s", state.last_failed_state or "ISSUING")
    return _with(state, state=state.last_failed_state or "ISSUING", consecutive_failures=0, last_failed_state=None)


def _with(s: cert_state.CertState, **changes) -> cert_state.CertState:
    return cert_state.CertState(**{**_state_dict(s), **changes})


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
