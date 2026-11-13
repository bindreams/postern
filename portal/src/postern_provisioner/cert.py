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
from dataclasses import dataclass, field, replace
from pathlib import Path
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
        return _advance_failed(state, settings, now, cert_dir)

    directory_drift = _directory_drift(state, settings)

    # NO_CERT: adopt existing valid cert OR begin issuance -------------------------------------------------------------
    if state.state == "NO_CERT":
        adopted = _try_adopt_existing(cert_dir, settings.domain, expected, now)
        if adopted is not None:
            logger.info("cert: adopting existing on-disk cert (no state.json)")
            return adopted
        return _begin_issuance(state, "ISSUING", now)

    # INSTALLED: check whether to renew --------------------------------------------------------------------------------
    if state.state == "INSTALLED":
        # Every path but expiry takes ISSUING (`lego run`); see `renewable` below for why not `renew`.
        target: cert_state.State = "ISSUING"
        live = _read_live_cert(cert_dir, settings.domain)
        if directory_drift:
            reason = "ACME directory changed"
        elif live is None or not live.sans_match(expected):
            # SAN list invariant: defends CT-leak hygiene.
            reason = "SAN mismatch or missing on-disk cert"
        elif trigger_present:
            reason = ".renew-cert trigger present"
        else:
            days_left = live.days_until_expiry(now=now)
            if days_left >= settings.cert_renewal_days_before_expiry:
                return state
            reason = f"{days_left:.1f} days to expiry < threshold"
            target = "RENEWING"
        # Checked here, not after leaving INSTALLED: otherwise every tick of an active guard would flip the state
        # to ISSUING and back, and the healthcheck with it.
        if not _rate_limit_guard_clear(state, settings, now):
            # INSTALLED reports a cert on disk: with none, ISSUING (whose deferral below logs and holds it) stands in.
            if live is None:
                return _begin_issuance(state, "ISSUING", now)
            if trigger_present:
                logger.warning(
                    "cert: 24h rate-limit guard active; the .renew-cert request was dropped. "
                    "Set CERT_FORCE_REISSUE=true and run `postern cert renew` again to override."
                )
            else:
                logger.warning(
                    "cert: 24h rate-limit guard active; staying INSTALLED. Set CERT_FORCE_REISSUE=true to override."
                )
            return state
        logger.info("cert: %s; transitioning to %s", reason, target)
        if trigger_present and directory_drift:
            logger.info("cert: .renew-cert trigger is served by this reissue")
        return _begin_issuance(state, target, now)

    # ISSUING / RENEWING: actually call Lego, then transition to PENDING_INSTALL.
    if state.state in ("ISSUING", "RENEWING"):
        if not _rate_limit_guard_clear(state, settings, now):
            logger.warning(
                "cert: 24h rate-limit guard active; deferring %s. Set CERT_FORCE_REISSUE=true to override.",
                state.state,
            )
            # Back to INSTALLED only with a cert to serve: INSTALLED with none would open the healthcheck gate.
            if _read_live_cert(cert_dir, settings.domain) is None:
                return state
            return replace(state, state="INSTALLED")

        # Lego keys an account by directory host and email, so a directory on a host shared with the previous one would
        # reuse an account registered with the other URL: either change discards every account.
        email_changed = bool(state.acme_account_email) and state.acme_account_email != settings.cert_acme_email
        # Failures counted under another directory say nothing about this one.
        under_new_directory = _latest_attempt_directory(state) not in ("", settings.cert_acme_directory)
        if email_changed or under_new_directory:
            changed = [
                n for n, hit in (("ACME account email", email_changed), ("ACME directory", under_new_directory)) if hit
            ]
            # Recording the attempt over a failed reset would key the next tick's reset off the new directory and skip it.
            if not _reset_lego_account_dir(" and ".join(changed)):
                return state

        # `renew` is a no-op on a fresh cert and fatal without a registered account or a cert under Lego's path (an
        # adopted BYO cert has neither), so it is only for a due cert Lego itself issued.
        renewable = _lego_account_registered(settings) and _lego_cert_exists(settings)
        action = "run" if state.state == "ISSUING" or directory_drift or not renewable else "renew"
        # Record the attempt BEFORE Lego: defends rate limits even on post-issuance failures (rename, etc.).
        attempt_state = replace(
            state,
            last_attempt_iso=now.isoformat(),
            last_issued_by_directory={**state.last_issued_by_directory, settings.cert_acme_directory: now.isoformat()},
            consecutive_failures=0 if under_new_directory else state.consecutive_failures,
            acme_account_email=settings.cert_acme_email,
        )
        try:
            output = lego.issue_or_renew(settings=settings, action=action)
        except subprocess.CalledProcessError as e:
            logger.error("cert: lego failed: %s", e)
            return _failed_or_increment(attempt_state, settings, now)

        return replace(
            attempt_state,
            state="ISSUED_PENDING_INSTALL",
            consecutive_failures=0,
            pending_cert_paths={
                "fullchain": str(output.fullchain),
                "privkey": str(output.privkey),
                "chain": str(output.chain),
            },
            pending_acme_directory=settings.cert_acme_directory,
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

        installed_cert = _read_live_cert(cert_dir, settings.domain)
        return replace(
            state,
            state="INSTALLED",
            consecutive_failures=0,
            # Not settings: the config may have changed since Lego ran.
            acme_directory=state.pending_acme_directory or settings.cert_acme_directory,
            pending_cert_paths={},
            pending_acme_directory="",
            not_after_iso=installed_cert.not_after.isoformat() if installed_cert else None,
            sans=list(installed_cert.sans) if installed_cert else [],
        )

    return state


# Helpers ==============================================================================================================
def _read_cert_or_none(path: Path) -> cert_inspect.CertInfo | None:
    if not path.exists():
        return None
    try:
        return cert_inspect.read_cert(path)
    except (OSError, ValueError) as e:
        logger.warning("cert: could not parse %s: %s", path, e)
        return None


def _read_live_cert(cert_dir: Path, domain: str) -> cert_inspect.CertInfo | None:
    return _read_cert_or_none(cert_dir / "live" / domain / "fullchain.pem")


def _try_adopt_existing(
    cert_dir: Path, domain: str, expected: set[str], now: dt.datetime
) -> cert_state.CertState | None:
    """If an on-disk cert exists with valid SANs and is currently in-validity,
    adopt to INSTALLED without calling Lego. Defends against accidental volume
    re-creation triggering wasteful re-issuance."""
    info = _read_live_cert(cert_dir, domain)
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
    """Time of the last Lego attempt under `directory`."""
    iso = state.last_issued_by_directory.get(directory)
    return dt.datetime.fromisoformat(iso) if iso else None


def _latest_attempt_directory(state: cert_state.CertState) -> str:
    """Directory of the most recent Lego attempt ('' if none)."""
    by_directory = state.last_issued_by_directory
    return max(by_directory, key=lambda d: dt.datetime.fromisoformat(by_directory[d]), default="")


def _account_host(directory: str) -> str:
    """Lego keeps accounts at `<path>/accounts/<url.Host, ':' -> '_'>/<email>/account.json`; Go's `url.Host` is the
    authority without userinfo, with the port and IPv6 brackets as written (lego v4.35.2, cmd/accounts_storage.go)."""
    return urlparse(directory).netloc.rpartition("@")[2].replace(":", "_")


def _lego_server_dir(settings: CertSettings) -> Path:
    return LEGO_PATH / "accounts" / _account_host(settings.cert_acme_directory)


def _lego_account_registered(settings: CertSettings) -> bool:
    return (_lego_server_dir(settings) / settings.cert_acme_email / "account.json").exists()


def _lego_cert_exists(settings: CertSettings) -> bool:
    return (LEGO_PATH / "certificates" / f"{settings.domain}.crt").exists()


def _rate_limit_guard_clear(state: cert_state.CertState, settings: CertSettings, now: dt.datetime) -> bool:
    if settings.cert_force_reissue:
        return True
    # Let's Encrypt limits are per directory: an issuance under another one (staging) does not count here.
    last = _issued_at(state, settings.cert_acme_directory)
    return last is None or (now - last).total_seconds() >= RATE_LIMIT_GUARD_SECONDS


def _advance_failed(
    state: cert_state.CertState, settings: CertSettings, now: dt.datetime, cert_dir: Path
) -> cert_state.CertState:
    """After the hold-off, retry the prior state. When the failures were under another directory than the configured
    one, the hold-off protects nothing: re-evaluate from INSTALLED (drift, SAN and expiry checks decide), or, with no
    cert installed to re-evaluate, issue."""
    attempted = _latest_attempt_directory(state)
    if attempted not in ("", settings.cert_acme_directory):
        logger.info("cert: FAILED under another ACME directory; skipping hold-off")
        installed = _read_live_cert(cert_dir, settings.domain) is not None
        retry = "INSTALLED" if installed else "ISSUING"
        return replace(state, state=retry, consecutive_failures=0, last_failed_state=None)
    if state.last_attempt_iso is None:
        return state
    last = dt.datetime.fromisoformat(state.last_attempt_iso)
    if (now - last).total_seconds() < FAILED_HOLDOFF_SECONDS:
        return state
    logger.info("cert: FAILED hold-off elapsed; retrying %s", state.last_failed_state or "ISSUING")
    return replace(state, state=state.last_failed_state or "ISSUING", consecutive_failures=0, last_failed_state=None)


def _begin_issuance(state: cert_state.CertState, target_state: str, now: dt.datetime) -> cert_state.CertState:
    return replace(state, state=target_state, last_attempt_iso=now.isoformat())


def _failed_or_increment(state: cert_state.CertState, settings: CertSettings, now: dt.datetime) -> cert_state.CertState:
    failures = state.consecutive_failures + 1
    if failures >= MAX_CONSECUTIVE_FAILURES:
        logger.error("cert: %d consecutive failures; transitioning to FAILED", failures)
        return replace(
            state,
            state="FAILED",
            consecutive_failures=failures,
            last_failed_state=state.state,
            last_attempt_iso=now.isoformat(),
        )
    return replace(state, consecutive_failures=failures, last_attempt_iso=now.isoformat())


def _reset_lego_account_dir(changed: str) -> bool:
    """Discard every Lego account; False (logged) when that failed, so the caller retries on its next tick."""
    accounts = LEGO_PATH / "accounts"
    if not accounts.exists():
        return True
    logger.info("cert: %s changed; resetting lego account dir", changed)
    try:
        shutil.rmtree(accounts)
    except OSError as e:
        logger.error("cert: could not remove %s: %s; will retry on the next tick", accounts, e)
        return False
    return True
