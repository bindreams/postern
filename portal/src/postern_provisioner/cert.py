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
import sys
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlparse

from postern.cert import inspect as cert_inspect
from postern.cert import state as cert_state

from . import install, lego_env, lego_store

logger = logging.getLogger(__name__)

CERT_DIR = Path("/etc/letsencrypt")
LEGO_PATH = CERT_DIR / "lego"
LIVE_DIR = CERT_DIR / "live"
# RFC 8555 §6.7 problem type lego prints when the CA does not know the account.
ACCOUNT_DOES_NOT_EXIST = "urn:ietf:params:acme:error:accountDoesNotExist"
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

    def __post_init__(self) -> None:
        cert_state.check_renewal_days(self.cert_renewal_days_before_expiry)


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

    def issue_or_renew(self, *, settings: CertSettings, force: bool) -> LegoOutput:
        """Run `lego run`: obtain a certificate, or replace the one lego already holds.

        lego v5 has no `renew`; `run` on an existing, not-yet-due certificate exits 0 and writes nothing. With `force`
        it passes `--renew-force`. Without, it passes Postern's own `--renew-days`: the caller found the live
        certificate due and knows that lego's own copy came from an attempt under this directory, so lego declines only
        a certificate newer than the live one (one an earlier run issued before its tick crashed): `advance_cert_state`
        tells that from a run that wrote nothing by the leaf's serial, and installs it once validated.
        `--force-cert-domains` keeps the SAN set exactly `--domains` (lego otherwise merges the old certificate's names
        in). ARI is off (`--ari-disable`) and so is the pre-renewal sleep (`--no-random-sleep`), so the due date is
        Postern's.
        """
        cfg = lego_env.lego_config(settings.dns_provider, self.env)
        run_env = dict(self.env)
        run_env.update(cfg.env)
        cmd = [
            "lego",
            "run",
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
            "--force-cert-domains",
            "--ari-disable",
            "--no-random-sleep",
        ]
        if force:
            cmd.append("--renew-force")
            logger.info("lego: invoking run --renew-force")
        else:
            cmd += ["--renew-days", str(settings.cert_renewal_days_before_expiry)]
            logger.info("lego: invoking run --renew-days %s", settings.cert_renewal_days_before_expiry)
        _run_lego(cmd, run_env)

        cert_dir = LEGO_PATH / "certificates"
        return LegoOutput(
            fullchain=cert_dir / f"{settings.domain}.crt",
            privkey=cert_dir / f"{settings.domain}.key",
            chain=cert_dir / f"{settings.domain}.issuer.crt",
        )


def _run_lego(cmd: list[str], env: dict[str, str]) -> None:
    """Run lego, relaying its output to ours as it arrives. Raises CalledProcessError, carrying that output, on a
    non-zero exit. lego logs to stdout, errors included."""
    seen: list[str] = []
    with subprocess.Popen(
        cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace"
    ) as lego:
        assert lego.stdout is not None
        for line in lego.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            seen.append(line)
    if lego.returncode:
        raise subprocess.CalledProcessError(lego.returncode, cmd, output="".join(seen))


# State machine ========================================================================================================
def _utc_now() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


def advance_cert_state(
    state: cert_state.CertState,
    *,
    settings: CertSettings,
    lego: LegoRunner,
    trigger_present: bool,
    now: dt.datetime | None = None,
    clock: Callable[[], dt.datetime] = _utc_now,
    cert_dir: Path = CERT_DIR,
) -> cert_state.CertState:
    """One transition. Idempotent enough to retry on failure.

    Pure with respect to fs+subprocess: takes everything as parameters or
    via the injected `lego` runner. Easy to unit-test by patching `lego`.

    The only source of time is `clock`: `now` (default: `clock()`) is when the tick began, and a run of lego reads
    `clock()` once more when it returns, since the certificate it issued may be valid only from then.
    """
    if now is None:
        now = clock()
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
        under_new_directory = state.last_attempt_directory not in ("", settings.cert_acme_directory)
        if email_changed or under_new_directory:
            changed = [
                n for n, hit in (("ACME account email", email_changed), ("ACME directory", under_new_directory)) if hit
            ]
            # Recording the attempt over a failed reset would key the next tick's reset off the new directory and skip it.
            if not _reset_lego_account_dir(" and ".join(changed)):
                return state

        # In memory before lego runs, persisted by the caller after it returns: a crash during a run loses the attempt,
        # so a forced run can cost one more issuance.
        attempt_state = replace(
            state,
            last_attempt_iso=now.isoformat(),
            last_attempt_directory=settings.cert_acme_directory,
            last_issued_by_directory={**state.last_issued_by_directory, settings.cert_acme_directory: now.isoformat()},
            consecutive_failures=0 if under_new_directory else state.consecutive_failures,
            acme_account_email=settings.cert_acme_email,
        )
        # Forced unless an attempt on record under this directory shows lego's certificate is ours.
        force = (
            state.state == "ISSUING" or email_changed or under_new_directory
            or settings.cert_acme_directory not in state.last_issued_by_directory
        )
        prior_serial = _stored_serial(settings.domain)
        unloadable_before = any(_unloadable_lego_state(settings))
        try:
            output = lego.issue_or_renew(settings=settings, force=force)
        except subprocess.CalledProcessError as e:
            logger.error("cert: lego failed: %s", e)
            failed_state = attempt_state
            if _discard_unusable_lego_state(settings, e.output or "", unloadable_before=unloadable_before):
                # State lego could not load when the run began, or an account the CA never knew, placed no order: leave
                # the 24h guard unarmed, so the next tick starts afresh at once.
                failed_state = replace(attempt_state, last_issued_by_directory=state.last_issued_by_directory)
            return _failed_or_increment(failed_state, settings, now)

        # The tick's `now` is when it began: a CA that does not backdate sets notBefore to the issuance time, after it.
        rejection = _reject_lego_output(
            output,
            expected,
            settings,
            forced=force,
            prior_serial=prior_serial,
            at=clock(),
        )
        if rejection:
            logger.error("cert: lego's output is not installable: %s", rejection.problem)
            if rejection.discard_files:
                _discard_lego_certificate(settings.domain)
            failed_state = attempt_state
            if not rejection.order_placed:
                failed_state = replace(attempt_state, last_issued_by_directory=state.last_issued_by_directory)
            return _failed_or_increment(failed_state, settings, now)

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


def _account_host(directory: str) -> str:
    """The `<host>` of lego's `<path>/accounts/<host>/<email>`: Go's `url.Host` (the authority without userinfo, port
    and IPv6 brackets as written) with `:` replaced by `_`."""
    return urlparse(directory).netloc.rpartition("@")[2].replace(":", "_")


def _lego_account_dir(settings: CertSettings) -> Path:
    return LEGO_PATH / "accounts" / _account_host(settings.cert_acme_directory) / settings.cert_acme_email


def _unloadable_lego_state(settings: CertSettings) -> tuple[bool, bool]:
    """Whether lego cannot load its account and its stored certificate, in that order (`lego_store`)."""
    return (
        lego_store.account_unloadable(_lego_account_dir(settings), settings.cert_acme_email),
        lego_store.certificate_unloadable(LEGO_PATH / "certificates", settings.domain),
    )


def _discard_unusable_lego_state(settings: CertSettings, lego_output: str, *, unloadable_before: bool) -> bool:
    """After a failed run, remove the lego account directory and the stored certificate that no later run can use (a
    removal failure is logged, not raised). True when the run cannot have placed an order, so the 24h guard stays
    clear: the CA answered `accountDoesNotExist`, or lego could not load its state when the run began
    (`unloadable_before`). State a run broke itself (its non-atomic save, after the CA issued) is removed all the same,
    but the guard stays armed.

    An account is unusable when the CA answered `accountDoesNotExist` (lego v5 looks an account up by its key and does
    not register anew; only a fresh directory registers) or when lego cannot load it; a certificate, when lego cannot
    load it. Any other failure keeps both: lego may still recover them."""
    account_dir = _lego_account_dir(settings)
    unknown_account = ACCOUNT_DOES_NOT_EXIST in lego_output
    account_unloadable, certificate_unloadable = _unloadable_lego_state(settings)
    if unknown_account or account_unloadable:
        try:
            logger.info("cert: removing lego account %s: no run can use it", account_dir)
            shutil.rmtree(account_dir)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.error("cert: could not remove lego account %s: %s", account_dir, e)
    if certificate_unloadable:
        logger.info("cert: removing lego's stored certificate for %s: no run can use it", settings.domain)
        _discard_lego_certificate(settings.domain)
    return unknown_account or unloadable_before


@dataclass(frozen=True)
class _Rejection:
    problem: str
    discard_files: bool  # lego's stored set is bad (or must not be handed back): delete it so the next run issues anew
    order_placed: bool  # whether this run asked the CA for a certificate: if so the 24h guard is armed


def _stored_serial(domain: str) -> int | None:
    """Serial of the leaf lego holds for `domain` before a run, None when there is none it can be read from."""
    info = _read_cert_or_none(LEGO_PATH / "certificates" / f"{domain}.crt")
    return info.serial if info else None


def _reject_lego_output(
    output: LegoOutput,
    expected: set[str],
    settings: CertSettings,
    *,
    forced: bool,
    prior_serial: int | None,
    at: dt.datetime,
) -> _Rejection | None:
    """Why the certificate lego left on disk must not be installed, or None.

    Lego exits 0 for a run that wrote nothing, and its non-atomic save (.crt, .issuer.crt, .key, then the resource file)
    can leave a new certificate beside the old key, so success says nothing about the files. On an unforced run (lego
    applies Postern's own threshold) the leaf's serial tells whether lego wrote anything: an unchanged serial means it
    declined and placed no order, and the certificate it handed back is installed only if it is not due, which is what
    an earlier run's certificate looks like after its tick crashed."""
    try:
        leaf = cert_inspect.read_cert(output.fullchain)
    except (OSError, ValueError) as e:
        # Whether lego wrote it is unknown: assume it did, which arms the guard.
        return _Rejection(f"cannot read the certificate: {e}", True, True)
    # An unforced run that left the serial alone wrote nothing: the CA was not asked, whatever else is wrong.
    order_placed = forced or leaf.serial != prior_serial
    try:
        key_matches = cert_inspect.key_matches_cert(output.fullchain, output.privkey)
        issued_by_chain = cert_inspect.issued_directly_by(output.fullchain, output.chain)
    except (OSError, ValueError) as e:
        return _Rejection(f"cannot read the key and issuer certificate: {e}", True, order_placed)
    if not key_matches:
        return _Rejection(f"the private key is not the key of {output.fullchain.name}", True, order_placed)
    if not issued_by_chain:
        return _Rejection(
            f"the issuer certificate {output.chain.name} did not issue {output.fullchain.name}", True, order_placed
        )
    if not leaf.sans_match(expected):
        return _Rejection(f"its names {sorted(leaf.sans)} are not {sorted(expected)}", True, order_placed)
    if at < leaf.not_before:
        return _Rejection(f"it is not valid until {leaf.not_before.isoformat()}", True, order_placed)
    if at > leaf.not_after:
        return _Rejection(f"it expired at {leaf.not_after.isoformat()}", True, order_placed)
    threshold = settings.cert_renewal_days_before_expiry
    days_left = leaf.days_until_expiry(now=at)
    if not order_placed and days_left < threshold:
        return _Rejection(
            f"it is the certificate lego already held, with {days_left:.1f} days left, which is due: "
            "lego declined to renew",
            True,
            order_placed,
        )
    lifetime_days = (leaf.not_after - leaf.not_before).total_seconds() / 86400.0
    if lifetime_days <= threshold:
        # Rejecting a valid certificate would leave the live one to expire; every certificate is due as soon as it is
        # issued, so the operator has to lower the threshold.
        logger.error(
            "cert: CERT_RENEWAL_DAYS_BEFORE_EXPIRY=%d is not shorter than the certificate's %.1f-day lifetime, so "
            "every certificate is due as soon as it is issued and is renewed whenever the 24h guard allows; lower it",
            threshold,
            lifetime_days,
        )
    return None


def _discard_lego_certificate(domain: str) -> None:
    """Delete lego's stored certificate for `domain` (a failure is logged, not raised).

    `lego run` renews only while the resource file (`<domain>.json`) exists, and otherwise obtains a new certificate
    whatever the renewal flags say. Removing it makes the next run a fresh
    issuance even when it is not forced, so the files just rejected cannot be handed back again. The resource file goes
    first and a failure stops the cleanup: lego holding a resource file with no certificate beside it cannot run."""
    for suffix in (".json", ".crt", ".issuer.crt", ".key"):
        path = LEGO_PATH / "certificates" / f"{domain}{suffix}"
        try:
            path.unlink(missing_ok=True)
        except OSError as e:
            logger.error("cert: could not remove %s: %s", path, e)
            return


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
    attempted = state.last_attempt_directory
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
