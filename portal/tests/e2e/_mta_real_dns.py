"""Per-run DKIM selectors for the ``e2e_mta_real`` suite, the ``postern-dns`` runner, and the sweep of records crashed
runs leave behind.

Every run publishes its own ``<selector>._domainkey.<MTA_TEST_DOMAIN>`` record, so concurrent runs share nothing on the
zone and need no CI concurrency group. A run's selector is
``postern-e2e-<GITHUB_REPOSITORY_ID>-<GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>`` in CI and ``postern-e2e-local-<random>``
elsewhere. The repository id keeps another repository's runs on the same zone out of this repository's sweep.

A run that dies before teardown (cancelled job, runner loss) leaves its record behind. The next CI run sweeps those: a
CI selector is stale when this repository's GitHub reports its run completed or no longer knows it (404), or when it is
an earlier attempt of this very run. Local selectors carry no run to ask about and are never swept; their owner
removes them.

``python -m tests.e2e._mta_real_dns`` is CI's sweep step.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager

import httpx

from ._helpers import E2E_PROVISIONER_IMAGE

logger = logging.getLogger(__name__)

SELECTOR_PREFIX = "postern-e2e-"
_CI_SELECTOR_RE = re.compile(rf"^{re.escape(SELECTOR_PREFIX)}(\d+)-(\d+)-(\d+)$")
_RUN_ENV = ("GITHUB_REPOSITORY_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")


# Selectors ============================================================================================================
class RunEnvError(Exception):
    """The CI run env (repository id, run id, attempt) is partly set or not numeric."""


def ci_run_ids(environ: Mapping[str, str]) -> tuple[int, int, int] | None:
    """``(repo_id, run_id, attempt)`` from the CI env, or None when none of it is set (a local run).

    Setting only some of it, or a non-numeric value, raises ``RunEnvError``: treating a half-set CI env as a local run
    would publish a record no sweep can attribute.
    """
    values = {name: environ.get(name, "").strip() for name in _RUN_ENV}
    if not any(values.values()):
        return None
    unset = [name for name, v in values.items() if not v]
    if unset:
        raise RunEnvError("CI run env must be all set or all unset; missing: " + ", ".join(unset))
    bad = [name for name, v in values.items() if not (v.isascii() and v.isdigit())]
    if bad:
        raise RunEnvError("CI run env must be numeric; not a number: " + ", ".join(bad))
    repo_id, run_id, attempt = (int(values[name]) for name in _RUN_ENV)
    return repo_id, run_id, attempt


def run_selector(environ: Mapping[str, str]) -> str:
    """The DKIM selector for this run (a valid DNS label: lowercase alphanumerics and hyphens)."""
    ids = ci_run_ids(environ)
    if ids is None:
        return f"{SELECTOR_PREFIX}local-{secrets.token_hex(4)}"
    return SELECTOR_PREFIX + "-".join(map(str, ids))


def parse_ci_selector(selector: str) -> tuple[int, int, int] | None:
    """``(repo_id, run_id, attempt)`` of a CI selector, or None for anything else (local selectors, foreign records)."""
    m = _CI_SELECTOR_RE.match(selector)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def stale_selectors(
    listing_json: str,
    domain: str,
    own_repo_id: int,
    own_run_id: int,
    own_attempt: int,
    run_is_finished: Callable[[int], bool],
) -> list[tuple[str, str]]:
    """``(fqdn, value)`` of every listed DKIM record that a crashed run of this repository left behind.

    ``listing_json`` is the output of ``postern-dns txt-list <domain> postern-e2e-``. Each ``fqdn`` is returned exactly
    as listed; ``txt-delete`` matches names case-insensitively. Records of other repositories are skipped: their run
    ids are not ours to look up.
    """
    suffix = f"._domainkey.{domain.lower().rstrip('.')}"
    stale: list[tuple[str, str]] = []
    for entry in json.loads(listing_json):
        fqdn: str = entry["fqdn"]
        lowered = fqdn.lower()
        if not lowered.endswith(suffix):
            continue
        parsed = parse_ci_selector(lowered.removesuffix(suffix))
        if parsed is None:
            continue
        repo_id, run_id, attempt = parsed
        if repo_id != own_repo_id:
            continue
        if run_id == own_run_id:
            # A re-run starts only after every earlier attempt has finished.
            is_stale = attempt < own_attempt
        else:
            is_stale = run_is_finished(run_id)
        if is_stale:
            stale.append((fqdn, entry["value"]))
    return stale


def warn(message: str) -> None:
    """Print a GitHub Actions ``::warning::`` annotation, so a failed best-effort step shows on the run page."""
    escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::warning::{escaped}", flush=True)


@contextmanager
def github_run_finished(repo: str, token: str, own_run_id: int) -> Iterator[Callable[[int], bool]]:
    """Yield a ``run_is_finished(run_id)`` backed by the GitHub API.

    True when ``repo`` reports the run completed or no longer knows it (404). Any other failure, including a reply that
    is not the expected JSON, counts as not finished: that run's record is left alone and the sweep carries on.

    A token that cannot see runs answers 404 for every id, which would read as "all finished". So the caller's own run,
    which certainly exists, is looked up first; anything but 200 raises ``RuntimeError``.
    """
    with httpx.Client(
        base_url="https://api.github.com",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=30.0,
    ) as client:
        own = client.get(f"/repos/{repo}/actions/runs/{own_run_id}")
        if own.status_code != 200:
            raise RuntimeError(
                f"GitHub answered {own.status_code} for this run ({own_run_id}); the token cannot see runs"
            )
        seen: dict[int, bool] = {}

        def run_is_finished(run_id: int) -> bool:
            if run_id not in seen:
                try:
                    resp = client.get(f"/repos/{repo}/actions/runs/{run_id}")
                    if resp.status_code == 404:
                        seen[run_id] = True
                    else:
                        resp.raise_for_status()
                        seen[run_id] = resp.json()["status"] == "completed"
                except (httpx.HTTPError, ValueError, LookupError, TypeError) as e:
                    warn(f"could not look up run {run_id}, leaving its record: {e}")
                    seen[run_id] = False
            return seen[run_id]

        yield run_is_finished


# Provider env =========================================================================================================
_PROVIDER_ENV: dict[str, tuple[str, ...]] = {
    "cloudflare": ("CLOUDFLARE_API_TOKEN", ),
    "route53": ("AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
    "gandi": ("GANDI_API_TOKEN", ),
    "digitalocean": ("DO_AUTH_TOKEN", ),
    "ovh": (
        "OVH_ENDPOINT",
        "OVH_APPLICATION_KEY",
        "OVH_APPLICATION_SECRET",
        "OVH_CONSUMER_KEY",
    ),
    "hetzner": ("HETZNER_API_TOKEN", ),
    "linode": ("LINODE_TOKEN", ),
    "namecheap": ("NAMECHEAP_API_KEY", "NAMECHEAP_API_USER", "NAMECHEAP_CLIENT_IP"),
}


class EnvError(Exception):
    """The maintainer-supplied real-infra env is missing or unusable; the message says what to fix."""


def require_env(environ: Mapping[str, str], *names: str) -> dict[str, str]:
    """The stripped values of ``names``, or ``EnvError`` naming those that are missing or blank."""
    missing = [n for n in names if not environ.get(n, "").strip()]
    if missing:
        raise EnvError(
            "Missing env for real-infra MTA tests: " + ", ".join(missing) +
            ".\nThese tests require a maintainer-owned test domain and DNS provider creds.\n"
            "See docs/development/testing.md > 'Real-infrastructure MTA suite' for the full checklist.\n"
            "Opt out instead: `pytest -m 'not e2e_mta_real'`."
        )
    return {n: environ[n].strip() for n in names}


def resolve_mta_test_env(environ: Mapping[str, str]) -> dict[str, str]:
    """Validated, stripped env for ``postern-dns`` against the maintainer's zone.

    The one resolver behind both the ``mta_test_env`` fixture and the CI sweep, so they cannot disagree about it.
    """
    base = require_env(environ, "MTA_TEST_DOMAIN", "MTA_TEST_DNS_PROVIDER")
    provider = base["MTA_TEST_DNS_PROVIDER"].lower()
    provider_envs = _PROVIDER_ENV.get(provider)
    if provider_envs is None:
        raise EnvError(
            f"Unknown MTA_TEST_DNS_PROVIDER {provider!r}. Supported: " + ", ".join(sorted(_PROVIDER_ENV)) + "."
        )
    base.update(require_env(environ, *provider_envs))
    base.setdefault("MTA_TEST_DNS_PROPAGATION_SECONDS", environ.get("MTA_TEST_DNS_PROPAGATION_SECONDS", "60").strip())
    return base


# postern-dns ==========================================================================================================
def describe_failure(e: Exception) -> str:
    """A log-safe account of a failed ``postern-dns`` run: exit status and stderr, never the command line."""
    if isinstance(e, subprocess.CalledProcessError):
        return f"exit status {e.returncode}: {e.stderr}"
    if isinstance(e, subprocess.TimeoutExpired):
        return f"timed out after {e.timeout}s"
    return f"{type(e).__name__}: {e}"


def postern_dns(env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    """Run the postern-dns binary in a one-off ``local/postern-provisioner-test`` container.

    ``env`` is ``resolve_mta_test_env``'s result. Credentials reach the container as ``-e NAME`` (the value comes from
    this process's environment), so the command line holds none.

    --network bridge (not --network none): the libdns API call needs HTTPS to
    reach the provider's API endpoint. We don't mount the docker socket or pass
    other capabilities -- network access is the only deviation from the safe
    default.

    --entrypoint postern-dns: the image's ENTRYPOINT is the rotation-state
    Python driver, which requires DOMAIN/DNS_PROVIDER and starts the full
    state machine. We just want the libdns wrapper, so we bypass the
    entrypoint and exec the binary directly.
    """
    # The fixture names the provider MTA_TEST_DNS_PROVIDER; postern-dns reads DNS_PROVIDER.
    container_env = {k: env[k] for k in _PROVIDER_ENV[env["MTA_TEST_DNS_PROVIDER"].lower()]}
    container_env["DNS_PROVIDER"] = env["MTA_TEST_DNS_PROVIDER"]
    cmd = ["docker", "run", "--rm", "--network", "bridge", "--entrypoint", "postern-dns"]
    for name in container_env:
        cmd.extend(("-e", name))
    cmd.extend((E2E_PROVISIONER_IMAGE, *args))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
            env={**os.environ, **container_env},
        )
    except subprocess.CalledProcessError as e:
        # Surface the captured streams unconditionally on failure so
        # postern-dns's stderr diagnostics survive pytest's rendering.
        sys.stderr.write(
            f"\n--- postern_dns({args!r}) FAILED stdout ---\n{e.stdout}\n--- stderr ---\n{e.stderr}\n--- end ---\n"
        )
        sys.stderr.flush()
        raise
    # Even on success, postern-dns may emit warnings on stderr (the
    # idempotency-recovery path on txt-set, for example). Surface those
    # so they appear in the test log next to the operation that produced
    # them.
    if result.stderr:
        sys.stderr.write(f"\n--- postern_dns({args[:2]!r}, ...) stderr ---\n{result.stderr}--- end ---\n")
        sys.stderr.flush()
    return result


# Sweep ================================================================================================================
def _still_listed(env: dict[str, str], domain: str, fqdn: str, value: str) -> bool:
    """Whether the ``(fqdn, value)`` record is still on the zone (names compare case-insensitively)."""
    listing = postern_dns(env, "txt-list", domain, SELECTOR_PREFIX).stdout
    return any(e["fqdn"].lower() == fqdn.lower() and e["value"] == value for e in json.loads(listing))


def sweep_stale_records(environ: Mapping[str, str]) -> None:
    """Delete DKIM records left by crashed CI runs (best-effort; a failed sweep only leaves clutter).

    Needs the CI run env plus ``GITHUB_REPOSITORY`` and ``GITHUB_TOKEN``. A local run has no run to ask GitHub about
    and sweeps nothing. Every skip and failure is a ``::warning::`` annotation: the step is ``continue-on-error``, so
    nothing else would show it.
    """
    repo, token = environ.get("GITHUB_REPOSITORY", ""), environ.get("GITHUB_TOKEN", "")
    try:
        ids = ci_run_ids(environ)
        if ids is None or not (repo and token):
            logger.info("not in CI (no GITHUB_RUN_ID/GITHUB_TOKEN): skipping the stale-record sweep")
            return
        repo_id, run_id, attempt = ids
        env = resolve_mta_test_env(environ)
        domain = env["MTA_TEST_DOMAIN"]
        listing = postern_dns(env, "txt-list", domain, SELECTOR_PREFIX).stdout
        with github_run_finished(repo, token, run_id) as run_is_finished:
            stale = stale_selectors(listing, domain, repo_id, run_id, attempt, run_is_finished)
    except Exception as e:  # noqa: BLE001 -- hygiene must not fail the job
        warn(f"stale DKIM record sweep skipped: {describe_failure(e)}")
        return
    for fqdn, value in stale:
        logger.info("sweeping stale record %s", fqdn)
        try:
            postern_dns(env, "txt-delete", fqdn, value)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
            # A concurrent sweeper may have deleted it first; only a record still on the zone is a failure.
            try:
                leaked = _still_listed(env, domain, fqdn, value)
            except Exception as relist_error:  # noqa: BLE001
                warn(
                    f"could not sweep stale record {fqdn} ({describe_failure(e)}); "
                    f"re-listing failed: {describe_failure(relist_error)}"
                )
                continue
            if leaked:
                warn(f"could not sweep stale record {fqdn}: {describe_failure(e)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sweep_stale_records(os.environ)
