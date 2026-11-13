"""Per-run DKIM selectors for the ``e2e_mta_real`` suite, and the sweep of records crashed runs leave behind.

Every run publishes its own ``<selector>._domainkey.<MTA_TEST_DOMAIN>`` record, so concurrent runs share nothing on the
zone and need no CI concurrency group. A run's selector is ``postern-e2e-<GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>`` in CI and
``postern-e2e-local-<random>`` elsewhere.

A run that dies before teardown (cancelled job, runner loss) leaves its record behind. The next CI run sweeps those: a
CI selector is stale when GitHub says its run is no longer in progress, or when it is an earlier attempt of this very
run. Local selectors carry no run to ask about and are never swept; their owner removes them.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable

import httpx

SELECTOR_PREFIX = "postern-e2e-"
_CI_SELECTOR_RE = re.compile(rf"^{re.escape(SELECTOR_PREFIX)}(\d+)-(\d+)$")


def run_selector(run_id: str, run_attempt: str) -> str:
    """The DKIM selector for this run (a valid DNS label: lowercase alphanumerics and hyphens)."""
    if run_id.strip() and run_attempt.strip():
        return f"{SELECTOR_PREFIX}{int(run_id)}-{int(run_attempt)}"
    return f"{SELECTOR_PREFIX}local-{secrets.token_hex(4)}"


def parse_ci_selector(selector: str) -> tuple[int, int] | None:
    """``(run_id, attempt)`` of a CI selector, or None for anything else (local selectors, foreign records)."""
    m = _CI_SELECTOR_RE.match(selector)
    return (int(m.group(1)), int(m.group(2))) if m else None


def stale_selectors(
    listing_json: str,
    domain: str,
    own_run_id: int,
    own_attempt: int,
    run_is_active: Callable[[int], bool],
) -> list[tuple[str, str]]:
    """``(fqdn, value)`` of every listed DKIM record that a crashed run left behind.

    ``listing_json`` is the output of ``postern-dns txt-list <domain> postern-e2e-``.
    """
    suffix = f"._domainkey.{domain.lower().rstrip('.')}"
    stale: list[tuple[str, str]] = []
    for entry in json.loads(listing_json):
        fqdn: str = entry["fqdn"]
        if not fqdn.endswith(suffix):
            continue
        parsed = parse_ci_selector(fqdn.removesuffix(suffix))
        if parsed is None:
            continue
        run_id, attempt = parsed
        if run_id == own_run_id:
            # A re-run starts only after every earlier attempt has finished.
            is_stale = attempt < own_attempt
        else:
            is_stale = not run_is_active(run_id)
        if is_stale:
            stale.append((fqdn, entry["value"]))
    return stale


def github_run_is_active_fn(repo: str, token: str) -> Callable[[int], bool]:
    """A ``run_is_active(run_id)`` backed by the GitHub API. A deleted run (404) counts as not active."""
    client = httpx.Client(
        base_url="https://api.github.com",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=30.0,
    )
    seen: dict[int, bool] = {}

    def run_is_active(run_id: int) -> bool:
        if run_id not in seen:
            resp = client.get(f"/repos/{repo}/actions/runs/{run_id}")
            if resp.status_code == 404:
                seen[run_id] = False
            else:
                resp.raise_for_status()
                seen[run_id] = resp.json()["status"] != "completed"
        return seen[run_id]

    return run_is_active
