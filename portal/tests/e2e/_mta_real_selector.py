"""Per-run DKIM selectors for the ``e2e_mta_real`` suite, and the sweep of records crashed runs leave behind.

Every run publishes its own ``<selector>._domainkey.<MTA_TEST_DOMAIN>`` record, so concurrent runs share nothing on the
zone and need no CI concurrency group. A run's selector is ``postern-e2e-<GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>`` in CI and
``postern-e2e-local-<random>`` elsewhere.

A run that dies before teardown (cancelled job, runner loss) leaves its record behind. The next CI run sweeps those: a
CI selector is stale when this repo's GitHub reports its run completed, or when it is an earlier attempt of this very
run. A run this repo does not know (404: a fork's, or a deleted one) may be live elsewhere, so its record is left alone.
Local selectors carry no run to ask about and are never swept; their owner removes them.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import httpx

logger = logging.getLogger(__name__)

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
    run_is_finished: Callable[[int], bool],
) -> list[tuple[str, str]]:
    """``(fqdn, value)`` of every listed DKIM record that a crashed run left behind.

    ``listing_json`` is the output of ``postern-dns txt-list <domain> postern-e2e-``. Each ``fqdn`` is returned exactly
    as listed, so ``txt-delete`` matches it; only the selector test ignores case.
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
        run_id, attempt = parsed
        if run_id == own_run_id:
            # A re-run starts only after every earlier attempt has finished.
            is_stale = attempt < own_attempt
        else:
            is_stale = run_is_finished(run_id)
        if is_stale:
            stale.append((fqdn, entry["value"]))
    return stale


@contextmanager
def github_run_finished(repo: str, token: str) -> Iterator[Callable[[int], bool]]:
    """Yield a ``run_is_finished(run_id)`` backed by the GitHub API.

    True only when ``repo`` reports the run completed. A 404 (not this repo's run) or any API error counts as not
    finished, so that run's record is left alone and the sweep carries on with the others.
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
        seen: dict[int, bool] = {}

        def run_is_finished(run_id: int) -> bool:
            if run_id not in seen:
                try:
                    resp = client.get(f"/repos/{repo}/actions/runs/{run_id}")
                    if resp.status_code == 404:
                        seen[run_id] = False
                    else:
                        resp.raise_for_status()
                        seen[run_id] = resp.json()["status"] == "completed"
                except httpx.HTTPError as e:
                    logger.warning("could not look up run %s, leaving its record: %s", run_id, e)
                    seen[run_id] = False
            return seen[run_id]

        yield run_is_finished
