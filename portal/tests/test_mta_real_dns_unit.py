"""Unit tests for the e2e_mta_real per-run DKIM selector helper.

Lives outside tests/e2e/ on purpose: it needs no docker or DNS, and must not inherit the e2e marker.
"""
from __future__ import annotations

import json
import re

import pytest

from tests.e2e._mta_real_dns import RunEnvError, parse_ci_selector, run_selector, stale_selectors

DOMAIN = "mta-test.example.com"
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
CI = {"GITHUB_REPOSITORY_ID": "42", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}


def _listing(*selectors: str) -> str:
    return json.dumps([{"fqdn": f"{s}._domainkey.{DOMAIN}", "value": f"v=DKIM1; p={s}"} for s in selectors])


def test_ci_selector_is_per_repo_run_and_attempt():
    assert run_selector(CI) == "postern-e2e-42-123-1"
    assert run_selector({**CI, "GITHUB_RUN_ATTEMPT": "2"}) != run_selector(CI)
    assert run_selector({**CI, "GITHUB_REPOSITORY_ID": "43"}) != run_selector(CI)
    assert LABEL_RE.match(
        run_selector({"GITHUB_REPOSITORY_ID": "9999999999", "GITHUB_RUN_ID": "9999999999", "GITHUB_RUN_ATTEMPT": "12"})
    )


def test_local_selector_is_random_and_not_a_ci_selector():
    a, b = run_selector({}), run_selector({})
    assert a != b
    assert LABEL_RE.match(a)
    assert parse_ci_selector(a) is None


@pytest.mark.parametrize("missing", ["GITHUB_REPOSITORY_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"])
def test_partial_ci_env_is_an_error_not_a_local_selector(missing: str):
    with pytest.raises(RunEnvError, match=missing):
        run_selector({k: v for k, v in CI.items() if k != missing})


def test_non_numeric_ci_env_is_an_error():
    with pytest.raises(RunEnvError, match="GITHUB_RUN_ID"):
        run_selector({**CI, "GITHUB_RUN_ID": "abc"})


def test_parse_ci_selector():
    assert parse_ci_selector("postern-e2e-42-123-4") == (42, 123, 4)
    assert parse_ci_selector("postern-e2e-123-4") is None
    assert parse_ci_selector("postern-e2e-test") is None
    assert parse_ci_selector("s1") is None


def test_sweep_selects_finished_runs_and_earlier_attempts_of_own_run():
    listing = _listing(
        "postern-e2e-42-100-1",  # finished run
        "postern-e2e-42-200-1",  # run still in progress
        "postern-e2e-42-300-1",  # own run, earlier attempt
        "postern-e2e-42-300-2",  # own run, this attempt
        "postern-e2e-local-ab12cd34",  # local run
        "postern-e2e-test",  # legacy fixed selector
    )
    stale = stale_selectors(listing, DOMAIN, 42, 300, 2, lambda run_id: run_id != 200)
    assert [fqdn for fqdn, _ in stale] == [
        f"postern-e2e-42-100-1._domainkey.{DOMAIN}",
        f"postern-e2e-42-300-1._domainkey.{DOMAIN}",
    ]
    assert stale[0][1] == "v=DKIM1; p=postern-e2e-42-100-1"


def test_sweep_skips_other_repos_without_asking_github():
    # A run id from another repository 404s here, which would otherwise read as "deleted".
    def boom(run_id: int) -> bool:
        raise AssertionError("another repository's run must not be looked up")

    assert stale_selectors(_listing("postern-e2e-99-100-1", "postern-e2e-99-300-1"), DOMAIN, 42, 300, 2, boom) == []


def test_sweep_ignores_other_domains_and_names():
    listing = json.dumps([
        {"fqdn": "postern-e2e-42-100-1._domainkey.other.example.org", "value": "x"},
        {"fqdn": f"postern-e2e-42-100-1.{DOMAIN}", "value": "x"},
    ])
    assert stale_selectors(listing, DOMAIN, 42, 1, 1, lambda _: True) == []


def test_sweep_does_not_ask_github_about_own_run():

    def boom(run_id: int) -> bool:
        raise AssertionError("own run must not be looked up")

    stale_selectors(_listing("postern-e2e-42-5-1"), DOMAIN, 42, 5, 2, boom)


def test_sweep_keeps_mixed_case_names_deletable_as_listed():
    listing = json.dumps([{"fqdn": f"Postern-E2E-42-100-1._domainkey.{DOMAIN}", "value": "x"}])
    assert stale_selectors(listing, DOMAIN, 42, 1, 1,
                           lambda _: True) == [(f"Postern-E2E-42-100-1._domainkey.{DOMAIN}", "x")]
