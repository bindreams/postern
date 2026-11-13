"""Unit tests for the e2e_mta_real per-run DKIM selector helper.

Lives outside tests/e2e/ on purpose: it needs no docker or DNS, and must not inherit the e2e marker.
"""
from __future__ import annotations

import json
import re

from tests.e2e._mta_real_selector import parse_ci_selector, run_selector, stale_selectors

DOMAIN = "mta-test.example.com"
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _listing(*selectors: str) -> str:
    return json.dumps([{"fqdn": f"{s}._domainkey.{DOMAIN}", "value": f"v=DKIM1; p={s}"} for s in selectors])


def test_ci_selector_is_per_run_and_attempt():
    assert run_selector("123", "1") == "postern-e2e-123-1"
    assert run_selector("123", "2") != run_selector("123", "1")
    assert LABEL_RE.match(run_selector("9999999999", "12"))


def test_local_selector_is_random_and_not_a_ci_selector():
    a, b = run_selector("", ""), run_selector("", "")
    assert a != b
    assert LABEL_RE.match(a)
    assert parse_ci_selector(a) is None


def test_parse_ci_selector():
    assert parse_ci_selector("postern-e2e-123-4") == (123, 4)
    assert parse_ci_selector("postern-e2e-test") is None
    assert parse_ci_selector("s1") is None


def test_sweep_selects_finished_runs_and_earlier_attempts_of_own_run():
    listing = _listing(
        "postern-e2e-100-1",  # finished run
        "postern-e2e-200-1",  # run still in progress
        "postern-e2e-300-1",  # own run, earlier attempt
        "postern-e2e-300-2",  # own run, this attempt
        "postern-e2e-local-ab12cd34",  # local run
        "postern-e2e-test",  # legacy fixed selector
    )
    stale = stale_selectors(listing, DOMAIN, 300, 2, lambda run_id: run_id != 200)
    assert [fqdn for fqdn, _ in stale] == [
        f"postern-e2e-100-1._domainkey.{DOMAIN}",
        f"postern-e2e-300-1._domainkey.{DOMAIN}",
    ]
    assert stale[0][1] == "v=DKIM1; p=postern-e2e-100-1"


def test_sweep_ignores_other_domains_and_names():
    listing = json.dumps([
        {"fqdn": "postern-e2e-100-1._domainkey.other.example.org", "value": "x"},
        {"fqdn": f"postern-e2e-100-1.{DOMAIN}", "value": "x"},
    ])
    assert stale_selectors(listing, DOMAIN, 1, 1, lambda _: True) == []


def test_sweep_does_not_ask_github_about_own_run():

    def boom(run_id: int) -> bool:
        raise AssertionError("own run must not be looked up")

    stale_selectors(_listing("postern-e2e-5-1"), DOMAIN, 5, 2, boom)


def test_sweep_keeps_mixed_case_names_deletable_as_listed():
    listing = json.dumps([{"fqdn": f"Postern-E2E-100-1._domainkey.{DOMAIN}", "value": "x"}])
    assert stale_selectors(listing, DOMAIN, 1, 1, lambda _: True) == [(f"Postern-E2E-100-1._domainkey.{DOMAIN}", "x")]
