"""Disruptive MTA test: opendkim down -> milter tempfail.

Isolated in its own file so the module-scoped restore fixture can `compose
restart mta` without affecting other tests. The shared session-scoped
``mta_e2e_stack`` survives the restart (the fixture targets one service).

Marker (`e2e_mta`) is added by ``conftest.pytest_collection_modifyitems``;
this file does not declare ``pytestmark``.
"""

from __future__ import annotations

import subprocess

import pytest

from ._helpers import run
from ._mta_helpers import (
    compose_mta,
    get_container_id,
    mta_exec,
    portal_mta_exec,  # noqa: F401  (kept available for any future test in this module)
    wait_for_healthy,
)


@pytest.fixture(scope="module")
def _disrupted_opendkim(mta_e2e_stack):
    """Kill opendkim before the test runs; restart the mta container after.

    The mta entrypoint Popens opendkim once and never respawns it. With
    ``milter_default_action = tempfail`` (an architectural invariant in
    CLAUDE.md), every SMTP transaction is rejected with 451 while opendkim is
    down -- exactly what the test verifies.

    The teardown does ``compose restart mta`` which re-runs the entrypoint
    (and re-spawns opendkim). state.json + key files survive on the volume,
    so the new entrypoint reuses them.
    """
    mta_exec("pkill", "-9", "opendkim")
    try:
        yield
    finally:
        # Best-effort: even if the test failed, get opendkim back up so the
        # session can tear down cleanly.
        subprocess.run(compose_mta("restart", "mta"), check=False)
        try:
            wait_for_healthy(get_container_id("mta"), timeout=90)
        except AssertionError:
            # If the restart fails to come back, surface a loud signal but
            # don't mask the original test failure.
            print("WARNING: mta did not return to healthy state after restart")  # noqa: T201


def test_milter_tempfails_when_opendkim_down(
    portal_mta_client,
    mailpit_mta_client,
    fresh_mta_user,
    _disrupted_opendkim,
):
    """With opendkim down, the smtpd milter is unreachable. Per
    `milter_default_action = tempfail` (loaded from main.cf.tmpl), Postfix
    rejects the SMTP transaction with a 4xx status; nothing reaches mailpit.

    Pinning this behavior catches a regression where someone "fixes
    resilience" by switching the default to ``accept`` (which would defeat
    DMARC p=reject by letting unsigned mail escape).
    """
    email = "tempfail@postern.test"
    fresh_mta_user("Tempfail Test", email)

    # The portal's POST /login swallows email-send errors and still returns 303
    # (it doesn't tell the user "we couldn't send"). What we verify is the mta-
    # side outcome: no message reaches the recipient.
    r = portal_mta_client.post("/login", data={"email": email})
    assert r.status_code == 303

    mailpit_mta_client.assert_no_message_to(email, wait=15.0)

    # Confirm the queue holds the message (or that the smtpd transaction was
    # rejected outright). Either is correct; both rule out "leaked unsigned".
    queue = mta_exec("postqueue", "-p").stdout
    log_excerpt = run(["docker", "logs", "--tail", "100", get_container_id("mta")]).stdout
    queue_or_rejected = (
        "postern.test" in queue or "Mail queue is empty" not in queue or "451" in log_excerpt
        or "tempfail" in log_excerpt.lower()
    )
    assert queue_or_rejected, (
        f"expected queue evidence or 451/tempfail in mta logs while opendkim is down; "
        f"postqueue:\n{queue!r}\nlast 100 mta log lines:\n{log_excerpt!r}"
    )
