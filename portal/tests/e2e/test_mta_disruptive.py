"""Disruptive MTA test: opendkim down -> milter tempfail.

Isolated in its own file so the module-scoped restore fixture can `compose
restart mta` without affecting other tests. The shared session-scoped
``mta_e2e_stack`` survives the restart (the fixture targets one service).

Marker (`e2e_mta`) is added by ``conftest.pytest_collection_modifyitems``;
this file does not declare ``pytestmark``.
"""

from __future__ import annotations

import subprocess
import time

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
    # Kill the opendkim process. We can't use `pkill -f opendkim` because the
    # running shell's argv contains "opendkim" via -c and would signal-suicide.
    # Read PIDs from /proc directly: scan /proc/*/comm for "opendkim" and kill
    # those PIDs. The shell's /proc/SELF/comm is "sh", so it won't be killed.
    kill_script = (
        "for p in /proc/[0-9]*; do "
        "  pid=${p##*/}; "
        "  comm=$(cat $p/comm 2>/dev/null); "
        "  if [ \"$comm\" = opendkim ]; then "
        "    echo killing pid=$pid comm=$comm; "
        "    kill -9 $pid; "
        "  fi; "
        "done"
    )
    kill_result = subprocess.run(
        compose_mta("exec", "-T", "mta", "sh", "-c", kill_script),
        capture_output=True,
        text=True,
        check=False,
    )
    print(f"opendkim kill stdout: {kill_result.stdout!r}")  # noqa: T201
    print(f"opendkim kill stderr: {kill_result.stderr!r}")  # noqa: T201
    # Verify opendkim is actually dead. Without this, an environment where
    # something respawns opendkim would silently invalidate the test.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        result = subprocess.run(
            compose_mta("exec", "-T", "mta", "pgrep", "-x", "opendkim"),
            capture_output=True,
            text=True,
            check=False,
        )
        # pgrep returns 1 when no match; we want no match.
        if result.returncode == 1 and not result.stdout.strip():
            break
        time.sleep(0.2)
    else:
        ps_dump = subprocess.run(
            compose_mta("exec", "-T", "mta", "ps", "-ef"),
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        raise AssertionError(
            "opendkim is still running after pkill -9 -f -- the test cannot verify "
            "milter tempfail behaviour. Last pgrep output: " + result.stdout.strip() + "\nFull `ps -ef`:\n" + ps_dump
        )
    # Confirm port 8891 (milter) actually closed. With opendkim PID gone the
    # listening socket is closed by the kernel; allow a brief race window.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        probe = subprocess.run(
            compose_mta("exec", "-T", "mta", "sh", "-c", "nc -z -w 1 127.0.0.1 8891 && echo OPEN || echo CLOSED"),
            capture_output=True,
            text=True,
            check=False,
        )
        if "CLOSED" in probe.stdout:
            break
        time.sleep(0.2)
    else:
        ps_dump = subprocess.run(
            compose_mta("exec", "-T", "mta", "ps", "-ef"),
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        raise AssertionError(
            "127.0.0.1:8891 is still accepting connections after killing opendkim "
            "-- milter is reachable, the test cannot prove tempfail behaviour.\n"
            f"Full `ps -ef`:\n{ps_dump}"
        )
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
