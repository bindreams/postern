"""Helpers bound to the ``postern-e2e-edge`` compose project.

Thin wrappers around ``_helpers.compose`` / ``_helpers.compose_exec`` that bind
the project name and compose-file list, plus utilities for seeding the
postern-edge volume and restarting nginx.

Tests import from here; ``_helpers`` stays single-project (the base e2e stack).
"""

from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from . import _helpers
from ._helpers import E2E_NGINX_IMAGE, TESTS_E2E_DIR, run

PROJECT_EDGE = "postern-e2e-edge"
COMPOSE_FILES_EDGE: tuple[Path, ...] = (TESTS_E2E_DIR / "e2e-edge.compose.yaml", )

EDGE_BASE_URL = "https://postern.test:8453"
# container_name pinned in e2e-edge.compose.yaml; used for docker restart.
EDGE_NGINX_CONTAINER = "postern-e2e-edge-nginx"
# Named volume that nginx reads RO; helper containers write RW to seed it.
EDGE_VOLUME_NAME = "postern-e2e-edge-edge"

# Sanity-check: a naming collision would make two e2e projects fight over the
# same Docker resources (networks, volumes).
assert PROJECT_EDGE != _helpers.PROJECT, "PROJECT_EDGE must differ from _helpers.PROJECT"


# Compose primitives ===================================================================================================
def compose_edge(*args: str) -> list[str]:
    return _helpers.compose(*args, project=PROJECT_EDGE, files=COMPOSE_FILES_EDGE)


# Edge-volume helpers ==================================================================================================
def _wait_nginx_healthy(*, timeout: float = 30.0) -> None:
    """Poll Docker's healthcheck status for the edge nginx container until healthy.

    Gates readiness on Docker's own healthcheck primitive -- the container is
    not considered ready until its healthcheck reports ``healthy``.  ``timeout``
    is the failure bound surfaced to the operator ("nginx did not become healthy
    after {timeout}s").
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", EDGE_NGINX_CONTAINER],
            capture_output=True,
            text=True,
        )
        if result.stdout.strip() == "healthy":
            return
        time.sleep(0.5)
    raise AssertionError(f"edge nginx did not become healthy after {timeout}s")


def seed_edge_ranges(*, ranges_conf: str = "set_real_ip_from 0.0.0.0/0;\n") -> None:
    """Write a Cloudflare-ranges conf into the postern-edge volume and restart nginx.

    Uses an ephemeral one-off container (E2E_NGINX_IMAGE, UID 0 so it can write to
    the root-owned volume) with an atomic rename (mv) so the inotifyd watcher
    inside nginx also sees IN_MOVED_TO.  After writing, RESTART the nginx
    container -- not just ``nginx -s reload`` -- so the old worker (old
    config) is gone for good and render.sh re-runs against the on-disk ranges.
    Docker resets health to ``starting`` on restart; the healthcheck probes
    the portal (a certless self-probe is blocked by ``ssl_verify_client on``),
    so "healthy" proves the container is up, not that :443 is bound.  If nginx
    is not serving yet, the test fails loudly with a connection error -- it
    can never silently read the stale config.

    ``ranges_conf`` defaults to ``set_real_ip_from 0.0.0.0/0;`` (trust all
    sources) so CF-Connecting-IP is recovered from any test client IP.  Pass a
    narrower CIDR when you need to test trust boundaries.
    """
    # Write via stdin to avoid shell-quoting the ranges_conf content.
    run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-i",
            "--user",
            "0",  # UID 0 can write to the root-owned volume mount
            "--entrypoint",
            "sh",
            "--volume",
            f"{EDGE_VOLUME_NAME}:/edge",
            E2E_NGINX_IMAGE,
            "-c",
            "cat > /edge/.cloudflare-ranges.conf.tmp && "
            "mv /edge/.cloudflare-ranges.conf.tmp /edge/cloudflare-ranges.conf",
        ],
        input=ranges_conf,
    )
    # Restart (not just reload): the old worker dies with the container, so a
    # stale-config read is impossible; worst case is a loud connection error.
    run(["docker", "restart", EDGE_NGINX_CONTAINER])
    _wait_nginx_healthy()


# Ungraceful-restart helpers ===========================================================================================
def _container_state() -> tuple[str, int]:
    """(status, last exit code) for the edge nginx container."""
    result = run(["docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", EDGE_NGINX_CONTAINER])
    status, _, exit_code = result.stdout.strip().partition(" ")
    return status, int(exit_code)


def _read_stale_pidfile() -> str:
    """Read /run/nginx.pid out of the STOPPED container's writable layer.

    ``docker cp`` rather than ``docker exec``: the container is not running, and
    the point is to observe the file the dead process left behind.  Returns ""
    when no pidfile is present.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "nginx.pid"
        result = subprocess.run(
            ["docker", "cp", f"{EDGE_NGINX_CONTAINER}:/run/nginx.pid",
             str(dest)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or not dest.exists():
            return ""
        return dest.read_text().strip()


def hard_restart_nginx() -> tuple[str, str]:
    """SIGKILL the edge nginx, start it again, and wait for its master; return (stale_pid, master_pid).

    This is the host-reboot path, and it is NOT what ``seed_edge_ranges`` does.
    ``docker restart`` is graceful: nginx catches SIGTERM and unlinks its own
    pidfile, so the container comes back with clean ``/run`` state.  That is why
    every restart this suite already performs stays green regardless of issue
    #245 -- and why the bug survived in production for twelve weeks.  Only an
    ungraceful death (host reboot, SIGKILL, the daemon going down under the
    container) leaves ``/run/nginx.pid`` behind, because it lives in the
    container's writable layer rather than on a tmpfs.

    ``stale_pid`` shows only that a pidfile survived the kill: restarting a
    container that left none exercises none of this and would pass vacuously. It
    need not equal the new entrypoint's pid.  ``master_pid`` is the pid the new
    container's ``/run/nginx.pid`` names once it names a live nginx master.

    Readiness is the real condition (see ``_wait_nginx_master``), not Docker's
    healthcheck, which probes the portal backend and says nothing about nginx. If
    the container stops instead, raises with the exit code -- 128+1=129 is the
    signature of the entrypoint being SIGHUPed by its own stale pidfile.
    """
    run(["docker", "kill", "--signal=KILL", EDGE_NGINX_CONTAINER])
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline and _container_state()[0] != "exited":
        time.sleep(0.2)
    status, _ = _container_state()
    assert status == "exited", f"container did not stop after SIGKILL (status={status!r})"

    stale_pid = _read_stale_pidfile()
    run(["docker", "start", EDGE_NGINX_CONTAINER])
    return stale_pid, _wait_nginx_master(stale_pid)


def _wait_nginx_master(stale_pid: str) -> str:
    """Block until the container runs a live nginx master; return its pid.

    Re-checks the entrypoint's own probe (``live_master_pid``) with no cap. The ways
    out besides success are the container leaving ``running`` and the probe itself
    failing, both of which raise.
    """
    while True:
        status, exit_code = _container_state()
        if status != "running":
            signal_note = " (128+1: killed by SIGHUP -- see issue #245)" if exit_code == 129 else ""
            raise AssertionError(
                f"edge nginx did not come back after an ungraceful restart: status={status!r} "
                f"exit={exit_code}{signal_note}; stale /run/nginx.pid held {stale_pid!r}"
            )
        master = live_master_pid()
        if master:
            return master
        time.sleep(0.2)


def _exec_in_nginx(*argv: str) -> str:
    """Run ``argv`` in the edge container; return its stripped stdout, or "" for "nothing there".

    Exit 0 is an answer and exit 1 is how every probe used here (``cat`` of a missing
    file, ``nginx_master_pid`` finding no master) says there is none -- the exact
    symptom of the regression these tests catch, so it is returned rather than
    raised. Anything else (126/127 for a missing binary, 2 for a ``.`` of a moved
    ``pidfile.sh``, 125 from the daemon) means the probe itself is broken, and is
    raised with its stderr: reading it as "not ready" would spin until the test
    timeout and lose the diagnostic.
    """
    result = subprocess.run(["docker", "exec", EDGE_NGINX_CONTAINER, *argv], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    if result.returncode == 1:
        return ""
    raise AssertionError(
        f"probe {argv!r} failed in {EDGE_NGINX_CONTAINER}: exit {result.returncode}: {result.stderr.strip()!r}"
    )


def live_master_pid() -> str:
    """The pid /run/nginx.pid names IF it is a live nginx master, else "".

    Runs the entrypoint's own probe (``nginx_master_pid`` in pidfile.sh), so the
    test and the guard it pins agree on what "a live master" means.  Because the
    entrypoint ends in ``exec nginx``, the master's pid is the one the entrypoint
    SHELL held; the runtime picks it, so compare readings of one boot with each
    other, never with a killed container's pid.
    """
    return _exec_in_nginx("sh", "-c", ". /usr/local/bin/pidfile.sh; nginx_master_pid")


def process_tree_master_pids() -> list[str]:
    """The pids of PID 1's children: tini's one supervised process, i.e. the real nginx master.

    Read from the process tree, independent of ``/run/nginx.pid``, so a test can check
    the pidfile against what is actually running rather than against itself.
    """
    return _exec_in_nginx("cat", "/proc/1/task/1/children").split()


def logs_since_last_start() -> str:
    """Container logs from the current run only, so a restart's output is isolated."""
    started = run(["docker", "inspect", "--format", "{{.State.StartedAt}}", EDGE_NGINX_CONTAINER])
    result = subprocess.run(
        ["docker", "logs", "--since", started.stdout.strip(), EDGE_NGINX_CONTAINER],
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr


def wait_for_log_line(needle: str) -> None:
    """Block until ``needle`` appears in the current run's logs.

    Docker copies container output to its log asynchronously, so a line the
    entrypoint already printed can be missing from ``docker logs`` for a moment
    after the master is up. Re-reads with no cap; a line that never comes (the
    entrypoint never printed it) ends in the per-test timeout, so a timeout here
    means ``needle`` was never logged. Raises if the container stops first.
    """
    while needle not in logs_since_last_start():
        status, exit_code = _container_state()
        assert status == "running", f"edge nginx stopped (status={status!r} exit={exit_code}) before logging {needle!r}"
        time.sleep(0.2)


def remove_edge_ranges() -> None:
    """Remove the seeded ranges file and restart nginx (fixture teardown)."""
    run([
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "0",
        "--entrypoint",
        "sh",
        "--volume",
        f"{EDGE_VOLUME_NAME}:/edge",
        E2E_NGINX_IMAGE,
        "-c",
        "rm -f /edge/cloudflare-ranges.conf",
    ])
    run(["docker", "restart", EDGE_NGINX_CONTAINER])
    _wait_nginx_healthy()
