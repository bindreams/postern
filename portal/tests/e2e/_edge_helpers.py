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


def hard_restart_nginx(*, timeout: float = 60.0) -> str:
    """SIGKILL the edge nginx, then start it again; return the pid it left behind.

    This is the host-reboot path, and it is NOT what ``seed_edge_ranges`` does.
    ``docker restart`` is graceful: nginx catches SIGTERM and unlinks its own
    pidfile, so the container comes back with clean ``/run`` state.  That is why
    every restart this suite already performs stays green regardless of issue
    #245 -- and why the bug survived in production for twelve weeks.  Only an
    ungraceful death (host reboot, SIGKILL, the daemon going down under the
    container) leaves ``/run/nginx.pid`` behind, because it lives in the
    container's writable layer rather than on a tmpfs.

    The returned pid is the caller's precondition check: restarting a container
    that left no pidfile exercises none of this and would pass vacuously.

    Raises with the exit code in the message rather than a bare health timeout --
    128+1=129 is the signature of the entrypoint being SIGHUPed by its own stale
    pidfile, and a test that only reported "never became healthy" would bury it.
    """
    run(["docker", "kill", "--signal=KILL", EDGE_NGINX_CONTAINER])
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline and _container_state()[0] != "exited":
        time.sleep(0.2)

    stale_pid = _read_stale_pidfile()
    run(["docker", "start", EDGE_NGINX_CONTAINER])
    try:
        _wait_nginx_healthy(timeout=timeout)
    except AssertionError:
        status, exit_code = _container_state()
        signal_note = " (128+1: killed by SIGHUP -- see issue #245)" if exit_code == 129 else ""
        raise AssertionError(
            f"edge nginx did not come back after an ungraceful restart: status={status!r} "
            f"exit={exit_code}{signal_note}; stale /run/nginx.pid held {stale_pid!r}"
        ) from None
    return stale_pid


def current_master_pid() -> str:
    """The pid nginx recorded for itself in the running container.

    Because the entrypoint ends in ``exec nginx``, this is also the pid the
    entrypoint SHELL held. Comparing it against the pid a killed container left
    behind is what proves a restart actually re-collides -- without that, an
    ungraceful-restart test only proves some file survived, and would pass against
    a broken build on any runtime whose pid numbering happens not to line up.
    """
    result = run(["docker", "exec", EDGE_NGINX_CONTAINER, "cat", "/run/nginx.pid"])
    return result.stdout.strip()


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
