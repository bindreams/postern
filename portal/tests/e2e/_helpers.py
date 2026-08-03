"""Shared utilities for e2e tests. Conftest fixtures and tests both import from here.

The split exists because pytest treats conftest.py specially -- importing from it
across files in the same directory is fragile. Putting the utilities in a regular
module sidesteps that.

The compose primitives (``compose``, ``compose_exec``) accept ``project`` and
``files`` kwargs so the same helpers can drive a second compose project (the MTA
overlay; see ``_mta_helpers.py``). The defaults preserve the original
single-project behaviour for ``test_tunnel.py``.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

# Resolve key paths once.
TESTS_E2E_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_E2E_DIR.parents[2]
COMPOSE_FILE = TESTS_E2E_DIR / "e2e.compose.yaml"
COMPOSE_FILES: tuple[Path, ...] = (COMPOSE_FILE, )
PROJECT = "postern-e2e"

# E2e image names ======================================================================================================
# Spelled out in full, not composed from a suffix constant: test_docs.py pins
# the shadowsocks literal from this file into docs/development/testing.md
# (see CLAUDE.md for the local/*-test convention).
E2E_SHADOWSOCKS_IMAGE = "local/shadowsocks-server-test"
E2E_NGINX_IMAGE = "local/nginx-test"
E2E_PROVISIONER_IMAGE = "local/postern-provisioner-test"

PORTAL_BASE_URL = "https://postern.test:8443"
MAILPIT_BASE_URL = "http://localhost:8025"


# Compose primitives ===================================================================================================
def compose(
    *args: str,
    project: str = PROJECT,
    files: tuple[Path, ...] = COMPOSE_FILES,
) -> list[str]:
    file_args: list[str] = []
    for f in files:
        file_args.extend(("-f", str(f)))
    return ["docker", "compose", "-p", project, *file_args, *args]


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)


def compose_exec(
    *cmd: str,
    service: str = "portal",
    project: str = PROJECT,
    files: tuple[Path, ...] = COMPOSE_FILES,
    stdin: str | None = None,
) -> subprocess.CompletedProcess:
    if stdin is not None:
        return run(compose("exec", "-T", service, *cmd, project=project, files=files), input=stdin)
    return run(compose("exec", "-T", service, *cmd, project=project, files=files))


def postern_cli(*args: str) -> subprocess.CompletedProcess:
    return compose_exec("postern", *args)


# Generous but real: an unbounded --wait on a background task in another process
# (the portal's reconciliation_loop) can hang forever with no diagnostic if that
# task ever dies independently of a slow pass -- the same hazard
# scripts/deploy.sh's DEFAULT_WAIT_TIMEOUT documents and bounds. A dead reconciler
# should surface as a failed test with the CLI's own "did not complete a pass"
# message, not an unattributable CI hang.
RECONCILE_WAIT_TIMEOUT = "60"


def trigger_reconcile() -> None:
    """Trigger a reconcile pass and block until it has finished.

    --wait registers a FIFO before touching the trigger, so on return the
    reconciler has completed a pass that started after this call -- container
    state can be asserted directly instead of polled.
    """
    compose_exec("postern", "reconcile", "--wait", "--wait-timeout", RECONCILE_WAIT_TIMEOUT)


def query_db(sql: str, *params: str) -> str:
    """SELECT in the portal container; returns the first column of the first row (or '')."""
    py = (
        "import sqlite3, sys\n"
        "row = sqlite3.connect('/data/postern.db').execute("
        f"{sql!r}, sys.argv[1:]).fetchone()\n"
        "print(row[0] if row else '')\n"
    )
    return compose_exec("python", "-c", py, *params).stdout.strip()


# Container introspection ==============================================================================================
def container_exists(name: str) -> bool:
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return name in result.stdout.split()


def container_running(name: str) -> bool:
    """Stronger than container_exists: a container that was stopped (even if
    not yet removed) does NOT count as surviving. `_remove_container`
    swallows stop/remove failures, so a container can be present-but-exited
    after a partially-failed removal attempt -- `container_exists` alone
    would miss that."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


# Path-token regex used by the connection fixture
CONNECTION_ID_RE = re.compile(r"Created connection ([0-9a-f-]{36})")
