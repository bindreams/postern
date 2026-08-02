"""Regression tests: the reconciler's container sweep must be scoped to its
own Postern deployment, not every deployment sharing a Docker daemon.

These are static YAML-parse checks (no Docker required) that pin the
compose-level wiring the runtime fix depends on: `COMPOSE_PROJECT_NAME` must
be forwarded into the portal container's environment (Settings.compose_project_name
-- see reconciler.resolve_instance_id) in every compose file that runs a
portal.
"""
from __future__ import annotations

from pathlib import Path

from ._compose import load_compose

# tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

COMPOSE_PROJECT_NAME_EXPR = "${COMPOSE_PROJECT_NAME:-}"


def _load_compose(relpath: str) -> dict:
    return load_compose(REPO_ROOT / relpath)


# COMPOSE_PROJECT_NAME forwarding ======================================================================================
def test_production_portal_forwards_compose_project_name():
    compose = _load_compose("compose.yaml")
    env = compose["services"]["portal"]["environment"]
    assert env.get("COMPOSE_PROJECT_NAME") == COMPOSE_PROJECT_NAME_EXPR, (
        "compose.yaml's portal service must forward COMPOSE_PROJECT_NAME so "
        "reconciler.resolve_instance_id can auto-derive this deployment's instance "
        f"id; got {env.get('COMPOSE_PROJECT_NAME')!r}"
    )


def test_e2e_portal_forwards_compose_project_name():
    compose = _load_compose("portal/tests/e2e/e2e.compose.yaml")
    env = compose["services"]["portal"]["environment"]
    assert env.get("COMPOSE_PROJECT_NAME") == COMPOSE_PROJECT_NAME_EXPR


def test_e2e_edge_portal_forwards_compose_project_name():
    compose = _load_compose("portal/tests/e2e/e2e-edge.compose.yaml")
    env = compose["services"]["portal"]["environment"]
    assert env.get("COMPOSE_PROJECT_NAME") == COMPOSE_PROJECT_NAME_EXPR
