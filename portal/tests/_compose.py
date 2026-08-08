"""One tolerant Compose YAML loader for the compose-asserting unit tests.

`compose.gateway.yaml` uses Docker Compose's `!reset` merge tag (`ports: !reset []`),
which plain `yaml.safe_load` rejects with a ConstructorError. Every test that
parses a compose file needs this loader, not just the gateway one.

Only `!reset` is registered; add `!override` (with its own test) when a file
first needs it -- not before.
"""
from __future__ import annotations

import functools
from pathlib import Path

import yaml

# tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class ComposeLoader(yaml.SafeLoader):
    """SafeLoader plus Compose's `!reset` merge tag. Subclassed so the constructor
    stays local -- registering on yaml.SafeLoader itself would mutate shared state
    for every other consumer in the process."""


# `!reset X` means "drop the inherited value". These tests read one file at a
# time and never perform the merge themselves, so resolving it to None is exact.
ComposeLoader.add_constructor("!reset", lambda loader, node: None)


def load_compose(path: Path) -> dict:
    """Parse a Docker Compose YAML file into a plain dict.

    Does not perform Compose's multi-file merge semantics -- callers that need
    the effect of `docker compose -f a -f b config` should shell out to the
    Compose CLI instead.
    """
    return yaml.load(path.read_text(encoding="utf-8"), Loader=ComposeLoader) or {}


# Derived constants shared across compose-parsing tests ================================================================
@functools.lru_cache(maxsize=1)
def production_mta_submit_subnet() -> str:
    """Production's IPAM-pinned mta-submit subnet, read from compose.yaml.

    Derived, never hand-typed: any consumer's whole requirement is being a
    *different* subnet from whatever production currently pins, and a literal
    copy would keep comparing against a stale value after production moved.

    Lives in this docker-free, loader-only module rather than in
    portal/tests/e2e/_mta_helpers.py -- both test_compose_colocation.py (no
    Docker required, per its own docstring) and the e2e-scoped test_mta.py
    need it, and the base suite must not depend on an e2e/docker-orchestration
    module to stay Docker-free.

    A plain, lazily-memoized function rather than a module-level constant:
    this loader is imported by several unrelated compose-parsing test modules
    that only need `load_compose` (test_compose_edge.py, test_compose_gateway.py,
    test_build_revision.py, ...), and an eager call here would make every one
    of their test collections depend on compose.yaml's mta-submit block, not
    just the two modules that actually use this value.
    """
    # Tolerant of every partial shape, same pattern as test_compose_colocation.py's
    # _pinned_subnet_of -- a KeyError/IndexError here would surface as an
    # unworded traceback in whichever test happens to trigger the first call,
    # instead of a clear message.
    networks = load_compose(REPO_ROOT / "compose.yaml").get("networks") or {}
    net = networks.get("mta-submit")
    assert net is not None, "compose.yaml declares no networks.mta-submit"
    configs = (net.get("ipam") or {}).get("config") or []
    assert configs and configs[0].get("subnet"), "compose.yaml networks.mta-submit has no pinned ipam subnet"
    subnet = configs[0]["subnet"]
    assert isinstance(subnet, str), f"compose.yaml mta-submit subnet is {subnet!r}"
    return subnet
