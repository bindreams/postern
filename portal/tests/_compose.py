"""One tolerant Compose YAML loader for the compose-asserting unit tests.

`compose.gateway.yaml` uses Docker Compose's `!reset` merge tag (`ports: !reset []`),
which plain `yaml.safe_load` rejects with a ConstructorError. Every test that
parses a compose file needs this loader, not just the gateway one.

Only `!reset` is registered; add `!override` (with its own test) when a file
first needs it -- not before.
"""
from __future__ import annotations

from pathlib import Path

import yaml


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
