"""Guard tests for the ex-ray / galoshes version pins (issue #191).

The tunnel server image and the e2e client image each install both plugins from
bindreams/hole. A client older than the server cannot negotiate features the
server offers -- ECH in particular -- so a drifted e2e pin silently turns ECH
coverage into a no-op instead of failing. These tests pin, without Docker or
network:

  (a) every ex-ray pin agrees, and every galoshes pin agrees, across all stages
      of both Dockerfiles;
  (b) every pin meets every floor recorded in `FLOORS`;
  (c) every pin carries the Renovate marker comment, so a Renovate bump moves
      all of them together rather than leaving license stages behind.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from packaging.version import Version

# portal/tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Both images install both plugins; they talk to each other, so they must agree.
RENOVATE_CONFIG = Path(".github/renovate.json")

PINNED_FILES = (
    Path("shadowsocks/Dockerfile"),
    Path("portal/tests/e2e/ssclient.Dockerfile"),
)

# The ARG names every pinned file must carry, one per plugin.
PLUGIN_ARGS = ("EX_RAY_VERSION", "GALOSHES_VERSION")

# ARG name -> slug -> (floor, why). Keyed by slug rather than held in a list so a
# consumer names the floor it wants instead of picking one out by position or by
# magnitude -- `FLOORS["GALOSHES_VERSION"]["mux"]` cannot silently become the ECH
# floor when another is added. See the "Two plugin binaries ship in the
# shadowsocks image" invariant in CLAUDE.md.
ECH_WHY = "ECH (`ech`/`ech-doh` plugin opts) is silently ignored below this"
FLOORS: dict[str, dict[str, tuple[Version, str]]] = {
    "EX_RAY_VERSION": {
        "ech": (Version("0.2.0"), ECH_WHY),
    },
    "GALOSHES_VERSION": {
        "ech": (Version("0.3.0"), ECH_WHY),
        "mux": (Version("0.4.0"),
                "galoshes appends `mux=0` to its embedded ex-ray, and `mux` also picks the "
                "server's dokodemo destination, so both ends must agree"),
    },
}

# Exactly the comment .github/renovate.json's customManagers match on. Renovate's
# matchStrings require it on the line immediately above the ARG; an ARG without it
# is invisible to Renovate and drifts.
RENOVATE_MARKER = "# renovate: datasource=github-tags depName=bindreams/hole"

ARG_RE = re.compile(r"^ARG (?P<name>EX_RAY_VERSION|GALOSHES_VERSION)=(?P<value>v\S+)$")


# helpers ==============================================================================================================
def _pins(path: Path) -> list[tuple[int, str, str, bool]]:
    """Return (line_number, arg_name, version, has_renovate_marker) for each pin in `path`."""
    lines = (REPO_ROOT / path).read_text().splitlines()
    found = []
    for index, line in enumerate(lines):
        match = ARG_RE.match(line)
        if match is None:
            continue
        marked = index > 0 and lines[index - 1].strip() == RENOVATE_MARKER
        found.append((index + 1, match["name"], match["value"], marked))
    return found


def _all_pins() -> list[tuple[Path, int, str, str, bool]]:
    return [(path, *pin) for path in PINNED_FILES for pin in _pins(path)]


# tests ================================================================================================================
def test_every_floor_names_a_pinned_arg():
    """A floor keyed under an ARG no file pins is never looked up, so it enforces nothing.

    `ECH_FLOOR` used to be both the floor map and the ARG list, which made this
    impossible; splitting them into `FLOORS` and `PLUGIN_ARGS` reopened it.
    """
    orphaned = set(FLOORS) - set(PLUGIN_ARGS)
    assert not orphaned, (f"FLOORS keys {sorted(orphaned)} are not in PLUGIN_ARGS, so their floors are "
                          f"never checked against any pin.")


def test_every_pinned_file_declares_both_plugins():
    """A file that stops pinning a plugin would make the agreement tests vacuous."""
    for path in PINNED_FILES:
        names = {name for _, name, _, _ in _pins(path)}
        assert names == set(PLUGIN_ARGS), (f"{path} pins {sorted(names)}; expected all of {sorted(PLUGIN_ARGS)}.")


def test_plugin_pins_agree_across_stages_and_images():
    """Server and client images -- and every stage within them -- use one version per plugin."""
    for arg_name in PLUGIN_ARGS:
        seen: dict[str, list[str]] = {}
        for path, line_number, name, value, _ in _all_pins():
            if name == arg_name:
                seen.setdefault(value, []).append(f"{path}:{line_number}")
        assert len(seen) == 1, (
            f"{arg_name} is pinned to more than one version; all stages of all images must agree:\n" +
            "\n".join(f"  {version}: {', '.join(sites)}" for version, sites in sorted(seen.items()))
        )


def test_plugin_pins_meet_every_floor():
    """Each floor marks a version below which something breaks silently rather than loudly.

    The galoshes `mux` floor is a wire-format one: below it, galoshes leaves
    Mux.Cool on for its embedded ex-ray, which re-splits the wire format between
    client and server.
    """
    for path, line_number, name, value, _ in _all_pins():
        pinned = Version(value.lstrip("v"))
        for slug, (floor, why) in FLOORS[name].items():
            assert pinned >= floor, (f"{path}:{line_number} pins {name}={value}, below the {slug} floor "
                                     f"v{floor}: {why}.")


def test_every_plugin_pin_carries_the_renovate_marker():
    """An unmarked ARG is invisible to Renovate and drifts away from the marked ones."""
    unmarked = [
        f"  {path}:{line_number} ({name}={value})" for path, line_number, name, value, marked in _all_pins()
        if not marked
    ]
    assert not unmarked, (
        f"These plugin pins lack the Renovate marker comment {RENOVATE_MARKER!r} on the "
        f"line directly above, so Renovate will not bump them:\n" + "\n".join(unmarked)
    )


def test_plugin_bumps_do_not_automerge():
    """A floor only rejects a downgrade; Renovate only ever bumps upward.

    So the floor above cannot catch the case it exists for -- an upstream release
    that re-splits the wire format, landing in the server image with nobody
    looking. CI would be green: the e2e job builds client and server from the
    same bumped pin, so it never stands up a skewed pair.
    """
    config = json.loads((REPO_ROOT / RENOVATE_CONFIG).read_text())
    dep_names = sorted({
        manager["depNameTemplate"]
        for manager in config["customManagers"]
        # Entry 0 captures depName from the file and has no template at all;
        # entry 1 is Lego, which this rule must not cover.
        if manager.get("depNameTemplate", "").startswith("bindreams/hole")
    })
    assert dep_names, f"{RENOVATE_CONFIG} has no bindreams/hole customManager; this test is watching nothing."

    for dep_name in dep_names:
        # packageRules are last-match-wins, so a later rule re-enabling automerge
        # would undo an earlier `false`. Resolve the way Renovate does.
        resolved = None
        for rule in config["packageRules"]:
            if dep_name in rule.get("matchDepNames", []) and "automerge" in rule:
                resolved = rule["automerge"]
        assert resolved is False, (
            f"{RENOVATE_CONFIG} resolves automerge={resolved} for {dep_name}; expected False. "
            f"These plugins are pre-1.0 and wire-facing, and their users supply their own client "
            f"binary, so a bump can be a flag day (galoshes v0.4.0 was one). A human has to decide."
        )
