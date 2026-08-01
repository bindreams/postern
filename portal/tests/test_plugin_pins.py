"""Guard tests for the ex-ray / galoshes version pins (issue #191).

The tunnel server image and the e2e client image each install both plugins from
bindreams/hole. A client older than the server cannot negotiate features the
server offers -- ECH in particular -- so a drifted e2e pin silently turns ECH
coverage into a no-op instead of failing. These tests pin, without Docker or
network:

  (a) every ex-ray pin agrees, and every galoshes pin agrees, across all stages
      of both Dockerfiles;
  (b) every pin meets the ECH floor documented in CLAUDE.md;
  (c) every pin carries the Renovate marker comment, so a Renovate bump moves
      all of them together rather than leaving license stages behind.
"""
from __future__ import annotations

import re
from pathlib import Path

from packaging.version import Version

# portal/tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Both images install both plugins; they talk to each other, so they must agree.
PINNED_FILES = (
    Path("shadowsocks/Dockerfile"),
    Path("portal/tests/e2e/ssclient.Dockerfile"),
)

# ECH (`ech` / `ech-doh` plugin opts) needs these minimums -- see the "Two plugin
# binaries ship in the shadowsocks image" invariant in CLAUDE.md.
ECH_FLOOR = {
    "EX_RAY_VERSION": Version("0.2.0"),
    "GALOSHES_VERSION": Version("0.3.0"),
}

# Exactly the comment .github/renovate.json's customManagers match on. Renovate's
# matchStrings require it on the line immediately above the ARG; an ARG without it
# is invisible to Renovate and drifts.
RENOVATE_MARKER = "# renovate: datasource=github-tags depName=bindreams/hole"

ARG_RE = re.compile(r"^ARG (?P<name>EX_RAY_VERSION|GALOSHES_VERSION)=(?P<value>v\S+)$")


# helpers =====
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


# tests =====
def test_every_pinned_file_declares_both_plugins():
    """A file that stops pinning a plugin would make the agreement tests vacuous."""
    for path in PINNED_FILES:
        names = {name for _, name, _, _ in _pins(path)}
        assert names == {"EX_RAY_VERSION", "GALOSHES_VERSION"}, (
            f"{path} pins {sorted(names)}; expected both EX_RAY_VERSION and GALOSHES_VERSION."
        )


def test_plugin_pins_agree_across_stages_and_images():
    """Server and client images -- and every stage within them -- use one version per plugin."""
    for arg_name in ECH_FLOOR:
        seen: dict[str, list[str]] = {}
        for path, line_number, name, value, _ in _all_pins():
            if name == arg_name:
                seen.setdefault(value, []).append(f"{path}:{line_number}")
        assert len(seen) == 1, (
            f"{arg_name} is pinned to more than one version; all stages of all images must agree:\n" +
            "\n".join(f"  {version}: {', '.join(sites)}" for version, sites in sorted(seen.items()))
        )


def test_plugin_pins_meet_the_ech_floor():
    """Below the floor, `ech`/`ech-doh` plugin opts are silently ignored."""
    for path, line_number, name, value, _ in _all_pins():
        floor = ECH_FLOOR[name]
        assert Version(value.lstrip("v")) >= floor, (
            f"{path}:{line_number} pins {name}={value}, below the ECH floor v{floor}. "
            f"ECH plugin opts would be silently ignored."
        )


def test_every_plugin_pin_carries_the_renovate_marker():
    """An unmarked ARG is invisible to Renovate and drifts away from the marked ones."""
    unmarked = [f"  {path}:{line_number} ({name}={value})"
                for path, line_number, name, value, marked in _all_pins()
                if not marked]
    assert not unmarked, (
        f"These plugin pins lack the Renovate marker comment {RENOVATE_MARKER!r} on the "
        f"line directly above, so Renovate will not bump them:\n" + "\n".join(unmarked)
    )
