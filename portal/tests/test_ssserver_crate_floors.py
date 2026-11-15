"""Rust crate floors for the ssserver and e2e sslocal builds (issues #254, #326).

`external/shadowsocks-rust/Cargo.lock` is upstream's, so a crate with a RustSec fix
newer than the lock is raised at build time by shadowsocks/crate-floors.sh, which both
shadowsocks/Dockerfile and portal/tests/e2e/ssclient.Dockerfile run before
`cargo build`. The floor list lives only in that script; this module reads it.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "shadowsocks/crate-floors.sh"
LOCKFILE = REPO_ROOT / "external/shadowsocks-rust/Cargo.lock"
DOCKERFILES = ("shadowsocks/Dockerfile", "portal/tests/e2e/ssclient.Dockerfile")

# The first releases that stop trusting the compromised eMudhra chain (#254).
EMSIGN_DISTRUST_FLOORS = {
    "rustls-webpki": Version("0.103.16"),
    "webpki-roots": Version("1.0.10"),
    "webpki-root-certs": Version("1.0.10"),
}


def _parse_floors(text: str) -> list[tuple[str, str]]:
    """`(crate, floor)` for each entry of the script's `floors=( ... )` array, in order."""
    block = re.search(r"^floors=\(\n(.*?)^\)$", text, re.M | re.S)
    assert block is not None, "no floors=( ... ) array in crate-floors.sh"
    entries = re.findall(r'^\t"(\S+) (\S+)"$', block[1], re.M)
    assert entries and len(entries) == len(block[1].strip().splitlines()), "malformed floors entry"
    return entries


FLOORS = _parse_floors(SCRIPT.read_text()) if SCRIPT.exists() else []


def _locked_versions(lockfile: Path, crate: str) -> list[str]:
    """Raw version strings of every locked entry of `crate`."""
    return re.findall(rf'^name = "{re.escape(crate)}"\nversion = "([^"]+)"', lockfile.read_text(), re.M)


def _same_series(locked: str, floor: str) -> bool:
    """Semver-compatible: same major, or for 0.x the same (major, minor). Build metadata
    (`+zstd.1.5.7`) is ignored."""
    version, floor_version = Version(locked.split("+")[0]), Version(floor)
    if floor_version.major == 0:
        return (version.major, version.minor) == (floor_version.major, floor_version.minor)
    return version.major == floor_version.major


def test_each_crate_is_floored_once():
    crates = [crate for crate, _floor in FLOORS]
    assert crates
    assert len(crates) == len(set(crates)), sorted({c for c in crates if crates.count(c) > 1})


@pytest.mark.parametrize(("crate", "floor"), FLOORS)
def test_floored_crate_is_in_the_vendored_lock(crate: str, floor: str):
    """A floor for a crate the lock no longer carries in that series is dead weight."""
    assert any(_same_series(v, floor) for v in _locked_versions(LOCKFILE, crate)), (crate, floor)


def test_emsign_distrust_floors_are_not_loosened():
    floors = {crate: Version(floor) for crate, floor in FLOORS}
    for crate, minimum in EMSIGN_DISTRUST_FLOORS.items():
        assert crate in floors, crate
        assert floors[crate] >= minimum, (crate, floors[crate], minimum)


@pytest.mark.parametrize("dockerfile", DOCKERFILES)
def test_build_stage_applies_floors_before_cargo_build(dockerfile: str):
    """Both builds compile the same vendored tree, so both raise the same crates."""
    text = (REPO_ROOT / dockerfile).read_text()
    assert re.search(r"^COPY --chmod=755 shadowsocks/crate-floors\.sh /usr/local/bin/crate-floors\.sh$", text, re.M)
    run = re.search(r"^RUN crate-floors\.sh$", text, re.M)
    build = re.search(r"^RUN cargo build ", text, re.M)
    assert run is not None and build is not None and run.start() < build.start()
    assert not re.search(r"cargo update", text), "floors belong in crate-floors.sh only"


# The script, run against a throwaway lock with a fake `cargo` =========================================================

_FAKE_CARGO = r"""#!/usr/bin/env bash
# Logs the call; `update -p <crate>@<old> --precise <new>` rewrites the lock unless CARGO_NOOP is set.
printf '%s\n' "$*" >> "$CARGO_LOG"
if [[ -n ${CARGO_NOOP:-} ]]; then exit 0; fi
spec=${3%@*}; old=${3#*@}
sed -i "/^name = \"$spec\"\$/{n;s/^version = \"$old\"\$/version = \"$5\"/}" Cargo.lock
"""


def _lock_text(overrides: dict[str, str]) -> str:
    entries = (f'[[package]]\nname = "{crate}"\nversion = "{overrides.get(crate, floor)}"\n' for crate, floor in FLOORS)
    # A same-named entry in another series is never touched: the floor is for its own series.
    return "version = 4\n\n" + "\n".join(entries) + '\n[[package]]\nname = "tokio"\nversion = "0.2.25"\n'


def _run_script(tmp_path: Path, lock: str, **env: str) -> tuple[subprocess.CompletedProcess[str], list[str], str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cargo = bin_dir / "cargo"
    cargo.write_text(_FAKE_CARGO)
    cargo.chmod(cargo.stat().st_mode | stat.S_IXUSR)
    work = tmp_path / "src"
    work.mkdir()
    (work / "Cargo.lock").write_text(lock)
    log = tmp_path / "cargo.log"
    log.touch()
    result = subprocess.run(
        ["bash", SCRIPT.as_posix()],
        cwd=work,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "CARGO_LOG": str(log), **env},
    )
    return result, log.read_text().splitlines(), (work / "Cargo.lock").read_text()


def test_script_raises_only_crates_below_their_floor(tmp_path: Path):
    stale = {"tokio": "1.0.0", "zstd-sys": "2.0.1+zstd.1.5.7"}
    result, calls, lock = _run_script(tmp_path, _lock_text(stale))
    assert result.returncode == 0, result.stderr
    floors = dict(FLOORS)
    assert sorted(calls) == sorted([
        f"update -p tokio@1.0.0 --precise {floors['tokio']}",
        f"update -p zstd-sys@2.0.1+zstd.1.5.7 --precise {floors['zstd-sys']}",
    ])
    assert f'name = "tokio"\nversion = "{floors["tokio"]}"' in lock
    assert 'name = "tokio"\nversion = "0.2.25"' in lock


def test_script_leaves_a_lock_that_meets_every_floor_alone(tmp_path: Path):
    result, calls, _lock = _run_script(tmp_path, _lock_text({}))
    assert result.returncode == 0, result.stderr
    assert calls == []


def test_script_fails_naming_a_crate_the_update_did_not_raise(tmp_path: Path):
    result, _calls, _lock = _run_script(tmp_path, _lock_text({"rustls": "0.23.1"}), CARGO_NOOP="1")
    assert result.returncode != 0
    assert "rustls" in result.stderr and "0.23.1" in result.stderr
