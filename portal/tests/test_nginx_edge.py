"""nginx edge runtime: Cloudflare origin-pull CA pin + edge.sh watcher (issue: edge profiles).

Host-sh + pytest harness. No docker: fake nginx/inotifyd are injected into edge.sh
via the EDGE_NGINX / EDGE_INOTIFYD seams (mirrors render.sh's TEMPLATE_DIR/TARGET_DIR).
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import pytest
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EDGE_SH = _REPO_ROOT / "nginx" / "edge.sh"
_CF_CA = _REPO_ROOT / "nginx" / "etc" / "cloudflare-origin-pull-ca.pem"

# Pins captured from a live fetch of Cloudflare's published origin-pull CA,
# verified 2026-07. File bytes + the DER fingerprint (CF's published value) are
# both pinned so neither a re-encode nor a swapped cert can slip through.
_CF_CA_FILE_SHA256 = "c14fed0ce5210db0719fea11d1f10b33750dc17d609aeaf47c75e9eff0d7b843"
_CF_CA_DER_SHA256 = "9a1ac2b4be15f9f27eee20a734cba4e9898f61001b3bd7c84b69b56a3e25a2b9"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


# Cloudflare origin-pull CA ============================================================================================
def test_cloudflare_origin_pull_ca_is_pinned_and_correct():
    data = _CF_CA.read_bytes()
    assert hashlib.sha256(data).hexdigest() == _CF_CA_FILE_SHA256
    cert = x509.load_pem_x509_certificate(data)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "origin-pull.cloudflare.net"
    assert cert.fingerprint(hashes.SHA256()).hex() == _CF_CA_DER_SHA256


# edge.sh watcher ======================================================================================================
def _edge_env(**over) -> dict:
    env = dict(os.environ)
    env.update(over)
    return env


def test_edge_start_watcher_is_noop_without_cloudflare(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    nginx_log = tmp_path / "nginx.log"
    _write_exec(bindir / "nginx", f'#!/bin/sh\nprintf \'%s\\n\' "$*" >> "{nginx_log}"\nexit 0\n')
    driver = f'set -eu\n. "{_EDGE_SH}"\nedge_start_watcher || exit 1\n'
    env = _edge_env(
        EDGE_PROFILE="none", EDGE_NGINX=str(bindir / "nginx"), EDGE_INOTIFYD=str(bindir / "inotifyd-absent")
    )
    r = subprocess.run(["sh", "-c", driver], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert not nginx_log.exists() or nginx_log.read_text() == ""  # profile gate: nginx untouched


def test_edge_missing_inotifyd_under_cloudflare_is_fatal(tmp_path):
    edge_dir = tmp_path / "edge"
    edge_dir.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "nginx", "#!/bin/sh\nexit 0\n")
    driver = f'. "{_EDGE_SH}"\nedge_start_watcher || exit 1\n'  # NOTE: no check=True; assert rc
    env = _edge_env(
        EDGE_PROFILE="cloudflare",
        EDGE_DIR=str(edge_dir),
        EDGE_SELF=str(_EDGE_SH),
        EDGE_NGINX=str(bindir / "nginx"),
        EDGE_INOTIFYD=str(bindir / "inotifyd-absent")
    )
    r = subprocess.run(["sh", "-c", driver], env=env, capture_output=True, text=True)
    assert r.returncode != 0
    assert "FATAL inotifyd missing" in r.stderr


def test_edge_initial_reconcile_applies_preexisting_conf(tmp_path):
    edge_dir = tmp_path / "edge"
    edge_dir.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    nginx_log = tmp_path / "nginx.log"
    (edge_dir / "cf-ranges.conf").write_text("set_real_ip_from 173.245.48.0/20;\n")  # seeded BEFORE watch
    _write_exec(bindir / "nginx", f'#!/bin/sh\nprintf \'%s\\n\' "$*" >> "{nginx_log}"\nexit 0\n')
    _write_exec(bindir / "inotifyd", "#!/bin/sh\nexit 0\n")  # backgrounded no-op; reconcile is synchronous
    driver = f'set -eu\n. "{_EDGE_SH}"\nedge_start_watcher || exit 1\n'
    env = _edge_env(
        EDGE_PROFILE="cloudflare",
        EDGE_DIR=str(edge_dir),
        EDGE_SELF=str(_EDGE_SH),
        EDGE_NGINX=str(bindir / "nginx"),
        EDGE_INOTIFYD=str(bindir / "inotifyd")
    )
    r = subprocess.run(["sh", "-c", driver], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert nginx_log.read_text().splitlines() == ["-t", "-s reload"]  # validated then reloaded


def test_edge_real_event_triggers_reload(tmp_path):
    edge_dir = tmp_path / "edge"
    edge_dir.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    nginx_log = tmp_path / "nginx.log"
    fifo = tmp_path / "inotify.fifo"
    try:
        os.mkfifo(fifo)
    except OSError:
        # Named pipes not supported on Windows — skip this Linux/named-pipe test
        if sys.platform == 'win32':
            pytest.skip("named pipes not supported on this platform")
        raise
    staged = tmp_path / "staged.conf"
    staged.write_text("set_real_ip_from 173.245.48.0/20;\n")
    conf = edge_dir / "cf-ranges.conf"
    _write_exec(bindir / "nginx", f'#!/bin/sh\nprintf \'%s\\n\' "$*" >> "{nginx_log}"\nexit 0\n')
    # Fake busybox inotifyd: block on a real named pipe until the test signals the
    # move, then EXEC PROG exactly like inotifyd would (PROG <events> <dir> <name>).
    _write_exec(
        bindir / "inotifyd", f'#!/bin/sh\nprog="$1"; spec="$2"; dir="${{spec%%:*}}"\n'
        f'name="$(cat "{fifo}")"\nexec "$prog" "y" "$dir" "$name"\n'
    )
    # Sequential driver: arm watch (EDGE_DIR empty -> warns, NO reconcile), then
    # atomic-rename the conf in, then rendezvous on the FIFO, then wait for PROG.
    driver = (
        f'set -eu\n. "{_EDGE_SH}"\n'
        f'edge_start_watcher || exit 1\n'
        f'mv "{staged}" "{conf}"\n'
        f'printf \'%s\\n\' "cf-ranges.conf" > "{fifo}"\n'
        f'wait "$EDGE_WATCHER_PID"\n'
    )
    env = _edge_env(
        EDGE_PROFILE="cloudflare",
        EDGE_DIR=str(edge_dir),
        EDGE_SELF=str(_EDGE_SH),
        EDGE_NGINX=str(bindir / "nginx"),
        EDGE_INOTIFYD=str(bindir / "inotifyd")
    )
    r = subprocess.run(["sh", "-c", driver], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert nginx_log.read_text().splitlines() == ["-t", "-s reload"]  # reload came from the EVENT
    assert "no range files" in r.stderr  # empty at arm time => reload was NOT an initial reconcile


# entrypoint wiring ====================================================================================================
def test_entrypoint_sources_and_gates_edge_watcher():
    ep = (_REPO_ROOT / "nginx" / "nginx-entrypoint.sh").read_text()
    assert ". /usr/local/bin/edge.sh" in ep
    assert "edge_start_watcher || exit 1" in ep
    # watcher armed before the exec so its inotifyd child (like the 6h loop) survives it
    assert ep.index("edge_start_watcher || exit 1") < ep.index("exec nginx")


def test_dockerfile_ships_edge_sh():
    df = (_REPO_ROOT / "nginx" / "Dockerfile").read_text()
    assert "COPY --chmod=755 edge.sh /usr/local/bin/edge.sh" in df


def test_edge_reload_failure_references_6h_backstop(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    nginx_log = tmp_path / "nginx.log"
    _write_exec(
        bindir / "nginx", f'#!/bin/sh\nprintf \'%s\\n\' "$*" >> "{nginx_log}"\n'
        f'case "$*" in "-t") exit 1 ;; esac\nexit 0\n'
    )  # validation REJECTS the config
    driver = f'. "{_EDGE_SH}"\nedge_reload\n'
    env = _edge_env(EDGE_NGINX=str(bindir / "nginx"))
    r = subprocess.run(["sh", "-c", driver], env=env, capture_output=True, text=True)
    assert r.returncode == 0  # non-fatal, retryable
    assert nginx_log.read_text().splitlines() == ["-t"]  # reload skipped after -t failure
    assert "6h reload loop is the bounded backstop" in r.stderr
    assert "next change" not in r.stderr  # must NOT claim retry-on-next-change
