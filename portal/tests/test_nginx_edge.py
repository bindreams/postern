"""nginx edge runtime: Cloudflare origin-pull CA pin + edge.sh watcher (issue: edge profiles).

Host-sh + pytest harness. No docker: fake nginx/inotifyd are injected into edge.sh
via the EDGE_NGINX / EDGE_INOTIFYD seams (mirrors render.sh's TEMPLATE_DIR/TARGET_DIR).
"""
from __future__ import annotations

import hashlib
import os
import subprocess
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


def test_edge_initial_reconcile_does_not_reload_a_not_yet_started_nginx(tmp_path):
    # The entrypoint execs nginx the moment edge_start_watcher returns, and nginx's
    # own startup config read picks up a pre-existing *.conf -- so the reconcile has
    # nothing to apply and must not signal. See the self-SIGHUP test below for why
    # signalling here is not merely useless but fatal (issue #245).
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
    assert not nginx_log.exists() or nginx_log.read_text() == ""  # nginx not invoked at all
    assert "no range files" not in r.stderr  # the conf WAS seen; it just needs no reload


def test_edge_initial_reconcile_does_not_signal_the_stale_pidfile(tmp_path):
    """A reconcile that reloads at entrypoint time SIGHUPs the entrypoint itself (#245).

    Drives the real failure rather than asserting the absence of a call: the pidfile
    is seeded with the driver shell's own pid, which is the state `exec nginx` leaves
    behind for the next container. See edge.sh's comment on the watch arm for the
    pid-namespace mechanism.
    """
    edge_dir = tmp_path / "edge"
    edge_dir.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    pidfile = tmp_path / "nginx.pid"
    (edge_dir / "cf-ranges.conf").write_text("set_real_ip_from 173.245.48.0/20;\n")
    # Unlike the logging fake above, this nginx models the part that bites: `-s reload`
    # signals the pidfile's pid rather than being an inert no-op.
    _write_exec(
        bindir / "nginx", f'#!/bin/sh\ncase "$*" in\n'
        f'\t"-s reload") exec kill -HUP "$(cat "{pidfile}")" ;;\n'
        f'esac\nexit 0\n'
    )
    _write_exec(bindir / "inotifyd", "#!/bin/sh\nexit 0\n")
    # The driver stands in for nginx-entrypoint.sh: it is the process that would go on
    # to `exec nginx`, so seeding the pidfile with its own pid is exactly the state a
    # restarted container starts in.
    driver = (
        f'set -eu\n. "{_EDGE_SH}"\n'
        f'echo $$ > "{pidfile}"\n'
        f'edge_start_watcher || exit 1\n'
        f'echo REACHED-EXEC-NGINX\n'
    )
    env = _edge_env(
        EDGE_PROFILE="cloudflare",
        EDGE_DIR=str(edge_dir),
        EDGE_SELF=str(_EDGE_SH),
        EDGE_NGINX=str(bindir / "nginx"),
        EDGE_INOTIFYD=str(bindir / "inotifyd")
    )
    r = subprocess.run(["sh", "-c", driver], env=env, capture_output=True, text=True)
    assert r.returncode == 0, f"entrypoint died (rc={r.returncode}); SIGHUP is rc -1 / 129"
    assert "REACHED-EXEC-NGINX" in r.stdout  # survived to the exec


def test_edge_real_event_triggers_reload(tmp_path):
    edge_dir = tmp_path / "edge"
    edge_dir.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    nginx_log = tmp_path / "nginx.log"
    fifo = tmp_path / "inotify.fifo"
    os.mkfifo(fifo)
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


def test_entrypoint_clears_the_stale_pidfile_before_anything_can_signal_it():
    # Second half of the issue #245 fix: the watcher no longer reloads at boot, but
    # inotifyd is armed BEFORE nginx starts, so a range file landing in that window
    # still reaches `nginx -s reload` while the pidfile is stale. Clearing the file
    # makes that harmless whoever holds the pid now.
    ep = (_REPO_ROOT / "nginx" / "nginx-entrypoint.sh").read_text()
    assert "rm -f /run/nginx.pid" in ep
    # A clear that names a different file than nginx writes is a silent no-op, and
    # the base image's compile-time --pid-path resolves through a /var/run symlink.
    # Pin both sides to one literal so a base-image bump cannot decouple them.
    conf_tmpl = (_REPO_ROOT / "nginx" / "etc" / "nginx.conf.tmpl").read_text()
    assert "pid /run/nginx.pid;" in conf_tmpl, (
        "nginx.conf.tmpl must state the pidfile path the entrypoint clears; "
        "without it the path is the base image's default and the clear can miss"
    )
    reload_loop = "(while true; do sleep 21600; nginx -s reload; done) &"  # anchor on the code, not prose
    assert reload_loop in ep
    assert ep.index("rm -f /run/nginx.pid") < ep.index(reload_loop)
    assert ep.index("rm -f /run/nginx.pid") < ep.index("edge_start_watcher || exit 1")


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
