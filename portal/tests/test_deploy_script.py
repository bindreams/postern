"""scripts/deploy.sh: the one-command deploy sequence (issue #196).

No Docker, no network, no deploy host. Fake `git`, `docker`, and `python3`
executables are put first on PATH; each one appends `<name>|<cwd>|<args>` to a log
file, so the tests assert on the exact commands issued and on their order. Same
harness idea as test_nginx_render.py / test_nginx_edge.py, which drive the nginx
shell scripts through injected seams.

`python3` is faked (not the real `scripts/verify-deploy.py`) because that script
shells out to `git` itself, and deploy.sh's own precondition git calls (this file's
GIT_SHIM) are bare (`git rev-parse HEAD`) rather than `-C`-qualified, so the two
would collide on one fake `git`. Faking the python3 entry point keeps this file
about deploy.sh's own command sequencing; scripts/verify-deploy.py has its own
test suite.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_SH = REPO_ROOT / "scripts" / "deploy.sh"

# Fake git. Behaviour is driven entirely by FAKE_GIT_* env vars so each test
# states its own repo state.
GIT_SHIM = r"""#!/usr/bin/env bash
printf 'git|%s|%s\n' "$PWD" "$*" >> "$DEPLOY_TEST_LOG"
case "$1 ${2:-}" in
"status --porcelain")
    printf '%s' "${FAKE_GIT_DIRTY:-}"
    ;;
"fetch --quiet")
    exit "${FAKE_GIT_FETCH_RC:-0}"
    ;;
"rev-parse HEAD")
    echo "${FAKE_GIT_HEAD:-1111111111111111111111111111111111111111}"
    ;;
"rev-parse origin/main")
    echo "${FAKE_GIT_UPSTREAM:-1111111111111111111111111111111111111111}"
    ;;
"rev-parse --short")
    echo "${FAKE_GIT_HEAD:-1111111}" | cut -c1-7
    ;;
"merge-base --is-ancestor")
    exit "${FAKE_GIT_ANCESTOR_RC:-0}"
    ;;
*)
    echo "fake git: unhandled: $*" >&2
    exit 99
    ;;
esac
"""

# Fake docker. FAKE_DOCKER_FAIL is a substring match against the joined args;
# when it matches, the call fails. Checked after the branches with their own
# canned stdout, so a fixture can still fail e.g. "compose config -q" (which
# has no output of its own to fake) without special-casing it here.
DOCKER_SHIM = r"""#!/usr/bin/env bash
printf 'docker|%s|%s\n' "$PWD" "$*" >> "$DEPLOY_TEST_LOG"
if [[ "$1 ${2:-} ${3:-}" == "compose config --services" ]]; then
    printf '%s\n' ${FAKE_COMPOSE_SERVICES:-nginx portal docker-proxy}
    exit 0
fi
if [[ "$1 ${2:-}" == "compose run" ]]; then
    printf '%s\n' "${FAKE_PORTAL_SS_IMAGE-local/shadowsocks-server}"
    exit 0
fi
if [[ -n "${FAKE_DOCKER_FAIL:-}" && "$*" == *"$FAKE_DOCKER_FAIL"* ]]; then
    exit 1
fi
exit 0
"""

# Fake python3. deploy.sh's only two python3 invocations are both
# `scripts/verify-deploy.py`, matched by their distinguishing flag.
PYTHON_SHIM = r"""#!/usr/bin/env bash
printf 'python3|%s|%s\n' "$PWD" "$*" >> "$DEPLOY_TEST_LOG"
if [[ "$1 ${2:-}" == "scripts/verify-deploy.py --print-revision" ]]; then
    printf '%s\n' "${FAKE_GIT_REVISION:-abc1234}"
    exit "${FAKE_PRINT_REVISION_RC:-0}"
fi
if [[ "$1 ${2:-}" == "scripts/verify-deploy.py --tunnels" ]]; then
    exit "${FAKE_VERIFY_RC:-0}"
fi
echo "fake python3: unhandled: $*" >&2
exit 99
"""


def _harness(tmp_path: Path, **env_over: str) -> tuple[list[str], dict[str, str], Path]:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name, body in (("git", GIT_SHIM), ("docker", DOCKER_SHIM), ("python3", PYTHON_SHIM)):
        shim = bindir / name
        shim.write_text(body)
        shim.chmod(0o755)
    log = tmp_path / "calls.log"
    log.touch()
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["DEPLOY_TEST_LOG"] = str(log)
    env.pop("SHADOWSOCKS_IMAGE", None)  # a host value must never influence a test
    env.pop("GIT_REVISION", None)  # ditto -- deploy.sh must resolve its own
    env.update(env_over)
    return [str(DEPLOY_SH)], env, log


def _run(tmp_path: Path, *args: str, **env_over: str):
    cmd, env, log = _harness(tmp_path, **env_over)
    proc = subprocess.run([*cmd, *args], env=env, capture_output=True, text=True, cwd=str(tmp_path))
    calls = [line.split("|", 2) for line in log.read_text().splitlines()]
    return proc, calls


def _args_of(calls, tool: str) -> list[str]:
    return [args for name, _cwd, args in calls if name == tool]


# Preconditions ========================================================================================================
def test_refuses_a_dirty_worktree(tmp_path):
    proc, calls = _run(tmp_path, FAKE_GIT_DIRTY=" M portal/src/postern/cli.py\n")
    assert proc.returncode != 0
    assert "dirty" in (proc.stdout + proc.stderr).lower()
    assert _args_of(calls, "docker") == []


def test_untracked_files_count_as_dirty(tmp_path):
    """An untracked file is not inert: both Dockerfiles COPY whole directories, so a
    stray file changes what gets baked into the image."""
    proc, calls = _run(tmp_path, FAKE_GIT_DIRTY="?? portal/src/postern/scratch.py\n")
    assert proc.returncode != 0
    assert _args_of(calls, "docker") == []


def test_allow_dirty_warns_instead_of_refusing(tmp_path):
    proc, _calls = _run(tmp_path, "--allow-dirty", FAKE_GIT_DIRTY=" M portal/src/postern/cli.py\n")
    combined = proc.stdout + proc.stderr
    assert "--allow-dirty" in combined  # the warning
    assert "commit, stash" not in combined  # not the refusal


def test_refuses_when_head_is_behind_origin_main(tmp_path):
    proc, calls = _run(tmp_path, FAKE_GIT_ANCESTOR_RC="1")
    assert proc.returncode != 0
    assert "origin/main" in (proc.stdout + proc.stderr)
    assert _args_of(calls, "docker") == []


def test_allow_behind_warns_instead_of_refusing(tmp_path):
    proc, _calls = _run(tmp_path, "--allow-behind", FAKE_GIT_ANCESTOR_RC="1")
    combined = proc.stdout + proc.stderr
    assert "--allow-behind" in combined
    assert "git pull" not in combined


def test_refuses_a_branch_deploy_without_allow_branch(tmp_path):
    proc, calls = _run(tmp_path, FAKE_GIT_HEAD="a" * 40, FAKE_GIT_UPSTREAM="b" * 40)
    assert proc.returncode != 0
    assert "--allow-branch" in (proc.stdout + proc.stderr)
    assert _args_of(calls, "docker") == []


def test_allow_branch_warns_instead_of_refusing(tmp_path):
    proc, _calls = _run(tmp_path, "--allow-branch", FAKE_GIT_HEAD="a" * 40, FAKE_GIT_UPSTREAM="b" * 40)
    combined = proc.stdout + proc.stderr
    assert "--allow-branch" in combined
    assert "must be explicit" not in combined


def test_fetches_origin_main_before_comparing(tmp_path):
    _proc, calls = _run(tmp_path)
    git_calls = _args_of(calls, "git")
    assert "fetch --quiet origin main" in git_calls
    assert git_calls.index("fetch --quiet origin main") < git_calls.index("merge-base --is-ancestor origin/main HEAD")


def test_no_fetch_skips_the_network_call(tmp_path):
    _proc, calls = _run(tmp_path, "--no-fetch")
    assert not any(a.startswith("fetch") for a in _args_of(calls, "git"))


def test_a_failed_fetch_aborts_the_deploy(tmp_path):
    proc, calls = _run(tmp_path, FAKE_GIT_FETCH_RC="1")
    assert proc.returncode != 0
    assert _args_of(calls, "docker") == []


def test_runs_from_the_repo_root_regardless_of_cwd(tmp_path):
    _proc, calls = _run(tmp_path)
    assert calls, "no commands recorded"
    assert all(cwd == str(REPO_ROOT) for _name, cwd, _args in calls)


def test_unknown_option_is_rejected(tmp_path):
    proc, calls = _run(tmp_path, "--turbo")
    assert proc.returncode != 0
    assert "--turbo" in (proc.stdout + proc.stderr)
    assert calls == []


def test_help_exits_zero_and_touches_nothing(tmp_path):
    proc, calls = _run(tmp_path, "--help")
    assert proc.returncode == 0
    assert calls == []


def test_deploy_script_is_executable():
    assert os.access(DEPLOY_SH, os.X_OK), "scripts/deploy.sh must be committed with the executable bit"


# Tunnel image resolution + build ======================================================================================
def test_builds_the_tag_the_portal_reports(tmp_path):
    _proc, calls = _run(tmp_path, FAKE_PORTAL_SS_IMAGE="local/ss-from-portal")
    build = [(cwd, args) for name, cwd, args in calls if name == "docker" and args.startswith("build ")]
    assert len(build) == 1
    cwd, args = build[0]
    assert cwd == str(REPO_ROOT)
    assert args.startswith("build -f shadowsocks/Dockerfile ")
    assert args.endswith("-t local/ss-from-portal .")


def test_default_tag_when_the_portal_reports_the_default(tmp_path):
    _proc, calls = _run(tmp_path)
    assert any(
        a.startswith("build -f shadowsocks/Dockerfile ") and a.endswith("-t local/shadowsocks-server .")
        for a in _args_of(calls, "docker")
    )


def test_the_tag_comes_from_the_portal_not_the_shell_environment(tmp_path):
    """compose.yaml gives the portal SHADOWSOCKS_IMAGE only via `env_file: .env`, so a
    value exported in the deploying shell never reaches it. Honouring the shell here
    would build a tag the reconciler never looks up."""
    _proc, calls = _run(tmp_path, SHADOWSOCKS_IMAGE="local/ss-shell", FAKE_PORTAL_SS_IMAGE="local/ss-portal")
    assert any(a.endswith("-t local/ss-portal .") for a in _args_of(calls, "docker"))
    assert not any("ss-shell" in a for a in _args_of(calls, "docker"))


def test_the_portal_image_is_built_before_it_is_queried(tmp_path):
    _proc, calls = _run(tmp_path)
    docker_calls = _args_of(calls, "docker")
    built = docker_calls.index("compose build portal")
    queried = next(i for i, a in enumerate(docker_calls) if a.startswith("compose run "))
    assert built < queried


def test_the_query_uses_a_throwaway_container_with_no_dependencies(tmp_path):
    _proc, calls = _run(tmp_path)
    query = next(a for a in _args_of(calls, "docker") if a.startswith("compose run "))
    assert query.startswith("compose run --rm --no-deps -T portal python -c ")
    assert "shadowsocks_image" in query


def test_refuses_when_the_portal_reports_an_empty_tag(tmp_path):
    proc, calls = _run(tmp_path, FAKE_PORTAL_SS_IMAGE="")
    assert proc.returncode != 0
    assert "SHADOWSOCKS_IMAGE" in (proc.stdout + proc.stderr)
    assert not any(a.startswith("build ") for a in _args_of(calls, "docker"))


def test_a_failed_portal_build_stops_the_deploy(tmp_path):
    proc, calls = _run(tmp_path, FAKE_DOCKER_FAIL="compose build portal")
    assert proc.returncode != 0
    assert not any(a.startswith("build ") for a in _args_of(calls, "docker"))
    assert not any(a.startswith("compose up") for a in _args_of(calls, "docker"))


def test_a_failed_shadowsocks_build_stops_the_deploy(tmp_path):
    proc, calls = _run(tmp_path, FAKE_DOCKER_FAIL="build -f shadowsocks/Dockerfile")
    assert proc.returncode != 0
    assert not any(a.startswith("compose up") for a in _args_of(calls, "docker"))


# Build provenance (GIT_REVISION) ======================================================================================
def test_resolves_and_stamps_the_git_revision_before_building(tmp_path):
    _proc, calls = _run(tmp_path, FAKE_GIT_REVISION="deadbeef-fake")
    python_calls = _args_of(calls, "python3")
    assert "scripts/verify-deploy.py --print-revision" in python_calls

    build = next(a for a in _args_of(calls, "docker") if a.startswith("build "))
    assert "--build-arg GIT_REVISION=deadbeef-fake" in build


def test_revision_is_resolved_before_the_shadowsocks_build(tmp_path):
    _proc, calls = _run(tmp_path)
    python_calls = _args_of(calls, "python3")
    docker_calls = _args_of(calls, "docker")
    resolved = python_calls.index("scripts/verify-deploy.py --print-revision")
    built = next(i for i, a in enumerate(docker_calls) if a.startswith("build "))
    # Different logs, but both append in issue order relative to the merged log:
    all_calls = [(name, args) for name, _cwd, args in calls]
    resolved_pos = all_calls.index(("python3", python_calls[resolved]))
    built_pos = all_calls.index(("docker", docker_calls[built]))
    assert resolved_pos < built_pos


def test_a_failed_revision_resolution_stops_the_deploy_before_any_build(tmp_path):
    proc, calls = _run(tmp_path, FAKE_PRINT_REVISION_RC="1")
    assert proc.returncode != 0
    assert not any(a.startswith("build ") for a in _args_of(calls, "docker"))
    assert not any(a.startswith("compose build") for a in _args_of(calls, "docker"))


# Compose + reconcile ==================================================================================================
def test_compose_up_builds_and_detaches(tmp_path):
    _proc, calls = _run(tmp_path)
    assert "compose up -d --build" in _args_of(calls, "docker")


def test_compose_calls_pass_no_file_or_profile_flags(tmp_path):
    """COMPOSE_FILE / COMPOSE_PROFILES come from .env; re-deriving them here would
    silently break the cert / gateway / edge overlays. Scoped to `compose` calls --
    the shadowsocks build legitimately uses `-f shadowsocks/Dockerfile`."""
    _proc, calls = _run(tmp_path)
    compose_calls = [a for a in _args_of(calls, "docker") if a.startswith("compose ")]
    assert compose_calls, "no compose calls recorded"
    for args in compose_calls:
        assert " -f " not in f" {args} "
        assert "--profile" not in args


def test_allow_flags_let_the_whole_deploy_proceed(tmp_path):
    """The precondition tests above prove the refusal is skipped; this proves the
    deploy that follows actually runs."""
    _proc, calls = _run(
        tmp_path,
        "--allow-dirty",
        "--allow-behind",
        "--allow-branch",
        FAKE_GIT_DIRTY=" M portal/src/postern/cli.py\n",
        FAKE_GIT_ANCESTOR_RC="1",
        FAKE_GIT_HEAD="a" * 40,
        FAKE_GIT_UPSTREAM="b" * 40,
    )
    docker_calls = _args_of(calls, "docker")
    assert any(a.startswith("build ") for a in docker_calls)
    assert "compose up -d --build" in docker_calls


def test_reconcile_is_triggered_and_waited_on(tmp_path):
    _proc, calls = _run(tmp_path)
    assert any(a.startswith("compose exec -T portal postern reconcile --wait") for a in _args_of(calls, "docker"))


def test_reconcile_wait_has_a_bounded_default_timeout(tmp_path):
    """Unbounded would hang this script (and every deploy after it) forever if the
    reconciler's single background task ever died for a reason unrelated to a slow
    pass -- see reconcile_and_wait's comment. A generous but real default replaces
    it."""
    _proc, calls = _run(tmp_path)
    assert "compose exec -T portal postern reconcile --wait --wait-timeout 1800" in _args_of(calls, "docker")


def test_wait_timeout_is_passed_through_when_asked_for(tmp_path):
    _proc, calls = _run(tmp_path, "--wait-timeout", "300")
    assert "compose exec -T portal postern reconcile --wait --wait-timeout 300" in _args_of(calls, "docker")
    assert not any("1800" in a for a in _args_of(calls, "docker"))


def test_wait_timeout_without_a_value_is_rejected(tmp_path):
    proc, calls = _run(tmp_path, "--wait-timeout")
    assert proc.returncode != 0
    assert calls == []


def test_a_non_numeric_wait_timeout_is_rejected_before_anything_runs(tmp_path):
    """Letting the failure surface at the reconcile step would mean two image builds
    and a stack restart first -- the same argument that put check_compose_config up
    front."""
    proc, calls = _run(tmp_path, "--wait-timeout", "abc")
    assert proc.returncode != 0
    assert calls == []


def test_wait_timeout_does_not_swallow_a_following_flag(tmp_path):
    proc, calls = _run(tmp_path, "--wait-timeout", "--no-fetch")
    assert proc.returncode != 0
    assert calls == []


def test_a_zero_wait_timeout_is_rejected(tmp_path):
    """The CLI reads 0 as 'wait forever', which is the opposite of a bound -- and
    this script always wants one (DEFAULT_WAIT_TIMEOUT unless overridden)."""
    proc, calls = _run(tmp_path, "--wait-timeout", "0")
    assert proc.returncode != 0
    assert calls == []


def test_steps_run_in_order(tmp_path):
    _proc, calls = _run(tmp_path)
    all_calls = [(name, args) for name, _cwd, args in calls]

    def pos(name: str, predicate) -> int:
        return next(i for i, (n, a) in enumerate(all_calls) if n == name and predicate(a))

    resolved = pos("python3", lambda a: a == "scripts/verify-deploy.py --print-revision")
    portal_build = pos("docker", lambda a: a == "compose build portal")
    query = pos("docker", lambda a: a.startswith("compose run "))
    ss_build = pos("docker", lambda a: a.startswith("build "))
    up = pos("docker", lambda a: a == "compose up -d --build")
    reconcile = pos("docker", lambda a: a.startswith("compose exec -T portal postern reconcile --wait"))
    verify = pos("python3", lambda a: a.startswith("scripts/verify-deploy.py --tunnels"))
    assert resolved < portal_build < query < ss_build < up < reconcile < verify


def test_a_failed_compose_up_stops_before_reconcile(tmp_path):
    proc, calls = _run(tmp_path, FAKE_DOCKER_FAIL="compose up")
    assert proc.returncode != 0
    assert not any("reconcile" in a for a in _args_of(calls, "docker"))


def test_a_failed_reconcile_stops_before_verification(tmp_path):
    """`--print-revision` legitimately ran earlier (build provenance); it's the
    `--tunnels` verification call specifically that must never happen."""
    proc, calls = _run(tmp_path, FAKE_DOCKER_FAIL="postern reconcile")
    assert proc.returncode != 0
    assert not any(a.startswith("scripts/verify-deploy.py --tunnels") for a in _args_of(calls, "python3"))


# Operator notices =====================================================================================================
def test_warns_that_every_tunnel_drops(tmp_path):
    proc, _calls = _run(tmp_path)
    out = proc.stdout + proc.stderr
    assert "tunnel" in out.lower()
    assert "ss-" in out


def test_notes_the_provisioner_startup_gate_when_the_provisioner_is_active(tmp_path):
    proc, _calls = _run(tmp_path, FAKE_COMPOSE_SERVICES="nginx portal provisioner")
    out = proc.stdout + proc.stderr
    assert "provisioner" in out
    assert "compose.cert.yaml" in out


def test_no_provisioner_note_when_it_is_not_in_the_active_profiles(tmp_path):
    proc, _calls = _run(tmp_path, FAKE_COMPOSE_SERVICES="nginx portal docker-proxy")
    assert "compose.cert.yaml" not in (proc.stdout + proc.stderr)


def test_a_broken_compose_config_is_refused_before_anything_is_built(tmp_path):
    """A missing .env is fatal for the portal's env_file:. Finding out at `compose up`
    would mean two image builds and a restarted stack first."""
    proc, calls = _run(tmp_path, FAKE_DOCKER_FAIL="compose config -q")
    assert proc.returncode != 0
    assert "docker compose config" in (proc.stdout + proc.stderr)
    docker_calls = _args_of(calls, "docker")
    assert not any(a.startswith("build ") for a in docker_calls)
    assert "compose build portal" not in docker_calls


# Verification (scripts/verify-deploy.py) ==============================================================================
def test_verification_runs_last_scoped_to_tunnels(tmp_path):
    _proc, calls = _run(tmp_path)
    python_calls = _args_of(calls, "python3")
    assert python_calls[-1] == "scripts/verify-deploy.py --tunnels"


def test_a_clean_verification_reports_success(tmp_path):
    proc, _calls = _run(tmp_path)
    assert proc.returncode == 0
    assert "Deploy complete" in proc.stdout


def test_a_stale_deploy_fails_the_script(tmp_path):
    proc, _calls = _run(tmp_path, FAKE_VERIFY_RC="1")
    assert proc.returncode != 0
    assert "Deploy complete" not in proc.stdout


def test_a_verifier_that_could_not_run_is_reported_distinctly_from_a_stale_deploy(tmp_path):
    """Exit 2 from verify-deploy.py means the gate itself could not run (bad
    --project-dir, docker missing, ...) -- not a verdict on the deployment. The
    operator-facing message must not say the deploy is stale when it might not be."""
    stale_proc, _ = _run(tmp_path, FAKE_VERIFY_RC="1")
    broken_proc, _ = _run(tmp_path, FAKE_VERIFY_RC="2")
    assert stale_proc.returncode != 0
    assert broken_proc.returncode != 0
    assert (stale_proc.stdout + stale_proc.stderr) != (broken_proc.stdout + broken_proc.stderr)
    broken_out = (broken_proc.stdout + broken_proc.stderr).lower()
    assert "could not run" in broken_out


def test_allow_dirty_is_forwarded_to_verification(tmp_path):
    """--allow-dirty means the built image corresponds to no committed revision;
    verify-deploy.py must be told, or its own dirty-checkout check fails a deploy
    the operator explicitly acknowledged."""
    _proc, calls = _run(tmp_path, "--allow-dirty", FAKE_GIT_DIRTY=" M portal/src/postern/cli.py\n")
    verify_call = next(a for a in _args_of(calls, "python3") if a.startswith("scripts/verify-deploy.py --tunnels"))
    assert "--allow-dirty" in verify_call


def test_allow_dirty_is_not_forwarded_on_a_clean_deploy(tmp_path):
    _proc, calls = _run(tmp_path)
    verify_call = next(a for a in _args_of(calls, "python3") if a.startswith("scripts/verify-deploy.py --tunnels"))
    assert "--allow-dirty" not in verify_call


def test_success_line_marks_a_dirty_deploy(tmp_path):
    """--allow-dirty means the built image matches no commit; the closing line must
    not claim a clean SHA without saying so."""
    proc, _calls = _run(tmp_path, "--allow-dirty", FAKE_GIT_DIRTY=" M portal/src/postern/cli.py\n")
    assert proc.returncode == 0
    assert "dirty worktree" in proc.stdout
