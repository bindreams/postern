"""Unit tests for scripts/verify-deploy.py (issue #195).

The script is host-side and stdlib-only, so it is loaded by path rather than
imported -- the same reach-out-of-portal pattern as tests/test_nginx_render.py.
No test here touches Docker or the network: `collect()` takes an injected
runner and `evaluate()` is pure.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "verify-deploy.py"


def _load():
    spec = importlib.util.spec_from_file_location("verify_deploy", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registering before exec is required, not cosmetic: the script uses
    # `from __future__ import annotations`, so every dataclass field annotation
    # is a string, and dataclasses resolves them via
    # sys.modules[cls.__module__].__dict__. Without this line every dataclass
    # in the script raises AttributeError: 'NoneType' has no attribute
    # '__dict__' at import, and the whole test file errors during collection.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vd = _load()


# Revision oracle ------------------------------------------------------------------------------------------------------
def _git(repo: Path, *args: str) -> None:
    # Disable signing: a global commit.gpgsign=true would break the fixture.
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "-c", "gpg.format=openpgp", *args],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a.txt").write_text("one\n")
    _git(tmp_path, "add", "a.txt")
    _git(tmp_path, "commit", "-qm", "one")
    return tmp_path


def test_git_revision_is_the_head_sha(repo):
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True,
                          text=True).stdout.strip()
    assert vd.git_revision(repo) == head


def test_git_revision_marks_a_modified_tree_dirty(repo):
    (repo / "a.txt").write_text("two\n")
    assert vd.git_revision(repo).endswith("-dirty")


def test_git_revision_marks_untracked_files_dirty(repo):
    (repo / "b.txt").write_text("new\n")
    assert vd.git_revision(repo).endswith("-dirty")


def test_git_revision_ignores_gitignored_files(repo):
    (repo / ".gitignore").write_text("junk/\n")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-qm", "ignore")
    (repo / "junk").mkdir()
    (repo / "junk" / "x").write_text("x\n")
    assert not vd.git_revision(repo).endswith("-dirty")


# Report ---------------------------------------------------------------------------------------------------------------
def test_exit_code_zero_when_nothing_failed():
    report = vd.Report(project="postern", revision="abc", checks=[vd.Check("a", "ok"), vd.Check("b", "skip")])
    assert report.exit_code == 0


def test_exit_code_one_on_any_failure():
    report = vd.Report(
        project="postern", revision="abc", checks=[vd.Check("a", "ok"),
                                                   vd.Check("b", "fail", fix="do it")]
    )
    assert report.exit_code == 1
    assert [c.label for c in report.failures] == ["b"]


def test_exit_code_override_wins_over_the_computed_value():
    """main()'s CollectError path needs a Report whose printed text/JSON
    reads as a failure (it carries one failing Check) but whose exit_code is
    2, not the computed 1 -- "could not run" is not "the deployment is
    stale"."""
    report = vd.Report(project="", revision="abc", checks=[vd.Check("a", "fail", fix="x")], exit_code_override=2)
    assert report.exit_code == 2


# Rendering ------------------------------------------------------------------------------------------------------------
def test_render_text_shows_project_revision_markers_and_fixes():
    report = vd.Report(
        project="postern",
        revision="abc123",
        checks=[
            vd.Check("portal", "ok", detail="on abc123"),
            vd.Check("nginx", "fail", detail="stale", fix="docker compose up -d --build"),
        ]
    )
    out = vd.render_text(report)
    assert "postern" in out and "abc123" in out
    assert "[OK]" in out and "[FAIL]" in out
    assert "docker compose up -d --build" in out
    assert "1 of 2 checks failed" in out


def test_render_text_all_passed():
    report = vd.Report(project="p", revision="abc123", checks=[vd.Check("portal", "ok")])
    assert "All 1 checks passed." in vd.render_text(report)


def test_render_text_columns_align():
    """Includes the longest label the tool actually emits, so _LABEL_W cannot
    silently become too narrow."""
    longest = f"tunnel ss-{'0' * 24}: image identity"
    report = vd.Report(project="p", revision="r", checks=[vd.Check("a", "ok", "d1"), vd.Check(longest, "ok", "d2")])
    rows = [ln for ln in vd.render_text(report).splitlines() if ln.startswith("[OK]")]
    assert rows[0].index("d1") == rows[1].index("d2")


def test_render_json_shape():
    report = vd.Report(project="postern", revision="abc123", checks=[vd.Check("portal", "fail", detail="d", fix="f")])
    payload = json.loads(vd.render_json(report))
    assert payload["exit_code"] == 1
    assert payload["project"] == "postern"
    assert payload["revision"] == "abc123"
    assert payload["checks"] == [{"label": "portal", "status": "fail", "detail": "d", "fix": "f"}]


# Collection -----------------------------------------------------------------------------------------------------------
HEAD = "c" * 40

_CONFIG_JSON = """
{"name": "postern", "services": {
  "portal": {"image": "local/postern-portal", "build": {"context": "."}},
  "nginx": {"image": "local/nginx", "build": {"context": "./nginx"}},
  "docker-proxy": {"image": "tecnativa/docker-socket-proxy:v0.4.2"}
}}
"""

_CONTAINERS_OUT = (
    f"/postern-portal\tportal\trunning\t0\tunless-stopped\tsha256:aaa\t{HEAD}\thealthy\n"
    f"/postern-nginx\tnginx\trunning\t0\tunless-stopped\tsha256:bbb\t{HEAD}\t\n"
    f"/postern-docker-proxy\tdocker-proxy\trunning\t0\tunless-stopped\tsha256:ccc\t\thealthy\n"
)

_TUNNELS_OUT = f"/ss-abc\t\trunning\t0\tunless-stopped\tsha256:ddd\t{HEAD}\t\n"


def _ok(stdout: str) -> "vd.Completed":
    return vd.Completed(0, stdout, "")


class FakeRunner:
    """Replays canned docker output.

    Dispatch is on argv *structure*, never on a substring of the joined command
    line: `--format` and friends sit between the tokens a naive substring key
    would try to match. Exactly one rule must match, so an ambiguous fixture
    fails loudly instead of silently returning the first hit.

    Every canned response is an explicit constructor knob -- no rule surgery
    from the outside, which would be silently order-dependent.
    """

    def __init__(
        self,
        *,
        tunnels=False,
        image_overrides=None,
        project_names=None,
        containers_out=None,
        tunnels_out=None,
        config_out=None,
        ps_out=None,
    ):
        self.image_overrides = image_overrides or {}
        self.calls: list[tuple[list[str], object]] = []
        project_names = (
            "postern-portal\npostern-nginx\npostern-docker-proxy\n" if project_names is None else project_names
        )
        containers_out = _CONTAINERS_OUT if containers_out is None else containers_out
        self.rules = [
            (
                lambda a: a[:3] == ["docker", "compose", "config"] and "--format" in a,
                _ok(_CONFIG_JSON) if config_out is None else config_out
            ),
            (
                lambda a: a[:2] == ["docker", "ps"] and any("compose.project" in x for x in a),
                _ok(project_names) if ps_out is None else ps_out
            ),
            (
                lambda a: a[:2] == ["docker", "ps"] and any("postern.managed" in x
                                                            for x in a), _ok("ss-abc\n" if tunnels else "")
            ),
            (
                lambda a: a[:4] == ["docker", "inspect", "--type", "container"] and any(x.startswith("ss-") for x in a),
                _ok(_TUNNELS_OUT if tunnels_out is None else tunnels_out)
            ),
            (
                lambda a: a[:4] == ["docker", "inspect", "--type", "container"
                                    ] and not any(x.startswith("ss-") for x in a),
                containers_out if isinstance(containers_out, vd.Completed) else _ok(containers_out)
            ),
        ]

    def __call__(self, argv, cwd=None):
        argv = list(argv)
        self.calls.append((argv, cwd))
        # Image inspects are keyed on a dynamic ref, so they bypass the rules.
        if argv[:3] == ["docker", "image", "inspect"]:
            ref = argv[3]
            return self.image_overrides.get(ref, _ok(f"sha256:{ref[-3:]}\t{HEAD}\n"))
        matches = [out for pred, out in self.rules if pred(argv)]
        assert len(matches) == 1, f"{len(matches)} rules matched {argv}"
        return matches[0]


def _collect(runner, tunnels=False):
    return vd.collect(runner, Path("/repo"), "local/shadowsocks-server", tunnels=tunnels)


def test_collect_rejects_a_service_with_no_image_tag():
    runner = FakeRunner(config_out=_ok('{"name": "postern", "services": {"portal": {"build": {}}}}'))
    with pytest.raises(vd.CollectError):
        vd.collect(runner, Path("/repo"), "", tunnels=False)


def test_collect_reads_desired_services_from_compose_config():
    obs = _collect(FakeRunner())
    assert obs.project == "postern"
    by_name = {s.name: s for s in obs.services}
    assert by_name["portal"].image == "local/postern-portal"
    assert by_name["portal"].first_party is True
    assert by_name["docker-proxy"].first_party is False


def test_collect_reads_container_identity_revision_and_health():
    portal = next(c for c in _collect(FakeRunner()).containers if c.service == "portal")
    assert (portal.name, portal.state) == ("postern-portal", "running")
    assert (portal.exit_code, portal.restart_policy) == (0, "unless-stopped")
    assert portal.image_id == "sha256:aaa"
    assert portal.revision == HEAD
    assert portal.health == "healthy"


def test_collect_reads_a_container_with_no_healthcheck_as_empty():
    nginx = next(c for c in _collect(FakeRunner()).containers if c.service == "nginx")
    assert nginx.health == ""


def test_collect_reads_tag_ids_and_tag_revisions():
    obs = _collect(FakeRunner())
    # The fake derives an ID from the ref's last three characters.
    assert obs.tag_ids["local/nginx"] == "sha256:inx"
    assert obs.tag_revisions["local/nginx"] == HEAD


def test_collect_records_a_missing_tag_as_empty_rather_than_raising():
    obs = _collect(FakeRunner(image_overrides={"local/nginx": vd.Completed(1, "", "No such image")}))
    assert obs.tag_ids["local/nginx"] == ""


def test_collect_tolerates_an_unlabelled_image():
    """Regression for `{{.Id}}`: an image with no Config.Labels must yield an
    empty revision, not a template error."""
    obs = _collect(FakeRunner(image_overrides={"local/nginx": _ok("sha256:bbb\t\n")}))
    assert obs.tag_ids["local/nginx"] == "sha256:bbb"
    assert obs.tag_revisions["local/nginx"] == ""


def test_collect_skips_tunnels_unless_asked():
    runner = FakeRunner()
    obs = _collect(runner)
    assert obs.ss_containers == ()
    assert not any("postern.managed" in token for argv, _ in runner.calls for token in argv)


def test_collect_gathers_tunnels_when_asked():
    obs = _collect(FakeRunner(tunnels=True), tunnels=True)
    assert [c.name for c in obs.ss_containers] == ["ss-abc"]
    assert obs.ss_containers[0].image_id == "sha256:ddd"
    assert obs.ss_containers[0].state == "running"


def test_collect_scopes_tunnels_to_this_deployments_instance():
    """Multiple Postern deployments (production, an e2e run, a second
    checkout) can share one Docker daemon. Without the instance filter,
    --tunnels would report every deployment's tunnels as this one's."""
    runner = FakeRunner(tunnels=True)
    _collect(runner, tunnels=True)
    ps_call = next(a for a, _ in runner.calls if a[:2] == ["docker", "ps"] and any("postern.managed" in t for t in a))
    assert "label=postern.instance=postern" in ps_call


def test_collect_honors_an_instance_id_override():
    """INSTANCE_ID reaches the portal via env_file, same as SHADOWSOCKS_IMAGE;
    `docker compose config` already resolves it into services.portal.environment."""
    config = _ok(
        json.dumps({
            "name": "postern",
            "services": {
                "portal": {
                    "image": "local/postern-portal",
                    "build": {"context": "."},
                    "environment": {"INSTANCE_ID": "custom-id"},
                },
            },
        })
    )
    runner = FakeRunner(tunnels=True, config_out=config)
    _collect(runner, tunnels=True)
    ps_call = next(a for a, _ in runner.calls if a[:2] == ["docker", "ps"] and any("postern.managed" in t for t in a))
    assert "label=postern.instance=custom-id" in ps_call


def test_collect_excludes_one_off_containers():
    """`docker compose run` leftovers carry both the project and service
    labels; including them would shadow the real container."""
    runner = FakeRunner()
    _collect(runner)
    ps_call = next(a for a, _ in runner.calls if a[:2] == ["docker", "ps"])
    assert "label=com.docker.compose.oneoff=False" in ps_call


def test_collect_handles_zero_containers():
    runner = FakeRunner(project_names="")
    obs = _collect(runner)
    assert obs.containers == ()
    assert not any(a[:4] == ["docker", "inspect", "--type", "container"] for a, _ in runner.calls)


def test_collect_uses_partial_output_when_a_container_vanished():
    """`docker inspect a missing` exits 1 but still prints `a`. The reconciler
    creates and removes ss-* containers continuously, so this is normal."""
    partial = vd.Completed(
        1, f"/postern-portal\tportal\trunning\t0\tunless-stopped\tsha256:aaa\t{HEAD}\thealthy\n",
        "No such container: postern-nginx"
    )
    obs = _collect(FakeRunner(containers_out=partial))
    assert [c.name for c in obs.containers] == ["postern-portal"]


def test_collect_runs_compose_with_cwd_set_to_the_project_dir():
    """--project-directory does not control compose-file discovery."""
    runner = FakeRunner()
    _collect(runner)
    compose_calls = [(a, c) for a, c in runner.calls if a[:2] == ["docker", "compose"]]
    assert compose_calls
    for _argv, cwd in compose_calls:
        assert cwd == Path("/repo")


def test_collect_raises_when_compose_config_fails():
    runner = FakeRunner(config_out=vd.Completed(1, "", "env file .env not found"))
    with pytest.raises(vd.CollectError) as excinfo:
        _collect(runner)
    assert "env file" in str(excinfo.value)


def test_collect_raises_when_docker_ps_fails():
    """A broken `docker ps` (daemon down, bad filter) has no useful partial
    output the way `docker inspect` does -- reading it as "zero containers"
    would misreport a broken environment as every service missing (a FAIL,
    exit 1) instead of "could not run" (exit 2)."""
    runner = FakeRunner(ps_out=vd.Completed(1, "", "Cannot connect to the Docker daemon"))
    with pytest.raises(vd.CollectError) as excinfo:
        _collect(runner)
    assert "Cannot connect to the Docker daemon" in str(excinfo.value)


def test_collect_raises_on_a_malformed_inspect_line():
    """A GIT_REVISION value containing an embedded tab would shift every
    field after it; silently truncating/padding could reassign `health` to
    part of a `revision` value instead of raising."""
    bad = f"/postern-portal\tportal\trunning\t0\tunless-stopped\tsha256:aaa\t{HEAD}\n"  # only 7 fields
    with pytest.raises(vd.CollectError):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_on_an_unparseable_exit_code():
    """An unparseable ExitCode must not silently become 0 -- completed_one_shot
    treats exit 0 as "ran to completion", which would downgrade a real
    failure to a passing skip."""
    bad = f"/postern-portal\tportal\trunning\tnot-a-number\tunless-stopped\tsha256:aaa\t{HEAD}\thealthy\n"
    with pytest.raises(vd.CollectError):
        _collect(FakeRunner(containers_out=bad))


def test_collect_refuses_an_empty_service_set():
    """A wrong --project-dir must not produce a green run that verified
    nothing. Same vacuous-pass guard the docs gates use."""
    runner = FakeRunner(config_out=_ok('{"name": "postern", "services": {}}'))
    with pytest.raises(vd.CollectError):
        _collect(runner)


def test_collect_refuses_an_unnamed_project():
    runner = FakeRunner(config_out=_ok('{"name": "", "services": {"portal": {"image": "x"}}}'))
    with pytest.raises(vd.CollectError):
        _collect(runner)


# Tunnel-image resolution ----------------------------------------------------------------------------------------------
def test_resolve_ss_image_prefers_the_flag():
    config = {"services": {"portal": {"environment": {"SHADOWSOCKS_IMAGE": "local/from-compose"}}}}
    assert vd.resolve_ss_image(config, "local/flag") == "local/flag"


def test_resolve_ss_image_reads_the_portals_resolved_environment(monkeypatch):
    """`docker compose config` folds env_file into services.<n>.environment, so
    the value the portal will actually see is already in the config."""
    monkeypatch.setenv("SHADOWSOCKS_IMAGE", "local/from-shell")
    config = {"services": {"portal": {"environment": {"SHADOWSOCKS_IMAGE": "local/from-compose"}}}}
    # The host shell must NOT win: SHADOWSOCKS_IMAGE reaches the portal through
    # env_file, which compose does not interpolate from the shell.
    assert vd.resolve_ss_image(config, "") == "local/from-compose"


def test_resolve_ss_image_default(monkeypatch):
    monkeypatch.setenv("SHADOWSOCKS_IMAGE", "local/from-shell")
    assert vd.resolve_ss_image({"services": {"portal": {"environment": {}}}}, "") == "local/shadowsocks-server"


def test_resolve_ss_image_without_a_portal_service():
    assert vd.resolve_ss_image({"services": {}}, "") == "local/shadowsocks-server"


# Instance resolution --------------------------------------------------------------------------------------------------
def test_resolve_instance_id_defaults_to_the_project_name():
    assert vd.resolve_instance_id({"services": {}}, "postern") == "postern"


def test_resolve_instance_id_prefers_an_override():
    config = {"services": {"portal": {"environment": {"INSTANCE_ID": "custom-id"}}}}
    assert vd.resolve_instance_id(config, "postern") == "custom-id"


def test_resolve_instance_id_ignores_a_blank_override():
    config = {"services": {"portal": {"environment": {"INSTANCE_ID": ""}}}}
    assert vd.resolve_instance_id(config, "postern") == "postern"


# Evaluation -----------------------------------------------------------------------------------------------------------
def _cs(service, name, image_id, revision, health="", *, state="running", exit_code=0, restart_policy="unless-stopped"):
    return vd.ContainerState(
        service=service,
        name=name,
        state=state,
        exit_code=exit_code,
        restart_policy=restart_policy,
        image_id=image_id,
        revision=revision,
        health=health
    )


_PROXY_REF = "tecnativa/docker-socket-proxy:v0.4.2"
# Third-party images ship their OWN project's revision label; docker-socket-proxy
# really does (verified on the deploy host).
_PROXY_REV = "2f04313b042c1bf4dfbd039475dfc42db79bde7a"


def _obs(**overrides):
    base = dict(
        project="postern",
        services=(
            vd.ServiceSpec("portal", "local/postern-portal", True),
            vd.ServiceSpec("docker-proxy", _PROXY_REF, False),
        ),
        containers=(
            _cs("portal", "postern-portal", "sha256:aaa", HEAD, "healthy"),
            _cs("docker-proxy", "postern-docker-proxy", "sha256:ccc", _PROXY_REV, "healthy"),
        ),
        tag_ids={
            "local/postern-portal": "sha256:aaa", _PROXY_REF: "sha256:ccc", "local/shadowsocks-server": "sha256:ddd"
        },
        tag_revisions={"local/postern-portal": HEAD, _PROXY_REF: _PROXY_REV, "local/shadowsocks-server": HEAD},
        ss_image="local/shadowsocks-server",
        ss_containers=(),
    )
    base.update(overrides)
    return vd.Observation(**base)


def _portal_and_proxy(portal):
    return (portal, _cs("docker-proxy", "postern-docker-proxy", "sha256:ccc", _PROXY_REV, "healthy"))


def _labels(report):
    return {c.label: c for c in report.checks}


def test_clean_deployment_passes():
    report = vd.evaluate(_obs(), HEAD)
    assert report.exit_code == 0, vd.render_text(report)


def test_missing_container_fails():
    check = _labels(vd.evaluate(_obs(containers=()), HEAD))["service portal: running"]
    assert check.status == "fail"
    assert "no container" in check.detail
    assert "docker compose up -d --build" in check.fix


def test_fix_hints_never_use_the_status_swallowing_export_form():
    """`export VAR=$(cmd)` always returns 0 regardless of cmd's exit status
    (verified separately), so a failing --print-revision inside a fix hint
    would go unnoticed and the chained `&&` would rebuild yet another
    unstamped image. Every fix hint that computes GIT_REVISION must use the
    two-statement `VAR=$(cmd) && export VAR` form instead."""
    check = _labels(vd.evaluate(_obs(containers=()), HEAD))["service portal: running"]
    assert 'export GIT_REVISION="$(' not in check.fix
    assert 'GIT_REVISION="$(scripts/verify-deploy.py --print-revision)" && export GIT_REVISION' in check.fix


def test_exited_container_fails():
    obs = _obs(
        containers=_portal_and_proxy(
            _cs("portal", "postern-portal", "sha256:aaa", HEAD, "", state="exited", exit_code=1)
        )
    )
    report = vd.evaluate(obs, HEAD)
    check = _labels(report)["service portal: running"]
    assert check.status == "fail" and "exited" in check.detail
    # Still diagnosed: "down" and "stale" are different questions.
    assert "service portal: revision" in _labels(report)


def test_completed_one_shot_service_is_not_a_failure():
    """The provisioner exits 0 with restart=no in the default topology (no
    DNS_PROVIDER). A correct install must not red-flag."""
    obs = _obs(
        containers=_portal_and_proxy(
            _cs("portal", "postern-portal", "sha256:aaa", HEAD, "", state="exited", exit_code=0, restart_policy="no")
        )
    )
    report = vd.evaluate(obs, HEAD)
    running = _labels(report)["service portal: running"]
    assert running.status == "skip" and "ran to completion" in running.detail
    # Its image is still verified -- exiting cleanly does not excuse staleness.
    assert _labels(report)["service portal: revision"].status == "ok"
    assert report.exit_code == 0


def test_two_containers_claiming_one_service_fails():
    obs = _obs(containers=_obs().containers + (_cs("portal", "postern-portal-old", "sha256:aaa", HEAD, "healthy"), ))
    check = _labels(vd.evaluate(obs, HEAD))["service portal: running"]
    assert check.status == "fail" and "2 containers claim" in check.detail


def test_stale_revision_fails_this_is_issue_195():
    """The reported incident: nothing was rebuilt, so tag and container agree --
    only the revision reveals the staleness."""
    old = "0" * 40
    obs = _obs(
        containers=_portal_and_proxy(_cs("portal", "postern-portal", "sha256:aaa", old, "healthy")),
        tag_revisions={"local/postern-portal": old, _PROXY_REF: _PROXY_REV, "local/shadowsocks-server": HEAD},
    )
    report = vd.evaluate(obs, HEAD)
    assert _labels(report)["service portal: image identity"].status == "ok"
    revision = _labels(report)["service portal: revision"]
    assert revision.status == "fail"
    assert "docker compose up -d --build" in revision.fix
    assert report.exit_code == 1


def test_unstamped_image_fails_with_a_provenance_message():
    obs = _obs(containers=_portal_and_proxy(_cs("portal", "postern-portal", "sha256:aaa", "", "healthy")))
    check = _labels(vd.evaluate(obs, HEAD))["service portal: revision"]
    assert check.status == "fail" and "GIT_REVISION" in check.detail


def _moved_tag(tag_revision):
    return _obs(
        tag_ids={
            "local/postern-portal": "sha256:zzz", _PROXY_REF: "sha256:ccc", "local/shadowsocks-server": "sha256:ddd"
        },
        tag_revisions={"local/postern-portal": tag_revision, _PROXY_REF: _PROXY_REV, "local/shadowsocks-server": HEAD},
    )


def test_third_party_tag_move_is_not_blamed_on_the_e2e_suite():
    """docker-socket-proxy ships its own upstream revision label; running it
    through the first-party diagnosis would misread that SHA."""
    obs = _obs(
        tag_ids={
            "local/postern-portal": "sha256:aaa", _PROXY_REF: "sha256:new", "local/shadowsocks-server": "sha256:ddd"
        }
    )
    check = _labels(vd.evaluate(obs, HEAD))["service docker-proxy: image identity"]
    assert check.status == "fail"
    assert "pull" in check.detail
    assert "#194" not in check.detail
    assert "--build" not in check.fix


def test_built_but_not_recreated_names_that_case():
    check = _labels(vd.evaluate(_moved_tag("0" * 40), HEAD))["service portal: image identity"]
    assert check.status == "fail"
    assert "built, not recreated" in check.detail


def test_same_revision_different_id_names_the_rebuild_case():
    check = _labels(vd.evaluate(_moved_tag(HEAD), HEAD))["service portal: image identity"]
    assert check.status == "fail" and "same revision" in check.detail


def test_unprovenanced_tag_is_diagnosed_without_naming_a_specific_culprit():
    """An unprovenanced rebuild (empty revision label) could come from
    anywhere -- a manual build, a different checkout, a restored image.
    Naming one specific historical cause risks becoming stale advice once
    that cause is fixed elsewhere."""
    check = _labels(vd.evaluate(_moved_tag(""), HEAD))["service portal: image identity"]
    assert check.status == "fail"
    assert "rebuilt without provenance" in check.detail
    assert "#194" not in check.detail


def test_missing_tag_fails():
    obs = _obs(tag_ids={"local/postern-portal": "", _PROXY_REF: "sha256:ccc", "local/shadowsocks-server": "sha256:ddd"})
    check = _labels(vd.evaluate(obs, HEAD))["service portal: image identity"]
    assert check.status == "fail" and "not present locally" in check.detail


def test_third_party_service_skips_the_revision_check():
    assert _labels(vd.evaluate(_obs(), HEAD))["service docker-proxy: revision"].status == "skip"


def test_healthy_container_passes():
    assert _labels(vd.evaluate(_obs(), HEAD))["service portal: health"].status == "ok"


def test_starting_container_passes():
    """Point-in-time, no polling: right after `up -d`, a container that has
    not yet had its first probe run reports `starting`, and that must pass --
    the alternative is a gate that reds on every single deploy."""
    obs = _obs(containers=_portal_and_proxy(_cs("portal", "postern-portal", "sha256:aaa", HEAD, "starting")))
    assert _labels(vd.evaluate(obs, HEAD))["service portal: health"].status == "ok"


def test_unhealthy_container_fails():
    obs = _obs(containers=_portal_and_proxy(_cs("portal", "postern-portal", "sha256:aaa", HEAD, "unhealthy")))
    check = _labels(vd.evaluate(obs, HEAD))["service portal: health"]
    assert check.status == "fail"
    assert "unhealthy" in check.detail
    assert "docker compose logs portal" in check.fix


def test_no_healthcheck_configured_skips():
    obs = _obs(containers=_portal_and_proxy(_cs("portal", "postern-portal", "sha256:aaa", HEAD, "")))
    check = _labels(vd.evaluate(obs, HEAD))["service portal: health"]
    assert check.status == "skip" and "no healthcheck" in check.detail


def test_orphan_container_fails():
    obs = _obs(containers=_obs().containers + (_cs("gone", "postern-gone", "sha256:xxx", HEAD, "healthy"), ))
    check = _labels(vd.evaluate(obs, HEAD))["orphan container postern-gone"]
    assert check.status == "fail" and "--remove-orphans" in check.fix


def test_stale_shadowsocks_image_fails():
    obs = _obs(
        tag_revisions={"local/postern-portal": HEAD, _PROXY_REF: _PROXY_REV, "local/shadowsocks-server": "0" * 40}
    )
    check = _labels(vd.evaluate(obs, HEAD))["shadowsocks image: revision"]
    assert check.status == "fail" and "shadowsocks/Dockerfile" in check.fix


def test_tunnel_rows_are_skipped_by_default():
    report = vd.evaluate(_obs(), HEAD)
    assert _labels(report)["tunnels: image identity"].status == "skip"
    assert report.exit_code == 0


def test_tunnel_on_a_stale_image_fails_and_points_at_reconcile():
    obs = _obs(ss_containers=(_cs("", "ss-abc", "sha256:old", "0" * 40, ""), ))
    check = _labels(vd.evaluate(obs, HEAD, tunnels=True))["tunnel ss-abc: image identity"]
    assert check.status == "fail" and "postern reconcile" in check.fix


def test_exited_tunnel_fails():
    obs = _obs(ss_containers=(_cs("", "ss-abc", "sha256:ddd", HEAD, "", state="exited", exit_code=1), ))
    check = _labels(vd.evaluate(obs, HEAD, tunnels=True))["tunnel ss-abc: running"]
    assert check.status == "fail" and "exited" in check.detail


def test_no_tunnel_containers_with_tunnels_requested_is_honestly_ambiguous():
    """Zero tunnels is indistinguishable, from this tool alone, between "no
    connections are enabled" and "the reconcile pass this check trusts has
    not converged yet" -- resolving that needs an authoritative expected
    count from the portal, which would violate the no-portal-dependency
    design (see the module docstring). The message must say so rather than
    implying a confirmed-empty state."""
    report = vd.evaluate(_obs(ss_containers=()), HEAD, tunnels=True)
    check = _labels(report)["tunnels: image identity"]
    assert check.status == "skip"
    assert "has not converged yet" in check.detail
    assert report.exit_code == 0


def test_tunnels_present_but_image_not_local_is_one_failure_not_one_per_tunnel():
    """When the tunnel tag itself is missing locally, every tunnel is "wrong"
    for the identical reason, and `postern reconcile` cannot fix that --
    only rebuilding the image can. A per-tunnel mismatch row with a
    guaranteed-no-op fix would be actively misleading."""
    obs = _obs(
        ss_containers=(_cs("", "ss-abc", "sha256:ddd", HEAD, ""), _cs("", "ss-def", "sha256:eee", HEAD, "")),
        tag_ids={"local/postern-portal": "sha256:aaa", _PROXY_REF: "sha256:ccc", "local/shadowsocks-server": ""},
    )
    report = vd.evaluate(obs, HEAD, tunnels=True)
    labels = _labels(report)
    check = labels["tunnels: image identity"]
    assert check.status == "fail"
    assert "not present locally" in check.detail
    assert "shadowsocks/Dockerfile" in check.fix
    assert "tunnel ss-abc: image identity" not in labels
    assert "tunnel ss-def: image identity" not in labels


def _dirty_obs(dirty):
    return _obs(
        containers=_portal_and_proxy(_cs("portal", "postern-portal", "sha256:aaa", dirty, "healthy")),
        tag_revisions={"local/postern-portal": dirty, _PROXY_REF: _PROXY_REV, "local/shadowsocks-server": dirty},
    )


def test_dirty_checkout_fails_by_default():
    """A -dirty revision is the same string for two different dirty trees, so
    matching it proves nothing."""
    dirty = f"{HEAD}-dirty"
    report = vd.evaluate(_dirty_obs(dirty), dirty)
    assert _labels(report)["checkout: clean"].status == "fail"
    assert report.exit_code == 1


def test_dirty_checkout_can_be_acknowledged():
    dirty = f"{HEAD}-dirty"
    report = vd.evaluate(_dirty_obs(dirty), dirty, allow_dirty=True)
    assert _labels(report)["checkout: clean"].status == "skip"
    assert report.exit_code == 0


# CLI ------------------------------------------------------------------------------------------------------------------
def test_print_revision_mode_emits_one_line(repo):
    out = subprocess.run([sys.executable, str(SCRIPT), "--print-revision", "--repo",
                          str(repo)],
                         check=True,
                         capture_output=True,
                         text=True).stdout
    assert out.strip() == vd.git_revision(repo)
    assert len(out.strip().splitlines()) == 1


def test_parse_args_defaults_both_dirs_to_the_repo_root():
    args = vd.parse_args([])
    assert args.project_dir == vd.REPO_ROOT
    assert args.repo == vd.REPO_ROOT


def test_parse_args_keeps_project_dir_and_repo_independent():
    args = vd.parse_args(["--project-dir", "/srv/postern", "--repo", "/src/postern"])
    assert (str(args.project_dir), str(args.repo)) == ("/srv/postern", "/src/postern")


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    """Stub the two boundaries main() crosses, and point --project-dir at an
    empty dir so nothing reaches the developer's real deployment."""
    monkeypatch.setattr(vd, "git_revision", lambda repo: HEAD)
    return ["--project-dir", str(tmp_path)]


def test_main_returns_one_when_a_check_fails(monkeypatch, capsys, isolated):
    monkeypatch.setattr(vd, "collect", lambda *a, **k: _obs(containers=()))
    assert vd.main(isolated) == 1
    assert "no container" in capsys.readouterr().out


def test_main_returns_zero_on_a_clean_deployment(monkeypatch, capsys, isolated):
    monkeypatch.setattr(vd, "collect", lambda *a, **k: _obs())
    assert vd.main(isolated) == 0
    assert "All" in capsys.readouterr().out


def test_main_honours_json(monkeypatch, capsys, isolated):
    monkeypatch.setattr(vd, "collect", lambda *a, **k: _obs())
    assert vd.main([*isolated, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["exit_code"] == 0


def test_main_honours_an_explicit_expected_revision(monkeypatch, capsys, isolated):
    monkeypatch.setattr(vd, "collect", lambda *a, **k: _obs())
    monkeypatch.setattr(vd, "git_revision", lambda repo: pytest.fail("git must not be consulted"))
    assert vd.main([*isolated, "--expected-revision", "0" * 40]) == 1


def test_main_reports_a_collect_failure_as_a_check_not_a_traceback(monkeypatch, capsys, isolated):

    def boom(*a, **k):
        raise vd.CollectError("env file .env not found")

    monkeypatch.setattr(vd, "collect", boom)
    # 2, not 1: a broken environment is not a stale deployment, and #196 must
    # be able to tell them apart.
    assert vd.main(isolated) == 2
    captured = capsys.readouterr()
    assert "env file .env not found" in captured.out
    assert "Traceback" not in captured.out + captured.err


def test_main_collect_failure_json_exit_code_matches_the_process_exit_code(monkeypatch, capsys, isolated):
    """The JSON payload's `exit_code` field and the real process exit code
    must agree -- a caller that parses the JSON (rather than reading `$?`)
    must not read a 1 where the process actually returned 2."""

    def boom(*a, **k):
        raise vd.CollectError("env file .env not found")

    monkeypatch.setattr(vd, "collect", boom)
    process_exit_code = vd.main([*isolated, "--json"])
    assert process_exit_code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["exit_code"] == 2


def test_main_reports_a_missing_project_dir_as_a_check_not_a_traceback(repo):
    """run_command must translate OSError, the same way git_revision does.

    --repo points at the throwaway git fixture, not REPO_ROOT, so a git failure
    cannot make this pass for the wrong reason -- the only thing wrong here is
    --project-dir."""
    result = subprocess.run([sys.executable,
                             str(SCRIPT), "--project-dir", "/nonexistent-dir-195", "--repo",
                             str(repo)],
                            capture_output=True,
                            text=True)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert "/nonexistent-dir-195" in result.stderr


def test_main_reports_a_bad_repo_as_usage_error_not_a_traceback(monkeypatch, capsys, tmp_path):
    """#196's deploy entrypoint calls --print-revision first; a stack dump
    there would kill the deploy with no explanation."""
    result = subprocess.run([sys.executable, str(SCRIPT), "--print-revision", "--repo",
                             str(tmp_path)],
                            capture_output=True,
                            text=True)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert "verify-deploy:" in result.stderr
