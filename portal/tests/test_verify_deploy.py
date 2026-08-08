"""Unit tests for scripts/verify-deploy.py (issue #195).

The script is host-side and stdlib-only, so it is loaded by path rather than
imported -- the same reach-out-of-portal pattern as tests/test_nginx_render.py.
No test here touches Docker or the network: `collect()` takes an injected
runner and `evaluate()` is pure.
"""
import importlib.util
import io
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


def _container_record(
    name: str,
    service: str,
    status: str,
    exit_code,
    restart_policy: str,
    image: str,
    revision: str = "",
    health: str = "",
) -> dict:
    """One element of `docker inspect`'s native JSON array, shaped like the
    real payload but trimmed to the keys the parser reads. `exit_code` is
    typed loosely so callers can pass a non-int to exercise validation.
    `State.Health` is omitted entirely when `health` is falsy: a container with no HEALTHCHECK has no `Health` key
    at all (`omitempty`), not `Health: null`."""
    labels = {}
    if service:
        labels["com.docker.compose.service"] = service
    if revision:
        labels["org.opencontainers.image.revision"] = revision
    state = {"Status": status, "ExitCode": exit_code}
    if health:
        state["Health"] = {"Status": health}
    return {
        "Name": f"/{name}",
        "Config": {"Labels": labels},
        "State": state,
        "HostConfig": {"RestartPolicy": {"Name": restart_policy}},
        "Image": image,
    }


_CONTAINERS_OUT = json.dumps([
    _container_record("postern-portal", "portal", "running", 0, "unless-stopped", "sha256:aaa", HEAD, "healthy"),
    _container_record("postern-nginx", "nginx", "running", 0, "unless-stopped", "sha256:bbb", HEAD),
    _container_record(
        "postern-docker-proxy", "docker-proxy", "running", 0, "unless-stopped", "sha256:ccc", "", "healthy"
    ),
])

_TUNNELS_OUT = json.dumps([
    _container_record("ss-abc", "", "running", 0, "unless-stopped", "sha256:ddd", HEAD),
])


def _image_record(image_id: str, revision: str = "") -> dict:
    """One element of `docker image inspect`'s native JSON array, trimmed to the keys the parser reads."""
    labels = {"org.opencontainers.image.revision": revision} if revision else {}
    return {"Id": image_id, "Config": {"Labels": labels}}


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
            return self.image_overrides.get(ref, _ok(json.dumps([_image_record(f"sha256:{ref[-3:]}", HEAD)])))
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
    """A real unlabelled image has an absent Config.Labels key, not a null one -- must still yield an empty revision."""
    bad = json.dumps([{"Id": "sha256:bbb", "Config": {}}])
    obs = _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))
    assert obs.tag_ids["local/nginx"] == "sha256:bbb"
    assert obs.tag_revisions["local/nginx"] == ""


def test_collect_tolerates_an_image_record_with_no_config_key_at_all():
    """`_optional_dict`'s contract is "absent or null", not just "null" -- this exercises the top-level `Config` key
    itself being absent from the record, distinct from test_collect_tolerates_an_unlabelled_image's Config-present
    but Labels-absent shape."""
    bad = json.dumps([{"Id": "sha256:bbb"}])
    obs = _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))
    assert obs.tag_ids["local/nginx"] == "sha256:bbb"
    assert obs.tag_revisions["local/nginx"] == ""


def test_collect_tolerates_a_null_labels_image():
    """Defensive: this host's daemon never produces a null (vs. absent) Config.Labels for images, but the parser must
    tolerate it too."""
    bad = json.dumps([{"Id": "sha256:bbb", "Config": {"Labels": None}}])
    obs = _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))
    assert obs.tag_ids["local/nginx"] == "sha256:bbb"
    assert obs.tag_revisions["local/nginx"] == ""


def test_collect_image_inspect_passes_no_format_flag():
    runner = FakeRunner()
    _collect(runner)
    image_call = next(a for a, _ in runner.calls if a[:3] == ["docker", "image", "inspect"])
    assert "--format" not in image_call


# JSON/array structure -------------------------------------------------------------------------------------------------
def test_collect_raises_on_unparseable_image_json():
    with pytest.raises(vd.CollectError, match="unparseable JSON"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok("not json at all")}))


def test_collect_raises_when_the_image_top_level_value_is_not_an_array():
    bad = json.dumps({"Id": "sha256:bbb"})
    with pytest.raises(vd.CollectError, match="not an array"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


def test_collect_raises_when_docker_image_inspect_reports_no_records():
    """Distinct from the nonzero-exit "tag not present locally" path (which
    `collect()` short-circuits before ever calling the image parser): a
    zero-exit call that somehow reports zero records is a shape this parser
    doesn't understand, and must not silently reuse the "" sentinel the
    nonzero-exit case already owns."""
    with pytest.raises(vd.CollectError, match="reported 0 image records"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok("[]")}))


def test_collect_raises_when_docker_image_inspect_reports_multiple_records():
    bad = json.dumps([{"Id": "sha256:aaa", "Config": {}}, {"Id": "sha256:bbb", "Config": {}}])
    with pytest.raises(vd.CollectError, match="reported 2 image records"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


def test_collect_raises_when_the_image_record_is_not_an_object():
    bad = json.dumps([1])
    with pytest.raises(vd.CollectError, match="record is not an object"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


def test_collect_raises_when_the_image_record_has_no_id():
    bad = json.dumps([{"Config": {}}])
    with pytest.raises(vd.CollectError, match="no usable 'Id'"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


def test_collect_raises_when_the_image_id_is_the_wrong_type():
    bad = json.dumps([{"Id": 123, "Config": {}}])
    with pytest.raises(vd.CollectError, match="no usable 'Id'"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


def test_collect_raises_when_the_image_id_is_an_empty_string():
    bad = json.dumps([{"Id": "", "Config": {}}])
    with pytest.raises(vd.CollectError, match="no usable 'Id'"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


def test_collect_raises_when_the_images_config_is_the_wrong_type():
    bad = json.dumps([{"Id": "sha256:bbb", "Config": ["not", "a", "dict"]}])
    with pytest.raises(vd.CollectError, match="non-object 'Config'"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


def test_collect_raises_when_the_images_labels_are_the_wrong_type():
    bad = json.dumps([{"Id": "sha256:bbb", "Config": {"Labels": ["not", "a", "dict"]}}])
    with pytest.raises(vd.CollectError, match="non-object 'Config.Labels'"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


def test_collect_raises_when_the_images_revision_label_is_the_wrong_type():
    bad = json.dumps([{"Id": "sha256:bbb", "Config": {"Labels": {"org.opencontainers.image.revision": 42}}}])
    with pytest.raises(vd.CollectError, match="non-string 'org.opencontainers.image.revision'"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


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
        1,
        json.dumps([
            _container_record(
                "postern-portal", "portal", "running", 0, "unless-stopped", "sha256:aaa", HEAD, "healthy"
            )
        ]), "No such container: postern-nginx"
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


def test_collect_container_inspect_passes_no_format_flag():
    """FakeRunner's dispatch rules match by argv PREFIX, so a stray --format would still match -- only an explicit
    assertion catches its absence."""
    runner = FakeRunner()
    _collect(runner)
    inspect_call = next(
        a for a, _ in runner.calls
        if a[:4] == ["docker", "inspect", "--type", "container"] and not any(x.startswith("ss-") for x in a)
    )
    assert "--format" not in inspect_call


# JSON/array structure -------------------------------------------------------------------------------------------------
def test_collect_raises_on_unparseable_json():
    with pytest.raises(vd.CollectError, match="unparseable JSON"):
        _collect(FakeRunner(containers_out="not json at all"))


def test_collect_raises_when_the_top_level_value_is_not_an_array():
    bad = json.dumps({"Name": "/x"})
    with pytest.raises(vd.CollectError, match="not an array"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_an_array_element_is_not_an_object():
    bad = json.dumps([1, 2])
    with pytest.raises(vd.CollectError, match="record is not an object"):
        _collect(FakeRunner(containers_out=bad))


# Required fields: missing ---------------------------------------------------------------------------------------------
def test_collect_raises_when_a_record_has_no_name():
    bad = json.dumps([{
        "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'Name'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_a_record_has_no_image():
    bad = json.dumps([{"Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {}}])
    with pytest.raises(vd.CollectError, match="no usable 'Image'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_a_record_has_no_state():
    bad = json.dumps([{"Name": "/x", "Config": {}, "HostConfig": {}, "Image": "sha256:aaa"}])
    with pytest.raises(vd.CollectError, match="no usable 'State'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_state_has_no_status():
    bad = json.dumps([{"Name": "/x", "Config": {}, "State": {"ExitCode": 0}, "HostConfig": {}, "Image": "sha256:aaa"}])
    with pytest.raises(vd.CollectError, match="no usable 'State.Status'"):
        _collect(FakeRunner(containers_out=bad))


# Required fields: present but the wrong JSON type ---------------------------------------------------------------------
def test_collect_raises_when_name_is_the_wrong_type():
    bad = json.dumps([{
        "Name": 123, "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {},
        "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'Name'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_name_is_an_empty_string():
    bad = json.dumps([{
        "Name": "", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'Name'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_image_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {}, "Image": [1, 2]
    }])
    with pytest.raises(vd.CollectError, match="no usable 'Image'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_image_is_an_empty_string():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {}, "Image": ""
    }])
    with pytest.raises(vd.CollectError, match="no usable 'Image'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_state_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": ["not", "a", "dict"], "HostConfig": {}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'State'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_status_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": 5, "ExitCode": 0}, "HostConfig": {}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'State.Status'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_status_is_an_empty_string():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "", "ExitCode": 0}, "HostConfig": {}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'State.Status'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_on_a_non_integer_exit_code():
    bad = json.dumps([
        _container_record("postern-portal", "portal", "running", "not-a-number", "unless-stopped", "sha256:aaa")
    ])
    with pytest.raises(vd.CollectError, match="non-integer ExitCode"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_on_a_boolean_exit_code():
    """bool is a subclass of int in Python -- True/False must not silently
    pass an isinstance(x, int) check as if they were 1/0."""
    bad = json.dumps([_container_record("postern-portal", "portal", "running", True, "unless-stopped", "sha256:aaa")])
    with pytest.raises(vd.CollectError, match="non-integer ExitCode"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_truncates_a_huge_hostile_exit_code_in_the_error_message():
    """Every sibling error in this parser truncates untrusted content at 200 chars (`{value!r:.200}`) because the
    message is rendered, not just raised -- main() puts it into a Check.detail that render_text/render_json both
    emit verbatim. The ExitCode message must not be the one exception."""
    bad = json.dumps([
        _container_record("postern-portal", "portal", "running", "X" * 5000, "unless-stopped", "sha256:aaa")
    ])
    with pytest.raises(vd.CollectError) as excinfo:
        _collect(FakeRunner(containers_out=bad))
    assert len(str(excinfo.value)) < 400


def test_collect_raises_when_state_has_no_exit_code():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running"}, "HostConfig": {}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="non-integer ExitCode"):
        _collect(FakeRunner(containers_out=bad))


# Optional fields: present but the wrong JSON type ---------------------------------------------------------------------
def test_collect_raises_when_config_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": ["not", "a", "dict"], "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {},
        "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="non-object 'Config'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_labels_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {"Labels": ["not", "a", "dict"]}, "State": {"Status": "running", "ExitCode": 0},
        "HostConfig": {}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="non-object 'Config.Labels'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_host_config_is_the_wrong_type():
    """`HostConfig` is required, not `_optional_dict`-style, so a wrong type raises the same "no usable" message an
    absent key would -- see test_collect_raises_when_host_config_is_missing."""
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": "nope",
        "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'HostConfig'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_host_config_is_missing():
    """A missing `RestartPolicy` must not collapse `restart_policy` into `""`, which `completed_one_shot` reads as
    "not meant to stay up" -- the same ambiguous-absence hazard `Image`/`ExitCode` are already required against."""
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'HostConfig'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_restart_policy_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {"RestartPolicy": [1]},
        "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'HostConfig.RestartPolicy'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_restart_policy_is_missing():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {},
        "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="no usable 'HostConfig.RestartPolicy'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_health_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0, "Health": [1]},
        "HostConfig": {"RestartPolicy": {}}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="non-object 'State.Health'"):
        _collect(FakeRunner(containers_out=bad))


# Optional leaf strings: present but the wrong JSON type ---------------------------------------------------------------
def test_collect_raises_when_the_service_label_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {"Labels": {"com.docker.compose.service": 123}},
        "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {"RestartPolicy": {}}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="non-string 'com.docker.compose.service'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_the_revision_label_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {"Labels": {"org.opencontainers.image.revision": 123}},
        "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {"RestartPolicy": {}}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="non-string 'org.opencontainers.image.revision'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_restart_policy_name_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0},
        "HostConfig": {"RestartPolicy": {"Name": [1]}}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="non-string 'Name'"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_when_health_status_is_the_wrong_type():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0, "Health": {"Status": 123}},
        "HostConfig": {"RestartPolicy": {}}, "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="non-string 'Status'"):
        _collect(FakeRunner(containers_out=bad))


# Optional fields: genuinely absent, must default rather than raise ----------------------------------------------------
def test_collect_defaults_absent_optional_fields_to_empty():
    """`HostConfig`/`RestartPolicy` themselves are required (see test_collect_raises_when_host_config_is_missing /
    test_collect_raises_when_restart_policy_is_missing) -- only the `Name` leaf inside a present RestartPolicy is
    optional, since real Docker output legitimately reports `Name: ""` for "no restart policy configured"."""
    obj = {
        "Name": "/postern-portal",
        "Config": {},  # no Labels key
        "State": {"Status": "running", "ExitCode": 0},  # no Health key
        "HostConfig": {"RestartPolicy": {}},  # no Name key
        "Image": "sha256:aaa",
    }
    portal = _collect(FakeRunner(containers_out=json.dumps([obj]))).containers[0]
    assert (portal.service, portal.revision, portal.health, portal.restart_policy) == ("", "", "", "")


def test_collect_tolerates_a_container_record_with_no_config_key_at_all():
    """`_optional_dict`'s contract is "absent or null", not just "null" -- this exercises the top-level `Config` key
    itself being absent from the record, distinct from test_collect_defaults_absent_optional_fields_to_empty's
    Config-present-but-Labels-absent shape."""
    obj = {
        "Name": "/postern-portal",
        "State": {"Status": "running", "ExitCode": 0},
        "HostConfig": {"RestartPolicy": {}},
        "Image": "sha256:aaa",
    }
    portal = _collect(FakeRunner(containers_out=json.dumps([obj]))).containers[0]
    assert (portal.service, portal.revision) == ("", "")


def test_collect_raises_on_a_revision_label_containing_a_control_character():
    """A tab or newline in a label value must not reach render_text's fixed-width table verbatim -- it can forge a
    line matching the `[OK]`/`[FAIL]` marker a log/CI scraper looks for."""
    hostile = "abc\tdef\nghi"
    record = _container_record(
        "postern-portal", "portal", "running", 0, "unless-stopped", "sha256:aaa", hostile, "healthy"
    )
    with pytest.raises(vd.CollectError, match="control characters"):
        _collect(FakeRunner(containers_out=json.dumps([record])))


def test_collect_raises_on_a_name_containing_a_control_character():
    """Coverage for a control character isn't limited to label leaves -- Name/Image/State.Status must keep it too."""
    bad = json.dumps([{
        "Name": "/x\ny", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {},
        "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="control characters"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_on_an_image_id_containing_a_control_character():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "running", "ExitCode": 0}, "HostConfig": {},
        "Image": "sha256:a\tb"
    }])
    with pytest.raises(vd.CollectError, match="control characters"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_on_a_status_containing_a_control_character():
    bad = json.dumps([{
        "Name": "/x", "Config": {}, "State": {"Status": "run\nning", "ExitCode": 0}, "HostConfig": {},
        "Image": "sha256:aaa"
    }])
    with pytest.raises(vd.CollectError, match="control characters"):
        _collect(FakeRunner(containers_out=bad))


def test_collect_raises_on_an_image_inspect_id_containing_a_control_character():
    bad = json.dumps([{"Id": "sha256:a\tb", "Config": {}}])
    with pytest.raises(vd.CollectError, match="control characters"):
        _collect(FakeRunner(image_overrides={"local/nginx": _ok(bad)}))


def test_collect_tolerates_benign_non_ascii_characters_in_a_label():
    """The control-character guard must reject only characters that can corrupt render_text's fixed-width table
    (tab, newline, CR, ...) -- not every character str.isprintable() considers non-printable. NBSP, a zero-width
    space, and a soft hyphen are harmless here and must not abort collection."""
    benign = "abc\u00a0def\u200bghi\u00adjkl"  # NBSP, zero-width space, soft hyphen
    record = _container_record(
        "postern-portal", "portal", "running", 0, "unless-stopped", "sha256:aaa", benign, "healthy"
    )
    portal = _collect(FakeRunner(containers_out=json.dumps([record]))).containers[0]
    assert portal.revision == benign


def test_parse_containers_returns_empty_tuple_for_an_empty_array():
    """`[]` is the empty tuple, not an error."""
    assert vd._parse_containers("[]") == ()


def test_parse_containers_raises_on_blank_stdout():
    """Blank stdout is not a shape a functioning docker inspect can produce
    (it always emits at least `[]`) -- unlike the empty-array case above,
    this must not be read as "zero containers", or a broken/truncated
    invocation would misreport as a clean, empty deployment."""
    with pytest.raises(vd.CollectError, match="unparseable JSON"):
        vd._parse_containers("")
    with pytest.raises(vd.CollectError, match="unparseable JSON"):
        vd._parse_containers("   \n")


def test_collect_defaults_null_labels_to_empty():
    """A present-and-null Config.Labels must be treated the same as an absent key."""
    obj = {
        "Name": "/postern-portal",
        "Config": {"Labels": None},
        "State": {"Status": "running", "ExitCode": 0},
        "HostConfig": {"RestartPolicy": {}},
        "Image": "sha256:aaa",
    }
    portal = _collect(FakeRunner(containers_out=json.dumps([obj]))).containers[0]
    assert (portal.service, portal.revision) == ("", "")


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


def test_resolve_ss_image_is_case_insensitive():
    """`Settings` (pydantic-settings) has no model_config overriding the
    library default of case-INSENSITIVE env vars -- a lowercase `.env` entry
    is authoritative for the portal and must not be missed here."""
    config = {"services": {"portal": {"environment": {"shadowsocks_image": "local/from-lowercase-env"}}}}
    assert vd.resolve_ss_image(config, "") == "local/from-lowercase-env"


# Instance resolution --------------------------------------------------------------------------------------------------
def test_resolve_instance_id_defaults_to_the_project_name():
    assert vd.resolve_instance_id({"services": {}}, "postern") == "postern"


def test_resolve_instance_id_prefers_an_override():
    config = {"services": {"portal": {"environment": {"INSTANCE_ID": "custom-id"}}}}
    assert vd.resolve_instance_id(config, "postern") == "custom-id"


def test_resolve_instance_id_ignores_a_blank_override():
    config = {"services": {"portal": {"environment": {"INSTANCE_ID": ""}}}}
    assert vd.resolve_instance_id(config, "postern") == "postern"


def test_resolve_instance_id_is_case_insensitive():
    config = {"services": {"portal": {"environment": {"instance_id": "lower-inst"}}}}
    assert vd.resolve_instance_id(config, "postern") == "lower-inst"


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


def test_exited_container_with_a_stale_unhealthy_probe_skips_health_not_fails():
    """Docker stops probing on exit and freezes Health.Status at the last
    probe. The provisioner (restart: "no", HEALTHCHECK defined) can exit 0
    cleanly with a stale "unhealthy" from before shutdown -- exactly the
    completed_one_shot case the neighboring `running` check already skips.
    A frozen, no-longer-meaningful probe result must not fail the gate."""
    obs = _obs(
        containers=_portal_and_proxy(
            _cs(
                "portal",
                "postern-portal",
                "sha256:aaa",
                HEAD,
                "unhealthy",
                state="exited",
                exit_code=0,
                restart_policy="no"
            )
        )
    )
    check = _labels(vd.evaluate(obs, HEAD))["service portal: health"]
    assert check.status == "skip"
    assert "frozen" in check.detail


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


def test_shadowsocks_build_hint_tags_the_actual_resolved_image():
    """SHADOWSOCKS_IMAGE is a supported override (portal/tests/e2e/e2e.compose.yaml
    sets one), and a fix hint that always builds `local/shadowsocks-server`
    regardless would tag the wrong ref -- leaving the check failing forever on a
    deployment that uses a custom name."""
    custom = "myorg/ss:1"
    obs = _obs(
        ss_image=custom,
        tag_ids={"local/postern-portal": "sha256:aaa", _PROXY_REF: "sha256:ccc", custom: ""},
        tag_revisions={"local/postern-portal": HEAD, _PROXY_REF: _PROXY_REV, custom: ""},
    )
    check = _labels(vd.evaluate(obs, HEAD))["shadowsocks image: revision"]
    assert check.status == "fail"
    assert f"-t {custom} ." in check.fix
    assert "local/shadowsocks-server" not in check.fix


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


_SS_A = "ss-" + "a" * 24
_SS_B = "ss-" + "b" * 24


def test_zero_tunnels_with_connections_enabled_fails():
    """The hole this closes: scripts/deploy.sh blocks on a completed reconcile
    pass before calling the gate, so with an authoritative expected set "zero
    tunnels" is a converged-to-nothing deploy, not an ambiguity. A finished
    pass is not a converged one -- per-container failures are logged and
    swallowed."""
    report = vd.evaluate(_obs(ss_containers=()), HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A, _SS_B}))
    labels = _labels(report)
    assert labels[f"tunnel {_SS_A}: exists"].status == "fail"
    assert labels[f"tunnel {_SS_B}: exists"].status == "fail"
    assert "postern reconcile" in labels[f"tunnel {_SS_A}: exists"].fix
    # Not both: with a caller-supplied expected set, "tunnels: image identity"'s
    # skip/fail is only for the no-set case (see the module docstring) -- a
    # regression that reintroduced it here would duplicate/confuse the verdict.
    assert "tunnels: image identity" not in labels
    assert report.exit_code == 1


def test_zero_tunnels_with_zero_connections_passes():
    """A deployment with no enabled connections is correct with no tunnel
    containers, and must not be red-flagged."""
    report = vd.evaluate(_obs(ss_containers=()), HEAD, tunnels=True, expected_tunnels=frozenset())
    assert _labels(report)["tunnels: expected set"].status == "ok"
    assert report.exit_code == 0


def test_a_missing_tunnel_is_named_individually():
    """Which tunnel is missing is the actionable part; a bare count would make
    the operator diff two lists by hand."""
    obs = _obs(ss_containers=(_cs("", _SS_A, "sha256:ddd", HEAD, ""), ))
    report = vd.evaluate(obs, HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A, _SS_B}))
    labels = _labels(report)
    assert labels[f"tunnel {_SS_B}: exists"].status == "fail"
    assert f"tunnel {_SS_A}: exists" not in labels
    assert report.exit_code == 1


def test_a_surplus_tunnel_is_named_individually():
    """After a converged pass the reconciler has removed every container whose
    connection is gone or disabled, and the listing is already scoped to this
    instance -- so a surplus is a removal that did not happen, not another
    deployment's tunnel."""
    obs = _obs(ss_containers=(_cs("", _SS_A, "sha256:ddd", HEAD, ""), _cs("", _SS_B, "sha256:ddd", HEAD, "")))
    report = vd.evaluate(obs, HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A}))
    check = _labels(report)[f"tunnel {_SS_B}: not expected"]
    assert check.status == "fail"
    assert "no enabled connection" in check.detail
    assert report.exit_code == 1


def test_a_shortfall_and_a_surplus_together_do_not_cancel_out():
    """The reason this compares sets and not counts: one container never
    created plus one never removed is a deployment that is provably not
    converged, and their cardinalities are identical."""
    obs = _obs(ss_containers=(_cs("", _SS_B, "sha256:ddd", HEAD, ""), ))
    report = vd.evaluate(obs, HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A}))
    labels = _labels(report)
    assert labels[f"tunnel {_SS_A}: exists"].status == "fail"
    assert labels[f"tunnel {_SS_B}: not expected"].status == "fail"
    assert report.exit_code == 1


def test_missing_tunnels_with_no_image_locally_are_one_row_pointing_at_the_build():
    """reconcile() returns normally when the tunnel image is missing: it logs,
    skips the container branch, and creates nothing -- so every further pass is
    identically a no-op and `postern reconcile` cannot fix this. One row, not
    one per missing tunnel: they are all wrong in the same way, and the
    neighbouring rows already refuse to repeat a fix hint that is a guaranteed
    no-op."""
    obs = _obs(
        ss_containers=(),
        tag_ids={"local/postern-portal": "sha256:aaa", _PROXY_REF: "sha256:ccc", "local/shadowsocks-server": ""},
    )
    report = vd.evaluate(obs, HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A, _SS_B}))
    labels = _labels(report)
    check = labels["tunnels: expected set"]
    assert check.status == "fail"
    assert "not present locally" in check.detail
    assert "shadowsocks/Dockerfile" in check.fix
    assert "postern reconcile" not in check.fix
    assert f"tunnel {_SS_A}: exists" not in labels


def test_missing_tunnels_build_hint_tags_the_actual_resolved_image():
    """Same custom-SHADOWSOCKS_IMAGE concern as the shadowsocks-image-revision
    row, for the tunnel-set row's own build hint."""
    custom = "myorg/ss:1"
    obs = _obs(
        ss_image=custom,
        ss_containers=(),
        tag_ids={"local/postern-portal": "sha256:aaa", _PROXY_REF: "sha256:ccc", custom: ""},
    )
    check = _labels(vd.evaluate(obs, HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A})))["tunnels: expected set"]
    assert f"-t {custom} ." in check.fix
    assert "local/shadowsocks-server" not in check.fix


def test_a_missing_image_with_surviving_tunnels_reports_both_questions_once_each():
    """Two rows, two questions: the containers that exist are on a tag that no
    longer does (`tunnels: image identity`), and the ones that do not exist
    were never created (`tunnels: expected set`). Pinned so the overlap is a
    reviewed decision rather than an accident."""
    obs = _obs(
        ss_containers=(_cs("", _SS_A, "sha256:ddd", HEAD, ""), ),
        tag_ids={"local/postern-portal": "sha256:aaa", _PROXY_REF: "sha256:ccc", "local/shadowsocks-server": ""},
    )
    labels = _labels(vd.evaluate(obs, HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A, _SS_B})))
    assert labels["tunnels: image identity"].status == "fail"
    assert labels["tunnels: expected set"].status == "fail"
    assert f"tunnel {_SS_A}: running" not in labels  # the per-tunnel loop is skipped when the tag is gone


def test_a_missing_image_collapses_missing_and_surplus_into_the_same_row():
    """With the image absent, reconcile() short-circuits its whole container
    branch: it neither creates nor removes. So a surplus container is as
    unfixable by `postern reconcile` as a missing one, and must not carry a fix
    hint that provably cannot work."""
    obs = _obs(
        ss_containers=(_cs("", _SS_B, "sha256:ddd", HEAD, ""), ),
        tag_ids={"local/postern-portal": "sha256:aaa", _PROXY_REF: "sha256:ccc", "local/shadowsocks-server": ""},
    )
    labels = _labels(vd.evaluate(obs, HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A})))
    check = labels["tunnels: expected set"]
    assert check.status == "fail"
    assert "1 missing, 1 unexpected" in check.detail
    assert "shadowsocks/Dockerfile" in check.fix
    assert f"tunnel {_SS_A}: exists" not in labels
    assert f"tunnel {_SS_B}: not expected" not in labels


def test_a_surplus_container_does_not_also_get_a_passing_running_row():
    """A container the report just condemned as one that should not exist must
    not appear two rows later as `running: ok`."""
    obs = _obs(ss_containers=(_cs("", _SS_A, "sha256:ddd", HEAD, ""), _cs("", _SS_B, "sha256:ddd", HEAD, "")))
    labels = _labels(vd.evaluate(obs, HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A})))
    assert labels[f"tunnel {_SS_A}: running"].status == "ok"  # expected: still checked
    assert f"tunnel {_SS_B}: running" not in labels
    assert f"tunnel {_SS_B}: image identity" not in labels


def test_a_matching_set_still_checks_each_tunnels_image():
    """The set row is an addition, not a replacement: a deployment with exactly
    the right tunnels can still be running all of them on last month's image."""
    obs = _obs(ss_containers=(_cs("", _SS_A, "sha256:old", "0" * 40, ""), ))
    report = vd.evaluate(obs, HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A}))
    assert _labels(report)["tunnels: expected set"].status == "ok"
    assert _labels(report)[f"tunnel {_SS_A}: image identity"].status == "fail"
    assert report.exit_code == 1


def test_a_shortfall_names_concurrent_mutation_as_the_other_possible_cause():
    """The expected set and the container listing are two unsynchronized
    observations, so a connection added while the gate runs produces this same
    row. Asserting non-convergence as fact would send the operator to hunt the
    wrong subsystem."""
    report = vd.evaluate(_obs(ss_containers=()), HEAD, tunnels=True, expected_tunnels=frozenset({_SS_A}))
    assert "added while this ran" in _labels(report)[f"tunnel {_SS_A}: exists"].detail


def test_without_an_expected_set_the_zero_case_stays_an_honest_skip():
    """An operator running the gate by hand has not necessarily blocked on a
    completed reconcile pass, so the tool cannot upgrade the ambiguity into a
    verdict on its own. Same command, less information from the caller, weaker
    answer."""
    report = vd.evaluate(_obs(ss_containers=()), HEAD, tunnels=True)
    labels = _labels(report)
    assert labels["tunnels: image identity"].status == "skip"
    assert "has not converged yet" in labels["tunnels: image identity"].detail
    assert labels["tunnels: expected set"].status == "skip"
    assert "--expected-tunnels-from" in labels["tunnels: expected set"].detail
    assert report.exit_code == 0


def test_no_set_rows_at_all_without_tunnels():
    assert "tunnels: expected set" not in _labels(vd.evaluate(_obs(), HEAD))


def test_evaluate_ignores_an_expected_set_when_tunnels_are_not_checked():
    """The pure function has no opinion on the combination; main() is where it
    is rejected. Pinned so a caller that bypasses the CLI (a script, a REPL)
    finds a tested contract rather than an accident."""
    report = vd.evaluate(_obs(), HEAD, tunnels=False, expected_tunnels=frozenset({_SS_A}))
    assert "tunnels: expected set" not in _labels(report)
    assert _labels(report)["tunnels: image identity"].status == "skip"
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


def test_read_expected_tunnels_parses_one_name_per_line(tmp_path):
    path = tmp_path / "names"
    path.write_text(f"{_SS_A}\n{_SS_B}\n\n")
    assert vd.read_expected_tunnels(str(path)) == frozenset({_SS_A, _SS_B})


def test_read_expected_tunnels_accepts_an_empty_list(tmp_path):
    """A deployment with no enabled connections sends nothing, and that is a
    real answer -- distinct from not passing the flag at all."""
    path = tmp_path / "names"
    path.write_text("")
    assert vd.read_expected_tunnels(str(path)) == frozenset()


def test_read_expected_tunnels_rejects_a_line_that_is_not_a_container_name(tmp_path):
    """If anything ever leaks onto the portal's stdout, it must be a loud stop,
    not a phantom tunnel the gate then reports as missing forever."""
    path = tmp_path / "names"
    path.write_text(f"{_SS_A}\nWARNING: could not determine this deployment's instance id\n")
    with pytest.raises(vd.CollectError):
        vd.read_expected_tunnels(str(path))


def test_read_expected_tunnels_reports_an_unreadable_file_without_a_traceback(tmp_path):
    with pytest.raises(vd.CollectError):
        vd.read_expected_tunnels(str(tmp_path / "nope"))


def test_read_expected_tunnels_reports_undecodable_stdin_as_a_collect_error(monkeypatch):
    """sys.stdin decodes strictly, and UnicodeDecodeError is not an OSError --
    the stdin half of this function must not be the one path that produces a
    traceback."""

    class Undecodable:

        def read(self):
            return b"\xff".decode("utf-8")  # raises UnicodeDecodeError

    monkeypatch.setattr("sys.stdin", Undecodable())
    with pytest.raises(vd.CollectError):
        vd.read_expected_tunnels("-")


def test_read_expected_tunnels_reports_closed_stdin_as_a_collect_error(monkeypatch):
    """CPython sets sys.stdin to None (not a stream that raises on .read()) when
    fd 0 is closed. An unguarded .read() there is an uncaught AttributeError,
    which exits 1 (verify-deploy's "stale deployment" verdict) rather than 2
    ("could not run"); deploy.sh's own branch on that distinction (die vs.
    re-read) depends on getting 2 here."""
    monkeypatch.setattr("sys.stdin", None)
    with pytest.raises(vd.CollectError):
        vd.read_expected_tunnels("-")


def test_read_expected_tunnels_reports_a_closed_stdin_stream_as_a_collect_error(monkeypatch):
    """A stdin object that exists but was already closed raises ValueError on
    .read(), not OSError -- a second way to hit the same traceback the None
    case does."""

    class Closed:

        def read(self):
            raise ValueError("I/O operation on closed file")

    monkeypatch.setattr("sys.stdin", Closed())
    with pytest.raises(vd.CollectError):
        vd.read_expected_tunnels("-")


def test_main_passes_the_expected_set_through_to_the_verdict(monkeypatch, capsys, isolated, tmp_path):
    path = tmp_path / "names"
    path.write_text(f"{_SS_A}\n")
    monkeypatch.setattr(vd, "collect", lambda *a, **k: _obs(ss_containers=()))
    assert vd.main([*isolated, "--tunnels", "--expected-tunnels-from", str(path)]) == 1
    assert f"tunnel {_SS_A}: exists" in capsys.readouterr().out


def test_main_reads_the_expected_set_from_stdin(monkeypatch, capsys, isolated):
    """`-` is how scripts/deploy.sh passes it: container names embed connection
    path tokens, and argv is world-readable through `ps` on the deploy host."""
    monkeypatch.setattr(vd, "collect", lambda *a, **k: _obs(ss_containers=()))
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{_SS_A}\n"))
    assert vd.main([*isolated, "--tunnels", "--expected-tunnels-from", "-"]) == 1
    assert f"tunnel {_SS_A}: exists" in capsys.readouterr().out


def test_main_rejects_an_expected_set_without_tunnels(monkeypatch, capsys, isolated, tmp_path):
    """Silently discarding it would be the worst outcome: the operator asked
    for the strictest check available and would get the weakest, with a green
    exit code."""
    monkeypatch.setattr(vd, "collect", lambda *a, **k: pytest.fail("must fail before collecting"))
    assert vd.main([*isolated, "--expected-tunnels-from", str(tmp_path / "names")]) == 2
    assert "--tunnels" in capsys.readouterr().err


def test_main_treats_an_explicitly_empty_flag_value_as_an_error_not_as_absence(capsys, isolated):
    """`--expected-tunnels-from ""` (an unset variable in a wrapper, a CI step
    whose earlier command produced nothing) must not silently downgrade to the
    no-set SKIP and exit 0. It is an unreadable path: exit 2."""
    assert vd.main([*isolated, "--tunnels", "--expected-tunnels-from", ""]) == 2
    out = capsys.readouterr()
    assert "Traceback" not in out.err
    # Its own row, not the compose-collection one: a bad --expected-tunnels-from
    # is not a bad --project-dir, and must not send the operator there.
    assert "expected tunnels: readable" in out.out
    assert "compose: readable" not in out.out


def test_main_reports_an_unreadable_expected_set_as_could_not_run(capsys, isolated, tmp_path):
    """Exit 2, not 1: the gate could not run. A caller must not read a missing
    input file as "the deployment is stale"."""
    assert vd.main([*isolated, "--tunnels", "--expected-tunnels-from", str(tmp_path / "nope")]) == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    assert "expected tunnels: readable" in captured.out
    assert "compose: readable" not in captured.out


def test_main_reports_closed_stdin_as_could_not_run_not_stale(monkeypatch, capsys, isolated):
    """Same fd-0-closed mechanism as
    test_read_expected_tunnels_reports_closed_stdin_as_a_collect_error, exercised
    through main() so the exit-code branch (2, not 1) is pinned end-to-end too."""
    monkeypatch.setattr("sys.stdin", None)
    assert vd.main([*isolated, "--tunnels", "--expected-tunnels-from", "-"]) == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    assert "expected tunnels: readable" in captured.out
