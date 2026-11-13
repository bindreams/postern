"""The docker-proxy allow-list against the live e2e stack.

Every case is DIFFERENTIAL: the same request with only the offending change, with the unmodified control accepted in
the same run. The requests are sent from inside the portal container through its own `DOCKER_HOST` (the same path
the reconciler uses), so what is tested is what a process in the portal can do.

A denial is a 403 whose message names the policy; a container id the daemon does not know is a 404, as dockerd answers.
"""

from __future__ import annotations

import copy
import json
import re
import secrets
import subprocess
from collections.abc import Callable, Iterator

import pytest

from postern import reconciler

from ._helpers import (
    E2E_DOCKER_PROXY_IMAGE,
    E2E_SHADOWSOCKS_IMAGE,
    E2E_SLEEPER_IMAGE,
    compose_exec,
    container_exists,
    docker_inspect,
    get_container_id,
    run,
    trigger_reconcile,
)

# Run in the portal container: send each scenario as a raw request through the proxy and report status and text.
_SEND = """
import json, sys, docker
api = docker.DockerClient.from_env().api
out = {}
for s in json.load(sys.stdin):
    url = api.base_url + s["path"] if s.get("unversioned") else api._url(s["path"])
    r = api.request(s["method"], url, params=s.get("params"), data=s.get("data"), headers=s.get("headers"), timeout=30)
    out[s["id"]] = {"status": r.status_code, "text": r.text[:4000]}
print(json.dumps(out))
"""

# Run in the portal container: the body docker-py sends for the reconciler's own create, taken from the real code.
_CONTROL_BODY = """
import json, docker
from postern import reconciler
from postern.models import Connection
from postern.settings import Settings

class Captured(Exception):
    pass

captured = {}
def grab(url, data=None, **kw):
    captured["data"] = json.loads(data)
    raise Captured

settings = Settings()
kwargs = {}
class Recorder:
    def run(self, **k):
        kwargs.update(k)
reconciler._create_container(
    type("Client", (), {"containers": Recorder()})(),
    Connection(user_id="u", path_token="a" * 24, label="l", password="pw"),
    settings,
    reconciler.resolve_instance_id(settings),
)
client = docker.DockerClient.from_env()
client.api._post = grab
try:
    client.containers.create(**kwargs)
except Captured:
    pass
print(json.dumps(captured["data"]))
"""

JSON_HEADERS = {"Content-Type": "application/json"}


def send(scenarios: list[dict]) -> dict[str, dict]:
    result = compose_exec("python", "-c", _SEND, stdin=json.dumps(scenarios))
    return json.loads(result.stdout)


def one(method: str, path: str, **kw) -> dict:
    return send([{"id": "x", "method": method, "path": path, **kw}])["x"]


def token() -> str:
    return secrets.token_hex(12)


def create_scenario(name: str, body: dict | str, *, query: dict | None = None) -> dict:
    """A create request. `container` lists the names it could create, so a test removes and counts only those."""
    params = query if query is not None else {"name": f"ss-{token()}"}
    named = params.get("name", [])
    return {
        "id": name, "method": "POST", "path": "/containers/create", "params": params,
        "container": [named] if isinstance(named, str) else list(named),
        "data": body if isinstance(body, str) else json.dumps(body), "headers": JSON_HEADERS,
    }  # yapf: disable


def container_names(scenarios: list[dict]) -> set[str]:
    return {name for s in scenarios for name in s.get("container", [])}


@pytest.fixture(scope="module")
def control_body(e2e_stack) -> dict:
    return json.loads(compose_exec("python", "-c", _CONTROL_BODY).stdout)


def _host_containers() -> set[str]:
    return set(run(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split())


@pytest.fixture
def created() -> Iterator[list[str]]:
    """Names of containers a test made through the proxy; removed by name afterwards."""
    names: list[str] = []
    yield names
    for name in names:
        subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)


def _denied(result: dict) -> bool:
    return result["status"] == 403 and "postern docker-proxy" in result["text"]


# Control ==============================================================================================================
def test_control_create_start_stop_delete_succeeds(control_body, created):
    name = f"ss-{token()}"
    created.append(name)
    made = one("POST", "/containers/create", params={"name": name}, data=json.dumps(control_body), headers=JSON_HEADERS)
    assert made["status"] == 201, made
    cid = json.loads(made["text"])["Id"]
    assert one("GET", f"/containers/{cid}/json")["status"] == 200
    assert one("POST", f"/containers/{cid}/start")["status"] == 204
    assert one("POST", f"/containers/{cid}/stop", params={"t": 10})["status"] == 204
    assert one("DELETE", f"/containers/{cid}", params={"v": False, "link": False, "force": True})["status"] == 204


# Create: nothing but the reconciler's exact shape ---------------------------------------------------------------------
def _mutations(body: dict) -> dict[str, dict]:
    """name -> body with exactly one change."""
    out: dict[str, dict] = {}

    def mutate(name: str, change: Callable[[dict], None]) -> None:
        variant = copy.deepcopy(body)
        change(variant)
        assert variant != body, name
        out[name] = variant

    host = lambda key, value: (lambda b: b["HostConfig"].__setitem__(key, value))  # noqa: E731
    top = lambda key, value: (lambda b: b.__setitem__(key, value))  # noqa: E731

    for key, value in {
        "Binds": ["/:/h"], "Privileged": True, "CapAdd": ["SYS_ADMIN"], "Devices": [{"PathOnHost": "/dev/sda"}],
        "PidMode": "host", "IpcMode": "host", "UsernsMode": "host", "VolumesFrom": ["portal"], "Sysctls": {"a": "b"},
        "Runtime": "runc", "PortBindings": {"80/tcp": [{"HostPort": "80"}]}, "PublishAllPorts": True,
        "Mounts": [{"Type": "volume", "Source": "postern-e2e-data", "Target": "/d"}],
        "Binds-named-volume": ["postern-e2e-data:/d"], "ExtraHosts": ["a:1.1.1.1"], "Links": ["x"],
    }.items():  # yapf: disable
        mutate(f"HostConfig.{key}", host(key.split("-")[0], value))
    for key, value in {
        "Cmd": ["sh"], "Entrypoint": ["sh"], "User": "root", "WorkingDir": "/", "Volumes": {"/x": {}},
        "Hostname": "x", "image": "alpine",
    }.items():  # yapf: disable
        mutate(f"top.{key}", top(key, value))
    for mode in ("host", "none", "bridge", f"container:{'a' * 64}", "default"):
        mutate(f"NetworkMode={mode}", host("NetworkMode", mode))
    for image in (
        f"{E2E_SHADOWSOCKS_IMAGE}:evil", E2E_SHADOWSOCKS_IMAGE.replace("-test", ""), "alpine",
        f"{E2E_SHADOWSOCKS_IMAGE}@sha256:{'a' * 64}", f"sha256:{'a' * 64}",
    ):  # yapf: disable
        mutate(f"Image={image}", top("Image", image))
    mutate("Env: extra variable", lambda b: b["Env"].append("LD_PRELOAD=/x"))
    mutate("Env: another variable", top("Env", ["FOO=bar"]))
    mutate("Labels: extra", lambda b: b["Labels"].__setitem__("x", "y"))
    mutate("Labels: another instance", lambda b: b["Labels"].__setitem__("postern.instance", "someone-else"))
    mutate("Labels: spec", lambda b: b["Labels"].__setitem__("postern.spec", "1"))
    mutate("SecurityOpt other", host("SecurityOpt", ["seccomp=unconfined"]))
    mutate("CapDrop weakened", host("CapDrop", ["NET_RAW"]))
    mutate("ReadonlyRootfs false", host("ReadonlyRootfs", False))
    mutate("Memory raised", host("Memory", reconciler.SS_MEMORY_BYTES * 2))
    mutate("PidsLimit unlimited", host("PidsLimit", -1))
    mutate("Tmpfs widened", host("Tmpfs", {**reconciler.SS_TMPFS, "/x": ""}))
    mutate("Tmpfs option changed", host("Tmpfs", {"/tmp": "exec", "/home/nonroot/.cache": "exec"}))
    for key in (
        "CapDrop", "SecurityOpt", "ReadonlyRootfs", "Memory", "PidsLimit", "Tmpfs", "Init", "RestartPolicy", "LogConfig"
    ):
        mutate(f"HostConfig.{key} removed", lambda b, key=key: b["HostConfig"].pop(key))
    return out


def test_every_create_that_differs_from_the_reconcilers_is_denied(control_body, created):
    variants = _mutations(control_body)
    scenarios = [create_scenario(name, body) for name, body in variants.items()]
    control = create_scenario("control", control_body)
    scenarios.append(control)
    named = container_names(scenarios)
    created.extend(named)
    results = send(scenarios)
    assert results["control"]["status"] == 201, results["control"]
    not_denied = {name: r for name, r in results.items() if name != "control" and not _denied(r)}
    assert not not_denied, not_denied
    made = named & _host_containers()
    assert made == set(control["container"]), f"only the control may have produced a container, got {made}"


def test_create_names_are_pinned_to_the_tunnel_shape(control_body, created):
    good = f"ss-{token()}"
    names = {
        "23 hex": f"ss-{token()[:23]}", "25 hex": f"ss-{token()}a", "upper-case hex": f"ss-{token().upper()}",
        "non-hex": f"ss-{token()[:23]}g", "other prefix": f"sx-{token()}", "plain": "tunnel",
    }  # yapf: disable
    scenarios = [create_scenario(label, control_body, query={"name": n}) for label, n in names.items()]
    scenarios.append(create_scenario("no name", control_body, query={}))
    scenarios.append(create_scenario("two names", control_body, query={"name": [good, good]}))
    scenarios.append(create_scenario("platform", control_body, query={"name": good, "platform": "linux/amd64"}))
    scenarios.append(create_scenario("control", control_body, query={"name": good}))
    created.extend(container_names(scenarios))
    results = send(scenarios)
    assert results["control"]["status"] == 201, results["control"]
    assert {n for n, r in results.items() if n != "control" and not _denied(r)} == set()


# Images: the image the proxy pins cannot be introduced, retagged or replaced ------------------------------------------
def _image_id() -> str:
    return docker_inspect(E2E_SHADOWSOCKS_IMAGE, "{{.Id}}")


def _instance_containers_off_the_tunnel_shape() -> set[str]:
    """This deployment's labelled containers that the reconciler would not have created (no `ss-<24 hex>` name)."""
    listed = run([
        "docker", "ps", "-a", "--filter", f"label=postern.instance={_portal_instance()}", "--format", "{{.Names}}"
    ]).stdout.split()  # yapf: disable
    return {name for name in listed if not re.fullmatch(r"ss-[0-9a-f]{24}", name)}


def test_no_request_can_introduce_retag_or_replace_an_image(control_body):
    ref = E2E_SHADOWSOCKS_IMAGE
    before_image, before_containers = _image_id(), _instance_containers_off_the_tunnel_shape()
    cid = "0" * 64
    attacks = {
        "pull alpine": ("POST", "/images/create", {"fromImage": "alpine", "tag": "latest"}),
        "pull the pinned reference": ("POST", "/images/create", {"fromImage": ref}),
        "import from a URL": ("POST", "/images/create", {"fromSrc": "http://127.0.0.1:1/x.tar", "repo": ref}),
        "retag onto the pinned reference": ("POST", "/images/alpine/tag", {"repo": ref.split(":")[0], "tag": "latest"}),
        "retag the pinned image": ("POST", f"/images/{ref}/tag", {"repo": "evil", "tag": "latest"}),
        "build over the pinned reference": ("POST", "/build", {"t": ref}),
        "load": ("POST", "/images/load", None),
        "commit": ("POST", "/commit", {"container": cid, "repo": ref}),
        "push": ("POST", f"/images/{ref}/push", None),
        "delete the pinned image": ("DELETE", f"/images/{ref}", {"force": True}),
        "prune": ("POST", "/images/prune", None),
        "export": ("GET", f"/images/{ref}/get", None),
        "search": ("GET", "/images/search", {"term": "alpine"}),
        "history": ("GET", f"/images/{ref}/history", None),
        "list": ("GET", "/images/json", None),
    }  # yapf: disable
    scenarios = [{"id": n, "method": m, "path": p, "params": q} for n, (m, p, q) in attacks.items()]
    scenarios.append({"id": "control", "method": "GET", "path": f"/images/{ref}/json"})
    results = send(scenarios)
    assert results["control"]["status"] == 200, results["control"]
    assert {n for n, r in results.items() if n != "control" and not _denied(r)} == set()
    assert _image_id() == before_image
    assert subprocess.run(["docker", "image", "inspect", "evil:latest"], capture_output=True).returncode != 0
    assert _instance_containers_off_the_tunnel_shape() == before_containers


# Everything else on the daemon ----------------------------------------------------------------------------------------
def test_unlisted_routes_are_denied(e2e_stack):
    routes = [
        ("GET", "/events"), ("GET", "/info"), ("GET", "/volumes"), ("POST", "/volumes/create"), ("GET", "/system/df"),
        ("POST", "/containers/prune"), ("POST", "/networks/create"), ("POST", "/networks/prune"), ("GET", "/plugins"),
        ("GET", "/swarm"), ("GET", "/services"), ("GET", "/secrets"), ("GET", "/configs"), ("POST", "/session"),
        ("GET", "/networks"), ("GET", "/containers/json"), ("GET", "/libpod/containers/json"),
    ]  # yapf: disable
    results = send([{"id": f"{m} {p}", "method": m, "path": p} for m, p in routes])
    assert {n for n, r in results.items() if not _denied(r)} == set()


@pytest.mark.parametrize("service", ["nginx", "portal", "docker-proxy", "mailpit", "go-httpbin"])
def test_other_containers_cannot_be_touched_or_read(e2e_stack, service):
    cid = get_container_id(service)
    verbs = [
        ("GET", "/json", None), ("POST", "/start", None), ("POST", "/stop", {"t": 10}), ("POST", "/kill", None),
        ("POST", "/restart", None), ("POST", "/rename", {"name": "x"}), ("POST", "/update", None),
        ("DELETE", "", {"force": True}), ("POST", "/attach", None), ("GET", "/archive", {"path": "/"}),
        ("POST", "/exec", None), ("GET", "/logs", {"stdout": 1}), ("GET", "/top", None), ("GET", "/export", None),
        ("POST", "/pause", None), ("GET", "/changes", None), ("GET", "/stats", {"stream": False}),
    ]  # yapf: disable
    results = send([{"id": f"{m}{t}", "method": m, "path": f"/containers/{cid}{t}", "params": q} for m, t, q in verbs])
    assert {n for n, r in results.items() if r["status"] != 403} == set(), results
    assert all("Env" not in r["text"] for r in results.values())


def test_a_foreign_deployments_tunnel_is_unreachable_and_its_secrets_unread(e2e_stack, created):
    name = f"ss-{token()}"
    created.append(name)
    run([
        "docker", "run", "-d", "--init", "--name", name, "--label", "postern.managed=true", "--label",
        "postern.instance=another-deployment", "-e", "SS_CONFIG=hunter2-the-secret", E2E_SLEEPER_IMAGE, "sleep",
        "infinity",
    ])  # yapf: disable
    cid = docker_inspect(name, "{{.Id}}")
    results = send([
        {"id": "inspect", "method": "GET", "path": f"/containers/{cid}/json"},
        {"id": "start", "method": "POST", "path": f"/containers/{cid}/start"},
        {"id": "stop", "method": "POST", "path": f"/containers/{cid}/stop", "params": {"t": 10}},
        {"id": "delete", "method": "DELETE", "path": f"/containers/{cid}", "params": {"force": True}},
        {"id": "by name", "method": "GET", "path": f"/containers/{name}/json"},
        {"id": "unscoped list", "method": "GET", "path": "/containers/json", "params": {"all": 1}},
    ])  # yapf: disable
    assert {n for n, r in results.items() if r["status"] != 403} == set(), results
    assert all("hunter2" not in r["text"] for r in results.values())
    assert container_exists(name)


def test_the_name_filtered_read_shows_labels_but_never_env(e2e_stack, created):
    """R5 in docs/security.md: the squatter read the reconciler needs returns labels, state and mounts of the one
    container with that name, never its configuration."""
    name = f"ss-{token()}"
    created.append(name)
    run([
        "docker", "run", "-d", "--init", "--name", name, "--label", "postern.managed=true", "--label",
        "postern.instance=another-deployment", "-e", "SS_CONFIG=hunter2-the-secret", E2E_SLEEPER_IMAGE, "sleep",
        "infinity",
    ])  # yapf: disable
    read = one(
        "GET", "/containers/json",
        params={"limit": -1, "all": 1, "size": 0, "trunc_cmd": 0, "filters": json.dumps({"name": [f"^/{name}$"]})},
    )  # yapf: disable
    assert read["status"] == 200
    listed = json.loads(read["text"])
    assert [c["Names"] for c in listed] == [[f"/{name}"]]
    assert listed[0]["Labels"]["postern.instance"] == "another-deployment"
    assert "hunter2" not in read["text"] and '"Env"' not in read["text"]


# Robustness: the cases the existing handlers were written for ---------------------------------------------------------
def test_vanished_container_is_not_found_not_forbidden(control_body, created):
    name = f"ss-{token()}"
    created.append(name)
    made = one("POST", "/containers/create", params={"name": name}, data=json.dumps(control_body), headers=JSON_HEADERS)
    cid = json.loads(made["text"])["Id"]
    subprocess.run(["docker", "rm", "-f", name], check=True, capture_output=True)
    results = send([
        {"id": "inspect", "method": "GET", "path": f"/containers/{cid}/json"},
        {"id": "start", "method": "POST", "path": f"/containers/{cid}/start"},
        {"id": "stop", "method": "POST", "path": f"/containers/{cid}/stop", "params": {"t": 10}},
        {"id": "delete", "method": "DELETE", "path": f"/containers/{cid}", "params": {"force": True}},
        {"id": "delete again", "method": "DELETE", "path": f"/containers/{cid}", "params": {"force": True}},
    ])  # yapf: disable
    assert {n: r["status"] for n, r in results.items()} == {n: 404 for n in results}, results
    assert all("No such container" in r["text"] for r in results.values())


def _portal_instance() -> str:
    return compose_exec("python", "-c", "import os; print(os.environ['COMPOSE_PROJECT_NAME'])").stdout.strip()


def test_stray_labelled_container_does_not_stall_reconcile(e2e_stack, fresh_user, fresh_connection, created):
    """A container carrying this deployment's two labels, under any name, is listed, inspected and swept as an
    orphan exactly as before the proxy existed."""
    fresh_user("Stray", "stray@postern.test")
    _, tunnel_token = fresh_connection("stray@postern.test", "stray")
    stray = f"l11-stray-{token()[:8]}"
    created.append(stray)
    run([
        "docker", "run", "-d", "--init", "--name", stray, "--label", "postern.managed=true", "--label",
        f"postern.instance={_portal_instance()}", E2E_SLEEPER_IMAGE, "sleep", "infinity",
    ])  # yapf: disable
    trigger_reconcile()
    assert not container_exists(stray), "the orphan sweep did not remove the stray labelled container"
    assert container_exists(f"ss-{tunnel_token}")


def test_reconcile_is_idempotent_through_the_proxy(e2e_stack, fresh_user, fresh_connection):
    fresh_user("Idem", "idem@postern.test")
    _, tunnel_token = fresh_connection("idem@postern.test", "idem")
    first = docker_inspect(f"ss-{tunnel_token}", "{{.Id}}")
    trigger_reconcile()
    trigger_reconcile()
    assert docker_inspect(f"ss-{tunnel_token}", "{{.Id}}") == first, "the tunnel was recreated: a recreate loop"


def test_created_tunnel_is_hardened(e2e_stack, fresh_user, fresh_connection):
    fresh_user("Hard", "hard@postern.test")
    _, tunnel_token = fresh_connection("hard@postern.test", "hard")
    cfg = json.loads(docker_inspect(f"ss-{tunnel_token}", "{{json .HostConfig}}"))
    labels = json.loads(docker_inspect(f"ss-{tunnel_token}", "{{json .Config.Labels}}"))
    assert cfg["CapDrop"] == ["ALL"] and not cfg["CapAdd"]
    assert cfg["ReadonlyRootfs"] is True
    assert "no-new-privileges:true" in cfg["SecurityOpt"]
    assert cfg["Memory"] == reconciler.SS_MEMORY_BYTES
    assert cfg["PidsLimit"] == reconciler.SS_PIDS_LIMIT
    assert set(cfg["Tmpfs"]) == set(reconciler.SS_TMPFS)
    assert not cfg["Privileged"] and not cfg["Binds"] and cfg["NetworkMode"] != "host"
    assert labels["postern.managed"] == "true" and labels["postern.instance"] == _portal_instance()


# The proxy's own isolation --------------------------------------------------------------------------------------------
def test_http2_prior_knowledge_is_refused(e2e_stack):
    """`proto h1` on the bind: an HTTP/2 client preface must not be answered with an HTTP/2 SETTINGS frame."""
    script = (
        "import socket\n"
        "s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect('/run/docker-api/docker.sock')\n"
        "s.sendall(b'PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n' + b'\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x00\\x00')\n"
        "print(s.recv(64).hex())\n"
    )
    reply = bytes.fromhex(compose_exec("python", "-c", script).stdout.strip())
    assert reply.startswith(b"HTTP/1.") or reply == b"", reply[:16]


def test_the_proxy_is_the_first_party_image_with_no_network(e2e_stack):
    proxy = get_container_id("docker-proxy", running_only=True)
    assert docker_inspect(proxy, "{{.Config.Image}}").partition(":")[0] == E2E_DOCKER_PROXY_IMAGE
    assert docker_inspect(proxy, "{{.HostConfig.NetworkMode}}") == "none"
    assert docker_inspect(proxy, "{{.HostConfig.ReadonlyRootfs}}") == "true"


def test_only_the_proxy_and_the_portal_mount_the_socket_volume(e2e_stack):
    proxy = get_container_id("docker-proxy", running_only=True)
    volume = docker_inspect(proxy, '{{range .Mounts}}{{if eq .Destination "/run/docker-api"}}{{.Name}}{{end}}{{end}}')
    assert volume
    mounting = set()
    for name in _host_containers():
        # A container can vanish between the listing and here (other tests remove theirs): inspect, skip what is gone.
        found = subprocess.run(
            ["docker", "inspect", name, "--format", '{{range .Mounts}}{{.Name}} {{end}}|{{index .Config.Labels "com.docker.compose.service"}}'],
            capture_output=True, text=True, check=False,
        )  # yapf: disable
        if found.returncode == 0 and volume in found.stdout.partition("|")[0].split():
            mounting.add(found.stdout.partition("|")[2].strip())
    assert mounting == {"docker-proxy", "portal"}
