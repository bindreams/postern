"""The docker-proxy allow-list, tested in the exact HAProxy and Lua build production runs.

`docker-proxy/policy.lua` is the allow-list; `docker-proxy/tests/test_policy.lua` holds every case and runs inside the
pinned base image's HAProxy (`core.register_init`, exit 0 on pass). This module does two things:

* records what the REAL reconciler (docker-py 7.1.0, the functions production calls) sends to a fake daemon, and hands
  the recording to the Lua suite, which requires every recorded request to be allowed and derives its create-body
  negatives from the recorded create body. A reconciler change that adds a call or a body key, or changes a constant,
  fails here until the policy and the tests are changed with it. Editing the recording instead of the reconciler is
  not an option: it is regenerated on every run.
* runs the suite and reports its output.

Needs a Docker daemon (it runs `docker run` of the base image, with no network); skipped when the docker CLI
reports it cannot reach one, and a failure when `$CI` is `true` or the CLI does not answer. Opt out with
`-m 'not haproxy_harness'`.

It also pins that the three places that validate an instance id agree: the portal (`reconciler.resolve_instance_id`),
the deploy gate (`scripts/verify-deploy.py`) and the proxy (`policy.config_from_env`, run through the harness).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus, urlsplit

import pytest

from postern import reconciler
from postern.models import Connection
from postern.settings import Settings

from ._compose import REPO_ROOT
from .test_verify_deploy import vd  # the one loader of scripts/verify-deploy.py

pytestmark = pytest.mark.haproxy_harness

PROXY_DIR = REPO_ROOT / "docker-proxy"
API_VERSION = "1.56"
INSTANCE = "postern"
TOKEN = "a1" * 12
OWNED_ID = "c" * 64
GONE_ID = "d" * 64


# Recording fake daemon ================================================================================================
@dataclass(frozen=True)
class Recorded:
    name: str
    method: str
    uri: str
    content_type: str
    body: str


class _Daemon(BaseHTTPRequestHandler):
    """Answers just enough for the reconciler functions to run to completion, and records every request."""

    protocol_version = "HTTP/1.1"
    log: list[Recorded]

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        self.log.append(Recorded("", self.command, self.path, self.headers.get("Content-Type") or "", body))
        parts = urlsplit(self.path)
        path = re.sub(r"^/v\d+\.\d+", "", parts.path)
        code, out = 200, {}
        container = {
            "Id": OWNED_ID,
            "Name": f"/ss-{TOKEN}",
            "Image": "sha256:" + "1" * 64,
            "State": {"Status": "exited"},
            "Config": {"Labels": {"postern.managed": "true", "postern.instance": INSTANCE}},
            "NetworkSettings": {"Networks": {"shadowsocks": {"NetworkID": "n1"}}},
        }
        if path == "/version":
            out = {"ApiVersion": API_VERSION, "Version": "29.9.3"}
        elif path == "/containers/create":
            code, out = 201, {"Id": OWNED_ID, "Warnings": []}
        elif path == "/containers/json":
            out = [{
                "Id": OWNED_ID, "Names": [f"/ss-{TOKEN}"], "State": "exited",
                "Labels": {"postern.managed": "true", "postern.instance": INSTANCE}
            }]
        elif path.endswith("/start") or path.endswith("/stop"):
            code, out = 204, None
        elif path.startswith("/containers/") and path.endswith("/json"):
            out = container
        elif path.startswith("/images/"):
            out = {"Id": "sha256:" + "1" * 64}
        elif path.startswith("/networks/"):
            out = {"Id": "n1", "Name": "shadowsocks"}
        elif self.command == "DELETE":
            code, out = 204, None
        data = b"" if out is None else json.dumps(out).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_DELETE = _handle

    def log_message(self, format: str, *args: Any) -> None:
        pass


@dataclass(frozen=True)
class FakeDaemon:
    url: str
    log: list[Recorded]


@contextmanager
def _serve() -> Iterator[FakeDaemon]:
    log: list[Recorded] = []
    handler = type("Handler", (_Daemon, ), {"log": log})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeDaemon(f"tcp://127.0.0.1:{server.server_port}", log)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.fixture
def fake_daemon() -> Iterator[FakeDaemon]:
    with _serve() as daemon:
        yield daemon


def _record_reconciler(daemon: FakeDaemon, settings: Settings) -> list[Recorded]:
    """Run every Docker-touching path of the reconciler (and nothing else) against the fake daemon."""
    conn = Connection(user_id="u", path_token=TOKEN, label="l", password="pw")
    name = f"ss-{TOKEN}"
    # Only around the client: a `docker run` started later must not inherit it.
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("DOCKER_HOST", daemon.url)
        client = reconciler._get_docker_client()
    try:
        reconciler._image_exists(client, settings.shadowsocks_image)
        reconciler._create_container(client, conn, settings, INSTANCE)
        container = reconciler._list_managed_containers(client, INSTANCE)[name]
        container.start()
        reconciler._remove_container(container)
        client.images.get(settings.shadowsocks_image)
        client.networks.get(settings.shadowsocks_network)
        reconciler.find_container_summary_by_name(client, name)
    finally:
        client.close()
    return daemon.log


def _wire_tsv(requests: list[Recorded]) -> str:
    lines = []
    for n, r in enumerate(requests):
        label = f"{n:02d} {r.method} {unquote_plus(urlsplit(r.uri).path)}"
        assert "\t" not in label + r.uri + r.content_type + r.body and "\n" not in r.body
        lines.append("\t".join([label, r.method, r.uri, r.content_type, r.body]))
    return "\n".join(lines) + "\n"


# Tests ================================================================================================================
def _settings() -> Settings:
    return Settings(secret_key="x" * 40, domain="postern.example.com", compose_project_name=INSTANCE)


def test_the_recording_covers_every_request_the_reconciler_sends(fake_daemon: FakeDaemon) -> None:
    """The contract test below is only as good as the recording: pin what it contains."""
    requests = _record_reconciler(fake_daemon, _settings())
    shapes = []
    for r in requests:
        path = re.sub(r"^/v\d+\.\d+", "/v<api>", urlsplit(r.uri).path)
        path = re.sub(r"/[0-9a-f]{64}", "/<id>", path)
        path = re.sub(r"ss-[0-9a-f]{24}", "ss-<token>", path)
        shapes.append((r.method, path))
    assert set(shapes) == {
        ("GET", "/version"),
        ("GET", "/v<api>/images/local/shadowsocks-server/json"),
        ("POST", "/v<api>/containers/create"),
        ("GET", "/v<api>/containers/<id>/json"),
        ("POST", "/v<api>/containers/<id>/start"),
        ("GET", "/v<api>/containers/json"),
        ("POST", "/v<api>/containers/<id>/stop"),
        ("DELETE", "/v<api>/containers/<id>"),
        ("GET", "/v<api>/networks/shadowsocks"),
    }
    queries = {urlsplit(r.uri).query for r in requests if urlsplit(r.uri).path.endswith("/containers/json")}
    assert len(queries) == 2, "expected the label-scoped list and the name-filtered read"


def _require_docker_daemon() -> None:
    """Skip the harness when the docker CLI says it cannot reach a daemon. Never skip on elapsed time: a CLI that does
    not answer within the bound fails, as does any missing daemon when `CI=true` (the workflow provisions one)."""
    try:
        # Failure bound on a child process (the CLI against an unreachable remote host can hang), below pyproject's
        # `timeout = 30`.
        info = subprocess.run(["docker", "info"], capture_output=True, text=True, check=False, timeout=10)
    except subprocess.TimeoutExpired:
        pytest.fail("`docker info` did not answer within 10 s: cannot tell whether a Docker daemon is reachable")
    except OSError as exc:
        reason = f"the docker CLI cannot be run ({exc})"
    else:
        if info.returncode == 0:
            return
        lines = info.stderr.strip().splitlines()
        reason = f"`docker info` exited {info.returncode}: {lines[-1] if lines else 'no message'}"
    message = f"no reachable Docker daemon: {reason} (the Lua policy suite runs in the pinned HAProxy image)"
    if os.environ.get("CI", "").lower() == "true":
        pytest.fail(message)
    pytest.skip(message)


def _base_image() -> str:
    dockerfile = (PROXY_DIR / "Dockerfile").read_text(encoding="utf-8")
    match = re.search(r"^FROM\s+(\S+)", dockerfile, re.M)
    assert match, "docker-proxy/Dockerfile has no FROM"
    return match.group(1)


# (INSTANCE_ID override, COMPOSE_PROJECT_NAME) pairs: what each validator must resolve, or refuse, identically.
INSTANCE_ID_CASES: list[tuple[str, str]] = [
    # Accepted
    ("a", ""), ("1", ""), ("0abc", ""), ("a" * 63, ""), ("A1_b.c-d", ""), ("a.b_c-d", ""), ("aB", ""), ("Ab", ""),
    ("", "proj"), ("a", "b"), ("  a  ", ""), ("\t\n a\r\v\f", ""), ("", "  b "), ("   ", "b"), ("a\n", ""),
    # Refused, with no fallback from a refused override to the project name
    ("", ""), ("   ", ""), ("   ", "   "), ("a" * 64, ""), ("-a", ""), (".a", ""), ("_a", ""), ("a:b", ""),
    ("a/b", ""), ("a b", ""), ('a"b', ""), ("a,b", ""), ("a\b", ""), ("a%b", ""), ("a&b", ""), ("a=b", ""),
    ("a\nb", ""), ("é", ""), ("aé", ""), (" a", ""), ("a ", ""), (" ", "b"),
    ("bad:id", "good"), ("", "bad:id"), ("", "a" * 64), ("", " a"),
]  # yapf: disable


def _hex(text: str) -> str:
    return text.encode().hex()


@dataclass(frozen=True)
class LuaRun:
    returncode: int
    stdout: str
    stderr: str


def _run_lua_suite(wire: str, settings: Settings) -> LuaRun:
    id_cases = ",".join(f"{_hex(o)}:{_hex(p)}" for o, p in INSTANCE_ID_CASES)
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "-i", "--network", "none",
            "-v", f"{PROXY_DIR}:/pn:ro",
            "-e", f"TEST_IMAGE={settings.shadowsocks_image}",
            "-e", f"TEST_NETWORK={settings.shadowsocks_network}",
            "-e", f"TEST_INSTANCE={INSTANCE}",
            "-e", f"TEST_API_VERSION={API_VERSION}",
            "-e", f"TEST_ID_CASES={id_cases}",
            "--entrypoint", "/usr/sbin/haproxy",
            _base_image(),
            "-f", "/pn/tests/haproxy.test.cfg", "-db",
        ],
        input=wire,
        capture_output=True,
        text=True,
        check=False,
        # Failure bound on a child process (an image pull on a cold runner), below pyproject's `timeout = 30`.
        timeout=25,
    )  # yapf: disable
    return LuaRun(proc.returncode, proc.stdout, proc.stderr)


@pytest.fixture(scope="module")
def lua_suite() -> LuaRun:
    """One run of the Lua suite, shared by the tests below."""
    _require_docker_daemon()
    settings = _settings()
    with _serve() as daemon:
        return _run_lua_suite(_wire_tsv(_record_reconciler(daemon, settings)), settings)


def test_lua_policy_suite(lua_suite: LuaRun) -> None:
    assert lua_suite.returncode == 0, (
        f"policy suite failed ({lua_suite.returncode}):\n{lua_suite.stdout}\n{lua_suite.stderr}"
    )
    assert re.search(r"^\d{3,} checks, 0 failed$", lua_suite.stdout, re.M), lua_suite.stdout


def _lua_instance_ids(stdout: str) -> dict[tuple[str, str], str | None]:
    """The suite prints `instance-id <hex override>:<hex project> <hex resolved id | ->` per case."""
    out: dict[tuple[str, str], str | None] = {}
    for override, project, resolved in re.findall(r"^instance-id ([0-9a-f]*):([0-9a-f]*) ([0-9a-f]+|-)$", stdout, re.M):
        case = (bytes.fromhex(override).decode(), bytes.fromhex(project).decode())
        out[case] = None if resolved == "-" else bytes.fromhex(resolved).decode()
    return out


def _portal_instance_id(override: str, project: str) -> str | None:
    settings = Settings(
        secret_key="x" * 40, domain="postern.example.com", instance_id=override, compose_project_name=project
    )
    return reconciler.resolve_instance_id(settings)


def _deploy_gate_instance_id(override: str, project: str) -> str | None:
    config = {"services": {"portal": {"environment": {"INSTANCE_ID": override}}}}
    try:
        return vd.resolve_instance_id(config, project)
    except vd.CollectError:
        return None


def test_the_proxy_the_portal_and_the_deploy_gate_resolve_every_instance_id_alike(lua_suite: LuaRun) -> None:
    """The portal must not run with an id the proxy refuses, and the deploy gate must filter on the id the portal
    labels containers with: all three validate by hand, so they are compared case by case."""
    proxy = _lua_instance_ids(lua_suite.stdout)
    assert set(proxy) == set(INSTANCE_ID_CASES), "the Lua suite did not report every case"
    assert any(v is not None for v in proxy.values()) and any(v is None for v in proxy.values())
    for case in INSTANCE_ID_CASES:
        assert _portal_instance_id(*case) == proxy[case], f"portal and proxy disagree on {case!r}"
        assert _deploy_gate_instance_id(*case) == proxy[case], f"deploy gate and proxy disagree on {case!r}"
