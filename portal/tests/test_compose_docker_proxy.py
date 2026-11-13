"""The docker-proxy's wiring, pinned across every compose file.

The allow-list itself is tested in test_docker_proxy_policy.py (Lua, in the pinned HAProxy) and the e2e suite. What
those cannot see is whether the stack is wired so the allow-list is the only way to the Docker socket and is configured
with the values the portal is: that is what this file pins. Static checks parse the YAML (and haproxy.cfg, the
Dockerfile, policy.lua); `compose_cli` tests resolve the real merged configuration with the Compose CLI (no daemon).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from postern import reconciler
from postern.settings import Settings

from ._compose import (
    ALL_COMPOSE_FILES,
    E2E_COMPOSE_DIR,
    PRODUCTION_COMPOSE_FILES,
    REPO_ROOT,
    load_compose,
    repo_relative,
    run_compose_config,
)

PROXY_DIR = REPO_ROOT / "docker-proxy"
SOCKET_DIR = "/run/docker-api"
SOCKET = f"{SOCKET_DIR}/docker.sock"
DOCKER_SOCK = "/var/run/docker.sock"


def _services(path: Path) -> dict[str, dict]:
    return {name: svc or {} for name, svc in (load_compose(path).get("services") or {}).items()}


def _files_defining_the_proxy() -> list[Path]:
    return [p for p in ALL_COMPOSE_FILES() if "build" in _services(p).get("docker-proxy", {})]


def _is_e2e(path: Path) -> bool:
    return E2E_COMPOSE_DIR in path.parents


# haproxy.cfg ==========================================================================================================
def _section(text: str, header: str) -> list[str]:
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith(header))
    end = next((i for i in range(start + 1, len(lines)) if lines[i] and not lines[i][0].isspace()
                and not lines[i].startswith("#")), len(lines))
    return [ln.strip() for ln in lines[start + 1:end] if ln.strip() and not ln.strip().startswith("#")]


def test_haproxy_cfg_fails_closed():
    """A Lua runtime error does NOT deny by itself (measured), so the only thing that lets a request through is the
    variable the action sets as its last statement, tested by the very next rule."""
    text = (PROXY_DIR / "haproxy.cfg").read_text(encoding="utf-8")
    rules = _section(text, "frontend proxy")
    action = rules.index("http-request lua.pn_filter")
    assert rules[action + 1] == "http-request deny deny_status 403 unless { var(txn.pn_allow) -m bool }"
    # The response-side hook only forgets an id the daemon confirmed removed; it cannot deny or allow anything.
    assert rules[action + 2] == "http-response lua.pn_evict"
    assert rules[action + 3] == "default_backend docker"
    assert not [r for r in rules if r.startswith("use_backend")]
    assert not re.search(r"^\s*use_backend", text, re.M), "a use_backend anywhere can route around the policy"
    assert text.count("default_backend") == 2, "exactly the two frontends route to the one backend"


def test_haproxy_cfg_binds_refuse_http2():
    """Without `proto h1` a bind answers HTTP/2 prior knowledge (measured), a framing the policy never parses."""
    binds = re.findall(r"^\s*bind\s+(.*)$", (PROXY_DIR / "haproxy.cfg").read_text(encoding="utf-8"), re.M)
    assert len(binds) == 2
    assert all(re.search(r"\bproto h1\b", b) for b in binds), binds


def test_haproxy_cfg_serves_the_policy_only_on_the_private_socket():
    text = (PROXY_DIR / "haproxy.cfg").read_text(encoding="utf-8")
    assert f"bind unix@{SOCKET} " in text
    assert "bind 127.0.0.1:2376 " in text
    assert not re.search(r"bind\s+(\*|0\.0\.0\.0|\[::\]|:)", text), "a proxy listener must not leave the namespace"


# The image ============================================================================================================
def test_dockerfile_pins_its_base_by_digest_and_copies_exactly_the_policy():
    lines = (PROXY_DIR / "Dockerfile").read_text(encoding="utf-8").splitlines()
    froms = [ln for ln in lines if ln.startswith("FROM ")]
    assert len(froms) == 1 and re.fullmatch(r"FROM ghcr\.io/linuxserver/socket-proxy:\S+@sha256:[0-9a-f]{64}", froms[0])
    assert [ln for ln in lines if ln.startswith("COPY ")] == ["COPY haproxy.cfg policy.lua action.lua /etc/postern-proxy/"]
    # Exec form: the base's shell entrypoint renders the stock section-per-variable config this image replaces.
    assert 'ENTRYPOINT ["/usr/sbin/haproxy", "-f", "/etc/postern-proxy/haproxy.cfg", "-db"]' in lines


def test_the_policy_constants_equal_the_reconcilers():
    """The create body must carry exactly what policy.lua demands; both sides state it."""
    policy = (PROXY_DIR / "policy.lua").read_text(encoding="utf-8")
    memory = re.search(r"^M\.SS_MEMORY_BYTES = (\d+)$", policy, re.M)
    pids = re.search(r"^M\.SS_PIDS_LIMIT = (\d+)$", policy, re.M)
    tmpfs = re.search(r"^M\.SS_TMPFS = \{(.*)\}$", policy, re.M)
    assert memory and pids and tmpfs, "policy.lua no longer states the constants on single `M.SS_*` lines"
    assert int(memory.group(1)) == reconciler.SS_MEMORY_BYTES
    assert int(pids.group(1)) == reconciler.SS_PIDS_LIMIT
    assert dict(re.findall(r'\["([^"]+)"\] = "([^"]*)"', tmpfs.group(1))) == reconciler.SS_TMPFS


def test_the_instance_id_pattern_equals_the_reconcilers():
    """The portal must not accept an instance id the proxy refuses; both sides state the same regex."""
    policy = (PROXY_DIR / "policy.lua").read_text(encoding="utf-8")
    stated = re.search(r'^M\.INSTANCE_ID_REGEX = "([^"]+)"$', policy, re.M)
    assert stated, "policy.lua no longer states the pattern on a single `M.INSTANCE_ID_REGEX` line"
    assert stated.group(1) == reconciler.INSTANCE_ID_PATTERN.pattern


# Per file =============================================================================================================
def test_every_stack_defines_the_proxy_from_the_same_context():
    defining = _files_defining_the_proxy()
    assert {p.name for p in defining} == {
        "compose.yaml", "e2e.compose.yaml", "e2e-edge.compose.yaml"
    }, "a file defines (or stopped defining) the docker-proxy: check its wiring against this module"
    for path in defining:
        svc = _services(path)["docker-proxy"]
        context = (path.parent / svc["build"]["context"]).resolve()
        assert context == PROXY_DIR, repo_relative(path)
        assert svc["build"]["args"] == {"GIT_REVISION": "${GIT_REVISION:-}"}, repo_relative(path)
        want = "local/postern-docker-proxy-test" if _is_e2e(path) else "local/postern-docker-proxy"
        assert svc["image"] == want, repo_relative(path)


def test_the_proxy_is_confined():
    for path in _files_defining_the_proxy():
        svc = _services(path)["docker-proxy"]
        where = repo_relative(path)
        assert svc.get("network_mode") == "none", where
        assert "networks" not in svc and "ports" not in svc and "expose" not in svc, where
        assert svc.get("read_only") is True, where
        assert svc.get("cap_drop") == ["ALL"], where
        assert sorted(svc.get("cap_add") or []) == ["CHOWN", "FOWNER"], where
        assert "no-new-privileges:true" in (svc.get("security_opt") or []), where
        assert svc.get("init") is True, where
        mounts = svc.get("volumes") or []
        binds = [m for m in mounts if isinstance(m, dict) and m.get("type") == "bind"]
        assert len(binds) == 1 and binds[0]["source"] == DOCKER_SOCK and binds[0].get("read_only") is True, where
        others = [m for m in mounts if m not in binds]
        assert len(others) == 1 and str(others[0]).endswith(f":{SOCKET_DIR}"), f"{where}: {others}"


def test_the_policy_is_not_a_bind_mount():
    """A policy read once from a bind mount can go stale unnoticed after a deploy; it is baked into the image."""
    for path in ALL_COMPOSE_FILES():
        for name, svc in _services(path).items():
            for mount in svc.get("volumes") or []:
                text = str(mount)
                assert "policy.lua" not in text and "haproxy.cfg" not in text, f"{repo_relative(path)}: {name}"


def test_nothing_else_reaches_the_docker_socket():
    for path in ALL_COMPOSE_FILES():
        for name, svc in _services(path).items():
            for mount in svc.get("volumes") or []:
                text = str(mount)
                if "docker.sock" in text:
                    assert name == "docker-proxy", f"{repo_relative(path)}: {name} mounts the Docker socket"
            env = svc.get("environment") or {}
            host = env.get("DOCKER_HOST") if isinstance(env, dict) else None
            if host is not None:
                assert name == "portal" and host == f"unix://{SOCKET}", f"{repo_relative(path)}: {name} {host}"


def test_the_portal_reaches_the_proxy_over_the_socket_volume_read_only():
    for path in _files_defining_the_proxy():
        portal = _services(path)["portal"]
        where = repo_relative(path)
        assert portal["environment"]["DOCKER_HOST"] == f"unix://{SOCKET}", where
        assert portal["depends_on"]["docker-proxy"] == {"condition": "service_healthy"}, where
        mounts = [m for m in portal["volumes"] if str(m).endswith(f":{SOCKET_DIR}:ro")]
        assert len(mounts) == 1, where
        proxy_mount = next(m for m in _services(path)["docker-proxy"]["volumes"] if str(m).endswith(f":{SOCKET_DIR}"))
        assert str(mounts[0]).split(":")[0] == str(proxy_mount).split(":")[0], f"{where}: different volumes"


def test_the_production_default_image_is_the_settings_default():
    """The proxy pins create bodies to ITS image; a portal that falls back to the Settings default must agree."""
    env = _services(REPO_ROOT / "compose.yaml")["docker-proxy"]["environment"]
    assert env["SHADOWSOCKS_IMAGE"] == "${SHADOWSOCKS_IMAGE:-" + Settings.model_fields["shadowsocks_image"].default + "}"


# Resolved by the real Compose CLI =====================================================================================
_SCRUBBED = {f.upper() for f in Settings.model_fields} | {
    "COMPOSE_FILE", "COMPOSE_PROFILES", "COMPOSE_PROJECT_NAME", "GIT_REVISION"
}
_CHAINS = [
    ["compose.yaml"],
    ["compose.yaml", "compose.cert.yaml"],
    ["compose.yaml", "compose.gateway.yaml"],
    ["compose.yaml", "compose.edge.yaml"],
    ["compose.yaml", "compose.cert.yaml", "compose.gateway.yaml", "compose.edge.yaml"],
    ["portal/tests/e2e/e2e.compose.yaml"],
    ["portal/tests/e2e/e2e.compose.yaml", "portal/tests/e2e/e2e-mta.compose.yaml"],
    ["portal/tests/e2e/e2e.compose.yaml", "portal/tests/e2e/e2e-mta-real.compose.yaml"],
    ["portal/tests/e2e/e2e-edge.compose.yaml"],
]
_NEEDED = {
    "SECRET_KEY": "x", "POSTERN_E2E_TLS_DIR": "/tmp/tls", "POSTERN_E2E_EDGE_CLIENT_CA_DIR": "/tmp/ca",
    "MTA_TEST_DOMAIN": "postern.test", "MTA_TEST_ADMIN_EMAIL": "a@postern.test", "MTA_TEST_DNS_PROVIDER": "none",
    "DOMAIN": "postern.example.com",
}  # yapf: disable


def _config(chain: list[str], tmp_path: Path, shell: dict[str, str] | None = None) -> dict:
    env_file = tmp_path / "empty.env"
    env_file.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in _SCRUBBED}
    env.update(_NEEDED)
    env["COMPOSE_PROFILES"] = "with-mta,with-cert-renewal,with-edge"
    env.update(shell or {})
    args = ["--env-file", str(env_file), "--project-name", "pin", *(a for f in chain for a in ("-f", str(REPO_ROOT / f)))]
    return run_compose_config(args, REPO_ROOT, env)


def _sources(service: dict) -> list[tuple[str, bool]]:
    return [(v["source"], bool(v.get("read_only"))) for v in service.get("volumes") or [] if v.get("type") == "volume"]


@pytest.mark.compose_cli
@pytest.mark.parametrize("chain", _CHAINS, ids="+".join)
def test_only_the_proxy_and_the_portal_mount_the_socket_volume(chain: list[str], tmp_path: Path):
    config = _config(chain, tmp_path)
    socket_volume = next(s for s, _ in _sources(config["services"]["docker-proxy"]))
    mounting = {
        name: ro
        for name, svc in config["services"].items()
        for source, ro in _sources(svc) if source == socket_volume
    }
    assert mounting == {"docker-proxy": False, "portal": True}


@pytest.mark.compose_cli
@pytest.mark.parametrize("chain", _CHAINS, ids="+".join)
def test_the_proxy_has_no_network_and_publishes_nothing(chain: list[str], tmp_path: Path):
    proxy = _config(chain, tmp_path)["services"]["docker-proxy"]
    assert proxy["network_mode"] == "none"
    assert not proxy.get("networks") and not proxy.get("ports")


@pytest.mark.compose_cli
@pytest.mark.parametrize("chain", _CHAINS, ids="+".join)
@pytest.mark.parametrize("mode", ["unset", "set", "empty"])
def test_the_proxy_is_configured_with_what_the_portal_is(chain: list[str], mode: str, tmp_path: Path):
    """If the two disagree every create is denied, or (worse) the proxy pins something the portal does not use.
    An exported-but-empty variable is its own case: a bare passthrough would hand the portal "" while an
    interpolated default hands the proxy the default."""
    names = ["SHADOWSOCKS_IMAGE", "SHADOWSOCKS_NETWORK", "INSTANCE_ID", "COMPOSE_PROJECT_NAME"]
    shell = {
        "unset": {},
        "set": {
            "SHADOWSOCKS_IMAGE": "registry.example/ss:1", "SHADOWSOCKS_NETWORK": "ss-net", "INSTANCE_ID": "pinned",
            "COMPOSE_PROJECT_NAME": "other",
        },
        "empty": dict.fromkeys(names, ""),
    }[mode]  # yapf: disable
    services = _config(chain, tmp_path, shell)["services"]
    portal, proxy = services["portal"]["environment"], services["docker-proxy"]["environment"]
    settings = Settings.model_fields
    # What the portal effectively runs with: its environment (a bare key that nothing set is absent), else the default.
    def effective_value(env: dict, key: str, default: str) -> str:
        return env[key] if env.get(key) is not None else default

    # Settings turns an empty string into an empty image name, so "" is a value here, not an absent one.
    effective = {
        "SHADOWSOCKS_IMAGE": effective_value(portal, "SHADOWSOCKS_IMAGE", settings["shadowsocks_image"].default),
        "SHADOWSOCKS_NETWORK": effective_value(portal, "SHADOWSOCKS_NETWORK", settings["shadowsocks_network"].default),
        "INSTANCE_ID": effective_value(portal, "INSTANCE_ID", ""),
        "COMPOSE_PROJECT_NAME": effective_value(portal, "COMPOSE_PROJECT_NAME", ""),
    }
    given = {k: effective_value(proxy, k, "") for k in effective}
    assert effective["SHADOWSOCKS_IMAGE"], "the portal would run with an empty image name"
    # The e2e files pin their own values and never export these; only production reads the exported ones.
    if chain[0] == "compose.yaml":
        assert given == effective
    else:
        assert given["SHADOWSOCKS_IMAGE"] == effective["SHADOWSOCKS_IMAGE"] == "local/shadowsocks-server-test"
        assert given["SHADOWSOCKS_NETWORK"] == effective["SHADOWSOCKS_NETWORK"]
        assert given["INSTANCE_ID"] == effective["INSTANCE_ID"]
        assert given["COMPOSE_PROJECT_NAME"] == effective["COMPOSE_PROJECT_NAME"]
