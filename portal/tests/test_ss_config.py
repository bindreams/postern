import base64
import json

from voyager.models import Connection
from voyager.ss_config import (
    client_config,
    generate_password,
    server_config,
    server_config_b64,
    server_config_json,
)

DOMAIN = "voyager.binarydreams.me"


def _make_connection(*, path_token="abcdef123456789012345678"):
    return Connection(
        user_id="user-uuid",
        path_token=path_token,
        label="Test",
        password="dGVzdGtleQ==",
    )


# Password generation ==================================================================================================
def test_generate_password_is_base64():
    pw = generate_password()
    decoded = base64.b64decode(pw)
    assert len(decoded) == 32


def test_generate_password_is_unique():
    passwords = {generate_password() for _ in range(50)}
    assert len(passwords) == 50


# Server config ========================================================================================================
def test_server_config():
    conn = _make_connection()
    cfg = server_config(conn, DOMAIN)

    assert len(cfg["servers"]) == 1
    server = cfg["servers"][0]
    assert server["password"] == "dGVzdGtleQ=="
    assert server["server"] == "::"
    assert server["server_port"] == 80
    assert server["method"] == "chacha20-ietf-poly1305"
    assert server["plugin"] == "v2ray-plugin"
    assert "path=/t/abcdef123456789012345678" in server["plugin_opts"]
    assert f"host={DOMAIN}" in server["plugin_opts"]
    assert server["plugin_opts"].startswith("server;")
    assert cfg["log"]["level"] == 0


# Client config ========================================================================================================
def test_client_config():
    conn = _make_connection()
    cfg = client_config(conn, DOMAIN)

    assert len(cfg["servers"]) == 1
    server = cfg["servers"][0]
    assert server["address"] == DOMAIN
    assert server["port"] == 443
    assert "tls;" in server["plugin_opts"]
    assert "path=/t/abcdef123456789012345678" in server["plugin_opts"]
    assert cfg["local_port"] == 1080


# Serialization ========================================================================================================
def test_server_config_json_is_valid_json():
    conn = _make_connection()
    raw = server_config_json(conn, DOMAIN)
    parsed = json.loads(raw)
    assert parsed["servers"][0]["method"] == "chacha20-ietf-poly1305"


def test_server_config_b64_roundtrips():
    conn = _make_connection()
    b64 = server_config_b64(conn, DOMAIN)
    decoded = base64.b64decode(b64).decode()
    parsed = json.loads(decoded)
    assert parsed["servers"][0]["password"] == "dGVzdGtleQ=="
