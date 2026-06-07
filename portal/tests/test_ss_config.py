import base64
import json

import pytest
from pydantic import ValidationError

from postern.models import Connection
from postern.ss_config import (
    client_config,
    generate_password,
    server_config,
    server_config_b64,
    server_config_json,
)

DOMAIN = "postern.example.com"


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
@pytest.mark.parametrize("plugin_name", ["v2ray-plugin", "galoshes"])
def test_server_config_per_plugin(plugin_name):
    conn = _make_connection().model_copy(update={"plugin": plugin_name})
    cfg = server_config(conn, DOMAIN)

    assert len(cfg["servers"]) == 1
    server = cfg["servers"][0]
    assert server["password"] == "dGVzdGtleQ=="
    assert server["server"] == "::"
    assert server["server_port"] == 80
    assert server["method"] == "chacha20-ietf-poly1305"
    assert server["plugin"] == plugin_name
    assert "path=/t/abcdef123456789012345678" in server["plugin_opts"]
    assert f"host={DOMAIN}" in server["plugin_opts"]
    assert server["plugin_opts"].startswith("server;")
    assert cfg["log"]["level"] == 0


# Client config ========================================================================================================
@pytest.mark.parametrize("plugin_name", ["v2ray-plugin", "galoshes"])
def test_client_config_per_plugin(plugin_name):
    conn = _make_connection().model_copy(update={"plugin": plugin_name})
    cfg = client_config(conn, DOMAIN)

    assert len(cfg["servers"]) == 1
    server = cfg["servers"][0]
    assert server["address"] == DOMAIN
    assert server["port"] == 443
    assert server["plugin"] == plugin_name
    assert "tls;" in server["plugin_opts"]
    assert "path=/t/abcdef123456789012345678" in server["plugin_opts"]
    assert cfg["local_port"] == 1080


def test_client_config_galoshes_enables_udp():
    """Galoshes' value-add over v2ray-plugin is UDP via yamux. The client config
    must opt sslocal into tcp_and_udp in three places (top-level listener mode,
    per-server relay mode, and plugin_mode) so UDP-ASSOCIATE opens and the
    datagrams route through the plugin -- see ss_config.client_config."""
    conn = _make_connection().model_copy(update={"plugin": "galoshes"})
    cfg = client_config(conn, DOMAIN)
    assert cfg["mode"] == "tcp_and_udp"
    assert cfg["servers"][0]["mode"] == "tcp_and_udp"
    assert cfg["servers"][0]["plugin_mode"] == "tcp_and_udp"


def test_client_config_v2ray_stays_tcp_only():
    """v2ray-plugin has no UDP path; advertising tcp_and_udp would let sslocal
    open UDP-ASSOCIATE that the server cannot service. Keep absence -- the
    top-level listener mode, per-server relay mode, and plugin_mode stay unset."""
    conn = _make_connection()  # default plugin = v2ray-plugin
    cfg = client_config(conn, DOMAIN)
    assert "mode" not in cfg
    assert "mode" not in cfg["servers"][0]
    assert "plugin_mode" not in cfg["servers"][0]


# Connection plugin field ==============================================================================================
def test_connection_default_plugin_is_v2ray():
    conn = Connection(user_id="u", path_token="x" * 24, label="L", password="P")
    assert conn.plugin == "v2ray-plugin"


def test_connection_accepts_galoshes():
    conn = Connection(user_id="u", path_token="x" * 24, label="L", password="P", plugin="galoshes")
    assert conn.plugin == "galoshes"


def test_connection_rejects_invalid_plugin():
    with pytest.raises(ValidationError):
        Connection(user_id="u", path_token="x" * 24, label="L", password="P", plugin="nope")


def test_model_validate_rejects_invalid_plugin():
    """Pydantic's model_copy(update=...) is documented NOT to validate, so the
    way to get a validated update is model_validate(). Pin that path."""
    conn = Connection(user_id="u", path_token="x" * 24, label="L", password="P")
    with pytest.raises(ValidationError):
        Connection.model_validate({**conn.model_dump(), "plugin": "bogus"})


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
