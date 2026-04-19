"""Shadowsocks server and client config generation."""

from __future__ import annotations

import base64
import json

from voyager.models import Connection

CIPHER = "chacha20-ietf-poly1305"
SERVER_PORT = 80


def generate_password() -> str:
    """Generate a 32-byte random key, base64-encoded (same entropy as ssservice genkey)."""
    import secrets

    return base64.b64encode(secrets.token_bytes(32)).decode()


def server_config(conn: Connection, domain: str) -> dict:
    """Generate a shadowsocks server config for a connection."""
    plugin_opts = f"server;fast-open;path=/t/{conn.path_token};host={domain}"

    return {
        "servers": [{
            "password": conn.password,
            "server": "::",
            "server_port": SERVER_PORT,
            "method": CIPHER,
            "mode": "tcp_and_udp",
            "fast_open": True,
            "no_delay": True,
            "keep_alive": 30,
            "plugin": "v2ray-plugin",
            "plugin_opts": plugin_opts,
            "plugin_mode": "tcp_and_udp",
        }],
        "log": {"level": 0},
    }


def client_config(conn: Connection, domain: str) -> dict:
    """Generate a shadowsocks client config for download."""
    plugin_opts = f"tls;fast-open;path=/t/{conn.path_token};host={domain}"

    return {
        "servers": [{
            "address": domain,
            "port": 443,
            "password": conn.password,
            "method": CIPHER,
            "plugin": "v2ray-plugin",
            "plugin_opts": plugin_opts,
        }],
        "local_port": 1080,
        "local_address": "127.0.0.1",
    }


def server_config_json(conn: Connection, domain: str) -> str:
    """Serialize server config to JSON string."""
    return json.dumps(server_config(conn, domain), indent="\t")


def server_config_b64(conn: Connection, domain: str) -> str:
    """Base64-encode the server config JSON (for passing as SS_CONFIG env var)."""
    return base64.b64encode(server_config_json(conn, domain).encode()).decode()
