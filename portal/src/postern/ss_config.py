"""Shadowsocks server and client config generation."""

from __future__ import annotations

import base64
import json

from postern.models import Connection

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
            "plugin": conn.plugin,
            "plugin_opts": plugin_opts,
            "plugin_mode": "tcp_and_udp",
        }],
        "log": {"level": 0},
    }


def client_config(conn: Connection, domain: str, *, ech_enabled: bool = False, ech_doh_url: str = "") -> dict:
    """Generate a shadowsocks client config for download.

    For galoshes connections we set `mode: tcp_and_udp` so sslocal opens
    UDP-ASSOCIATE -- otherwise galoshes' raison d'etre over plain v2ray-plugin
    (UDP via yamux) is silently TCP-only and the user has to hand-edit JSON.
    v2ray-plugin connections stay TCP-only (the historical default) since
    plain v2ray-plugin has no UDP path; advertising tcp_and_udp there would
    open UDP-ASSOCIATE on sslocal but UDP traffic would be dropped server-side.

    For galoshes the mode is set in THREE places, mirroring the server config
    (these are shadowsocks-rust 1.24.0 config semantics, independent of the
    galoshes version):
      - top-level `mode`: sslocal derives the local SOCKS5 listener's mode from
        it (it defaults to tcp_only for the `local_port`/`local_address` config
        form -- see shadowsocks-rust config.rs `global_mode`) and gates the
        UDP-ASSOCIATE command on that listener mode.
      - server `mode`: governs server-side relay.
      - server `plugin_mode`: defaults to tcp_only, which routes UDP *directly*
        to the server (`udp_external_addr` -> real addr) bypassing the plugin,
        so datagrams are dropped. tcp_and_udp routes UDP through galoshes'
        local plugin socket. SIP003 plugins are TCP-only by spec; this is the
        SIP003u extension that lets galoshes carry UDP over its yamux transport.
    """
    if ech_enabled and not ech_doh_url:
        raise ValueError("client_config: ech_doh_url must be non-empty when ech_enabled=True")
    plugin_opts = f"tls;fast-open;path=/t/{conn.path_token};host={domain}"
    if ech_enabled:
        plugin_opts += f";ech=always;ech-doh={ech_doh_url}"
    server: dict = {
        "address": domain,
        "port": 443,
        "password": conn.password,
        "method": CIPHER,
        "plugin": conn.plugin,
        "plugin_opts": plugin_opts,
    }
    config: dict = {
        "servers": [server],
        "local_port": 1080,
        "local_address": "127.0.0.1",
    }
    if conn.plugin == "galoshes":
        server["mode"] = "tcp_and_udp"
        server["plugin_mode"] = "tcp_and_udp"
        config["mode"] = "tcp_and_udp"

    return config


def server_config_json(conn: Connection, domain: str) -> str:
    """Serialize server config to JSON string."""
    return json.dumps(server_config(conn, domain), indent="\t")


def server_config_b64(conn: Connection, domain: str) -> str:
    """Base64-encode the server config JSON (for passing as SS_CONFIG env var)."""
    return base64.b64encode(server_config_json(conn, domain).encode()).decode()
