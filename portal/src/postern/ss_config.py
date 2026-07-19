"""Shadowsocks server and client config generation."""

from __future__ import annotations

import base64
import json
import logging

from postern.models import Connection

logger = logging.getLogger(__name__)

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


def client_config(conn: Connection, domain: str, *, ech_doh_url: str = "") -> dict:
    """Generate a shadowsocks client config for download.

    ECH is per-connection (`conn.ech`); ECH is armed by the plugin only when
    ech-doh is set:
      - "never"  -> append nothing.
      - "auto"   -> ;ech=auto;ech-doh=<url> if ech_doh_url set, else nothing
                    (opportunistic degrades to plaintext -- not an error).
      - "always" -> ;ech=always;ech-doh=<url>; empty ech_doh_url raises (fail-closed
                    cannot be honored). server_config never emits ech.

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
    plugin_opts = f"tls;fast-open;path=/t/{conn.path_token};host={domain}"
    if conn.ech in ("auto", "always"):
        if not ech_doh_url:
            if conn.ech == "always":
                raise ValueError("client_config: ech_doh_url must be non-empty for ech=always")
            logger.debug("client_config: ech=auto for %s but ECH_DOH_URL is unset; omitting ECH", conn.id)
        else:
            # Defense-in-depth: Settings._validate_ech_doh_url already rejects these
            # SIP003 metacharacters at startup, so the only production caller (the route,
            # via settings.ech_doh_url) can't reach this. It guards direct/non-Settings
            # callers (and is exercised by tests that bypass Settings).
            if ";" in ech_doh_url or "\\" in ech_doh_url or any(c.isspace() for c in ech_doh_url):
                raise ValueError(
                    "client_config: ech_doh_url must not contain ';', '\\', or whitespace (SIP003 metacharacters)"
                )
            plugin_opts += f";ech={conn.ech};ech-doh={ech_doh_url}"
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
