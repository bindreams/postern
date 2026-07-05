# Postern VPN

Postern is a self-hosted, multi-user [Shadowsocks](https://shadowsocks.org/) portal. Users sign in with an email one-time code and download a ready-made client config; every enabled connection runs in its own tunnel container, camouflaged as WebSocket+TLS traffic on port 443. A reconciliation loop keeps the running containers in sync with the portal database.

## Architecture

```
                         ┌──────────────┐
                         │   operator   │
                         │   (CLI +     │
 internet                │    docker    │
 ──────►  nginx :443 ────┤    compose)  │
           │    │        └──────────────┘
           │    │
           │    └─► portal :8000 ──(Docker API via docker-proxy)──► creates/removes
           │                                                        ss-{token} containers
           │
           └─► ss-{token} :80 ──► v2ray-plugin | galoshes ──► Shadowsocks
```

- **nginx** — TLS termination, path-based WebSocket routing, security headers, login rate limiting.
- **portal** — FastAPI: OTP email login, dashboard, config download, admin CLI, and the container-reconciliation loop.
- **ss-{token}** — one Shadowsocks-rust container per enabled connection, fronted by [ex-ray](https://github.com/bindreams/hole) (installed as `v2ray-plugin`) or galoshes (adds UDP via yamux).
- **docker-proxy** — a verb-scoped Docker API; the portal never sees the raw socket.

Optional components: a built-in privacy-preserving MTA (no third party learns who your users are), automatic wildcard-certificate renewal, and CDN/gateway fronting.

## Quick start

```bash
git clone https://github.com/bindreams/postern
cd postern

cp example.env .env
python -c "import secrets; print(secrets.token_hex(32))"   # → SECRET_KEY in .env
# Set DOMAIN and the email settings in .env (see the docs for the choices).

# The per-connection tunnel image is spawned at runtime — build it first:
docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .
docker compose up -d --build

# Create the first user and connection:
docker compose exec portal postern user add "Alice" alice@example.com
docker compose exec portal postern connection add alice@example.com "laptop"
```

The portal is served at `https://<your-domain>/`. The full walkthrough, including prerequisites and verification, is in the documentation.

## Documentation

**<https://postern.readthedocs.io>** — [getting started](docs/getting-started.md), [deployment guides](docs/deployment/index.md) (email, certificates, CDN/gateway fronting), [operations](docs/operations/index.md), the [security model](docs/security.md), and [development docs](docs/development/index.md). The MyST sources under [docs/](docs/) are readable on GitHub too.

## License

<img align="right" src="https://www.gnu.org/graphics/agplv3-with-text-162x68.png">

Copyright (C) 2026, Anna Zhukova

This project is licensed under the [GNU AGPL version 3.0](/LICENSE.md), which means it is free for you to use. Some files in this repository are external and are licensed under their own terms, conveyed in an in-file license header.

## About

A _postern_ is a small, hidden door set in the wall of a medieval fortification. Where the main gate was the formally guarded entrance, the postern let inhabitants slip in and out unnoticed — to launch a sortie, smuggle in supplies, or quietly retreat. Postern VPN takes the same shape: a discreet way through a wall.
