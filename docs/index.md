# Postern

Postern is a self-hosted, multi-user [Shadowsocks](https://shadowsocks.org/) portal. Users sign in with an email one-time code and download a client config for their tunnel. Each enabled connection runs in its own container behind an nginx reverse proxy, and a reconciliation loop keeps the running containers in sync with the portal database.

## Features

- **Email-OTP login portal** — no passwords to phish or reuse, and no self-serve signup: the operator creates every account.
- **Isolated per-connection tunnels** — every connection gets its own Shadowsocks-rust container, camouflaged as WebSocket + TLS traffic on port 443.
- **Two pluggable transports** — [ex-ray](https://github.com/bindreams/hole) (wire-compatible with v2ray-plugin) or galoshes (adds UDP via yamux multiplexing), chosen per connection.
- **Built-in MTA option** — a self-hosted mail stack delivers login codes without a third-party provider seeing who your users are or when they log in.
- **Optional CDN or gateway fronting** — hide the origin behind Cloudflare, or share port 443 with other services via a local gateway.
- **Single-host Docker Compose deployment** — one VPS, one compose file, opt-in overlays for everything else.

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

## Where to go next

````{grid} 2
```{grid-item-card} Deploy Postern
---
link: getting-started
link-type: doc
---
From an empty VPS to a working tunnel.
```
```{grid-item-card} Connect as a user
---
link: connecting
link-type: doc
---
Sign in, download a config, set up a client.
```
```{grid-item-card} Operate a deployment
---
link: operations/index
link-type: doc
---
Manage users and connections with the `postern` CLI.
```
```{grid-item-card} Evaluate the security model
---
link: security
link-type: doc
---
Threat model and what each layer defends against.
```
```{grid-item-card} Read the deployment guides
---
link: deployment/index
link-type: doc
---
Email, certificates, CDN edge, gateway, customization.
```
```{grid-item-card} Hack on Postern
---
link: development/index
link-type: doc
---
Architecture internals and the test suite.
```
````

## About the name

A _postern_ is a small, hidden door set in the wall of a medieval fortification. Where the main gate was the formally guarded entrance, the postern let inhabitants slip in and out unnoticed — to launch a sortie, smuggle in supplies, or quietly retreat. Postern takes the same shape: a discreet way through a wall.

## License

Postern is licensed under the [GNU AGPL version 3.0](license.md); the source lives in the [GitHub repository](https://github.com/bindreams/postern). Some vendored files carry their own terms, conveyed in in-file license headers.

```{toctree}
---
hidden:
---
getting-started.md
Connecting as a user <connecting.md>
deployment/index.md
operations/index.md
security.md
development/index.md
License <license.md>
GitHub repository <https://github.com/bindreams/postern>
```
