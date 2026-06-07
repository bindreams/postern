# Postern VPN

Postern VPN is a self-hosted, multi-user Shadowsocks portal. It pairs a small FastAPI web portal with an Nginx reverse proxy and a dynamic fleet of Shadowsocks-rust containers (one per connection), each running v2ray-plugin (default) or galoshes (adds UDP via yamux multiplexing) per the connection's setting. Users sign in with an email one-time code, then download a client config for their tunnel. An internal reconciliation loop keeps running containers in sync with the portal database.

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

- **nginx** — TLS termination, HTTP→HTTPS redirect, path-based WebSocket routing, security headers, rate limiting on `/login*`. Periodically self-reloads to pick up renewed Let's Encrypt certs.
- **portal** — Python 3.13 / FastAPI. OTP email login, dashboard, JSON config download, admin CLI, and a background reconciliation loop that manages per-connection Shadowsocks containers via the Docker API.
- **ss-{token} containers** — one Shadowsocks-rust instance per enabled connection, fronted by either v2ray-plugin (default) or galoshes (adds UDP via yamux multiplexing) in TLS + WebSocket mode. `{token}` is a 24-hex-char path token; Nginx proxies `wss://<domain>/t/{token}` to `ss-{token}:80`. The plugin choice is set per-connection via `postern connection add ... --plugin {v2ray-plugin,galoshes}`. The `v2ray-plugin` binary is [ex-ray](https://github.com/bindreams/hole), a wire-compatible v2ray-core SIP003 shim installed under the `v2ray-plugin` name, so existing clients need no change.
- **docker-proxy** — [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy), a restricted Docker API exposed to the portal over TCP. The portal never sees the raw `/var/run/docker.sock`.

## Prerequisites

- Docker Engine and Docker Compose v2
- A public domain you control, with Let's Encrypt certificates at `/etc/letsencrypt/live/<domain>/` (bind-mounted into the Nginx container)
- A free [Docker Hub](https://hub.docker.com) account with a Personal Access Token. The base images used by Nginx and the portal come from [Docker Hardened Images](https://docs.docker.com/dhi/) (`dhi.io`); the catalog is free under Apache 2.0 but pulls require authentication. Run `docker login dhi.io` with your Docker Hub username + PAT before the first build.

**SMTP — pick one:**

- **Built-in MTA (default).** Postern ships a self-hosted Postfix + opendkim + Unbound + postsrsd + mta-sts-resolver stack as the default `with-mta` Compose profile. Eliminates the third-party metadata leak (no provider sees who your users are or when they log in). Additional prerequisites:
  - Public IPv4 with **port 25 outbound allowed**. Many cloud providers block it by default (AWS, GCP, DigitalOcean new accounts); Hetzner-class VPS providers usually allow it. Without port 25 outbound, the built-in MTA cannot deliver mail.
  - Reverse DNS (PTR) on the IP set to `mail.<domain>`. Configured at the VPS provider's panel; cannot be automated.
  - Three Let's Encrypt certs at `/etc/letsencrypt/live/<domain>/`, `/etc/letsencrypt/live/mail.<domain>/`, `/etc/letsencrypt/live/mta-sts.<domain>/`. A multi-SAN cert covering all three works too: `certbot certonly --standalone -d <domain> -d mail.<domain> -d mta-sts.<domain>`.
  - DNS records published as listed by `docker compose exec portal postern mta show-dns`. Includes MX, SPF, DMARC `p=reject` strict, MTA-STS, TLS-RPT, DKIM. The DKIM TXT is auto-managed when `DNS_PROVIDER` is set to a libdns-supported provider (Cloudflare, Route53, Gandi, DigitalOcean, OVH, Hetzner, Linode, Namecheap); otherwise published manually after first run.
  - **Strongly recommended: DNSSEC enabled at your TLD/registrar.** Without it, MTA-STS and DKIM records can be silently tampered with by anyone with upstream-DNS access. Most modern registrars (Cloudflare Registrar, Gandi, Namecheap, Porkbun, Hover) support this; verify with `dig +dnssec DS <yourdomain>` returning a signed RRset. DNSSEC is auto-detected at MTA startup (`MTA_REQUIRE_DNSSEC=auto` default); set explicitly to `true` for fail-closed production.
  - An external mailbox you read for technical reports (postmaster, abuse, tls-rpt, bounces). Set `MTA_ADMIN_EMAIL=` in `.env`. Postern forwards there; it does not host an inbox.
  - See [docs/mta.md](docs/mta.md) for a full deployer walkthrough.
- **Third-party SMTP relay** (Resend, SES, Mailgun, Postmark, etc.). Comment `COMPOSE_PROFILES=with-mta` in `.env` and set `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` to your provider. TLS mode is derived from the port: 465 → implicit TLS, 587 → STARTTLS.

## Quick start

```bash
# 1. Clone
git clone <this repo>
cd hole-server

# 2. Create your environment file
cp .env.example .env

# 3. Generate a SECRET_KEY and paste it into .env
python -c "import secrets; print(secrets.token_hex(32))"

# 4. Fill in SMTP credentials in .env (SMTP_HOST / PORT / USER / PASSWORD / FROM)

# 5. (If your domain is not postern.example.com, see "Re-hosting" below.)

# 6. Build the per-connection tunnel image. Compose does not build this one —
#    the reconciler spawns it at runtime, so it must exist first.
docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .

# 7. Build and start the rest of the stack
docker compose up -d --build
```

The portal is served from `https://<your-domain>/`. First login requires that you add yourself as a user (see [Admin workflow](#admin-workflow)).

## Configuration

Environment variables are loaded from `.env` (copied from `.env.example`) into the `portal` container only. All settings are read by [portal/src/postern/settings.py](portal/src/postern/settings.py) via pydantic-settings (env vars are case-insensitive: `SECRET_KEY` in `.env` ↔ `settings.secret_key` in code).

| Variable                      | Default                    | Purpose                                                                                                                                                                   |
| ----------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SECRET_KEY`                  | _(required)_               | Server secret. Portal fails to start without it. Generate with `python -c "import secrets; print(secrets.token_hex(32))"`.                                                |
| `DATABASE_PATH`               | `/data/postern.db`         | SQLite path inside the portal container. Lives on the `postern-data` named volume, not `./data/`.                                                                         |
| `SMTP_HOST`                   | `localhost`                | Outbound SMTP server.                                                                                                                                                     |
| `SMTP_PORT`                   | `465`                      | `465` → implicit TLS; `587` → STARTTLS; anything else → plaintext.                                                                                                        |
| `SMTP_USER`                   | _(empty)_                  | SMTP auth username.                                                                                                                                                       |
| `SMTP_PASSWORD`               | _(empty)_                  | SMTP auth password.                                                                                                                                                       |
| `SMTP_FROM`                   | `noreply@example.com`      | `From:` header for OTP emails.                                                                                                                                            |
| `OTP_EXPIRY_SECONDS`          | `600`                      | OTP lifetime (10 min).                                                                                                                                                    |
| `OTP_MAX_ATTEMPTS`            | `5`                        | Wrong-code attempts before the OTP is invalidated.                                                                                                                        |
| `OTP_MAX_REQUESTS_PER_WINDOW` | `3`                        | Max active OTPs per email in the rate window.                                                                                                                             |
| `OTP_RATE_WINDOW_SECONDS`     | `900`                      | OTP rate-limit window (15 min).                                                                                                                                           |
| `SESSION_EXPIRY_DAYS`         | `7`                        | Browser session lifetime.                                                                                                                                                 |
| `RECONCILE_INTERVAL_SECONDS`  | `60`                       | How often the reconciler syncs DB → containers.                                                                                                                           |
| `SHADOWSOCKS_IMAGE`           | `local/shadowsocks-server` | Image the reconciler spawns per connection.                                                                                                                               |
| `SHADOWSOCKS_NETWORK`         | `shadowsocks`              | Docker bridge network `ss-*` containers join; Nginx attaches to the same one.                                                                                             |
| `DOMAIN`                      | `postern.example.com`      | Public domain. Used in client configs and server `plugin_opts`.                                                                                                           |
| `PRODUCT_NAME`                | `Postern`                  | Cosmetic display name shown in UI page titles, OTP email subject, and config-download filename prefix. Decoupled from `DOMAIN`.                                           |
| `PRODUCT_ICON_PATH`           | _(empty)_                  | Absolute path to a custom SVG (preferred) or PNG brand icon, served via the `/brand-icon` route. See [docs/frontend.md](docs/frontend.md).                                |
| `GEOIP_DB_DIR`                | _(empty)_                  | Directory holding `GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb`. Enables the login-page identity card's flag/city/ISP/ASN columns. See [docs/frontend.md](docs/frontend.md). |
| `COMPOSE_PROFILES`            | `with-mta`                 | Compose profiles to activate. Built-in MTA default-on; comment to opt out and set `SMTP_HOST` to a third-party relay.                                                     |
| `MTA_VERIFY_DNS`              | `true`                     | Built-in MTA refuses to start if any required DNS record is missing or wrong. Set `false` for dev/CI only.                                                                |
| `MTA_REQUIRE_DNSSEC`          | `auto`                     | Tri-state. `auto` (default) probes DNSSEC at startup and enforces if signed. `true` always enforces (fail-closed). `false` skips.                                         |
| `MTA_ADMIN_EMAIL`             | _(empty)_                  | **Required when `MTA_VERIFY_DNS=true`.** External mailbox where postmaster/abuse/tls-rpt/bounces are forwarded.                                                           |
| `MTA_DKIM_SELECTOR_PREFIX`    | `postern`                  | DKIM selectors take the form `<prefix>-<YYYY-MM>` (date-suffixed for rotation).                                                                                           |
| `MTA_DKIM_ROTATION_DAYS`      | `180`                      | How often the provisioner rotates DKIM keys (when auto-rotation is enabled).                                                                                              |
| `DNS_PROVIDER`                | `none`                     | libdns provider name for DKIM auto-rotation and (optional) TLS cert renewal (`cloudflare`, `route53`, `gandi`, `digitalocean`, `ovh`, `hetzner`, etc.).                   |

## Re-hosting to a different domain

Set in `.env`:

```ini
DOMAIN=your.domain.example
SMTP_FROM=Postern VPN <noreply@your.domain.example>
MTA_ADMIN_EMAIL=ops@your.domain.example   # required when using the built-in MTA
# PRODUCT_NAME=YourBrand                  # optional: cosmetic display name (UI titles, OTP subject)
```

That's it — no source edits. The nginx container renders its config templates from `DOMAIN` at start (see [nginx/nginx-entrypoint.sh](nginx/nginx-entrypoint.sh)); the portal reads `DOMAIN` and `PRODUCT_NAME` from env directly.

If you want to run the test suite against your domain, two test fixtures reference `postern.example.com`:

- [portal/tests/test_reconciler.py](portal/tests/test_reconciler.py)
- [portal/tests/test_ss_config.py](portal/tests/test_ss_config.py)

([portal/tests/test_routes.py](portal/tests/test_routes.py) reads `settings.product_name` and `settings.domain` and adapts to whatever you set, so it doesn't need editing.)

To rebuild the nginx image after pulling a new `nginx/etc/*.tmpl`:

```bash
docker compose up -d --build nginx
```

For deployments that put postern behind an external reverse proxy doing TCP+SNI passthrough (Traefik, HAProxy, etc.) — see [docs/gateway.md](docs/gateway.md).

## Admin workflow

Postern has no self-serve signup. Users and their connections are created by the operator via the `postern` CLI, which ships inside the portal image:

```bash
# Add a user
docker compose exec portal postern user add "Alice" alice@example.com

# Give them a connection (creates a 24-hex-char path token + random password)
docker compose exec portal postern connection add alice@example.com "laptop"

# Inspect
docker compose exec portal postern user list
docker compose exec portal postern connection list --user-email alice@example.com

# Disable / enable / delete
docker compose exec portal postern connection disable <connection_id>
docker compose exec portal postern connection enable  <connection_id>
docker compose exec portal postern user disable alice@example.com
docker compose exec portal postern user delete  alice@example.com
```

CLI commands that change connection state (`connection add/enable/disable`, `user disable/delete`) create `/data/.reconcile-now` to wake the reconciler; the corresponding container appears (or disappears) within a few seconds. Pure reads (`list`) and `user add` do not trigger a reconcile — a user with no connections doesn't need any container.

From the user's side:

1. Visit `https://<your-domain>/login`, enter their email.
1. Receive a 6-digit OTP by email, submit it.
1. On the dashboard, click their connection to download a JSON config (file name `postern-<label>.json`).
1. Import that JSON into a Shadowsocks-rust client. It points at `wss://<your-domain>:443` with `plugin_opts=tls;fast-open;path=/t/<token>;host=<your-domain>`.

## How the VPN tunnel works

A client connects to `wss://<your-domain>:443/t/<token>` (v2ray-plugin or galoshes in TLS + WebSocket mode; both wire-compatible at the WebSocket+TLS layer). Nginx matches the path with `^/t/([a-f0-9]{24})$` and proxies the upgraded connection to `http://ss-<token>:80`, resolved on the `shadowsocks` Docker network via Docker's embedded DNS. The `ss-<token>` container runs the configured plugin → Shadowsocks-rust, decrypts the tunnel, and forwards traffic to the destination.

## Operations

- **Logs.** Nginx logs are on the host at [nginx/log/](nginx/log/) (`access.log`, `error.log`). Portal logs go to `docker compose logs -f portal`. `ss-*` containers run with `LogConfig(type="none")` — they're deliberately logless.
- **Reconciliation.** The portal runs a background loop every `RECONCILE_INTERVAL_SECONDS` (default 60s). To trigger it immediately after a DB mutation: `docker compose exec portal postern reconcile`. It also restarts exited `ss-*` containers and recreates them when the `local/shadowsocks-server` image ID changes.
- **Cert renewal.** Nginx self-reloads every 6 hours via a background shell loop injected by [nginx/Dockerfile](nginx/Dockerfile). This picks up certbot-renewed certificates from the bind-mounted `/etc/letsencrypt` without restarting the container. `inotifywait` is not used — it does not reliably observe Let's Encrypt's symlink-target updates across Docker bind mounts.
- **Portal restarts stop all tunnels.** When the `portal` container's lifespan ends, it calls `cleanup_all_containers()`, which stops and removes every `ss-*` container. They come back on the next reconciliation pass (a few seconds later), but connections are interrupted. Cleanup is best-effort — if the docker-proxy is unavailable during shutdown, containers can survive into the next portal start; the reconciler adopts them by their `postern.managed=true` label on the following pass.
- **Data.** The SQLite database lives only in the `postern-data` named Docker volume. `./data/` is gitignored ([`.gitignore`](.gitignore)) and not otherwise used by the project.

## Project layout

```
compose.yaml                    # Orchestration (nginx + portal + docker-proxy + optional mta + provisioner)
nginx/                          # Reverse proxy
    Dockerfile
    etc/nginx.conf
    etc/conf.d/                 # ssl.conf, cert include, mta-sts vhost
    log/                        # Bind-mounted; nginx writes access/error logs here
portal/                         # FastAPI management service (Python 3.13)
    Dockerfile
    pyproject.toml
    src/postern/                # app.py, auth.py, db.py, reconciler.py, cli.py, mta/...
    tests/
mta/                            # Built-in MTA (Postfix + opendkim + Unbound + postsrsd + mta-sts-resolver)
    Dockerfile
    entrypoint.py
    etc/                        # string.Template config templates
provisioner/                    # DKIM rotation + (planned) ACME DNS-01 cert renewal
    Dockerfile
    entrypoint.py
    postern-dns/                # Go module: txt-set/txt-delete via libdns
shadowsocks/                    # Per-connection tunnel image (Go + Rust multi-stage)
    Dockerfile
docs/                           # Deployer guides
    mta.md
external/                       # Vendored upstreams, managed as git-subrepos
    shadowsocks-rust/             # ex-ray (installed as v2ray-plugin) and galoshes are downloaded from bindreams/hole release assets at image build time -- no subrepo.
scripts/                        # Prek (pre-commit) helpers
.github/workflows/              # subrepo-pull.yaml: Renovate-driven subrepo updates
```

## See also

- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, tests, prek, subrepo workflow
- [CLAUDE.md](CLAUDE.md) — guide for AI coding agents working on this repo

## License

<img align="right" src="https://www.gnu.org/graphics/agplv3-with-text-162x68.png">

Copyright (C) 2026, Anna Zhukova

This project is licensed under the [GNU AGPL version 3.0](/LICENSE.md), which means it is free for you to use. Some files in this repository are external and are licensed under their own terms, conveyed in an in-file license header.

## About

A _postern_ is a small, hidden door set in the wall of a medieval fortification. Where the main gate was the formally guarded entrance, the postern let inhabitants slip in and out unnoticed — to launch a sortie, smuggle in supplies, or quietly retreat. Postern VPN takes the same shape: a discreet way through a wall.
