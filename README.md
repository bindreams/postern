# Voyager VPN

Voyager VPN is a self-hosted, multi-user Shadowsocks portal. It pairs a small FastAPI web portal with an Nginx reverse proxy and a dynamic fleet of Shadowsocks-rust + v2ray-plugin containers (one per connection). Users sign in with an email one-time code, then download a client config for their tunnel. An internal reconciliation loop keeps running containers in sync with the portal database.

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
           └─► ss-{token} :80 ──► v2ray-plugin ──► Shadowsocks
```

- **nginx** — TLS termination, HTTP→HTTPS redirect, path-based WebSocket routing, security headers, rate limiting on `/login*`. Periodically self-reloads to pick up renewed Let's Encrypt certs.
- **portal** — Python 3.13 / FastAPI. OTP email login, dashboard, JSON config download, admin CLI, and a background reconciliation loop that manages per-connection Shadowsocks containers via the Docker API.
- **ss-{token} containers** — one Shadowsocks-rust instance per enabled connection, fronted by v2ray-plugin in WebSocket mode. `{token}` is a 24-hex-char path token; Nginx proxies `wss://<domain>/t/{token}` to `ss-{token}:80`.
- **docker-proxy** — [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy), a restricted Docker API exposed to the portal over TCP. The portal never sees the raw `/var/run/docker.sock`.

## Prerequisites

- Docker Engine and Docker Compose v2
- A public domain you control, with Let's Encrypt certificates at `/etc/letsencrypt/live/<domain>/` (bind-mounted into the Nginx container)
- SMTP credentials for OTP email delivery (Voyager was developed against [Resend](https://resend.com), but any SMTP server works — TLS mode is derived from the port: 465 → implicit TLS, 587 → STARTTLS)
- Access to the [Chainguard Docker Images](https://images.chainguard.dev) registry (`dhi.io`). The base images used by Nginx and the portal pull from there — run `docker login dhi.io` with your Chainguard credentials before the first build.

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

# 5. (If your domain is not voyager.binarydreams.me, see "Re-hosting" below.)

# 6. Build the per-connection tunnel image. Compose does not build this one —
#    the reconciler spawns it at runtime, so it must exist first.
docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .

# 7. Build and start the rest of the stack
docker compose up -d --build
```

The portal is served from `https://<your-domain>/`. First login requires that you add yourself as a user (see [Admin workflow](#admin-workflow)).

## Configuration

Environment variables are loaded from `.env` (copied from `.env.example`) into the `portal` container only. All settings are read by [portal/src/voyager/settings.py](portal/src/voyager/settings.py) via pydantic-settings (env vars are case-insensitive: `SECRET_KEY` in `.env` ↔ `settings.secret_key` in code).

| Variable                      | Default                    | Purpose                                                                                                                    |
| ----------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `SECRET_KEY`                  | _(required)_               | Server secret. Portal fails to start without it. Generate with `python -c "import secrets; print(secrets.token_hex(32))"`. |
| `DATABASE_PATH`               | `/data/voyager.db`         | SQLite path inside the portal container. Lives on the `voyager-data` named volume, not `./data/`.                          |
| `SMTP_HOST`                   | `localhost`                | Outbound SMTP server.                                                                                                      |
| `SMTP_PORT`                   | `465`                      | `465` → implicit TLS; `587` → STARTTLS; anything else → plaintext.                                                         |
| `SMTP_USER`                   | _(empty)_                  | SMTP auth username.                                                                                                        |
| `SMTP_PASSWORD`               | _(empty)_                  | SMTP auth password.                                                                                                        |
| `SMTP_FROM`                   | `noreply@example.com`      | `From:` header for OTP emails.                                                                                             |
| `OTP_EXPIRY_SECONDS`          | `600`                      | OTP lifetime (10 min).                                                                                                     |
| `OTP_MAX_ATTEMPTS`            | `5`                        | Wrong-code attempts before the OTP is invalidated.                                                                         |
| `OTP_MAX_REQUESTS_PER_WINDOW` | `3`                        | Max active OTPs per email in the rate window.                                                                              |
| `OTP_RATE_WINDOW_SECONDS`     | `900`                      | OTP rate-limit window (15 min).                                                                                            |
| `SESSION_EXPIRY_DAYS`         | `7`                        | Browser session lifetime.                                                                                                  |
| `RECONCILE_INTERVAL_SECONDS`  | `60`                       | How often the reconciler syncs DB → containers.                                                                            |
| `SHADOWSOCKS_IMAGE`           | `local/shadowsocks-server` | Image the reconciler spawns per connection.                                                                                |
| `SHADOWSOCKS_NETWORK`         | `shadowsocks`              | Docker bridge network `ss-*` containers join; Nginx attaches to the same one.                                              |
| `DOMAIN`                      | `voyager.binarydreams.me`  | Public domain. Used in client configs and server `plugin_opts`.                                                            |

The Nginx container doesn't read `.env`. Its domain and cert paths are baked into the config — see [Re-hosting to a different domain](#re-hosting-to-a-different-domain).

## Re-hosting to a different domain

The default config is built around `voyager.binarydreams.me`. To deploy under your own domain, edit the following:

1. **[nginx/etc/nginx.conf](nginx/etc/nginx.conf)** — replace every occurrence of `voyager.binarydreams.me` (the `server_name` directive and both `include conf.d/certs/...` lines).
1. **[nginx/etc/conf.d/certs/voyager.binarydreams.me.conf](nginx/etc/conf.d/certs/voyager.binarydreams.me.conf)** — rename the file to match your domain and edit the three `/etc/letsencrypt/live/...` paths inside it. Then update the `include` lines from step 1 to point at the renamed file.
1. **[.env](.env)** — change `SMTP_FROM` from `<noreply@voyager.binarydreams.me>` to `<noreply@<your-domain>>`, and uncomment/set `DOMAIN=<your-domain>` (overrides the default in `settings.py`).
1. **Test fixtures** (optional; only if you plan to run the test suite with your domain). Three test files reference the default:
   - [portal/tests/test_reconciler.py](portal/tests/test_reconciler.py)
   - [portal/tests/test_routes.py](portal/tests/test_routes.py)
   - [portal/tests/test_ss_config.py](portal/tests/test_ss_config.py)

After editing, rebuild Nginx: `docker compose up -d --build nginx`.

## Admin workflow

Voyager has no self-serve signup. Users and their connections are created by the operator via the `voyager` CLI, which ships inside the portal image:

```bash
# Add a user
docker compose exec portal voyager user add "Alice" alice@example.com

# Give them a connection (creates a 24-hex-char path token + random password)
docker compose exec portal voyager connection add alice@example.com "laptop"

# Inspect
docker compose exec portal voyager user list
docker compose exec portal voyager connection list --user-email alice@example.com

# Disable / enable / delete
docker compose exec portal voyager connection disable <connection_id>
docker compose exec portal voyager connection enable  <connection_id>
docker compose exec portal voyager user disable alice@example.com
docker compose exec portal voyager user delete  alice@example.com
```

CLI commands that change connection state (`connection add/enable/disable`, `user disable/delete`) touch `/data/.reconcile-now` to wake the reconciler; the corresponding container appears (or disappears) within a few seconds. Pure reads (`list`) and `user add` do not trigger a reconcile — a user with no connections doesn't need any container.

From the user's side:

1. Visit `https://<your-domain>/login`, enter their email.
1. Receive a 6-digit OTP by email, submit it.
1. On the dashboard, click their connection to download a JSON config (file name `voyager-<label>.json`).
1. Import that JSON into a Shadowsocks-rust client. It points at `wss://<your-domain>:443` with `plugin_opts=tls;fast-open;path=/t/<token>;host=<your-domain>`.

## How the VPN tunnel works

A client connects to `wss://<your-domain>:443/t/<token>` (v2ray-plugin in TLS + WebSocket mode). Nginx matches the path with `^/t/([a-f0-9]{24})$` and proxies the upgraded connection to `http://ss-<token>:80`, resolved on the `shadowsocks` Docker network via Docker's embedded DNS. The `ss-<token>` container runs v2ray-plugin → Shadowsocks-rust, decrypts the tunnel, and forwards traffic to the destination.

## Operations

- **Logs.** Nginx logs are on the host at [nginx/log/](nginx/log/) (`access.log`, `error.log`). Portal logs go to `docker compose logs -f portal`. `ss-*` containers run with `LogConfig(type="none")` — they're deliberately logless.
- **Reconciliation.** The portal runs a background loop every `RECONCILE_INTERVAL_SECONDS` (default 60s). To trigger it immediately after a DB mutation: `docker compose exec portal touch /data/.reconcile-now`. It also restarts exited `ss-*` containers and recreates them when the `local/shadowsocks-server` image ID changes.
- **Cert renewal.** Nginx self-reloads every 6 hours via a background shell loop injected by [nginx/Dockerfile](nginx/Dockerfile). This picks up certbot-renewed certificates from the bind-mounted `/etc/letsencrypt` without restarting the container. `inotifywait` is not used — it does not reliably observe Let's Encrypt's symlink-target updates across Docker bind mounts.
- **Portal restarts stop all tunnels.** When the `portal` container's lifespan ends, it calls `cleanup_all_containers()`, which stops and removes every `ss-*` container. They come back on the next reconciliation pass (a few seconds later), but connections are interrupted. Cleanup is best-effort — if the docker-proxy is unavailable during shutdown, containers can survive into the next portal start; the reconciler adopts them by their `voyager.managed=true` label on the following pass.
- **Data.** The SQLite database lives only in the `voyager-data` named Docker volume. `./data/` is gitignored ([`.gitignore`](.gitignore)) and not otherwise used by the project.

## Project layout

```
compose.yaml                    # Orchestration (nginx + portal + docker-proxy)
nginx/                          # Reverse proxy
    Dockerfile
    etc/nginx.conf
    etc/conf.d/                 # ssl.conf, cert include, mozilla ssl policy
    log/                        # Bind-mounted; nginx writes access/error logs here
portal/                         # FastAPI management service (Python 3.13)
    Dockerfile
    pyproject.toml
    src/voyager/                # app.py, auth.py, db.py, reconciler.py, cli.py, ...
    tests/
shadowsocks/                    # Per-connection tunnel image (Go + Rust multi-stage)
    Dockerfile
external/                       # Vendored upstreams, managed as git-subrepos
    shadowsocks-rust/
    v2ray-plugin/
scripts/                        # Prek (pre-commit) helpers
.github/workflows/              # subrepo-pull.yml: Renovate-driven subrepo updates
```

## See also

- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, tests, prek, subrepo workflow
- [CLAUDE.md](CLAUDE.md) — guide for AI coding agents working on this repo
