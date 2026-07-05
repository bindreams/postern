# Architecture

Postern is a small set of cooperating containers plus a dynamic fleet: an Nginx reverse proxy, a FastAPI portal, a restricted Docker API proxy, and one Shadowsocks container per enabled connection — created and destroyed at runtime by the portal's reconciliation loop, never by Compose.

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

## Component map

- **nginx** — TLS termination, HTTP→HTTPS redirect, path-based WebSocket routing to the tunnels, security headers (including the CSP below), and rate limiting on `/login*`. Configs are rendered from templates ([nginx/etc/nginx.conf.tmpl](https://github.com/bindreams/postern/blob/main/nginx/etc/nginx.conf.tmpl)) at container start. Nginx joins both the `default` and `shadowsocks` networks so it can reach the tunnel containers.
- **portal** — Python 3.13 / FastAPI. OTP email login, dashboard, client-config download, the `postern` admin CLI ([CLI reference](../operations/cli.md)), and the background reconciler. There is no public API: OpenAPI docs are disabled, and connections are created only through the CLI — no `POST /connection` route exists.
- **docker-proxy** — [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy), a filtered Docker API exposed to the portal over TCP. The portal never mounts the raw Docker socket.
- **ss-\{token} containers** — one Shadowsocks-rust instance per enabled connection, fronted by a SIP003 plugin in TLS + WebSocket mode. Spawned from the `local/shadowsocks-server` image, which Compose does *not* build — build it yourself before first start (see [shadowsocks/Dockerfile](https://github.com/bindreams/postern/blob/main/shadowsocks/Dockerfile); the build context is the repo root).
- **mta + provisioner** (optional, `with-mta` profile) — a self-hosted Postfix stack for OTP mail and a DNS/certificate provisioner. They are deliberately separate containers: the mta holds the DKIM signing key and listens on public port 25, while the provisioner holds the DNS provider API token and has zero inbound listeners, so compromising one does not yield the other's credentials. See [email](../deployment/email.md) and [certificates](../deployment/certificates.md).

Repository layout:

```
compose.yaml                    # Orchestration (nginx + portal + docker-proxy + optional mta + provisioner)
nginx/                          # Reverse proxy
    Dockerfile
    etc/                        # nginx.conf.tmpl + conf.d/ (ssl, cert include, mta-sts vhost)
    log/                        # Bind-mounted; nginx writes access/error logs here
portal/                         # FastAPI management service (Python 3.13)
    Dockerfile
    src/postern/                # app.py, auth.py, db.py, reconciler.py, cli.py, mta/...
    tests/
mta/                            # Built-in MTA (Postfix + opendkim + Unbound + postsrsd + mta-sts-resolver)
provisioner/                    # DKIM rotation + ACME DNS-01 cert renewal
shadowsocks/                    # Per-connection tunnel image (Go + Rust multi-stage)
docs/                           # This documentation
external/                       # Vendored upstreams, managed as git-subrepos
scripts/                        # Prek (pre-commit) helpers
```

## How a tunnel byte flows

1. The client opens `wss://<domain>:443/t/<token>` — a WebSocket over TLS.
1. Nginx matches the path against `^/t/([a-f0-9]{24})$` and proxies the upgraded connection to `http://ss-<token>:80`. The hostname resolves through Docker's embedded DNS (`resolver 127.0.0.11`) on the `shadowsocks` network — a container's name *is* its DNS name there.
1. Inside the container, the plugin (`v2ray-plugin` or `galoshes`) unwraps the WebSocket framing and hands the stream to `ssserver`, which decrypts the Shadowsocks layer (`chacha20-ietf-poly1305`, hardcoded in [ss_config.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/ss_config.py)) and forwards traffic to its destination.

```{important}
Three places define the path token and must always agree: the nginx regex `^/t/([a-f0-9]{24})$`, the CLI's `secrets.token_hex(12)` (12 bytes → 24 hex chars, [cli.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/cli.py)), and the reconciler's `ss-<token>` container name ([reconciler.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/reconciler.py)). The `ss-` prefix is the DNS hostname nginx proxies to — it is not cosmetic. Changing any one of the three without the others silently breaks every tunnel.
```

The `plugin_opts` strings generated by `ss_config.py` are part of the same contract: `path=/t/{token}` must match the nginx regex, and `host={domain}` sets the TLS SNI the plugin validates.

## The reconciler

The database is the source of truth; containers are derived state. [reconciler.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/reconciler.py) runs as a background task in the FastAPI lifespan and, every `RECONCILE_INTERVAL_SECONDS` (default 60):

- creates a container for every enabled connection that lacks one;
- removes orphan containers whose connection is gone or disabled;
- restarts containers that have exited;
- recreates containers whose recorded image ID differs from the current `local/shadowsocks-server` — rebuilding the image is enough to roll the fleet;
- deletes expired sessions and OTPs from the database.

State-mutating CLI commands skip the wait by touching a trigger file, `.reconcile-now`, next to the database; the loop watches for it and runs immediately. Operators can do the same with `postern reconcile`. Existence of the file is the whole protocol — the consumer deletes it after handling, and because a pass is idempotent, two triggers collapsing into one pass is harmless.

Containers the reconciler creates carry the `postern.managed=true` label, and the reconciler only ever looks at labeled containers. On portal shutdown, the lifespan removes every managed container. Removal is best-effort: if the docker-proxy is unreachable at that moment, survivors are simply adopted by label on the next pass after restart.

```{note}
A portal restart interrupts all tunnels for a few seconds until the next reconciliation pass recreates them. Code and tests must not assume `ss-*` containers persist across portal restarts — or that they were lost, either.
```

Tunnel containers run with logging disabled (`LogConfig(type="none")`): deliberately logless.

## Runtime hardening

**The portal runtime is distroless.** The runtime stage of [portal/Dockerfile](https://github.com/bindreams/postern/blob/main/portal/Dockerfile) ships Python and nothing else — no shell, no busybox, no package manager. `docker compose exec portal sh` fails by design; healthchecks and entrypoints are plain Python.

````{tip}
To poke around a live portal, run Python directly or attach an ephemeral debug container:

```bash
docker compose exec portal python -c "import os; print(os.listdir('/data'))"
```

The shadowsocks image is *not* distroless (Debian base, required by galoshes' glibc-linked binary) and can be entered normally:

```bash
docker run --rm -it --init --entrypoint sh local/shadowsocks-server
```
````

**The portal filesystem is read-only.** [compose.yaml](https://github.com/bindreams/postern/blob/main/compose.yaml) sets `read_only: true`, `tmpfs: [/tmp]`, and `no-new-privileges:true`. The only writable paths are `/data` (named volume) and `/tmp` (tmpfs).

**Every container runs `tini` as PID 1.** All services set `init: true`, and the reconciler passes `init=True` when spawning tunnel containers. This matters twice over: in tunnel containers, `ssserver` spawns the plugin as a child process that would zombify without a reaper; in the distroless portal, there is no shell to act as init or forward signals.

**Docker API access is proxied.** The portal's `DOCKER_HOST` points at `tcp://docker-proxy:2375`; the proxy grants only the `CONTAINERS`, `NETWORKS`, `IMAGES` API sections plus `POST` (needed to create and remove containers). Everything else — volumes, exec, swarm, host info — is denied, and the raw `/var/run/docker.sock` is never mounted into the portal. A new Docker API call that needs another section must be enabled on the proxy explicitly.

## Database

SQLite, at `/data/postern.db` inside the `postern-data` named volume (the gitignored `./data/` directory in the repo is unused). All access goes through `db.get_connection()` in [db.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/db.py), which sets three load-bearing PRAGMAs on every connection: `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`. Opening the file with a bare `aiosqlite.connect()` bypasses them and is a bug.

Schema changes are append-only migrations. A migration is immutable once shipped: to change the schema — for example, extending the `CHECK` constraint on the connection `plugin` column for a new plugin — add migration N+1 rather than editing a published one.

## Plugin binaries

The shadowsocks image ships two SIP003 plugin binaries, both downloaded at build time from [bindreams/hole](https://github.com/bindreams/hole) release assets and verified against pinned SHA256 checksums:

- **ex-ray**, installed at `/usr/local/bin/v2ray-plugin`. It is a wire-compatible v2ray-core SIP003 shim published under the historical `v2ray-plugin` name, so existing client configs keep working unchanged.
- **galoshes**, installed at `/usr/local/bin/galoshes`. It adds UDP transport via yamux multiplexing and vendors ex-ray internally, so it accepts the same `plugin_opts` string.

Each connection stores a `plugin` field (`v2ray-plugin` or `galoshes`, chosen at `postern connection add --plugin ...`); `ssserver` looks the binary up by that name from the rendered `SS_CONFIG` JSON. Removing either binary from the image breaks every connection that selected it.

## Frontend

### Asset stack

The frontend ships fully inside the portal wheel; no CDN dependency.

- `postern.css` — single dark theme, design tokens declared as CSS variables on `:root`. Section-ordered: tokens, reset, brand, chrome, background, cards, footer.
- `postern.js` — IIFE-wrapped, self-bootstraps on `DOMContentLoaded`. Drives the GoL canvas, fade transitions, and footer controls. Honors `prefers-reduced-motion`.
- `static/fonts/InterVariable.woff2` (rsms/Inter v4.1, OFL) — variable axis, ~350 KB, browser-cached after first hit.
- `static/fonts/FiraCode-Regular.woff2` (tonsky/FiraCode v6.2, OFL) — monospace, ~100 KB.
- `static/flags/<cc>.svg` (lipis/flag-icons v7.5.0, MIT) — one file per ISO 3166-1 alpha-2 country, rendered into the identity card via the `flag-<cc>` class declared in `static/flags/flags.css`.

The flags directory is reproducible from upstream via [portal/scripts/sync-flags.sh](https://github.com/bindreams/postern/blob/main/portal/scripts/sync-flags.sh) — bump the `FLAG_ICONS_TAG` constant at the top to update.

### CSP

Nginx sets `Content-Security-Policy: default-src 'self'` on every portal response ([nginx/etc/nginx.conf.tmpl](https://github.com/bindreams/postern/blob/main/nginx/etc/nginx.conf.tmpl)). This forbids inline `<style>` blocks, inline `<script>` blocks, and HTML event-handler attributes (`onclick=`, `onerror=`, etc.). All CSS lives in `postern.css`; all JS lives in `postern.js`; event handlers attach via `addEventListener`, gated on element presence. Templates never call into the script — new behavior belongs in `postern.js`, not in template markup. The test suite asserts all of this; operators need no action to enforce it.

```{seealso}
[Testing](testing.md) for the unit and e2e suites that pin these invariants, and [deployment](../deployment/index.md) for the operator-facing view of the same stack.
```
