# CLAUDE.md

Project-specific guide for AI coding agents. Read [README.md](README.md) first for what the project is; this file covers invariants and landmines.

## One-line summary

Postern is a FastAPI portal + Nginx reverse proxy + per-connection Shadowsocks-rust containers. The portal reconciles Docker container state against its SQLite database.

## Architecture invariants

These are load-bearing. Changing any of them without understanding the chain will silently break the system. Line numbers below are accurate at the time of writing — if an edit has drifted them, re-locate by the quoted symbol.

- **Path-token chain.** All three must agree:
  - [nginx/etc/nginx.conf:36](nginx/etc/nginx.conf) regex `^/t/([a-f0-9]{24})$`
  - [portal/src/postern/cli.py:137](portal/src/postern/cli.py#L137) `secrets.token_hex(12)` (12 bytes → 24 hex chars)
  - [portal/src/postern/reconciler.py:29-30](portal/src/postern/reconciler.py#L29-L30) `f"ss-{conn.path_token}"`
- **Container name = DNS hostname.** Nginx proxies `http://ss-$1`, resolved via Docker's embedded DNS (`resolver 127.0.0.11` in nginx.conf). The `ss-` prefix is not cosmetic.
- **Reconciler is the source of truth.** DB state → container state. Connection creation is CLI-only (there is no `POST /connection` route). Reconciler responsibilities, all in [portal/src/postern/reconciler.py](portal/src/postern/reconciler.py):
  - Create missing containers, remove orphans
  - Restart exited containers (lines 111–120)
  - Recreate containers when the `local/shadowsocks-server` image ID changes (lines 122–139)
  - Clean up expired sessions/OTPs each pass (line 160 → `db.cleanup_expired`)
- **Manual reconcile trigger.** The trigger file path (`<dirname(database_path)>/.reconcile-now`) is derived in two places that must stay in sync: [cli.py:28](portal/src/postern/cli.py#L28) (`_trigger_reconcile`, called by all state-mutating CLI commands and by `postern reconcile`) and [reconciler.py:163](portal/src/postern/reconciler.py#L163) (the watcher). The e2e helper [tests/e2e/\_helpers.py:43](portal/tests/e2e/_helpers.py#L43) and operators both go through `postern reconcile` rather than re-deriving the path. Any new code path that mutates connection state must call `_trigger_reconcile`.
- **Production runtime is distroless (portal only).** [portal/Dockerfile](portal/Dockerfile)'s runtime stage is `dhi.io/python:3.13-alpine3.23` (no `-dev`). It ships only Python and its bundled libs — no `sh`, no busybox, no `touch`/`cat`/`ls`/`id`, no apk. Anything that previously assumed a shell — entrypoint scripts, `docker compose exec ... <unix tool>` patterns, healthchecks using `[CMD-SHELL ...]`, runtime-stage `RUN` instructions — must be rewritten in Python or moved to the build stage (which is `-dev` and still has Alpine + apk). Container debugging via `docker compose exec portal sh` will fail; use `python -c '...'` (see [tests/e2e/\_helpers.py:47](portal/tests/e2e/_helpers.py#L47) `query_db` for the pattern) or an ephemeral debug container. The **shadowsocks** runtime ([shadowsocks/Dockerfile](shadowsocks/Dockerfile) on `dhi.io/alpine-base:3.23`) is NOT distroless — it ships busybox sh and uses a real entrypoint script, and `docker run --init --entrypoint sh local/shadowsocks-server` works for debugging.
- **PID 1 is `tini`.** Every container in this repo runs with `init: true` (compose) or `init=True` (`docker.containers.run` in the reconciler). Docker injects `tini` at PID 1, which forwards signals and reaps zombies; the user process runs as PID 2. This matters for the **per-connection shadowsocks containers** (where `ssserver` spawns `v2ray-plugin` as a child that would otherwise zombify) and for the **distroless portal** (where there is no shell to act as init). Probe from the host with `docker inspect <name> --format '{{.HostConfig.Init}}'`; from inside the portal `/proc/1/exe` is root-owned and unreadable from the `nonroot` user, so use `/proc/1/comm` (world-readable) instead.
- **Shutdown wipes all `ss-*` containers.** [portal/src/postern/app.py:54](portal/src/postern/app.py#L54) calls `cleanup_all_containers()` on lifespan exit. Cleanup is best-effort — exceptions are swallowed ([reconciler.py:198-199](portal/src/postern/reconciler.py#L198-L199)). If the docker-proxy is unavailable at shutdown, containers survive; the reconciler adopts them on the next pass via the `postern.managed=true` label. Do not assume containers persist across portal restarts in tests or in code.
- **Docker API access is proxied.** The portal uses `docker.DockerClient.from_env()` ([reconciler.py:34](portal/src/postern/reconciler.py#L34)), which reads `DOCKER_HOST=tcp://docker-proxy:2375` (set in [compose.yaml](compose.yaml)). The `docker-proxy` grants `CONTAINERS`, `NETWORKS`, `IMAGES`, `POST` verbs only. Never hardcode `/var/run/docker.sock`. If you add a new Docker API call that needs a different verb, enable it on the proxy.
- **Portal container is read-only.** `read_only: true` + `tmpfs: [/tmp]` + `no-new-privileges:true`. Writes go to `/data` (named volume) or `/tmp` (tmpfs). Nothing else is writable at runtime.
- **DB lives in the `postern-data` named volume, NOT `./data/`.** `./data/` is gitignored and not created anywhere in the repo — it is not a working directory. Tests use `tmp_path` (see [portal/tests/conftest.py](portal/tests/conftest.py)). Never hardcode `/data/postern.db` in tests or scripts.
- **SQLite PRAGMAs are load-bearing.** [db.py:51-53](portal/src/postern/db.py#L51-L53) sets `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`. Always go through `db.get_connection()`; never `aiosqlite.connect()` directly.
- **datetime adapter is registered at module import.** [db.py](portal/src/postern/db.py) calls `sqlite3.register_adapter(datetime, ...)` so `Session.expires_at` (typed `str | datetime`) and any future model that lets a Python `datetime` reach the aiosqlite boundary serialize to the same `YYYY-MM-DD HH:MM:SS` shape used by `auth.py`'s strftime path. Aware values are normalized to UTC; naive values raise `ValueError` (Postern is UTC-everywhere, and silently storing local time as UTC is a foot-gun). Removing the registration revives the Python-3.12 deprecation warning and breaks outright in 3.14+.
- **Constant-time comparisons.** OTP verification ([db.py:234](portal/src/postern/db.py#L234)) uses `hmac.compare_digest`. Never simplify to `==`.
- **Email-enumeration defence.** [auth.py:44-52](portal/src/postern/auth.py#L44-L52) always creates an OTP row, using `__dummy__{email}` for unknown emails, so timing and rate-limit buckets don't reveal which emails are registered. Do not remove the dummy path "for simplicity."
- **SMTP TLS mode is port-derived.** [email.py:33-34](portal/src/postern/email.py#L33-L34): `use_tls = port == 465`, `start_tls = port == 587`. Any other port means plaintext. If you add a new port, also update these conditions.
- **Session cookies require HTTPS.** `login.py` sets `secure=True`. Login cannot complete over plain HTTP. Local dev needs TLS — see [CONTRIBUTING.md](CONTRIBUTING.md).
- **Cookie names are load-bearing.** `otp_email` and `session` are referenced across `routes/login.py` and `routes/dashboard.py`. Renaming either breaks auth.
- **`ss_config.py` invariants.** [ss_config.py:10-11](portal/src/postern/ss_config.py#L10-L11) hardcodes cipher `chacha20-ietf-poly1305` and `SERVER_PORT=80`. Both must match what the Shadowsocks image accepts and what Nginx upstreams to. The `plugin_opts` strings are also load-bearing: server mode uses `server;fast-open;path=/t/{token};host={domain}`, client mode uses `tls;fast-open;path=/t/{token};host={domain}`. The `path=` must match the Nginx regex; `host=` sets the TLS SNI that v2ray-plugin validates.
- **OpenAPI is disabled on purpose.** [app.py:22](portal/src/postern/app.py#L22): `docs_url=None, redoc_url=None, openapi_url=None`. There is no public API surface. Do not re-enable.
- **Pydantic settings are env-case-insensitive.** `.env` uses `UPPER_SNAKE_CASE`; Python code reads `settings.lower_snake_case`. They refer to the same field.
- **Auth flow spans two places.** `OTP_EXPIRY_SECONDS` (default 600) controls the OTP's DB lifetime, but the `otp_email` cookie's `max_age` is hardcoded to 900 in [routes/login.py:42](portal/src/postern/routes/login.py#L42). Changing the setting without updating the cookie can leave a cookie pointing at an expired OTP (or vice versa). Keep them in sync.
- **Adding an auth route requires an nginx block.** The `auth` rate-limit zone is applied per-`location` in [nginx/etc/nginx.conf](nginx/etc/nginx.conf) — currently only on `/login` and `= /login/verify`. A new route like `/signup` or `/reset-password` will bypass rate limiting unless you add a matching `location` block with `limit_req zone=auth burst=5 nodelay;`.
- **E2e nginx auth rate limit diverges from production on purpose.** [portal/tests/e2e/nginx.conf](portal/tests/e2e/nginx.conf) uses `rate=600r/m, burst=20`; production [nginx/etc/nginx.conf](nginx/etc/nginx.conf) uses `rate=10r/m, burst=5`. The divergence exists because all e2e tests share a single source IP and the production rate exhausts the bucket mid-suite (GitHub issue #7). The boundary is pinned by `test_login_rate_limit_has_suite_burst_headroom` in [portal/tests/e2e/test_tunnel.py](portal/tests/e2e/test_tunnel.py); if you tighten the e2e rate, expect that test (and then the rest of the suite) to fail. If you add a new auth `location` to the e2e config, mirror the burst there too — it must stay `>= 20`.
- **Shadowsocks build context is the repo root, not `./shadowsocks/`.** [shadowsocks/Dockerfile](shadowsocks/Dockerfile) `COPY`s from `external/v2ray-plugin/` and `external/shadowsocks-rust/`, which live outside the Dockerfile's directory. Build with `docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .` from the repo root. A `docker build ./shadowsocks/` command will fail.
- **Portal build context is also the repo root, not `./portal/`.** [portal/Dockerfile](portal/Dockerfile) `COPY`s `LICENSE.md` from the repo root for AGPL §5(a) compliance and uses `portal/`-prefixed paths for its own sources. [compose.yaml](compose.yaml) and [portal/tests/e2e/e2e.compose.yaml](portal/tests/e2e/e2e.compose.yaml) both set `context:` accordingly. A `docker build ./portal/` command will fail.
- **mta and provisioner build context is also the repo root.** Both [mta/Dockerfile](mta/Dockerfile) and [provisioner/Dockerfile](provisioner/Dockerfile) `COPY portal/src/postern/mta /usr/lib/python3.13/site-packages/postern_mta` so the DKIM rendering / verification logic is shared between portal CLI, mta entrypoint, and provisioner entrypoint. Compose's `build:` does **not** detect cross-service file deps — when [portal/src/postern/mta/dns.py](portal/src/postern/mta/dns.py) changes, both `docker compose build mta provisioner` must re-run.
- **The mta and provisioner are split deliberately.** The mta holds the DKIM signing key and is exposed on public port 25. The provisioner holds the DNS provider API token and has zero inbound listeners. A Postfix RCE on port 25 cannot escalate to DNS-record hijack because the credentials live in a different container. Do **not** "consolidate for simplicity."
- **mta is intentionally non-distroless and non-read-only.** The runtime is `dhi.io/alpine-base:3.23` (busybox + Python 3). Postfix and OpenDKIM write to many paths during normal operation (`postmap`-compiled `*.db`, `/etc/resolv.conf`, queue management). The portal's `read_only: true` pattern is dropped here; security comes from `cap_drop: [ALL]` plus a minimal `cap_add` set ([compose.yaml](compose.yaml) `mta:`).
- **opendkim runs as UID/GID 110:110 in both mta and provisioner**, pinned in both Dockerfiles ([mta/Dockerfile](mta/Dockerfile) and [provisioner/Dockerfile](provisioner/Dockerfile) call `addgroup -g 110 -S opendkim && adduser -u 110 -S -G opendkim`). The provisioner runs as this user (compose `user: "110:110"`) so files it writes to the shared `postern-mta-data` volume are readable by mta's opendkim. Do not let Alpine package version drift change this.
- **`mynetworks` is scoped to the `mta-submit` /29 subnet only** ([mta/etc/main.cf.tmpl](mta/etc/main.cf.tmpl); IPAM-fixed `172.30.42.0/29` in [compose.yaml](compose.yaml) `mta-submit:`), not the shared `default` bridge. Only the `portal` joins `mta-submit`. Adding any other service to `mta-submit` would let it relay through mta without authentication. If a future feature genuinely needs to submit, add SASL or use a separate network.
- **`milter_default_action = tempfail`** ([mta/etc/main.cf.tmpl](mta/etc/main.cf.tmpl)). If opendkim is down, mail queues rather than going out unsigned. An unsigned outbound from this MTA defeats DMARC `p=reject` and is worse than delayed delivery. Don't change to `accept` "for resilience."
- **DANE outbound requires the local Unbound resolver** in the mta container. `smtp_tls_security_level = dane` is a silent no-op without DNSSEC validation. The mta entrypoint writes `/etc/resolv.conf` to point at `127.0.0.1:53` (Unbound). Removing Unbound silently degrades outbound TLS to `may`.
- **Postfix queue lives in the `postern-mta-queue` named volume.** Putting it on tmpfs would lose deferred mail on every container restart — including greylist-deferred OTPs that are about to retry. tmpfs for the queue is wrong even at low volume.
- **DKIM key sharing.** `postern-mta-data` is mounted rw on mta and provisioner, ro on portal. The portal's `postern mta show-dns` reads `<selector>.txt` directly via this read-only mount. No HTTP listener.
- **Trigger files mirror the reconciler pattern.** [portal/src/postern/mta/rotation.py](portal/src/postern/mta/rotation.py) defines two: `.rotate-dkim` (portal CLI -> provisioner) and `.reload-opendkim` (provisioner -> mta). Existence is the signal; consumer deletes after handling. Same race acceptance as `.reconcile-now` at [reconciler.py:163](portal/src/postern/reconciler.py#L163): double-trigger may collapse, which is fine because the state machine is idempotent.
- **MTA-STS policy is served by nginx**, not by mta. The `mta-sts.<domain>` server block at [nginx/etc/conf.d/mta-sts.conf](nginx/etc/conf.d/mta-sts.conf) is load-bearing for the MTA-STS standard (RFC 8461 §3.3 mandates HTTPS with a publicly-trusted CA). Outbound MTA-STS enforcement (consuming recipient policies) is via `postfix-mta-sts-resolver` running inside mta.
- **e2e-mta uses a static IP for `MTA_E2E_TRANSPORT_OVERRIDE`.** The mta entrypoint rewrites `/etc/resolv.conf` to point at local Unbound (127.0.0.1), and CI runners cannot reach root nameservers. Two consequences: (1) the e2e-mta overlay [portal/tests/e2e/e2e-mta.compose.yaml](portal/tests/e2e/e2e-mta.compose.yaml) targets a fixed IP (`smtp:[172.30.99.10]:1025`, mailpit pinned via IPAM) instead of a hostname, so Postfix never does DNS lookup for the next hop; (2) it bind-mounts a test-only [portal/tests/e2e/unbound.e2e-mta.conf.tmpl](portal/tests/e2e/unbound.e2e-mta.conf.tmpl) over `/usr/local/share/mta-templates/unbound.conf.tmpl` that declares `postern.test` and `elsewhere.test` authoritatively (so `reject_unknown_sender_domain` passes for `noreply@postern.test`). Switching to a hostname requires either dropping that Unbound override or providing a real DNS environment.
- **`postern-dns` (the libdns wrapper) lives in the provisioner only.** The DNS provider API token is in the provisioner's env (`MTA_DNS_PROVIDER` plus libdns-native env vars like `CLOUDFLARE_API_TOKEN`). The mta image does not have it and cannot publish/retire DNS records.

## Where things live

```
portal/src/postern/
    app.py           # PosternApp(FastAPI) subclass + lifespan (reconciler start + shutdown cleanup)
    settings.py      # All tunables, pydantic-settings
    db.py            # Schema, migrations, PRAGMAs, queries
    auth.py          # OTP generation, hashing, session tokens
    email.py         # SMTP send (port-derived TLS mode)
    ss_config.py     # Shadowsocks server/client JSON generation
    reconciler.py    # Background loop, container CRUD, image-change detection, cleanup
    cli.py           # typer-based admin CLI (entry point: `postern`)
    mta/             # Built-in MTA support (also COPYed into mta + provisioner images)
        dns.py       # DNS record rendering + verification
        dkim.py      # DKIM key file helpers (read pubkey, list selectors)
        rotation.py  # Rotation state machine schema, persistence, triggers
        dnssec.py    # DNSSEC AD-bit checking via external validating resolvers
    routes/login.py      # /login, /login/verify, /logout
    routes/dashboard.py  # /, /connection/{id}/config, /healthz
    models.py        # User, Connection, OtpCode, Session dataclasses
    templates/       # Jinja2 templates

mta/
    Dockerfile       # Postfix + opendkim + Unbound + postsrsd + mta-sts-resolver
    entrypoint.py    # Renders configs, waits for state.json, verifies DNS, exec's postfix
    etc/             # string.Template config templates

provisioner/
    Dockerfile       # libdns-wrapped Go binary + Python state-machine driver
    entrypoint.py    # Generates initial DKIM key; runs rotation state machine if MTA_DNS_PROVIDER set
    postern-dns/     # Go module: txt-set / txt-delete via libdns providers
```

## Vendored code

[external/](external/) is managed with [git-subrepo](https://github.com/ingydotnet/git-subrepo), not submodules. `external/shadowsocks-rust` and `external/v2ray-plugin` are pinned upstream copies.

- Prek excludes `^external/` ([prek.toml](prek.toml)).
- `.gitattributes` marks them `linguist-vendored`.
- [.github/workflows/subrepo-pull.yaml](.github/workflows/subrepo-pull.yaml) automates `git subrepo pull` when Renovate bumps the pinned refs.

**Do not** edit these files by hand, lint them, or include them in changes you make to the first-party code.

## Testing

Run from the `portal/` directory:

```bash
cd portal
uv run pytest
uv run pytest tests/test_reconciler.py::test_foo   # single test
```

- `asyncio_mode = "auto"` ([pyproject.toml](portal/pyproject.toml)); async tests need no explicit marker.
- Tests use `tmp_path` for SQLite, never `/data/postern.db`.
- Tests do not need a real Docker daemon — the docker client is mocked where needed.

## Style deltas

Global convention: Python is yapf-formatted, type-hinted, and section-comment-annotated. The formatter for section comments is [scripts/format-section-comments.py](scripts/format-section-comments.py):

- Primary section: `# <name> =====`
- Sub-section: `# <name> -----`

That script is ALSO a pytest module (the tests live in the same file). If you find yourself "cleaning up dead code" there, stop — you are looking at its test suite.

Type checking is `ty` (invoked via `uvx ty check` in prek).

Commit subjects follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/): `type(scope): subject`. Allowed types: `feat`, `fix`, `refactor`, `chore`, `ci`, `docs`, `test`, `build`, `perf`. Scope is optional but encouraged (e.g. `cli`, `portal`, `shadowsocks`, `nginx`, `deps`). The subject stays single-line; trailers like `Approved-By:` go after a blank line and are reserved for tool-generated metadata. Renovate is configured to follow the same convention via `semanticCommits` in [.github/renovate.json](.github/renovate.json).

## Do-not list

- Don't change the nginx path regex without updating `token_hex(12)` in `cli.py` and `_container_name` in `reconciler.py`.
- Don't create Shadowsocks containers outside the reconciler.
- Don't bypass `db.get_connection()` with a raw `aiosqlite.connect()`.
- Don't open an aiosqlite connection without `async with db.get_connection(...) as conn:` (or fixture teardown). The aiosqlite worker is a non-daemon `Thread` and a missed `close()` hangs interpreter exit forever after pytest finishes. `db.get_connection` is an `@asynccontextmanager` exactly to make this impossible to get wrong.
- Don't simplify `hmac.compare_digest` to `==`.
- Don't remove the `__dummy__{email}` path in `auth.request_otp`.
- Don't rename the `session` or `otp_email` cookies.
- Don't re-enable `docs_url` / `redoc_url` / `openapi_url`.
- Don't commit to anything under `external/` — use `git subrepo pull` / `push`.
- Don't hardcode `/var/run/docker.sock`; access goes through `docker-proxy`.
- Don't write tests or code that assume `./data/postern.db` or that `ss-*` containers persist across portal restarts.
- Don't change `OTP_EXPIRY_SECONDS` without also updating the `otp_email` cookie `max_age` in [routes/login.py](portal/src/postern/routes/login.py).
- Don't build the shadowsocks image with `docker build ./shadowsocks/` — the Dockerfile pulls from `external/` and needs the repo root as context.
- Don't add shell-form `RUN`, `CMD`, or `HEALTHCHECK` in the runtime stage of [portal/Dockerfile](portal/Dockerfile), and don't use `[CMD-SHELL ...]` for the portal in compose. The runtime is distroless. Use Python (`python -c '...'`) or move shell work to the build stage.
- Don't drop `init: true` (compose) or `init=True` (`containers.run` kwarg) when adding a new service or container launch. Every container in this repo runs with tini at PID 1 — see the **PID 1 is `tini`** invariant.
- Don't write commit subjects that don't follow Conventional Commits 1.0.0 — applies to humans, AI agents, and Renovate equally.
- Don't put the DNS provider API token in any container other than the provisioner. The mta is exposed on public port 25; cross-container credential sharing defeats the split-container attack-surface argument.
- Don't set `MTA_REQUIRE_DNSSEC=false` in production. The default `auto` infers and enforces for signed domains; `false` disables the startup safety check entirely. Use `=true` only when you want fail-closed for unsigned-domain detection. Without DNSSEC, MTA-STS and DKIM records can be silently tampered with by anyone with upstream-DNS access — defeating most of what the rest of the security configuration buys you.
- Don't put `/var/spool/postfix` (the Postfix queue) on tmpfs. Mail in flight is lost on container restart.
- Don't set `milter_default_action = accept` in [mta/etc/main.cf.tmpl](mta/etc/main.cf.tmpl). If opendkim is down, mail must queue, not escape unsigned.
- Don't change opendkim's UID/GID away from 110 in either [mta/Dockerfile](mta/Dockerfile) or [provisioner/Dockerfile](provisioner/Dockerfile) without changing both. The shared volume permissions depend on them matching.

## Useful commands

```bash
# Build the per-connection tunnel image (compose doesn't build this one)
docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .

# Build and run the full stack (includes mta + provisioner via COMPOSE_PROFILES=with-mta in .env)
docker compose up -d --build

# Run the admin CLI
docker compose exec portal postern user list
docker compose exec portal postern user add "Name" email@example.com
docker compose exec portal postern connection add email@example.com "label"

# Built-in MTA admin
docker compose exec portal postern mta show-dns          # canonical DNS records to publish
docker compose exec portal postern mta verify-dns        # check DNS state matches
docker compose exec portal postern mta dnssec-status     # check AD bit on the sending domain
docker compose exec portal postern mta rotate-dkim       # request a rotation step
docker compose exec portal postern mta rotation-status   # show rotation state machine

# Manual reconcile trigger (bypasses the 60s poll)
docker compose exec portal postern reconcile

# Tail logs
docker compose logs -f portal
docker compose logs -f nginx
docker compose logs -f mta
docker compose logs -f provisioner

# Shell into the shadowsocks image (ENTRYPOINT execs ssserver -- override to get a shell)
docker run --rm -it --init --entrypoint sh local/shadowsocks-server

# Tests
cd portal && uv run pytest

# Full prek run
prek run --all-files
```
