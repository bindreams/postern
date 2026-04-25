# CLAUDE.md

Project-specific guide for AI coding agents. Read [README.md](README.md) first for what the project is; this file covers invariants and landmines.

## One-line summary

Voyager is a FastAPI portal + Nginx reverse proxy + per-connection Shadowsocks-rust containers. The portal reconciles Docker container state against its SQLite database.

## Architecture invariants

These are load-bearing. Changing any of them without understanding the chain will silently break the system. Line numbers below are accurate at the time of writing — if an edit has drifted them, re-locate by the quoted symbol.

- **Path-token chain.** All three must agree:
  - [nginx/etc/nginx.conf:36](nginx/etc/nginx.conf) regex `^/t/([a-f0-9]{24})$`
  - [portal/src/voyager/cli.py:137](portal/src/voyager/cli.py#L137) `secrets.token_hex(12)` (12 bytes → 24 hex chars)
  - [portal/src/voyager/reconciler.py:29-30](portal/src/voyager/reconciler.py#L29-L30) `f"ss-{conn.path_token}"`
- **Container name = DNS hostname.** Nginx proxies `http://ss-$1`, resolved via Docker's embedded DNS (`resolver 127.0.0.11` in nginx.conf). The `ss-` prefix is not cosmetic.
- **Reconciler is the source of truth.** DB state → container state. Connection creation is CLI-only (there is no `POST /connection` route). Reconciler responsibilities, all in [portal/src/voyager/reconciler.py](portal/src/voyager/reconciler.py):
  - Create missing containers, remove orphans
  - Restart exited containers (lines 111–120)
  - Recreate containers when the `local/shadowsocks-server` image ID changes (lines 122–139)
  - Clean up expired sessions/OTPs each pass (line 160 → `db.cleanup_expired`)
- **Manual reconcile trigger.** `touch <database_path>.parent/.reconcile-now`. Both [cli.py:28](portal/src/voyager/cli.py#L28) and [reconciler.py:168](portal/src/voyager/reconciler.py#L168) derive this path from `settings.database_path` — they must stay in sync. Any new code path that mutates connection state must trigger it too.
- **Shutdown wipes all `ss-*` containers.** [portal/src/voyager/app.py:41](portal/src/voyager/app.py#L41) calls `cleanup_all_containers()` on lifespan exit. Cleanup is best-effort — exceptions are swallowed ([reconciler.py:198-199](portal/src/voyager/reconciler.py#L198-L199)). If the docker-proxy is unavailable at shutdown, containers survive; the reconciler adopts them on the next pass via the `voyager.managed=true` label. Do not assume containers persist across portal restarts in tests or in code.
- **App factory pattern.** [portal/src/voyager/app.py:71](portal/src/voyager/app.py#L71) is `app = _get_app` — a callable factory, not a `FastAPI` instance — because the Dockerfile runs `uvicorn voyager.app:app --factory`. Do NOT "clean this up" to `app = _get_app()`: it opens the DB at module-import time and breaks. Tests that need an app should call `create_app()` directly, not import `voyager.app.app`.
- **Docker API access is proxied.** The portal uses `docker.DockerClient.from_env()` ([reconciler.py:34](portal/src/voyager/reconciler.py#L34)), which reads `DOCKER_HOST=tcp://docker-proxy:2375` (set in [compose.yaml](compose.yaml)). The `docker-proxy` grants `CONTAINERS`, `NETWORKS`, `IMAGES`, `POST` verbs only. Never hardcode `/var/run/docker.sock`. If you add a new Docker API call that needs a different verb, enable it on the proxy.
- **Portal container is read-only.** `read_only: true` + `tmpfs: [/tmp]` + `no-new-privileges:true`. Writes go to `/data` (named volume) or `/tmp` (tmpfs). Nothing else is writable at runtime.
- **DB lives in the `voyager-data` named volume, NOT `./data/`.** `./data/` is gitignored and not created anywhere in the repo — it is not a working directory. Tests use `tmp_path` (see [portal/tests/conftest.py](portal/tests/conftest.py)). Never hardcode `/data/voyager.db` in tests or scripts.
- **SQLite PRAGMAs are load-bearing.** [db.py:51-53](portal/src/voyager/db.py#L51-L53) sets `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`. Always go through `db.get_connection()`; never `aiosqlite.connect()` directly.
- **Constant-time comparisons.** OTP verification ([db.py:234](portal/src/voyager/db.py#L234)) uses `hmac.compare_digest`. Never simplify to `==`.
- **Email-enumeration defence.** [auth.py:44-52](portal/src/voyager/auth.py#L44-L52) always creates an OTP row, using `__dummy__{email}` for unknown emails, so timing and rate-limit buckets don't reveal which emails are registered. Do not remove the dummy path "for simplicity."
- **SMTP TLS mode is port-derived.** [email.py:33-34](portal/src/voyager/email.py#L33-L34): `use_tls = port == 465`, `start_tls = port == 587`. Any other port means plaintext. If you add a new port, also update these conditions.
- **Session cookies require HTTPS.** `login.py` sets `secure=True`. Login cannot complete over plain HTTP. Local dev needs TLS — see [CONTRIBUTING.md](CONTRIBUTING.md).
- **Cookie names are load-bearing.** `otp_email` and `session` are referenced across `routes/login.py` and `routes/dashboard.py`. Renaming either breaks auth.
- **`ss_config.py` invariants.** [ss_config.py:10-11](portal/src/voyager/ss_config.py#L10-L11) hardcodes cipher `chacha20-ietf-poly1305` and `SERVER_PORT=80`. Both must match what the Shadowsocks image accepts and what Nginx upstreams to. The `plugin_opts` strings are also load-bearing: server mode uses `server;fast-open;path=/t/{token};host={domain}`, client mode uses `tls;fast-open;path=/t/{token};host={domain}`. The `path=` must match the Nginx regex; `host=` sets the TLS SNI that v2ray-plugin validates.
- **OpenAPI is disabled on purpose.** [app.py:50](portal/src/voyager/app.py#L50): `docs_url=None, redoc_url=None, openapi_url=None`. There is no public API surface. Do not re-enable.
- **Pydantic settings are env-case-insensitive.** `.env` uses `UPPER_SNAKE_CASE`; Python code reads `settings.lower_snake_case`. They refer to the same field.
- **Auth flow spans two places.** `OTP_EXPIRY_SECONDS` (default 600) controls the OTP's DB lifetime, but the `otp_email` cookie's `max_age` is hardcoded to 900 in [routes/login.py:42](portal/src/voyager/routes/login.py#L42). Changing the setting without updating the cookie can leave a cookie pointing at an expired OTP (or vice versa). Keep them in sync.
- **Adding an auth route requires an nginx block.** The `auth` rate-limit zone is applied per-`location` in [nginx/etc/nginx.conf](nginx/etc/nginx.conf) — currently only on `/login` and `= /login/verify`. A new route like `/signup` or `/reset-password` will bypass rate limiting unless you add a matching `location` block with `limit_req zone=auth burst=5 nodelay;`.
- **Shadowsocks build context is the repo root, not `./shadowsocks/`.** [shadowsocks/Dockerfile](shadowsocks/Dockerfile) `COPY`s from `external/v2ray-plugin/` and `external/shadowsocks-rust/`, which live outside the Dockerfile's directory. Build with `docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .` from the repo root. A `docker build ./shadowsocks/` command will fail.
- **Portal build context is also the repo root, not `./portal/`.** [portal/Dockerfile](portal/Dockerfile) `COPY`s `LICENSE.md` from the repo root for AGPL §5(a) compliance and uses `portal/`-prefixed paths for its own sources. [compose.yaml](compose.yaml) and [portal/tests/e2e/e2e.compose.yaml](portal/tests/e2e/e2e.compose.yaml) both set `context:` accordingly. A `docker build ./portal/` command will fail.

## Where things live

```
portal/src/voyager/
    app.py           # FastAPI factory + lifespan (reconciler start + shutdown cleanup)
    settings.py      # All tunables, pydantic-settings
    db.py            # Schema, migrations, PRAGMAs, queries
    auth.py          # OTP generation, hashing, session tokens
    email.py         # SMTP send (port-derived TLS mode)
    ss_config.py     # Shadowsocks server/client JSON generation
    reconciler.py    # Background loop, container CRUD, image-change detection, cleanup
    cli.py           # typer-based admin CLI (entry point: `voyager`)
    routes/login.py      # /login, /login/verify, /logout
    routes/dashboard.py  # /, /connection/{id}/config, /healthz
    models.py        # User, Connection, OtpCode, Session dataclasses
    templates/       # Jinja2 templates
```

## Vendored code

[external/](external/) is managed with [git-subrepo](https://github.com/ingydotnet/git-subrepo), not submodules. `external/shadowsocks-rust` and `external/v2ray-plugin` are pinned upstream copies.

- Prek excludes `^external/` ([prek.toml](prek.toml)).
- `.gitattributes` marks them `linguist-vendored`.
- [.github/workflows/subrepo-pull.yml](.github/workflows/subrepo-pull.yml) automates `git subrepo pull` when Renovate bumps the pinned refs.

**Do not** edit these files by hand, lint them, or include them in changes you make to the first-party code.

## Testing

Run from the `portal/` directory:

```bash
cd portal
uv run pytest
uv run pytest tests/test_reconciler.py::test_foo   # single test
```

- `asyncio_mode = "auto"` ([pyproject.toml](portal/pyproject.toml)); async tests need no explicit marker.
- Tests use `tmp_path` for SQLite, never `/data/voyager.db`.
- Tests do not need a real Docker daemon — the docker client is mocked where needed.

## Style deltas

Global convention: Python is yapf-formatted, type-hinted, and section-comment-annotated. The formatter for section comments is [scripts/format-section-comments.py](scripts/format-section-comments.py):

- Primary section: `# <name> =====`
- Sub-section: `# <name> -----`

That script is ALSO a pytest module (the tests live in the same file). If you find yourself "cleaning up dead code" there, stop — you are looking at its test suite.

Type checking is `ty` (invoked via `uvx ty check` in prek). Commit messages are single-line; trailers like `Approved-By:` go after a blank line and are reserved for tool-generated metadata.

## Do-not list

- Don't change the nginx path regex without updating `token_hex(12)` in `cli.py` and `_container_name` in `reconciler.py`.
- Don't create Shadowsocks containers outside the reconciler.
- Don't bypass `db.get_connection()` with a raw `aiosqlite.connect()`.
- Don't simplify `hmac.compare_digest` to `==`.
- Don't remove the `__dummy__{email}` path in `auth.request_otp`.
- Don't rename the `session` or `otp_email` cookies.
- Don't re-enable `docs_url` / `redoc_url` / `openapi_url`.
- Don't commit to anything under `external/` — use `git subrepo pull` / `push`.
- Don't hardcode `/var/run/docker.sock`; access goes through `docker-proxy`.
- Don't convert `app = _get_app` to `app = _get_app()`.
- Don't write tests or code that assume `./data/voyager.db` or that `ss-*` containers persist across portal restarts.
- Don't change `OTP_EXPIRY_SECONDS` without also updating the `otp_email` cookie `max_age` in [routes/login.py](portal/src/voyager/routes/login.py).
- Don't build the shadowsocks image with `docker build ./shadowsocks/` — the Dockerfile pulls from `external/` and needs the repo root as context.

## Useful commands

```bash
# Build the per-connection tunnel image (compose doesn't build this one)
docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .

# Build and run the full stack
docker compose up -d --build

# Run the admin CLI
docker compose exec portal voyager user list
docker compose exec portal voyager user add "Name" email@example.com
docker compose exec portal voyager connection add email@example.com "label"

# Manual reconcile trigger (bypasses the 60s poll)
docker compose exec portal touch /data/.reconcile-now

# Tail logs
docker compose logs -f portal
docker compose logs -f nginx

# Tests
cd portal && uv run pytest

# Full prek run
prek run --all-files
```
