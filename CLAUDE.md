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
- **Production runtime is distroless.** [portal/Dockerfile](portal/Dockerfile)'s runtime stage is `dhi.io/python:3.13-alpine3.23` (no `-dev`). It ships only Python and its bundled libs — no `sh`, no busybox, no `touch`/`cat`/`ls`/`id`, no apk. Anything that previously assumed a shell — entrypoint scripts, `docker compose exec ... <unix tool>` patterns, healthchecks using `[CMD-SHELL ...]`, runtime-stage `RUN` instructions — must be rewritten in Python or moved to the build stage (which is `-dev` and still has Alpine + apk). Container debugging via `docker compose exec portal sh` will fail; use `python -c '...'` (see [tests/e2e/\_helpers.py:47](portal/tests/e2e/_helpers.py#L47) `query_db` for the pattern) or an ephemeral debug container.
- **Shutdown wipes all `ss-*` containers.** [portal/src/postern/app.py:41](portal/src/postern/app.py#L41) calls `cleanup_all_containers()` on lifespan exit. Cleanup is best-effort — exceptions are swallowed ([reconciler.py:198-199](portal/src/postern/reconciler.py#L198-L199)). If the docker-proxy is unavailable at shutdown, containers survive; the reconciler adopts them on the next pass via the `postern.managed=true` label. Do not assume containers persist across portal restarts in tests or in code.
- **App factory pattern.** [portal/src/postern/app.py:71](portal/src/postern/app.py#L71) is `app = _get_app` — a callable factory, not a `FastAPI` instance — because the Dockerfile runs `uvicorn postern.app:app --factory`. Do NOT "clean this up" to `app = _get_app()`: it opens the DB at module-import time and breaks. Tests that need an app should call `create_app()` directly, not import `postern.app.app`.
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
- **OpenAPI is disabled on purpose.** [app.py:50](portal/src/postern/app.py#L50): `docs_url=None, redoc_url=None, openapi_url=None`. There is no public API surface. Do not re-enable.
- **Pydantic settings are env-case-insensitive.** `.env` uses `UPPER_SNAKE_CASE`; Python code reads `settings.lower_snake_case`. They refer to the same field.
- **Auth flow spans two places.** `OTP_EXPIRY_SECONDS` (default 600) controls the OTP's DB lifetime, but the `otp_email` cookie's `max_age` is hardcoded to 900 in [routes/login.py:42](portal/src/postern/routes/login.py#L42). Changing the setting without updating the cookie can leave a cookie pointing at an expired OTP (or vice versa). Keep them in sync.
- **Adding an auth route requires an nginx block.** The `auth` rate-limit zone is applied per-`location` in [nginx/etc/nginx.conf](nginx/etc/nginx.conf) — currently only on `/login` and `= /login/verify`. A new route like `/signup` or `/reset-password` will bypass rate limiting unless you add a matching `location` block with `limit_req zone=auth burst=5 nodelay;`.
- **Shadowsocks build context is the repo root, not `./shadowsocks/`.** [shadowsocks/Dockerfile](shadowsocks/Dockerfile) `COPY`s from `external/v2ray-plugin/` and `external/shadowsocks-rust/`, which live outside the Dockerfile's directory. Build with `docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .` from the repo root. A `docker build ./shadowsocks/` command will fail.
- **Portal build context is also the repo root, not `./portal/`.** [portal/Dockerfile](portal/Dockerfile) `COPY`s `LICENSE.md` from the repo root for AGPL §5(a) compliance and uses `portal/`-prefixed paths for its own sources. [compose.yaml](compose.yaml) and [portal/tests/e2e/e2e.compose.yaml](portal/tests/e2e/e2e.compose.yaml) both set `context:` accordingly. A `docker build ./portal/` command will fail.

## Where things live

```
portal/src/postern/
    app.py           # FastAPI factory + lifespan (reconciler start + shutdown cleanup)
    settings.py      # All tunables, pydantic-settings
    db.py            # Schema, migrations, PRAGMAs, queries
    auth.py          # OTP generation, hashing, session tokens
    email.py         # SMTP send (port-derived TLS mode)
    ss_config.py     # Shadowsocks server/client JSON generation
    reconciler.py    # Background loop, container CRUD, image-change detection, cleanup
    cli.py           # typer-based admin CLI (entry point: `postern`)
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
- Tests use `tmp_path` for SQLite, never `/data/postern.db`.
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
- Don't open an aiosqlite connection without `async with db.get_connection(...) as conn:` (or fixture teardown). The aiosqlite worker is a non-daemon `Thread` and a missed `close()` hangs interpreter exit forever after pytest finishes. `db.get_connection` is an `@asynccontextmanager` exactly to make this impossible to get wrong.
- Don't simplify `hmac.compare_digest` to `==`.
- Don't remove the `__dummy__{email}` path in `auth.request_otp`.
- Don't rename the `session` or `otp_email` cookies.
- Don't re-enable `docs_url` / `redoc_url` / `openapi_url`.
- Don't commit to anything under `external/` — use `git subrepo pull` / `push`.
- Don't hardcode `/var/run/docker.sock`; access goes through `docker-proxy`.
- Don't convert `app = _get_app` to `app = _get_app()`.
- Don't write tests or code that assume `./data/postern.db` or that `ss-*` containers persist across portal restarts.
- Don't change `OTP_EXPIRY_SECONDS` without also updating the `otp_email` cookie `max_age` in [routes/login.py](portal/src/postern/routes/login.py).
- Don't build the shadowsocks image with `docker build ./shadowsocks/` — the Dockerfile pulls from `external/` and needs the repo root as context.
- Don't add shell-form `RUN`, `CMD`, or `HEALTHCHECK` in the runtime stage of [portal/Dockerfile](portal/Dockerfile), and don't use `[CMD-SHELL ...]` for the portal in compose. The runtime is distroless. Use Python (`python -c '...'`) or move shell work to the build stage.

## Useful commands

```bash
# Build the per-connection tunnel image (compose doesn't build this one)
docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .

# Build and run the full stack
docker compose up -d --build

# Run the admin CLI
docker compose exec portal postern user list
docker compose exec portal postern user add "Name" email@example.com
docker compose exec portal postern connection add email@example.com "label"

# Manual reconcile trigger (bypasses the 60s poll)
docker compose exec portal postern reconcile

# Tail logs
docker compose logs -f portal
docker compose logs -f nginx

# Tests
cd portal && uv run pytest

# Full prek run
prek run --all-files
```
