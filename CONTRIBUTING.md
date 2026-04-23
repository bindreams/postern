# Contributing

Voyager is a small codebase and is easy to develop on locally. Read [README.md](README.md) first to understand what the project does and how it deploys; this document covers the contributor workflow only.

## Prerequisites

- [`uv`](https://docs.astral.sh/uv/) (manages Python and virtualenvs)
- Python 3.13 (uv will install it for you)
- Docker Engine + Docker Compose v2 — only if you want to run the full stack locally
- [`prek`](https://prek.j178.dev) (for hooks; a drop-in, faster replacement for `pre-commit`)

The deployment-side prerequisites (Let's Encrypt certs, SMTP, Chainguard registry) are only needed when running the full stack end-to-end. They are not required to write and test Python changes.

## Setup

```bash
cd portal
uv sync --all-extras         # installs runtime + dev deps into portal/.venv
cd ..
prek install                 # installs pre-commit and commit-msg hook types (default_install_hook_types)
```

## Running tests

There are two test layers. Unit tests (default) are mock-based and run anywhere. End-to-end tests boot the real compose stack and require Linux + docker.

### Unit tests

```bash
cd portal
uv run pytest -m "not e2e"                         # full unit suite (default if you skip the marker)
uv run pytest tests/test_db.py                     # single file
uv run pytest tests/test_db.py::test_create_user   # single test
```

Tests use a temporary SQLite file (`tmp_path` fixture in [tests/conftest.py](portal/tests/conftest.py)) and mock the Docker client where needed, so they do NOT require a running Docker daemon. `asyncio_mode = "auto"` is set in `pyproject.toml`, so `async def test_...` functions need no `@pytest.mark.asyncio` marker.

### End-to-end tests

The e2e suite under [portal/tests/e2e/](portal/tests/e2e/) brings up the real stack (portal + nginx + docker-proxy + mailpit + go-httpbin + ssclient) in an isolated `voyager-e2e` compose project, drives the full OTP login flow against HTTPS, and proves a TCP byte round-trips through a reconciler-spawned `ss-*` container. It is opt-in:

```bash
cd portal
uv sync --group e2e
uv run pytest -m e2e -v
```

**Prerequisites (all required, all one-time):**

- **Linux + docker.** Same constraint as the production stack. WSL2 works.
- **`/etc/hosts`** must map `voyager.test` to localhost so the host-side pytest client resolves the test domain to the nginx container's exposed port:
  ```bash
  echo "127.0.0.1 voyager.test" | sudo tee -a /etc/hosts
  ```
- **DHI auth.** Same prerequisite as building any production image. `docker login dhi.io` with a Docker Hub PAT on an org with the Docker Hardened Images entitlement.
- **`local/shadowsocks-server` image** must exist before the suite starts. Build it from the repo root:
  ```bash
  docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .
  ```

The session fixture builds the other images (`local/voyager-portal`, `local/nginx`, `local/voyager-ssclient`) automatically via `docker compose up --build`.

**Test certs.** The e2e stack uses a self-signed CA + leaf for `voyager.test` committed under [portal/tests/e2e/certs/](portal/tests/e2e/certs/). To regenerate (1-year validity):

```bash
bash portal/tests/e2e/certs/regen.sh
```

Tests trust the committed CA via `httpx(verify=...)` for the host-side client and via `update-ca-certificates` baked into the ssclient image.

## Running the stack locally

```bash
docker compose up --build
```

**Heads-up: login requires HTTPS.** Session cookies are set with `secure=True` ([portal/src/voyager/routes/login.py](portal/src/voyager/routes/login.py)), so a browser will not send them over plain HTTP and the login flow cannot complete without TLS.

For local testing, you have two realistic options:

- **Use [`mkcert`](https://github.com/FiloSottile/mkcert)** to generate a locally-trusted cert for a hostname you control (e.g. `voyager.localtest.me`). Nginx expects Let's-Encrypt-style layout; put the files where the bind mount picks them up:

  ```bash
  sudo mkdir -p /etc/letsencrypt/live/voyager.localtest.me
  cd /etc/letsencrypt/live/voyager.localtest.me
  sudo mkcert -cert-file fullchain.pem -key-file privkey.pem voyager.localtest.me
  sudo cp fullchain.pem chain.pem   # nginx reads chain.pem separately for OCSP
  ```

  Then edit [nginx/etc/nginx.conf](nginx/etc/nginx.conf) and [nginx/etc/conf.d/certs/](nginx/etc/conf.d/certs/) to point at the new domain (see README §"Re-hosting").

- **Skip Nginx and run the portal directly** if you only need to exercise non-auth flows (templates, dashboard rendering, reconciler unit tests):

  ```bash
  cd portal
  SECRET_KEY=dev uv run uvicorn voyager.app:app --factory --port 8000
  ```

  `--factory` is required — `voyager.app:app` is a callable factory, not a `FastAPI` instance. You cannot complete the OTP login end-to-end this way (session cookies need HTTPS).

The admin CLI works regardless: `docker compose exec portal voyager user list`.

## Code style

Prek (a Rust-based drop-in replacement for `pre-commit`) enforces everything; just run `prek install` once and let the hooks do the work. In detail:

- **yapf** — formatter.
- **ty** — type checker (Astral's pyright-compatible checker), run as `uvx ty check`.
- **format-section-comments** — [scripts/format-section-comments.py](scripts/format-section-comments.py) aligns the project's section-comment convention: `# <name> =====` for primary sections, `# <name> -----` for subsections.
- **mdformat** — normalizes Markdown; it WILL reflow new .md files. Commit the reflowed output rather than fight the tool.
- **editorconfig-checker**, **mixed-line-ending**, **check-executables-have-shebangs**, **check-shebang-scripts-are-executable** — file hygiene.

To run every hook on the whole tree:

```bash
prek run --all-files
```

## Commit messages

- **Single line.** Everything after the first `\n` is reserved for tool-generated trailers (e.g. `Approved-By: …`).
- Use the imperative mood: "add X", "fix Y", "update Z".

## Working with vendored code

[external/shadowsocks-rust](external/shadowsocks-rust) and [external/v2ray-plugin](external/v2ray-plugin) are pinned upstream copies, managed with [`git subrepo`](https://github.com/ingydotnet/git-subrepo) (not submodules):

```bash
# Pull upstream changes into a subrepo
git subrepo pull external/shadowsocks-rust
git subrepo pull external/v2ray-plugin

# Push back upstream (rare — usually only upstream maintainers need this)
git subrepo push external/<name>
```

These directories are:

- Excluded from prek (`exclude = "^external/"` in [prek.toml](prek.toml))
- Marked `linguist-vendored` in [.gitattributes](.gitattributes) (so they don't skew GitHub language stats)
- Excluded from most project tooling

[.github/workflows/subrepo-pull.yml](.github/workflows/subrepo-pull.yml) automates subrepo pulls in response to Renovate PRs that bump the pinned refs — you generally won't need to run `git subrepo pull` by hand.

**Do not edit files under `external/` directly.** Fixes to upstream code go upstream first, then flow back in via a subrepo pull.

## Opening a PR

Before pushing:

1. `cd portal && uv run pytest` — all tests pass.
1. `prek run --all-files` — clean.
1. `external/` unchanged, unless the PR is intentionally pulling a new upstream ref.
1. Commit messages are single-line and describe the change, not the process.

If your change touches anything under the "architecture invariants" list in [CLAUDE.md](CLAUDE.md), explicitly call out why the invariant still holds (or why you updated all the linked locations together).
