# Contributing

Postern is a small codebase and is easy to develop on locally. Read [README.md](README.md) first to understand what the project does and how it deploys; this document covers the contributor workflow only.

## Prerequisites

- [`uv`](https://docs.astral.sh/uv/) (manages Python and virtualenvs)
- Python 3.13 (uv will install it for you)
- Docker Engine + Docker Compose v2 — only if you want to run the full stack locally
- [`prek`](https://prek.j178.dev) (for hooks; a drop-in, faster replacement for `pre-commit`)

The deployment-side prerequisites (Let's Encrypt certs, SMTP, Docker Hardened Images registry) are only needed when running the full stack end-to-end. They are not required to write and test Python changes.

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

The e2e suite under [portal/tests/e2e/](portal/tests/e2e/) brings up the real stack (portal + nginx + docker-proxy + mailpit + go-httpbin + ssclient) in an isolated `postern-e2e` compose project, drives the full OTP login flow against HTTPS, and proves a TCP byte round-trips through a reconciler-spawned `ss-*` container. It is opt-in:

```bash
cd portal
uv sync --group e2e
uv run pytest -m e2e -v
```

**Prerequisites (all required, all one-time):**

- **Linux + docker.** Same constraint as the production stack. WSL2 works.
- **`/etc/hosts`** must map `postern.test` to localhost so the host-side pytest client resolves the test domain to the nginx container's exposed port:
  ```bash
  echo "127.0.0.1 postern.test" | sudo tee -a /etc/hosts
  ```
- **DHI auth.** Same prerequisite as building any production image. `docker login dhi.io` with a Docker Hub PAT (any free Docker Hub account works; the DHI catalog is free under Apache 2.0).

  Renovate (Mend Cloud App) authenticates to `dhi.io` independently of GitHub Actions. Credentials live in the Mend UI at [developer.mend.io](https://developer.mend.io) under the repo's Credentials section, as `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` — referenced from [.github/renovate.json](.github/renovate.json) via `{{ secrets.NAME }}`. Rotating the Docker Hub PAT requires updating GitHub Actions secrets and Mend Credentials together.

- **`local/shadowsocks-server` image** must exist before the suite starts. Build it from the repo root:
  ```bash
  docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .
  ```
- **Compose images** (`local/postern-portal`, `local/nginx`, `local/postern-ssclient`) must also exist before the suite starts. The session fixture only does `compose up --wait` so the build is not subject to the per-test timeout. Build them once from the repo root:
  ```bash
  docker compose -p postern-e2e -f portal/tests/e2e/e2e.compose.yaml build
  ```

**Test certs** are generated at session start by the `e2e_certs` fixture (Ed25519 self-signed CA + leaf, 30-day validity). The fixture writes them under pytest's tmp dir and exposes the path via `POSTERN_E2E_TLS_DIR` for compose to interpolate into volume mounts. No manual setup or yearly regeneration.

If you need to bring the stack up by hand outside pytest, set `POSTERN_E2E_TLS_DIR` first — any compose command other than `build`/`logs` will refuse without it. Quickest path from inside `portal/`:

```bash
POSTERN_E2E_TLS_DIR=$(uv run python tests/e2e/_certs.py /tmp/postern-e2e-tls) \
  docker compose -p postern-e2e -f tests/e2e/e2e.compose.yaml up -d --build --wait
```

## Running the stack locally

```bash
docker compose up --build
```

**Heads-up: login requires HTTPS.** Session cookies are set with `secure=True` ([portal/src/postern/routes/login.py](portal/src/postern/routes/login.py)), so a browser will not send them over plain HTTP and the login flow cannot complete without TLS.

For local testing, you have two realistic options:

- **Use [`mkcert`](https://github.com/FiloSottile/mkcert)** to generate a locally-trusted cert for a hostname you control (e.g. `postern.localtest.me`). Nginx expects Let's-Encrypt-style layout; put the files where the bind mount picks them up:

  ```bash
  sudo mkdir -p /etc/letsencrypt/live/postern.localtest.me
  cd /etc/letsencrypt/live/postern.localtest.me
  sudo mkcert -cert-file fullchain.pem -key-file privkey.pem postern.localtest.me
  sudo cp fullchain.pem chain.pem   # nginx reads chain.pem separately for OCSP
  ```

  Then edit [nginx/etc/nginx.conf](nginx/etc/nginx.conf) and [nginx/etc/conf.d/certs/](nginx/etc/conf.d/certs/) to point at the new domain (see README §"Re-hosting").

- **Skip Nginx and run the portal directly** if you only need to exercise non-auth flows (templates, dashboard rendering, reconciler unit tests):

  ```bash
  cd portal
  SECRET_KEY=dev uv run uvicorn postern.app:PosternApp --factory --port 8000
  ```

  `--factory` tells uvicorn to call the target (`PosternApp`) once to produce the ASGI app, instead of treating the class itself as an ASGI callable. You cannot complete the OTP login end-to-end this way (session cookies need HTTPS).

The admin CLI works regardless: `docker compose exec portal postern user list`.

## Code style

Prek (a Rust-based drop-in replacement for `pre-commit`) enforces everything; just run `prek install` once and let the hooks do the work. In detail:

- **yapf** — formatter.
- **ty** — type checker (Astral's pyright-compatible checker), run as `uvx ty check`.
- **format-section-comments** — [scripts/format-section-comments.py](scripts/format-section-comments.py) aligns the project's section-comment convention: `# <name> =====` for primary sections, `# <name> -----` for subsections.
- **prettier** — normalizes Markdown; it WILL reflow new .md files. Commit the reflowed output rather than fight the tool.
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

[.github/workflows/subrepo-pull.yaml](.github/workflows/subrepo-pull.yaml) automates subrepo pulls in response to Renovate PRs that bump the pinned refs — you generally won't need to run `git subrepo pull` by hand.

**Do not edit files under `external/` directly.** Fixes to upstream code go upstream first, then flow back in via a subrepo pull.

## Opening a PR

Before pushing:

1. `cd portal && uv run pytest` — all tests pass.
1. `prek run --all-files` — clean.
1. `external/` unchanged, unless the PR is intentionally pulling a new upstream ref.
1. Commit messages are single-line and describe the change, not the process.

If your change touches anything under the "architecture invariants" list in [CLAUDE.md](CLAUDE.md), explicitly call out why the invariant still holds (or why you updated all the linked locations together).
