# Development

Postern is a small codebase and is easy to develop on locally. This page covers the contributor workflow: environment setup, running the stack, code style, and opening a PR. For how the pieces fit together, read [Architecture](architecture.md); for the unit and end-to-end suites, read [Testing](testing.md).

## Prerequisites

- [`uv`](https://docs.astral.sh/uv/) — manages Python and virtualenvs
- Python 3.13 — uv installs it for you
- Docker Engine + Docker Compose v2 — only if you want to run the full stack locally
- [`prek`](https://prek.j178.dev) — a drop-in, faster replacement for `pre-commit`, used for git hooks

The deployment-side prerequisites (TLS certificates, SMTP, Docker Hardened Images registry login) are only needed when running the full stack end-to-end. They are not required to write and test Python changes.

## Setup

```bash
cd portal
uv sync --all-extras         # installs runtime + dev deps into portal/.venv
cd ..
prek install                 # installs pre-commit and commit-msg hooks
```

## Running the stack locally

```bash
docker compose up --build
```

```{important}
Login requires HTTPS. Session cookies are set with `secure=True` ([routes/login.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/routes/login.py)), so a browser will not send them over plain HTTP and the login flow cannot complete without TLS.
```

Two realistic options for local testing:

- **Use [`mkcert`](https://github.com/FiloSottile/mkcert)** to generate a locally-trusted certificate for a hostname you control (e.g. `postern.localtest.me`). Nginx expects a Let's-Encrypt-style layout; put the files where the bind mount picks them up:

  ```bash
  sudo mkdir -p /etc/letsencrypt/live/postern.localtest.me
  cd /etc/letsencrypt/live/postern.localtest.me
  sudo mkcert -cert-file fullchain.pem -key-file privkey.pem postern.localtest.me
  sudo cp fullchain.pem chain.pem   # nginx reads chain.pem separately for OCSP
  ```

  Then point the stack at the new domain: set `DOMAIN=postern.localtest.me` in `.env`. Nginx renders its config from that variable at container start ([nginx/etc/nginx.conf.tmpl](https://github.com/bindreams/postern/blob/main/nginx/etc/nginx.conf.tmpl)); see [Configuration](../deployment/configuration.md).

- **Skip nginx and run the portal directly** if you only need non-auth flows (templates, dashboard rendering, reconciler work):

  ```bash
  cd portal
  SECRET_KEY=dev uv run uvicorn postern.app:PosternApp --factory --port 8000
  ```

  `--factory` tells uvicorn to call the target (`PosternApp`) once to produce the ASGI app, instead of treating the class itself as an ASGI callable. You cannot complete the OTP login end-to-end this way (session cookies need HTTPS).

The [admin CLI](../operations/cli.md) works regardless: `docker compose exec portal postern user list`.

### Built-in MTA

The `mta` and `provisioner` services are gated by the `with-mta` Compose profile, on by default via `COMPOSE_PROFILES=with-mta` in `example.env` (see [Email](../deployment/email.md)). For local development you have two options:

- **Comment out `COMPOSE_PROFILES=with-mta`** in `.env` and use a fake SMTP server for OTP testing. The simplest pattern matches the e2e suite: bring up [mailpit](https://github.com/axllent/mailpit) on the side, set `SMTP_HOST=mailpit`, and read OTPs from its HTTP UI at `:8025`. No DNS or certificate setup needed.

- **Bring up the real built-in MTA with `MTA_VERIFY_DNS=false`** and locally-trusted certificates for `mail.<dev-domain>` and `mta-sts.<dev-domain>`, extending the mkcert pattern above:

  ```bash
  for sub in '' 'mail.' 'mta-sts.'; do
    sudo mkdir -p /etc/letsencrypt/live/${sub}postern.localtest.me
    cd /etc/letsencrypt/live/${sub}postern.localtest.me
    sudo mkcert -cert-file fullchain.pem -key-file privkey.pem ${sub}postern.localtest.me
    sudo cp fullchain.pem chain.pem
  done
  ```

  Set `MTA_VERIFY_DNS=false`, `MTA_REQUIRE_DNSSEC=false`, `DNS_PROVIDER=none`, `MTA_ADMIN_EMAIL=admin@elsewhere.example` in `.env`. (`MTA_REQUIRE_DNSSEC=auto` would resolve to `false` for the unsigned `postern.localtest.me` anyway, but `false` is explicit and skips the probe entirely.) The provisioner generates the initial DKIM key and exits; the mta starts but cannot deliver mail to the public internet (rDNS, SPF, etc. are unset). Useful for testing the bring-up path of the MTA itself, not for actually sending OTPs.

## Code style

Prek enforces everything; run `prek install` once and let the hooks do the work. The hooks, as configured in [prek.toml](https://github.com/bindreams/postern/blob/main/prek.toml):

- **yapf** — Python formatter.
- **ty** — type checker (Astral's pyright-compatible checker), run through uv against the `portal/` project.
- **format-section-comments** — [scripts/format-section-comments.py](https://github.com/bindreams/postern/blob/main/scripts/format-section-comments.py) aligns the section-comment convention: `# <name> =====` for primary sections, `# <name> -----` for subsections.
- **mdformat** — normalizes Markdown, as two hooks with separate plugin environments: `mdformat-gfm` (GitHub-Flavored Markdown) for files outside `docs/`, and `mdformat-myst` for `docs/`. Documentation directives use backtick fences exclusively; the formatter escapes colon fences. mdformat WILL reformat `.md` files — commit the reformatted output rather than fight the tool.
- **shellcheck**, **editorconfig-checker**, **mixed-line-ending**, **check-executables-have-shebangs**, **check-shebang-scripts-are-executable** — script and file hygiene.

To run every hook on the whole tree:

```bash
prek run --all-files
```

## Commit messages

Commit subjects follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/): `type(scope): subject`.

- Allowed types: `feat`, `fix`, `refactor`, `chore`, `ci`, `docs`, `test`, `build`, `perf`.
- Scope is optional but encouraged (e.g. `cli`, `portal`, `shadowsocks`, `nginx`, `deps`).
- The subject stays single-line and uses the imperative mood ("add X", "fix Y"). Everything after the first newline is reserved for tool-generated trailers (e.g. `Approved-By: …`), placed after a blank line.

## Working with vendored code

[external/](https://github.com/bindreams/postern/tree/main/external) is managed with [`git subrepo`](https://github.com/ingydotnet/git-subrepo), not submodules. [external/shadowsocks-rust](https://github.com/bindreams/postern/tree/main/external/shadowsocks-rust) is a pinned upstream copy:

```bash
# Pull upstream changes into the subrepo
git subrepo pull external/shadowsocks-rust

# Push back upstream (rare — usually only upstream maintainers need this)
git subrepo push external/shadowsocks-rust
```

The `v2ray-plugin` and `galoshes` binaries are NOT subrepos — they are downloaded as pre-built release assets from [bindreams/hole](https://github.com/bindreams/hole)'s `releases/ex-ray/v*` and `releases/galoshes/v*` tracks at image build time. The `v2ray-plugin` binary is **ex-ray**, a wire-compatible v2ray-core SIP003 shim installed under the historical name. Versions are pinned via `ARG EX_RAY_VERSION=` / `ARG GALOSHES_VERSION=` in [shadowsocks/Dockerfile](https://github.com/bindreams/postern/blob/main/shadowsocks/Dockerfile) and SHA256-verified against the release's `SHA256SUMS`; Renovate bumps both versions via custom managers in [.github/renovate.json](https://github.com/bindreams/postern/blob/main/.github/renovate.json).

The vendored directories are:

- Excluded from prek (`exclude = "^external/"` in [prek.toml](https://github.com/bindreams/postern/blob/main/prek.toml))
- Marked `linguist-vendored` in [.gitattributes](https://github.com/bindreams/postern/blob/main/.gitattributes), so they don't skew GitHub language stats
- Excluded from most project tooling

[subrepo-pull.yaml](https://github.com/bindreams/postern/blob/main/.github/workflows/subrepo-pull.yaml) automates subrepo pulls in response to Renovate PRs that bump the pinned refs — you generally won't need to run `git subrepo pull` by hand.

```{warning}
Never edit files under `external/` directly. Fixes to upstream code go upstream first, then flow back in via a subrepo pull.
```

## Opening a PR

Before pushing:

1. `cd portal && uv run pytest` — all tests pass.
1. `prek run --all-files` — clean.
1. `external/` unchanged, unless the PR is intentionally pulling a new upstream ref.
1. Commit messages follow the Conventional Commits convention above.

If your change touches anything under the "architecture invariants" list in [CLAUDE.md](https://github.com/bindreams/postern/blob/main/CLAUDE.md), explicitly call out why the invariant still holds (or why you updated all the linked locations together).

```{toctree}
---
maxdepth: 1
---
architecture.md
testing.md
```
