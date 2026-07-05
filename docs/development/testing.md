# Testing

Postern's tests are layered: mock-based unit tests that run anywhere, hermetic end-to-end suites that boot the real compose stack, and maintainer-only suites that touch real DNS and real port 25. Every layer except the default unit suite is opt-in via a pytest marker; the marker names in [portal/pyproject.toml](https://github.com/bindreams/postern/blob/main/portal/pyproject.toml) are the source of truth. CI jobs live in [.github/workflows/test.yaml](https://github.com/bindreams/postern/blob/main/.github/workflows/test.yaml).

```{list-table}
---
header-rows: 1
widths: 16 32 28 24
---
- * Suite
  * What it proves
  * Requirements
  * Where it runs
- * Unit (no marker)
  * Portal logic against a mocked Docker client and temporary SQLite; docs content gates
  * `uv` only — no Docker daemon
  * `unit` CI job, every PR
- * `e2e`
  * Full OTP login over HTTPS + a TCP byte round-trip through a reconciler-spawned tunnel container
  * Linux + Docker, pre-built images, `dhi.io` login
  * `e2e` CI job
- * `e2e_edge`
  * Fail-closed real-IP recovery and origin-pull mTLS under `EDGE_PROFILE=cloudflare`
  * Same as `e2e`; no Cloudflare account
  * `e2e-edge` CI job
- * `e2e_mta`
  * DKIM signing/verification, postmaster forwarding, milter tempfail — against the production `mta` + `provisioner` images
  * Same as `e2e`; no real DNS, no port 25
  * `e2e-mta` CI job
- * `e2e_mta_real`
  * libdns TXT round-trip and the DNSSEC AD-bit oracle, against real infrastructure
  * A domain you control + DNS provider credentials
  * `e2e-mta-real` CI job (maintainer secrets), or manually
- * `e2e_mta_outbound`
  * Real port-25 OTP delivery to an IMAP-polled mailbox
  * A VPS with unblocked outbound 25, test domain, recipient mailbox
  * Manual, VPS only
- * Go unit
  * `postern-dns` wrapper logic against a self-authored Cloudflare fake
  * Go toolchain
  * `go-unit` CI job
- * `cfcontract` (Go build tag)
  * The one live-API assumption behind `--proxied` support (error 81058 keying)
  * Cloudflare token + a maintainer-owned test zone
  * Manual dispatch of [cf-contract.yaml](https://github.com/bindreams/postern/blob/main/.github/workflows/cf-contract.yaml)
```

## Unit tests

```bash
cd portal
uv run pytest -m "not e2e"                         # unit suite
uv run pytest tests/test_db.py                     # single file
uv run pytest tests/test_db.py::test_create_user   # single test
```

Conventions:

- SQLite lives in a temporary file (`tmp_path` fixture); tests never touch a real `/data/postern.db`.
- The Docker client is mocked where needed, so no Docker daemon is required.
- `asyncio_mode = "auto"` is set in `pyproject.toml`; `async def test_...` functions need no `@pytest.mark.asyncio` marker.
- The CI `unit` job deselects every e2e marker explicitly.

The unit suite also includes content gates in [portal/tests/test_docs.py](https://github.com/bindreams/postern/blob/main/portal/tests/test_docs.py) that bind this documentation to the code it describes:

- **CLI inventory** — [the CLI reference](../operations/cli.md) must document every `postern` command exactly once.
- **Settings coverage and defaults** — every settings field must appear in [the configuration reference](../deployment/configuration.md), with no stale rows, and each documented default must byte-match `settings.py`.
- **GitHub link paths** — every repository source link must use the `blob`/`tree`-at-`main` shape, point at a path that exists, and carry no line anchors.
- **Caveat tripwires** — distinctive phrases from load-bearing caveats must remain on their pages (some are also cross-checked against the source file that owns the literal), so a deleted warning fails the build instead of rotting silently.

## End-to-end tests

The base `e2e` suite under [portal/tests/e2e/](https://github.com/bindreams/postern/tree/main/portal/tests/e2e) brings up the real stack (portal + nginx + docker-proxy + mailpit + go-httpbin + ssclient) in an isolated `postern-e2e` compose project, drives the full OTP login flow over HTTPS, and proves a TCP byte round-trips through a reconciler-spawned `ss-*` container.

```bash
cd portal
uv sync --group e2e
uv run pytest -m e2e -v
```

One-time prerequisites, all required:

- **Linux + Docker.** Same constraint as the production stack; WSL2 works.

- **`/etc/hosts` entry** mapping `postern.test` to localhost, so the host-side pytest client resolves the test domain to the nginx container's exposed port:

  ```bash
  echo "127.0.0.1 postern.test" | sudo tee -a /etc/hosts
  ```

- **Registry login:** `docker login dhi.io` with a Docker Hub PAT (any free Docker Hub account works; the DHI catalog is free under Apache 2.0).

  ```{dropdown} Renovate credentials for dhi.io
  Renovate (Mend Cloud App) authenticates to `dhi.io` independently of GitHub Actions. Credentials live in the Mend UI at [developer.mend.io](https://developer.mend.io) under the repo's Credentials section, as `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. Rotating the Docker Hub PAT requires updating GitHub Actions secrets and Mend credentials together.
  ```

- **The `local/shadowsocks-server` image** must exist before the suite starts (compose does not build it). From the repo root:

  ```bash
  docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .
  ```

- **The compose images** (`local/postern-portal`, `local/nginx`, `local/postern-ssclient`) must also exist beforehand — the session fixture only runs `compose up --wait`, keeping the build out of the per-test timeout. From the repo root:

  ```bash
  docker compose -p postern-e2e -f portal/tests/e2e/e2e.compose.yaml build
  ```

Test certificates need no manual setup: the `e2e_certs` fixture generates an Ed25519 self-signed CA + leaf (30-day validity) at session start, writes them under pytest's tmp dir, and exposes the path via `POSTERN_E2E_TLS_DIR` for compose to interpolate into volume mounts.

To bring the stack up by hand outside pytest, set `POSTERN_E2E_TLS_DIR` first — any compose command other than `build`/`logs` refuses without it. From inside `portal/`:

```bash
POSTERN_E2E_TLS_DIR=$(uv run python tests/e2e/_certs.py /tmp/postern-e2e-tls) \
  docker compose -p postern-e2e -f tests/e2e/e2e.compose.yaml up -d --build --wait
```

## Edge suite (`e2e_edge`)

Boots a real nginx with `EDGE_PROFILE=cloudflare` (see [Edge fronting](../deployment/edge.md)) and asserts the two load-bearing edge behaviors end-to-end: fail-closed real-IP recovery (`CF-Connecting-IP` is honored only after a ranges file is seeded) and origin-pull mTLS enforcement (a locally generated throwaway client CA stands in for Cloudflare's — no Cloudflare account needed).

```bash
cd portal
uv sync --group e2e
uv run pytest -m e2e_edge -v --timeout=180
```

The compose project is `postern-e2e-edge` and nginx publishes on `127.0.0.1:8453`, so the suite can run alongside the base `postern-e2e` stack. Both TLS fixtures (`POSTERN_E2E_TLS_DIR` server certs and `POSTERN_E2E_EDGE_CLIENT_CA_DIR` client CA) are generated by pytest — no manual setup.

## Hermetic MTA suite (`e2e_mta`)

Boots the production `mta` + `provisioner` images alongside a mailpit "recipient MTA" — no real DNS, no port-25 outbound. It verifies DKIM signing + verification, postmaster forwarding, milter tempfail behavior, and a handful of architectural invariants (opendkim UID/GID, internal-network flag, Postfix listener health).

```bash
cd portal
uv sync --group e2e
uv run pytest -m e2e_mta -v --timeout=180
```

```{note}
The compose project is `postern-e2e-mta` (separate from `postern-e2e`), but both projects publish nginx on `127.0.0.1:8443` and mailpit on `127.0.0.1:8025` — only one project can be up at a time on the same host.
```

Manual bring-up, from inside `portal/`:

```bash
POSTERN_E2E_TLS_DIR=$(uv run python tests/e2e/_certs.py /tmp/postern-e2e-mta-tls) \
  docker compose -p postern-e2e-mta \
    -f tests/e2e/e2e.compose.yaml \
    -f tests/e2e/e2e-mta.compose.yaml \
    up -d --build --wait
```

```{tip}
The hermetic suite doubles as a working reference for `MTA_VERIFY_DNS=false` + `DNS_PROVIDER=none` deployments of the [built-in MTA](../deployment/email.md).
```

## Real-infrastructure MTA suite (`e2e_mta_real`)

Maintainer-only. [portal/tests/e2e/test_mta_real.py](https://github.com/bindreams/postern/blob/main/portal/tests/e2e/test_mta_real.py) covers the two boundaries the hermetic suite cannot exercise:

1. **libdns round-trip** (`test_libdns_provider_round_trip`) — the provisioner's Go binary actually publishes and retires a TXT record via the configured provider, and the change becomes visible via public resolvers. Pins the libdns wrapper against API breakage.
1. **DNSSEC AD-bit detection** (`test_dnssec_status_detects_signed_domain`) — the DNSSEC checker returns clean against a known-signed zone (default `iana.org`).

End-to-end DNS verification against fully-configured baseline records (MX/SPF/DMARC/MTA-STS/TLS-RPT plus a publicly-trusted MTA-STS HTTPS endpoint) is intentionally **not** in this tier — that much zone setup is incompatible with a CI job that runs on every PR. The full pipeline is exercised by the `e2e_mta_outbound` suite below.

You need a domain you control plus provider credentials. The test publishes and retires a single TXT record (`postern-e2e-test._domainkey.<domain>`); no other records are required and nothing else on the zone is touched.

| Variable                           | Notes                                                                                                                                                                                                                                                                                                             | Default    |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `MTA_TEST_DOMAIN`                  | A domain you control. Only the `postern-e2e-test._domainkey.<domain>` TXT is published/retired during the test.                                                                                                                                                                                                   | (required) |
| `MTA_TEST_DNS_PROVIDER`            | One of: `cloudflare`, `route53`, `gandi`, `digitalocean`, `ovh`, `hetzner`, `linode`, `namecheap`.                                                                                                                                                                                                                | (required) |
| Provider credentials               | Provider-native env: `CLOUDFLARE_API_TOKEN` for cloudflare; `AWS_REGION` + `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` for route53; `GANDI_API_TOKEN`; `DO_AUTH_TOKEN`; etc. Full mapping in [provisioner/postern-dns/main.go](https://github.com/bindreams/postern/blob/main/provisioner/postern-dns/main.go). | (required) |
| `MTA_TEST_DNS_PROPAGATION_SECONDS` | Wait between `txt-set` and the public-resolver query; raise for slow providers.                                                                                                                                                                                                                                   | `60`       |
| `MTA_TEST_DNSSEC_DOMAIN`           | The DNSSEC-status oracle for `test_dnssec_status_detects_signed_domain`.                                                                                                                                                                                                                                          | `iana.org` |

Run, from the repo root:

```bash
docker build -f provisioner/Dockerfile -t local/postern-provisioner .
cd portal
uv run pytest -m e2e_mta_real -v --timeout=300
```

In CI, the `e2e-mta-real` job runs on every PR and on push to main once the maintainer has populated the corresponding `vars.MTA_TEST_*` repository variables and provider secrets. Fork PRs see no secrets (GitHub default) and fail loud on the missing-env assertion — that is expected. The job has `concurrency: e2e-mta-real` so runs serialize on the shared `postern-e2e-test` DKIM selector instead of racing on publish/cleanup.

## Outbound MTA suite (`e2e_mta_outbound`)

VPS-only. [portal/tests/e2e/test_mta_outbound.py](https://github.com/bindreams/postern/blob/main/portal/tests/e2e/test_mta_outbound.py) does end-to-end OTP delivery through the real-mode mta over real outbound port 25 to a real recipient mailbox, polled via IMAP. It does not run on GitHub-hosted runners (port 25 is blocked there); run it on a VPS that allows outbound 25:

```bash
export MTA_TEST_DOMAIN=mta-test.example.com
export MTA_TEST_ADMIN_EMAIL=admin@something-else.example.com
export MTA_TEST_DNS_PROVIDER=cloudflare
export CLOUDFLARE_API_TOKEN=...
export MTA_TEST_RECIPIENT_EMAIL=test-mailbox@maintainer.example.com
export MTA_TEST_RECIPIENT_IMAP_HOST=imap.maintainer.example.com
export MTA_TEST_RECIPIENT_IMAP_USER=test-mailbox
export MTA_TEST_RECIPIENT_IMAP_PASS=...
export POSTERN_E2E_TLS_DIR=/etc/letsencrypt/live/${MTA_TEST_DOMAIN}
uv run pytest -m e2e_mta_outbound -v --timeout=600
```

## Cloudflare contract test (`cfcontract`)

The edge profile's `--proxied` support ([provisioner/postern-dns/cloudflare_proxied.go](https://github.com/bindreams/postern/blob/main/provisioner/postern-dns/cloudflare_proxied.go)) rests on one Cloudflare-API assumption: error 81058 ("identical record already exists") keys on `(zone, type, name, content)` and **excludes** `proxied`. The hermetic `go-unit` job only checks this against a self-authored fake coded to the same assumption; [provisioner/postern-dns/cloudflare_contract_test.go](https://github.com/bindreams/postern/blob/main/provisioner/postern-dns/cloudflare_contract_test.go) verifies it against a live Cloudflare zone.

It is gated behind the `cfcontract` build tag, so `go test ./...` never compiles it (the `go-unit` CI job does run `go vet -tags cfcontract` as a compile check, so refactors cannot bit-rot it silently). Run it manually:

```bash
cd provisioner/postern-dns
export CLOUDFLARE_API_TOKEN=...            # token scoped to the test zone
export CF_CONTRACT_TEST_ZONE=example.com   # a maintainer-owned test zone
go test -tags cfcontract -run TestCloudflareProxiedContract -count=1 -v ./...
```

The test creates records at unique per-run FQDNs (TEST-NET `192.0.2.x` / `2001:db8::` content) and deletes every one via `t.Cleanup`, even on failure. It also probes an open question — whether live Cloudflare normalizes equivalent IPv6 textual forms — and logs the answer on a `CONTRACT PROBE RESULT` line rather than hard-asserting it.

In CI, the manually-triggered [cf-contract.yaml](https://github.com/bindreams/postern/blob/main/.github/workflows/cf-contract.yaml) workflow (`workflow_dispatch`) runs it with `secrets.CLOUDFLARE_API_TOKEN` and `vars.CF_CONTRACT_TEST_ZONE`. Populate both before dispatching. Fork PRs cannot trigger `workflow_dispatch`, so the token is never exposed to untrusted code.

## Fail-loud policy

```{important}
Suites that need external resources (`e2e_mta_real`, `e2e_mta_outbound`, `cfcontract`) never skip silently when their environment is missing — each missing variable produces a failure message pointing back at this page. To exclude a suite, deselect its marker explicitly, e.g. `pytest -m "not e2e_mta_real"`.
```
