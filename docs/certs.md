# TLS certs

Postern supports two cert deployment modes.

## Mode 1: Bring-your-own (default)

The default `compose.yaml` bind-mounts the host's `/etc/letsencrypt` into both nginx (rw) and mta (ro). Operators provision Let's Encrypt certs externally — typically with `certbot certonly --standalone`.

```bash
certbot certonly --standalone \
    -d <domain> -d mail.<domain> -d mta-sts.<domain>
```

(A wildcard at `<domain>` + `*.<domain>` works too — see Mode 2.)

Renewal is the operator's responsibility (cron, systemd timer, etc.). Nginx self-reloads every 6 hours via the entrypoint background loop in [nginx/Dockerfile](../nginx/Dockerfile), picking up renewed certs without a restart.

## Mode 2: Auto-renewal via ACME DNS-01

The `provisioner` container can also obtain and renew a single wildcard cert covering `<domain>` and `*.<domain>` via ACME DNS-01. The wildcard SAN list intentionally hides subdomain enumeration from Certificate Transparency logs — only `<domain>` itself is publicly logged.

### Setup

In `.env`:

```
COMPOSE_FILE=compose.yaml:compose.cert.yaml
COMPOSE_PROFILES=with-mta,with-cert-renewal     # drop with-mta if no MTA
DNS_PROVIDER=cloudflare                          # or route53, gandi, etc.
CERT_RENEWAL=true
CERT_ACME_EMAIL=ops@<your-domain>
CLOUDFLARE_API_TOKEN=...                         # provider-specific creds
```

Then:

```bash
docker compose up -d --build
docker compose logs -f provisioner    # watch for INSTALLED transition
docker compose exec portal postern cert show
```

### What happens on first start

1. Provisioner starts, runs DKIM init, then enters the cert state machine: `NO_CERT → ISSUING`.
2. Lego runs DNS-01 — talks to the DNS provider directly (no nginx required).
3. Cert files written via symlink-flip to `/etc/letsencrypt/live/<domain>/`. State → `INSTALLED`. Healthcheck flips healthy.
4. nginx and mta start (they were waiting on `depends_on: condition: service_healthy`).
5. The provisioner ticks every 60 minutes thereafter; renews when `not_after - now < 30 days` (configurable via `CERT_RENEWAL_DAYS_BEFORE_EXPIRY`).

### Test against LE staging first

```bash
echo CERT_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory >> .env
docker compose up -d --build
docker compose exec portal postern cert show
# Expect: issuer "(STAGING) Pretend Pear X1" or similar
```

When happy, remove the `CERT_ACME_DIRECTORY` line. The state machine detects directory drift in `state.json`, transitions `INSTALLED → RENEWING`, and gets a real cert.

### CLI commands

```bash
docker compose exec portal postern cert show             # path, issuer, expiry, SANs
docker compose exec portal postern cert verify           # 5-check verifier (parseable, exact-SAN, nginx-served, CAA, state.json)
docker compose exec portal postern cert renew            # force a renewal (writes the .renew-cert trigger)
docker compose exec portal postern cert renewal-status   # show the state machine
```

### Migrating from BYO certs

If you already have certs in `/etc/letsencrypt` on the host, the simplest path is to run with `compose.cert.yaml` from a clean install. The provisioner will issue a fresh wildcard cert against ACME — wasteful but unambiguous. If you want to keep the existing cert until the wildcard is ready, leave `compose.cert.yaml` out of `COMPOSE_FILE` until the auto-renewal stack is verified, then switch.

### State machine

```
NO_CERT  ──(adopt: existing on-disk cert with valid SANs)──▶  INSTALLED
NO_CERT  ──(no on-disk cert; or SAN mismatch)──▶  ISSUING
ISSUING  ──(lego success; record last_issued_iso)──▶  ISSUED_PENDING_INSTALL
ISSUED_PENDING_INSTALL  ──(symlink-flip success)──▶  INSTALLED
INSTALLED  ──(expiry / SAN mismatch / directory drift / .renew-cert)──▶  RENEWING
RENEWING   ──(success)──▶  ISSUED_PENDING_INSTALL
*  ──(consecutive_failures >= 6)──▶  FAILED
FAILED  ──(60-min hold-off)──▶  prior pre-FAILED state retried
```

`FAILED` is non-terminal; a transient outage longer than ~64 minutes self-heals.

### Rate-limit defences

Two layers protect Let's Encrypt's 5-issuances-per-7-days limit:

1. **24-hour guard** (`last_issued_iso` recorded BEFORE Lego call): refuses any new issuance within 24h regardless of state, even on partial-failure paths like a successful Lego run that fails to install.
2. **`CERT_FORCE_REISSUE=true` operator override**: one-shot bypass of the 24-hour guard, used after a cert revocation or compromise.

### Threat model notes

- The DNS provider API token lives **only** in the provisioner container (zero inbound listeners). A Postfix RCE on port 25 cannot escalate to DNS-record hijack.
- The wildcard SAN list is exactly `[<domain>, *.<domain>]`. Adding subdomain SANs leaks them to CT logs and is rejected by `postern cert verify`.
- `os.replace` on a non-empty directory is **not** atomic; the install path uses symlink-flip (atomic on Linux).
- Lego account keys live at `/etc/letsencrypt/lego/accounts/`. Account-key rotation is out of scope for v1; delete the directory if you need to rotate.
