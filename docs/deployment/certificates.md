# TLS certificates

Postern supports two certificate deployment modes: bring your own certs (the default), or automatic issuance and renewal via ACME DNS-01.

## Mode 1: bring your own (default)

The base `compose.yaml` bind-mounts the host's `/etc/letsencrypt` into nginx (read-write) and mta (read-only). You provision Let's Encrypt certs externally — typically:

```bash
certbot certonly --standalone \
    -d <domain> -d mail.<domain> -d mta-sts.<domain>
```

A wildcard covering `<domain>` + `*.<domain>` works too — see mode 2 for why you might prefer one.

Renewal is your responsibility (cron, systemd timer, etc.). Nginx self-reloads every 6 hours via a background loop in its entrypoint ([nginx/Dockerfile](https://github.com/bindreams/postern/blob/main/nginx/Dockerfile)), picking up renewed certs without a restart.

## Mode 2: auto-renewal via ACME DNS-01

With the [compose.cert.yaml](https://github.com/bindreams/postern/blob/main/compose.cert.yaml) overlay, the `provisioner` container obtains and renews a single wildcard cert covering `<domain>` and `*.<domain>`. One cert serves the portal, the MTA-STS subdomain, and Postfix on `mail.<domain>`. The wildcard SAN list intentionally hides subdomain enumeration from Certificate Transparency logs — only `<domain>` itself is publicly logged.

DNS-01 talks to the DNS provider's API directly, so issuance does not depend on nginx being up. The same `DNS_PROVIDER` credentials also drive DKIM rotation — see [email](email.md).

```{warning}
Never run a host-side certbot (or any other ACME client) while `compose.cert.yaml` is active — two writers on the same cert paths will fight. Under this overlay, certs live in the `postern-letsencrypt` named volume written only by the provisioner; the host `/etc/letsencrypt` bind-mount is replaced.
```

### Setup

In `.env` (see [configuration](configuration.md) for the full reference):

```
COMPOSE_FILE=compose.yaml:compose.cert.yaml
COMPOSE_PROFILES=with-mta,with-cert-renewal     # drop with-mta if no built-in MTA
DNS_PROVIDER=cloudflare                          # or route53, gandi, etc.
CERT_RENEWAL=true
CERT_ACME_EMAIL=ops@example.com
PUBLIC_IPV4=203.0.113.10
CLOUDFLARE_API_TOKEN=...                         # provider-specific creds
```

- Profiles must be set in `.env` — a CLI-only `docker compose --profile` flag is not visible to the provisioner container.
- `CERT_ACME_EMAIL` is required when `CERT_RENEWAL=true`; Let's Encrypt sends expiry warnings there.
- `PUBLIC_IPV4` is required whenever the provisioner manages DNS (it publishes apex A/AAAA records); the provisioner refuses to start without it. `PUBLIC_IPV6` is optional — if previously set and now unset, AAAA records are deleted (delete-on-unset, no stale-IP foot-gun).

Then:

```bash
docker compose up -d --build
docker compose logs -f provisioner    # watch for the INSTALLED transition
docker compose exec portal postern cert show
```

### What happens on first start

1. The provisioner starts, runs DKIM init, then enters the cert state machine: `NO_CERT → ISSUING`.
1. Lego runs DNS-01 — it talks to the DNS provider directly (no nginx required).
1. Cert files are written via symlink-flip to `/etc/letsencrypt/live/<domain>/`. State → `INSTALLED`; the healthcheck flips healthy.
1. nginx and mta start (they were waiting on `depends_on: condition: service_healthy`).
1. The provisioner ticks every 60 minutes thereafter; it renews when `not_after - now < 30 days` (`CERT_RENEWAL_DAYS_BEFORE_EXPIRY` — must stay shorter than cert validity, currently 90 days for LE).

````{tip}
Test against the Let's Encrypt staging directory first — rate limits are relaxed and mistakes are cheap (the certs are untrusted):

```bash
echo CERT_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory >> .env
docker compose up -d --build
docker compose exec portal postern cert show
# Expect: issuer "(STAGING) Pretend Pear X1" or similar
```

When happy, remove the `CERT_ACME_DIRECTORY` line. The state machine detects directory drift in `state.json`, transitions `INSTALLED → RENEWING`, and gets a real cert.
````

### CLI commands

```bash
docker compose exec portal postern cert show             # path, issuer, expiry, SANs
docker compose exec portal postern cert verify           # 5-check verifier (parseable, exact-SAN, nginx-served, CAA, state.json)
docker compose exec portal postern cert renew            # force a renewal (writes the .renew-cert trigger)
docker compose exec portal postern cert renewal-status   # show the state machine
```

### Migrating from BYO certs

If you already have certs in `/etc/letsencrypt` on the host, the simplest path is to run with `compose.cert.yaml` from a clean install: the provisioner issues a fresh wildcard against ACME — wasteful but unambiguous. To keep the existing cert until the wildcard is ready, leave `compose.cert.yaml` out of `COMPOSE_FILE` until the auto-renewal stack is verified, then switch.

### Rate-limit defences

Two layers protect Let's Encrypt's 5-issuances-per-7-days limit:

1. **24-hour guard** — `last_issued_iso` is recorded BEFORE calling Lego, so any new issuance within 24 hours is refused regardless of state, even on partial-failure paths (e.g. a successful Lego run that then fails to install).
1. **`CERT_FORCE_REISSUE=true`** — a one-shot bypass of the 24-hour guard, used after a cert revocation or compromise. Reset it to `false` after the next renewal.

````{dropdown} State machine detail

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

`FAILED` is non-terminal: after the 60-min hold-off the prior pre-FAILED state is retried, so a transient outage longer than ~64 minutes self-heals. State is persisted at `/etc/letsencrypt/state.json`.
````

### Threat-model notes

- The DNS provider API token lives **only** in the provisioner container (zero inbound listeners). A Postfix RCE on port 25 cannot escalate to DNS-record hijack.
- The wildcard SAN list is exactly `{<domain>, *.<domain>}`, nothing else. Adding subdomain SANs leaks them to CT logs and is rejected by `postern cert verify`.
- `os.replace` on a non-empty directory is **not** atomic; the install path uses symlink-flip (atomic on Linux).
- Lego account keys live at `/etc/letsencrypt/lego/accounts/`. Account-key rotation is out of scope for v1; delete the directory if you need to rotate.
