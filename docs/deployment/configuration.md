# Configuration reference

Settings live in `.env` at the repository root — copy [example.env](https://github.com/bindreams/postern/blob/main/example.env) and edit. The portal reads them via pydantic-settings, and environment names are case-insensitive: `SECRET_KEY` in `.env` is `settings.secret_key` in code. The authoritative list of names and defaults is [settings.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/settings.py). `COMPOSE_FILE` and `COMPOSE_PROFILES` are consumed by docker compose itself, not the portal; `PROXY_PROTOCOL_FROM` is interpolated into the nginx service by compose.

## Core

Server secret, database, domain, and branding. Branding and GeoIP setup is covered in [customization](customization.md).

| Variable            | Default               | Description                                                                                                                                                                                                 |
| ------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SECRET_KEY`        | *(required)*          | Server secret. The portal refuses to start without it, or if it is left as the `example.env` placeholder. Generate with `python -c "import secrets; print(secrets.token_hex(32))"`.                         |
| `DATABASE_PATH`     | `/data/postern.db`    | SQLite path inside the portal container, on the `postern-data` named volume.                                                                                                                                |
| `DOMAIN`            | `postern.example.com` | Public domain. Used in client configs, server `plugin_opts`, and nginx template rendering. See [Changing the domain](#changing-the-domain).                                                                 |
| `PRODUCT_NAME`      | `Postern`             | Cosmetic display name: UI page titles, OTP-email subject, config-download filename prefix. Decoupled from `DOMAIN` and from `MTA_DKIM_SELECTOR_PREFIX`.                                                     |
| `PRODUCT_ICON_PATH` | `""`                  | Absolute in-container path to a custom brand icon (SVG preferred, PNG accepted; up to 256 KB). Served via `/brand-icon`, which falls back to the built-in icon on any error. Empty means the built-in icon. |
| `GEOIP_DB_DIR`      | `""`                  | Directory containing `GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb`; enables country/city/ISP/ASN on the login-page identity card. Empty renders the card with the IP address only.                             |

## Email and SMTP

Where OTP emails are submitted. With the built-in MTA (`with-mta` profile) keep the defaults; for a third-party relay see [email](email.md).

| Variable        | Default               | Description                                                                                                                                                                                                       |
| --------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SMTP_HOST`     | `localhost`           | Outbound SMTP server. `example.env` sets `mta-submit` — the built-in MTA's internal network alias. Do not point it at the bare `mta` name: that resolves to the wrong network and Postfix rejects the submission. |
| `SMTP_PORT`     | `465`                 | TLS mode is port-derived: `465` means implicit TLS, `587` means STARTTLS, any other port means plaintext.                                                                                                         |
| `SMTP_USER`     | `""`                  | SMTP auth username.                                                                                                                                                                                               |
| `SMTP_PASSWORD` | `""`                  | SMTP auth password.                                                                                                                                                                                               |
| `SMTP_FROM`     | `noreply@example.com` | `From:` header for OTP emails.                                                                                                                                                                                    |

## Login and sessions

One-time-password and browser-session lifetimes.

| Variable                      | Default | Description                                            |
| ----------------------------- | ------- | ------------------------------------------------------ |
| `OTP_EXPIRY_SECONDS`          | `600`   | OTP lifetime in the database.                          |
| `OTP_MAX_ATTEMPTS`            | `5`     | Wrong-code attempts before the OTP is invalidated.     |
| `OTP_MAX_REQUESTS_PER_WINDOW` | `3`     | Maximum OTP requests per email within the rate window. |
| `OTP_RATE_WINDOW_SECONDS`     | `900`   | OTP rate-limit window.                                 |
| `SESSION_EXPIRY_DAYS`         | `7`     | Browser session lifetime.                              |

```{warning}
`OTP_EXPIRY_SECONDS` controls the code's DB lifetime, but the `otp_email` cookie `max_age` is hardcoded to 900 seconds in the login route. Changing one without the other leaves a cookie pointing at an expired code (or vice versa) — keep them in sync.
```

## Tunnels and reconciler

The reconciler syncs database state to per-connection Shadowsocks containers.

| Variable                     | Default                    | Description                                                                                                   |
| ---------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `RECONCILE_INTERVAL_SECONDS` | `60`                       | How often the reconciler syncs DB state to containers.                                                        |
| `SHADOWSOCKS_IMAGE`          | `local/shadowsocks-server` | Image the reconciler spawns per connection. Compose does not build it — build it yourself before first start. |
| `SHADOWSOCKS_NETWORK`        | `shadowsocks`              | Docker bridge network the `ss-*` containers join; nginx attaches to the same one.                             |

## Built-in MTA

Active only with the `with-mta` compose profile. DNS records, DKIM rotation, and relay alternatives are covered in [email](email.md).

| Variable                   | Default | Description                                                                                                                                                                                                       |
| -------------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MTA_VERIFY_DNS`           | `true`  | The MTA refuses to start if any required DNS record is missing or wrong. Set `false` in dev/CI only.                                                                                                              |
| `MTA_REQUIRE_DNSSEC`       | `auto`  | Tri-state. `auto` probes at startup and enforces DNSSEC if the domain is signed; `true` always enforces (fail-closed, even on unsigned domains); `false` skips the startup check — dev/CI only, never production. |
| `MTA_DKIM_SELECTOR_PREFIX` | `s`     | Base of the rotating DKIM selector pair: selectors toggle `<base>1`/`<base>2` across rotations.                                                                                                                   |
| `MTA_ADMIN_EMAIL`          | `""`    | Required in production: postmaster/abuse/tls-rpt/bounce reports are forwarded here. Use a real external mailbox you read — Postern does not host an inbox.                                                        |
| `MTA_DKIM_ROTATION_DAYS`   | `180`   | How often the provisioner rotates DKIM keys, when auto-rotation is enabled via `DNS_PROVIDER`.                                                                                                                    |

## DNS provider and certificates

`DNS_PROVIDER` is shared by DKIM auto-rotation and TLS cert auto-renewal; credentials are the provider's native environment variables (e.g. `CLOUDFLARE_API_TOKEN`), set alongside it in `.env` and passed to the provisioner container only. Enabling cert renewal also requires the `compose.cert.yaml` overlay and the `with-cert-renewal` profile — see [certificates](certificates.md).

| Variable                          | Default                                          | Description                                                                                                                                                                                                                       |
| --------------------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DNS_PROVIDER`                    | `none`                                           | libdns provider name (`cloudflare`, `route53`, `gandi`, `digitalocean`, `ovh`, `hetzner`, `linode`, `namecheap`). `none` means manual DNS: the provisioner generates the initial DKIM keypair on first start, then exits cleanly. |
| `CERT_RENEWAL`                    | `false`                                          | Enable ACME DNS-01 cert auto-renewal. Requires `DNS_PROVIDER`, `CERT_ACME_EMAIL`, and `PUBLIC_IPV4`.                                                                                                                              |
| `CERT_ACME_EMAIL`                 | `""`                                             | Required when `CERT_RENEWAL=true`. ACME account contact (Let's Encrypt sends expiry warnings here); an `@example.*` address is rejected.                                                                                          |
| `CERT_ACME_DIRECTORY`             | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory URL. Point at the Let's Encrypt staging directory while testing (relaxed rate limits, untrusted certs).                                                                                                            |
| `CERT_RENEWAL_DAYS_BEFORE_EXPIRY` | `30`                                             | Renew this many days before expiry. Must be at least 1 and shorter than cert validity (currently 90 days for Let's Encrypt).                                                                                                      |
| `CERT_FORCE_REISSUE`              | `false`                                          | One-shot override of the 24-hour rate-limit guard. Use only after a cert revocation or compromise; reset to `false` after the next renewal.                                                                                       |
| `PUBLIC_IPV4`                     | `""`                                             | Origin IPv4 for published apex A records. Required whenever the provisioner manages DNS: `CERT_RENEWAL=true`, `with-mta` with `DNS_PROVIDER` set, or `EDGE_PROFILE=cloudflare`. The provisioner refuses to start without it.      |
| `PUBLIC_IPV6`                     | `""`                                             | Optional origin IPv6; if set, AAAA records are published. Delete-on-unset: if previously published and later unset, AAAA records are deleted, avoiding a stale address after a v6-to-v4-only migration.                           |

## Edge and gateway

Fronting the public `:443` endpoint with a CDN/reverse proxy is covered in [edge](edge.md); TLS-passthrough gateways (Traefik, HAProxy) in [gateway](gateway.md).

| Variable                            | Default  | Description                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `EDGE_PROFILE`                      | `none`   | `none` is direct-to-origin. `cloudflare` orange-clouds the apex (requires `DNS_PROVIDER=cloudflare`, `PUBLIC_IPV4`, and `with-edge` in `COMPOSE_PROFILES`). `generic` is any other trusted reverse proxy that sets a real-IP header.                                                                                                                                                             |
| `EDGE_TRUSTED_CIDRS`                | `""`     | `generic` only, required: CIDR(s) allowed to set the real-IP header. Comma/space/tab/newline-separated.                                                                                                                                                                                                                                                                                          |
| `EDGE_REALIP_HEADER`                | `""`     | `generic` only, required: header name carrying the real client IP (e.g. `X-Real-IP`).                                                                                                                                                                                                                                                                                                            |
| `EDGE_CF_AUTHENTICATED_ORIGIN_PULL` | `true`   | `cloudflare` only: require Cloudflare Authenticated Origin Pull mTLS at the origin. The CA is Cloudflare-global — it proves "reached us via Cloudflare", not "via your zone". Setting it under any other profile fails loud.                                                                                                                                                                     |
| `EDGE_CF_MANAGE_ZONE_ECH`           | `false`  | `cloudflare` only, opt-in: auto-enable Cloudflare's zone-level ECH setting so the front actually serves ECH for `auto`/`always` connections. Off by default: the toggle is zone-WIDE and needs a `Zone Settings:Edit` CF token. Postern only ever turns it ON, never off. Setting it under any other profile fails loud.                                                                         |
| `EDGE_CF_MANAGE_SSL_MODE`           | `true`   | `cloudflare` only: auto-manage the zone's SSL/TLS encryption mode so Cloudflare fetches the origin over HTTPS (raising `off`/`flexible` to at least `full` — avoiding the `ERR_TOO_MANY_REDIRECTS` loop). Zone-WIDE; set `false` to manage it yourself on a shared zone. Postern only ever issues raising changes and never turns management off. Setting it under any other profile fails loud. |
| `EDGE_CF_SSL_MODE`                  | `strict` | `cloudflare` only: target SSL/TLS mode to raise to (`full` or `strict`). `strict` validates the origin cert (Postern serves a valid LE cert); use `full` on a shared zone with an invalid-cert co-tenant. Only governs the initial raise from `off`/`flexible`; a zone already at `full`/`strict` is left untouched.                                                                             |
| `PROXY_PROTOCOL_FROM`               | `""`     | CIDR(s) allowed to send PROXY protocol v2 to nginx's `:443`; comma/space-separated. Set only when a TLS-passthrough proxy fronts nginx and you are not using `compose.gateway.yaml`, which sets a safe default for you.                                                                                                                                                                          |

```{warning}
Setting `PROXY_PROTOCOL_FROM` without a PROXY-v2-sending proxy in front makes nginx drop **all** `:443` connections — browsers cannot speak PROXY protocol. Only set it when nginx's `:443` is unreachable except through that trusted proxy (host ports stripped or firewalled); otherwise anyone who can reach `:443` can forge a PROXY header and spoof their source IP.
```

## ECH (client SNI concealment)

Encrypted Client Hello hides the hostname in the TLS handshake. ECH mode is **per-connection** (`postern connection add --ech never|auto|always`, see [CLI reference](../operations/cli.md#postern-connection-add)) — there is no server-wide enable flag. `auto`/`always` connections have the v2ray/ex-ray plugin request an ECH config via DoH before connecting.

| Variable      | Default                                | Description                                                                                                                                                                                   |
| ------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ECH_DOH_URL` | `https://cloudflare-dns.com/dns-query` | DoH resolver the plugin uses for `auto`/`always` connections. Must be an `https://` URL; must not contain `;`, `\`, or whitespace (SIP003 metacharacters). Validated at startup whenever set. |

```{note}
**Upgrading to per-connection ECH (`ECH_ENABLED` is removed).** Migration 3 sets every existing connection to `ech=auto` (opportunistic). Two consequences:
- Deployments that ran `ECH_ENABLED=true` (fail-closed) have those connections become **fail-open** `auto` — ECH is still used when available, but no longer *required*. To keep fail-closed, recreate affected connections with `postern connection add --ech always`.
- The server-wide toggle is gone. `ECH_DOH_URL` (default Cloudflare) is now the only client-side ECH knob; `auto` connections opportunistically attempt ECH whenever it is set. `EDGE_CF_MANAGE_ZONE_ECH` (now default `false`) is the separate, opt-in switch for postern to enable ECH at a Cloudflare front.

To disable ECH entirely, set `ECH_DOH_URL=` (empty) or create connections with `postern connection add --ech never`.

You can remove any leftover `ECH_ENABLED` line from your `.env` — it is now ignored.
```

## Compose

These are read by docker compose during interpolation, not by the portal.

| Variable           | Default        | Description                                                                                                                                                  |
| ------------------ | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `COMPOSE_PROFILES` | `with-mta`     | Profiles to activate: `with-mta` (built-in MTA, on by default), `with-cert-renewal`, `with-edge`. Comment out `with-mta` to use a third-party relay instead. |
| `COMPOSE_FILE`     | `compose.yaml` | Compose file stack. Append overlays as needed, e.g. `compose.yaml:compose.cert.yaml` for cert auto-renewal; `compose.edge.yaml` layers last.                 |

```{note}
Profiles must be set in `.env` — a CLI-only `docker compose --profile` flag is not visible to the provisioner container.
```

## Changing the domain

```{seealso}
For a live deployment with published DNS records and issued certificates, follow the [rename runbook](../operations/rename.md) — provisioner state and old DNS records do not migrate by themselves.
```

Set in `.env`:

```ini
DOMAIN=postern.example.com
SMTP_FROM=Postern VPN <noreply@postern.example.com>
MTA_ADMIN_EMAIL=ops@postern.example.com   # required when using the built-in MTA
# PRODUCT_NAME=YourBrand                  # optional cosmetic display name
```

No source edits are needed: the nginx container renders its config templates from `DOMAIN` at start ([nginx-entrypoint.sh](https://github.com/bindreams/postern/blob/main/nginx/nginx-entrypoint.sh)), and the portal reads `DOMAIN` and `PRODUCT_NAME` from the environment directly. After pulling updated `nginx/etc/*.tmpl` templates, rebuild nginx:

```bash
docker compose up -d --build nginx
```

```{note}
Two test fixtures hardcode `postern.example.com`: [test_reconciler.py](https://github.com/bindreams/postern/blob/main/portal/tests/test_reconciler.py) and [test_ss_config.py](https://github.com/bindreams/postern/blob/main/portal/tests/test_ss_config.py). Edit them only if you run the test suite against your own domain; the other tests read `settings.domain` and adapt.
```
