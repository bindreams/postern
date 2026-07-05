# Deployment

Postern deploys with Docker Compose on a single host. The minimal deployment is the base [compose.yaml](https://github.com/bindreams/postern/blob/main/compose.yaml) with default settings: Postern's nginx owns port 443 directly, TLS certificates are bring-your-own Let's Encrypt certs bind-mounted from the host, and login emails are sent by the built-in MTA (the default `with-mta` Compose profile). Everything else is opt-in, chosen along the three axes below.

Every topology needs:

- Docker Engine and Docker Compose v2.
- A public domain you control (`postern.example.com` throughout these docs).
- A free Docker Hub account with a Personal Access Token: the base images come from [Docker Hardened Images](https://docs.docker.com/dhi/) (`dhi.io`), whose catalog is free but requires authenticated pulls. Run `docker login dhi.io` with your Docker Hub username and PAT before the first build.

## Email delivery

Users sign in with one-time codes sent by email, so every deployment needs outbound SMTP:

- **Built-in MTA (default).** A self-hosted Postfix + opendkim stack, enabled by the default `with-mta` profile. It eliminates the third-party metadata leak — no provider sees who your users are or when they log in. Requires port 25 outbound (many cloud providers block it by default), reverse DNS (PTR) set to `mail.postern.example.com`, published DNS records (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT), and an external mailbox for technical reports (`MTA_ADMIN_EMAIL`). DNSSEC on the domain is strongly recommended.
- **Third-party relay** (Resend, SES, Mailgun, Postmark, …). Comment out `COMPOSE_PROFILES=with-mta` in `.env` and set `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD`. TLS mode is derived from the port: 465 → implicit TLS, 587 → STARTTLS.

Details: [email](email.md).

## TLS certificates

- **Bring-your-own (default).** The host's `/etc/letsencrypt` is bind-mounted into nginx; you provision certs externally (typically `certbot certonly --standalone`) and own renewal. Nginx self-reloads every 6 hours, so renewed certs are picked up without a restart. With the built-in MTA you also need coverage for the `mail.` and `mta-sts.` subdomains (a multi-SAN or wildcard cert works).
- **Auto-renewal (ACME DNS-01).** The provisioner obtains and renews a single wildcard cert covering `postern.example.com` and `*.postern.example.com` against your DNS provider's API — the wildcard keeps subdomains out of Certificate Transparency logs. Requires the [compose.cert.yaml](https://github.com/bindreams/postern/blob/main/compose.cert.yaml) overlay, the `with-cert-renewal` profile, `CERT_RENEWAL=true`, and a supported `DNS_PROVIDER`.

```{warning}
Pick one mode. Running a host-side certbot while `compose.cert.yaml` is active puts two writers on the same cert paths.
```

Details: [certificates](certificates.md).

## Network front

Who accepts the client's TCP connection on `:443`:

- **Direct (default).** Postern's nginx binds host ports 80/443 and is the internet-facing edge.
- **Local gateway.** A shared reverse proxy on the same host (Traefik, HAProxy) fans `:443` out to multiple services. The [compose.gateway.yaml](https://github.com/bindreams/postern/blob/main/compose.gateway.yaml) overlay strips nginx's host port bindings, joins the external `gateway` network, and recovers the real client IP via PROXY protocol v2. The mta keeps its host `:25` binding — the gateway pattern covers HTTPS only. Details: [gateway](gateway.md).
- **Remote CDN edge.** Cloudflare (turnkey; pairs with ECH to hide the SNI) or a generic CDN fronts the origin, hiding the origin IP from scanners — provided the origin firewall is locked down to the edge's IP ranges. Selected with `EDGE_PROFILE` plus the `with-edge` profile and the [compose.edge.yaml](https://github.com/bindreams/postern/blob/main/compose.edge.yaml) overlay. Details: [edge](edge.md).

```{note}
Gateway and edge are different things. The gateway overlay is a **local** TCP+SNI passthrough proxy that never terminates TLS — Postern's nginx still serves the leaf certificate. The edge profile is a **remote** CDN that terminates TLS and forwards the client IP in an HTTP header.
```

## Compose files and profiles

Set `COMPOSE_FILE` and `COMPOSE_PROFILES` in `.env` ([example.env](https://github.com/bindreams/postern/blob/main/example.env) is the annotated template; the full variable reference is in [configuration](configuration.md)):

```{list-table}
---
header-rows: 1
---
- - Topology
  - `COMPOSE_FILE`
  - `COMPOSE_PROFILES`
- - Minimal: direct, BYO certs, built-in MTA
  - _(unset — `compose.yaml` alone)_
  - `with-mta`
- - Cert auto-renewal
  - `compose.yaml:compose.cert.yaml`
  - `with-mta,with-cert-renewal`
- - CDN edge, BYO certs
  - `compose.yaml:compose.edge.yaml`
  - `with-mta,with-edge`
- - CDN edge + cert auto-renewal
  - `compose.yaml:compose.cert.yaml:compose.edge.yaml`
  - `with-mta,with-cert-renewal,with-edge`
- - Local gateway (requires cert auto-renewal)
  - `compose.yaml:compose.cert.yaml:compose.gateway.yaml`
  - `with-mta,with-cert-renewal`
```

- Using a third-party relay? Drop `with-mta` from the profiles in any row (for the minimal row, comment the `COMPOSE_PROFILES` line out entirely).
- Rows with `compose.cert.yaml` also need `CERT_RENEWAL=true`, `CERT_ACME_EMAIL`, and `DNS_PROVIDER` credentials; rows with `compose.edge.yaml` also need `EDGE_PROFILE` and its variables.
- `compose.gateway.yaml` requires `compose.cert.yaml` in the `COMPOSE_FILE` chain: without it, nginx mounts the host `/etc/letsencrypt` bind instead of the `postern-letsencrypt` volume, and a fresh deploy with no host certs starts nginx with no cert at all.
- Overlay order matters: `compose.edge.yaml` goes last, after `compose.cert.yaml`.

```{warning}
`COMPOSE_PROFILES` must be set in `.env`, not via a `docker compose --profile` flag — the provisioner reads it from the environment to decide which subsystems to activate, and a CLI-only flag is not visible to it.
```

```{toctree}
---
maxdepth: 1
---
configuration.md
email.md
certificates.md
edge.md
gateway.md
customization.md
```
