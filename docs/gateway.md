# Postern behind a Traefik / HAProxy gateway

Postern's default deployment owns ports 80 and 443 directly. Some operators run a shared reverse proxy in front (Traefik, HAProxy, etc.) that fans traffic out to multiple services on the same host. Postern supports this via [compose.gateway.yaml](../compose.gateway.yaml), an overlay that:

- Strips the `80:80` / `443:443` host bindings from postern's nginx (the gateway owns them now).
- Joins postern's nginx to an external docker network named `gateway`.
- Adds Traefik labels for a TCP router matching `` HostSNI(`${DOMAIN}`) `` with `tls.passthrough: true`, routing to `postern-nginx:443`.
- Renames every postern container with a `postern-` prefix so they coexist cleanly with other services in `docker ps`.

The gateway is expected to **TCP+SNI passthrough**, not TLS-terminate. Postern's nginx serves the TLS leaf cert (either from a BYO bind mount or from the `postern-letsencrypt` named volume populated by the provisioner — see [docs/certs.md](certs.md)); the gateway must not re-encrypt or rewrite.

## Usage

In `.env`:

```ini
COMPOSE_FILE=compose.yaml:compose.cert.yaml:compose.gateway.yaml
COMPOSE_PROFILES=with-mta,with-cert-renewal
DOMAIN=your.domain.example
# … the rest of your normal .env …
```

Then `docker compose up -d --build` as usual. Verify the Traefik label resolved correctly:

```bash
docker compose config | grep HostSNI
# expected: traefik.tcp.routers.postern.rule: HostSNI(`your.domain.example`)
```

`compose.gateway.yaml` requires `compose.cert.yaml` in the chain. Without it, postern's nginx mounts the host `/etc/letsencrypt` bind directly instead of the `postern-letsencrypt` named volume, and a fresh deploy with no host certs would start nginx with no cert at all (Traefik passes through to nothing).

## Gateway-side prerequisites

A separate compose stack (yours or someone else's) must provide:

- A docker network named `gateway` (external to postern's compose), reachable from the host running both stacks.
- A Traefik service watching that network for the `traefik.expose=true` label, with a `websecure` entrypoint on TCP `:443`.
- Either no catch-all TCP router, or a catch-all with priority below 100 — `compose.gateway.yaml` pins `priority: 100` so postern's explicit `` HostSNI(`${DOMAIN}`) `` deterministically wins.

The mta keeps its host `:25` binding directly — Traefik is not an SMTP proxy and the gateway pattern only covers HTTPS.

## What the gateway never sees

Under TCP+SNI passthrough, the gateway terminates no TLS, sees no HTTP, and proxies the raw TLS bytes to postern's nginx. Postern's nginx still gets the TLS handshake and the rest of the connection, but the source IP is the gateway container's IP — not the real client. This affects nginx variables derived from the connection peer (`$binary_remote_addr` in `limit_req` zones, access-log client IP, any per-IP logic). The PROXY-v2 protocol can bridge this when the gateway supports it; tracked separately at <https://github.com/bindreams/postern/issues/98>.
