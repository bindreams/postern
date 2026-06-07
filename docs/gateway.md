# Postern behind a Traefik / HAProxy gateway

Postern's default deployment owns ports 80 and 443 directly. Some operators run a shared reverse proxy in front (Traefik, HAProxy, etc.) that fans traffic out to multiple services on the same host. Postern supports this via [compose.gateway.yaml](../compose.gateway.yaml), an overlay that:

- Strips the `80:80` / `443:443` host bindings from postern's nginx (the gateway owns them now).
- Joins postern's nginx to an external docker network named `gateway`.
- Adds Traefik labels for a TCP router matching ``HostSNI(`${DOMAIN}`)`` with `tls.passthrough: true`, routing to `postern-nginx:443`.
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
- Either no catch-all TCP router, or a catch-all with priority below 100 — `compose.gateway.yaml` pins `priority: 100` so postern's explicit ``HostSNI(`${DOMAIN}`)`` deterministically wins.

The mta keeps its host `:25` binding directly — Traefik is not an SMTP proxy and the gateway pattern only covers HTTPS.

## Real client IP (PROXY protocol)

Under TCP+SNI passthrough the gateway terminates no TLS and proxies raw bytes to postern's nginx, so without help nginx sees the _gateway's_ container IP, not the client. That would break the login identity card, the per-IP `limit_req` rate-limit buckets (they'd collapse onto one gateway IP), access logs, and any per-IP logic.

`compose.gateway.yaml` fixes this automatically with PROXY protocol v2:

- It tells Traefik to send a PROXY-v2 header ahead of the passthrough bytes (`traefik.tcp.services.postern.loadbalancer.proxyProtocol.version: "2"`).
- It sets `PROXY_PROTOCOL_FROM` to the in-cluster private ranges, which makes postern's nginx accept PROXY-v2 on `:443` and recover the real client IP (`set_real_ip_from` + `real_ip_header proxy_protocol`). This default is safe because, in gateway mode, nginx's host ports are stripped — it's reachable only over the gateway network.

No action is required for the reference deployment. To tighten the trust boundary, set `PROXY_PROTOCOL_FROM` in `.env` to your gateway's exact subnet (CIDR; comma/space-separated for multiple).

**Caveat:** `proxy_protocol` is a listening-socket option, so once enabled it applies to _every_ server block sharing `:443` (the portal, the `mta-sts.<domain>` vhost, and the catch-all). Any other SNI you route to postern's nginx through the gateway must therefore also be sent with PROXY-v2, and you must never set `PROXY_PROTOCOL_FROM` unless a PROXY-v2-sending proxy is actually in front _and_ nginx's `:443` is unreachable except through it (host ports stripped, as `compose.gateway.yaml` does, or firewalled) — otherwise nginx drops every `:443` connection with a "broken header" error, and a client that can reach `:443` directly could forge a PROXY header to spoof its source IP.
