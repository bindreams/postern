# Running behind a gateway proxy

Postern's default deployment owns host ports 80 and 443. If a shared reverse proxy (Traefik, HAProxy, etc.) already fans traffic out to multiple services on the same host, apply the [compose.gateway.yaml](https://github.com/bindreams/postern/blob/main/compose.gateway.yaml) overlay, which:

- Strips the `80:80` / `443:443` host bindings from Postern's nginx (the gateway owns them now).
- Joins Postern's nginx to an external docker network named `gateway`.
- Adds Traefik labels for a TCP router matching `` HostSNI(`${DOMAIN}`) `` with `tls.passthrough: true`, routing to `postern-nginx:443`.
- Renames every Postern container with a `postern-` prefix so they coexist cleanly with other services in `docker ps`.

The gateway must do **TCP+SNI passthrough**, not TLS termination. Postern's nginx serves the TLS leaf cert (from the `postern-letsencrypt` named volume populated by the provisioner — see [certificates](certificates.md)); the gateway must not re-encrypt or rewrite. For a TLS-*terminating* front (a CDN such as Cloudflare, or any proxy that presents its own cert), use the edge profiles instead — see [edge](edge.md).

## Usage

In `.env`:

```ini
COMPOSE_FILE=compose.yaml:compose.cert.yaml:compose.gateway.yaml
COMPOSE_PROFILES=with-mta,with-cert-renewal
DOMAIN=postern.example.com
# … the rest of your normal .env …
```

Then `docker compose up -d --build` as usual. Verify the Traefik label resolved correctly:

```bash
docker compose config | grep HostSNI
# expected: traefik.tcp.routers.postern.rule: HostSNI(`postern.example.com`)
```

```{important}
`compose.gateway.yaml` requires `compose.cert.yaml` in the chain. Without it, Postern's nginx mounts the host `/etc/letsencrypt` bind directly instead of the `postern-letsencrypt` named volume, and a fresh deploy with no host certs would start nginx with no cert at all (Traefik passes through to nothing). `compose.cert.yaml` also adds `depends_on: provisioner: service_healthy`, so nginx waits for first issuance.
```

## Gateway-side prerequisites

A separate compose stack (yours or someone else's) must provide:

- A docker network named `gateway` (external to Postern's compose), reachable from the host running both stacks.
- A Traefik service watching that network for the `traefik.expose=true` label, with a `websecure` entrypoint on TCP `:443`.
- Either no catch-all TCP router, or a catch-all with priority below 100 — `compose.gateway.yaml` pins `priority: 100` so Postern's explicit `` HostSNI(`${DOMAIN}`) `` deterministically wins.

The mta keeps its host `:25` binding directly — Traefik is not an SMTP proxy, and the gateway pattern only covers HTTPS.

## Real client IP (PROXY protocol)

Under TCP+SNI passthrough the gateway terminates no TLS and proxies raw bytes to Postern's nginx, so without help nginx sees the *gateway's* container IP, not the client's. That would break the login identity card, the per-IP `limit_req` rate-limit buckets (they'd collapse onto one gateway IP), access logs, and any per-IP logic.

`compose.gateway.yaml` fixes this automatically with PROXY protocol v2:

- It tells Traefik to send a PROXY-v2 header ahead of the passthrough bytes (`traefik.tcp.services.postern.loadbalancer.proxyProtocol.version: "2"`).
- It sets `PROXY_PROTOCOL_FROM` to the in-cluster private ranges (IPv4 RFC1918 + IPv6 ULA `fc00::/7`), which makes Postern's nginx accept PROXY-v2 on `:443` and recover the real client IP (`set_real_ip_from` + `real_ip_header proxy_protocol`). This default is safe because, in gateway mode, nginx's host ports are stripped — it is reachable only over the gateway network.

No action is required for the reference deployment. To tighten the trust boundary, set `PROXY_PROTOCOL_FROM` in `.env` (see [example.env](https://github.com/bindreams/postern/blob/main/example.env)) to your gateway's exact subnet (CIDR; comma/space-separated for multiple).

```{warning}
`proxy_protocol` is a listening-socket option, so once enabled it applies to *every* server block sharing `:443` (the portal, the `mta-sts.<domain>` vhost, and the catch-all). Any other SNI you route to Postern's nginx through the gateway must therefore also be sent with PROXY-v2. Never set `PROXY_PROTOCOL_FROM` unless a PROXY-v2-sending proxy is actually in front *and* nginx's `:443` is unreachable except through it (host ports stripped, as `compose.gateway.yaml` does, or firewalled) — otherwise nginx drops every `:443` connection with a "broken header" error (browsers cannot speak PROXY protocol), and a client that can reach `:443` directly could forge a PROXY header to spoof its source IP.
```
