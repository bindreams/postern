# Fronting Postern with an edge (Cloudflare / generic CDN)

By default Postern's nginx is the internet-facing edge: clients connect straight
to your origin's `:443`. The **edge profile** puts a CDN/proxy in front instead.
Two variants, selected by `EDGE_PROFILE` (`none` default, `cloudflare`, `generic`):

- **`cloudflare`** — turnkey. Cloudflare proxies (orange-clouds) your traffic.
  Postern publishes the proxied apex DNS records, auto-trusts Cloudflare's edge IP
  ranges so nginx recovers the real client IP, and (by default) enforces
  Authenticated Origin Pull mTLS so the origin only accepts connections arriving
  through Cloudflare. Pairs with Encrypted Client Hello (ECH) to hide the SNI from
  the on-path network.
- **`generic`** — any other proxy/CDN that forwards the real client IP in a header
  (Fastly, a self-hosted front, etc.). You supply the trusted ranges and the header
  name; you own DNS, the origin firewall, and any origin authentication.

> Not the same as [docs/gateway.md](gateway.md). The gateway overlay is for a
> **TCP+SNI passthrough** proxy on the same host that never terminates TLS. The
> edge profile is for a **remote CDN** that terminates TLS and forwards the client
> IP in an HTTP header.

## Why front the tunnel at all

An edge buys censorship-resistance the origin alone cannot:

- **Hide the SNI.** Cloudflare + ECH means the on-path network sees only
  `TLS to Cloudflare`, not `your.domain`. SNI-based blocking of your host stops
  working.
- **Hide the origin IP** from the internet-wide scanners that enumerate
  Shadowsocks endpoints — provided every origin-exposing DNS record is proxied and
  the firewall is locked to the edge (caveats below).
- **Recover the real client IP.** Behind any proxy nginx otherwise sees the
  *edge's* address, which collapses the per-IP `limit_req` login rate-limit buckets
  onto one IP and breaks the login identity card. Both profiles restore the true
  client IP via `set_real_ip_from` + `real_ip_header`.

## Cloudflare golden path

Prerequisites:

- Your domain's nameservers are delegated to Cloudflare (the zone is active in your
  Cloudflare account).
- A Cloudflare API token with `Zone:DNS:Edit` on that zone — the same token used for
  DKIM / cert DNS-01 ([docs/certs.md](certs.md)).
- Your origin's public IPv4 (IPv6 optional).

In `.env`:

```ini
COMPOSE_FILE=compose.yaml:compose.edge.yaml
COMPOSE_PROFILES=with-mta,with-edge
EDGE_PROFILE=cloudflare
DNS_PROVIDER=cloudflare
CLOUDFLARE_API_TOKEN=...            # Zone:DNS:Edit
PUBLIC_IPV4=203.0.113.10           # your origin's real address
# PUBLIC_IPV6=2001:db8::10         # optional
DOMAIN=your.domain.example
```

> **`COMPOSE_PROFILES` must be set in `.env`**, not only via `docker compose --profile`. The provisioner reads it from the environment to decide which
> subsystems to activate; a CLI-only `--profile` flag is not visible to it.

`EDGE_PROFILE=cloudflare` is validated at portal start: it requires
`DNS_PROVIDER=cloudflare` and a non-empty `PUBLIC_IPV4`, and fails loud otherwise.
(Combine with `compose.cert.yaml` for wildcard auto-renewal — the edge and cert
stacks share the same provider token.)

Then:

```bash
docker compose up -d --build
docker compose logs -f provisioner   # watch the edge tick publish ranges + proxied records
```

On first start the provisioner:

1. Publishes the apex `A`/`AAAA` records **proxied** (orange cloud) at
   `PUBLIC_IPV4` / `PUBLIC_IPV6`.
1. Fetches Cloudflare's published edge ranges (`https://api.cloudflare.com/client/v4/ips`)
   and writes them to the shared edge volume as nginx `set_real_ip_from` snippets.
1. nginx's watcher applies the snippets (validate-then-reload) so real-client-IP
   recovery goes live without a restart.

Authenticated Origin Pull mTLS is on by default
(`EDGE_CF_AUTHENTICATED_ORIGIN_PULL=true`): nginx demands Cloudflare's origin-pull
client certificate on every `:443` handshake.

### Lock down the origin (do this — it is the real protection)

Proxied DNS hides the origin IP from casual lookups, but anyone who learns it can
still reach `:443` directly unless the firewall stops them. Restrict `:80`/`:443`
to Cloudflare's ranges:

```bash
# Refresh whenever Cloudflare changes its ranges (rare):
#   https://www.cloudflare.com/ips-v4  /  https://www.cloudflare.com/ips-v6
for cidr in $(curl -fsS https://www.cloudflare.com/ips-v4) \
            $(curl -fsS https://www.cloudflare.com/ips-v6); do
  ufw allow from "$cidr" to any port 80,443 proto tcp
done
ufw deny 80/tcp
ufw deny 443/tcp
```

Leave `:25` open to the world if you run the built-in MTA: SMTP cannot be proxied
by Cloudflare, so `mail.<domain>` is published gray-clouded and its `A` record
points straight at the origin (see the caveats).

Validate:

```bash
docker compose exec portal postern mta verify-dns   # apex proxied; mail gray
curl -fsS -o /dev/null -w '%{http_code}\n' https://your.domain.example/login   # via CF -> 200
curl -fsS --resolve your.domain.example:443:203.0.113.10 https://your.domain.example/login
# direct-to-origin -> TLS handshake fails (no Cloudflare origin-pull cert): AOP working
```

## Generic profile

For a non-Cloudflare front. You are responsible for DNS, the origin firewall, and
knowing the proxy's egress ranges and the header it uses for the client IP.

```ini
COMPOSE_FILE=compose.yaml:compose.edge.yaml
COMPOSE_PROFILES=with-mta,with-edge
EDGE_PROFILE=generic
EDGE_TRUSTED_CIDRS=198.51.100.0/24 2001:db8:1::/48   # the proxy's egress ranges
EDGE_REALIP_HEADER=X-Forwarded-For                   # header carrying the client IP
DOMAIN=your.domain.example
```

`generic` requires both `EDGE_TRUSTED_CIDRS` and `EDGE_REALIP_HEADER` non-empty
(whitespace-only is rejected at start). nginx trusts the given ranges and reads the
client IP from the named header. There is **no** auto-fetched range list, **no**
proxied DNS management, and **no** Authenticated Origin Pull — the front and its
trust boundary are yours to secure.

## Authenticated Origin Pull: what it proves (and what it doesn't)

Under `cloudflare`, AOP mTLS is **on by default** and does raise the bar: a naive
`curl https://<origin-ip>` is rejected because it can't present Cloudflare's client
certificate. Be precise about the guarantee, though:

- The certificate nginx trusts is Cloudflare's **global** origin-pull CA, shared
  across **all** Cloudflare tenants. AOP authenticates *"this connection came
  through Cloudflare"*, **not** *"this connection came through your zone."*
- So an attacker who discovers your origin IP can point **their own** Cloudflare
  zone at it and present the very same, valid origin-pull certificate. AOP alone
  does not stop them.

**The host firewall (`:443` restricted to Cloudflare ranges) is the real
lockdown.** AOP is defence-in-depth on top of it, not a substitute. Per-hostname
(zone-scoped) Authenticated Origin Pull — which *would* bind to your zone
specifically — is a documented **v0.4 follow-up**.

## Threat model: what Cloudflare sees

Orange-clouding routes the **tunnel itself** through Cloudflare, and Cloudflare
**terminates the outer TLS**. Consequences:

- Cloudflare can observe per-connection path tokens (`/t/{token}`) and traffic
  **metadata** — timing, volume, connection counts.
- Cloudflare **cannot** read the tunnelled traffic: the Shadowsocks payload stays
  end-to-end encrypted between the client and the `ss-{token}` container;
  Cloudflare only relays the ciphertext.

This is inherent to CF-fronted ECH (Cloudflare must terminate TLS to decrypt the
ECH-protected inner ClientHello) and to orange-cloud proxying in general. The trade
is deliberate: **hide the SNI from the on-path network (the censor), in exchange
for revealing connection metadata to Cloudflare** — a party outside the censor's
jurisdiction. Choose the edge profile only where that trade favors your users.

The `/t/{token}` identification-hardening work (#154) makes tunnel responses
uniform against *on-path* fingerprinting; it does **not** hide the tokens from
Cloudflare, which sits inside the TLS.

## Caveats

- **ECH is Cloudflare-only in 2026.** Encrypted Client Hello at scale is
  effectively a Cloudflare feature today; no `generic` front gives you SNI-hiding
  out of the box. `generic` buys real-IP recovery, nothing more.
- **The origin IP leaks via `mail.<domain>` when the built-in MTA is on.** SMTP
  can't be proxied, so the mail record is gray-clouded and resolves to your real
  address. The Cloudflare profile hides the SNI and fronts the tunnel, but does not
  hide the origin IP while the MTA runs; the `:443`-from-Cloudflare firewall still
  blocks direct tunnel access to the origin.
- **`mta-sts.<domain>` is auto-published proxied when both MTA and edge are on.**
  When `with-mta` and `with-edge` (Cloudflare) are both active, the provisioner
  automatically publishes an orange-clouded `mta-sts.<domain>` A/AAAA record in
  your DNS zone. This keeps the MTA-STS policy URL
  (`https://mta-sts.<domain>/.well-known/mta-sts.txt`) reachable through Cloudflare
  even with the origin `:443` firewall locked to Cloudflare ranges. No manual DNS
  step is required; the record is created and maintained by the provisioner.
- **Cloudflare Terms of Service.** Cloudflare's self-serve (free/pro) plans are
  scoped to serving websites; proxying general, non-HTML tunnel traffic can run
  afoul of §2.8 of the Self-Serve Subscription Agreement. On abuse reports,
  Cloudflare can reactively suspend the zone or terminate the account. Review the
  current ToS for your plan before relying on this in production.
