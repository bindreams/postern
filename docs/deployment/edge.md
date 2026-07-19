# Fronting with a CDN edge

By default Postern's nginx is the internet-facing edge: clients connect straight to your origin's `:443`. The **edge profile** ([compose.edge.yaml](https://github.com/bindreams/postern/blob/main/compose.edge.yaml)) puts a CDN or reverse proxy in front instead. `EDGE_PROFILE` selects the variant (`none` by default):

- **`cloudflare`** — turnkey. Cloudflare proxies (orange-clouds) your traffic. Postern publishes the proxied apex DNS records, auto-trusts Cloudflare's edge IP ranges so nginx recovers the real client IP, and (by default) enforces Authenticated Origin Pull mTLS so the origin only accepts connections arriving through Cloudflare. Pairs with Encrypted Client Hello (ECH) to hide the SNI from the on-path network.
- **`generic`** — any other proxy/CDN that forwards the real client IP in a header (Fastly, a self-hosted front, etc.). You supply the trusted ranges and the header name; you own DNS, the origin firewall, and any origin authentication.

```{note}
Not the same as the [gateway overlay](gateway.md), which is for a **TCP+SNI passthrough** proxy on the same host that never terminates TLS. The edge profile is for a **remote CDN** that terminates TLS and forwards the client IP in an HTTP header.
```

## Why front the tunnel at all

An edge buys censorship-resistance the origin alone cannot:

- **Hide the SNI.** Cloudflare + ECH means the on-path network sees only "TLS to Cloudflare", not your domain. SNI-based blocking of your host stops working.
- **Hide the origin IP** from the internet-wide scanners that enumerate Shadowsocks endpoints — provided every origin-exposing DNS record is proxied and the firewall is locked to the edge (caveats below).
- **Recover the real client IP.** Behind any proxy nginx otherwise sees the *edge's* address, which collapses the per-IP `limit_req` login rate-limit buckets onto one IP and breaks the login identity card. Both profiles restore the true client IP via `set_real_ip_from` + `real_ip_header`.

## Cloudflare golden path

Prerequisites:

- Your domain's nameservers are delegated to Cloudflare (the zone is active in your Cloudflare account).
- A Cloudflare API token with `Zone:DNS:Edit` on that zone — the same token used for DKIM / cert DNS-01 (see [certificates](certificates.md)).
- Your origin's public IPv4 (IPv6 optional).

In `.env` (the edge section of [example.env](https://github.com/bindreams/postern/blob/main/example.env) mirrors this):

```ini
COMPOSE_FILE=compose.yaml:compose.edge.yaml
COMPOSE_PROFILES=with-mta,with-edge
EDGE_PROFILE=cloudflare
DNS_PROVIDER=cloudflare
CLOUDFLARE_API_TOKEN=...           # Zone:DNS:Edit
PUBLIC_IPV4=203.0.113.10           # your origin's real address
# PUBLIC_IPV6=2001:db8::10         # optional
DOMAIN=postern.example.com
```

```{warning}
`COMPOSE_PROFILES` must be set in `.env`, not only via `docker compose --profile`. The provisioner reads it from the environment to decide which subsystems to activate; a CLI-only `--profile` flag is not visible to it.
```

`EDGE_PROFILE=cloudflare` is validated at portal start: it requires `DNS_PROVIDER=cloudflare` and a non-empty `PUBLIC_IPV4`, and fails loud otherwise. Combine with `compose.cert.yaml` for wildcard auto-renewal — the edge and cert stacks share the same provider token.

Then:

```bash
docker compose up -d --build
docker compose logs -f provisioner   # watch the edge tick publish ranges + proxied records
```

On first start the provisioner:

1. Publishes the apex `A`/`AAAA` records **proxied** (orange cloud) at `PUBLIC_IPV4` / `PUBLIC_IPV6`.
1. Fetches Cloudflare's published edge ranges (`https://api.cloudflare.com/client/v4/ips`) and writes them to the shared edge volume as nginx `set_real_ip_from` snippets.
1. nginx's watcher applies the snippets (validate-then-reload) so real-client-IP recovery goes live without a restart.

Authenticated Origin Pull mTLS is on by default (`EDGE_CF_AUTHENTICATED_ORIGIN_PULL=true`): nginx demands Cloudflare's origin-pull client certificate on every `:443` handshake. Setting this variable under any non-`cloudflare` profile is rejected at start.

### Lock down the origin

Do this — **the firewall, not hidden DNS, is the real protection.** Proxied DNS hides the origin IP from casual lookups, but anyone who learns it can still reach `:443` directly unless the firewall stops them. Restrict `:80`/`:443` to Cloudflare's ranges:

```bash
# Refresh whenever Cloudflare changes its ranges (rare):
#   https://www.cloudflare.com/ips-v4  /  https://www.cloudflare.com/ips-v6
for cidr in $(curl -fsS https://www.cloudflare.com/ips-v4) \
            $(curl -fsS https://www.cloudflare.com/ips-v6); do
  ufw allow from "$cidr" to any port 80,443 proto tcp
done
ufw deny 80/tcp
ufw deny 443/tcp   # built-in MTA? replace with `ufw allow 443/tcp` -- MTA-STS needs :443 (see below)
```

Leave `:25` open to the world if you run the [built-in MTA](email.md): SMTP cannot be proxied by Cloudflare, so `mail.<domain>` is published gray-clouded and its `A` record points straight at the origin (see the caveats).

The same applies to `:443` when the MTA is on: the MTA-STS policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt` is served **gray** (Cloudflare's Universal SSL can't authenticate the two-label `mta-sts.<domain>` — see the caveats), so external sending MTAs fetch it straight from the origin. They connect from arbitrary IPs, not Cloudflare's, so under ufw's default-deny-incoming policy the Cloudflare-only `allow` rules above still block them — **add an explicit `ufw allow 443/tcp`** (dropping the `ufw deny 443/tcp` line is not enough; the default policy denies anyway). This opens `:443` to the internet but leaks no new address (the origin IP is already public via `mail.<domain>`), and the tunnel vhost still refuses non-Cloudflare handshakes via AOP (below) — only the AOP-exempt `mta-sts` vhost answers.

Validate:

```bash
docker compose exec portal postern mta verify-dns   # apex proxied; mail gray
curl -fsS -o /dev/null -w '%{http_code}\n' https://postern.example.com/login   # via CF -> 200
curl -fsS --resolve postern.example.com:443:203.0.113.10 https://postern.example.com/login
# direct-to-origin -> TLS handshake fails (no Cloudflare origin-pull cert): AOP working
```

## Generic profile

For a non-Cloudflare front. You are responsible for DNS, the origin firewall, and knowing the proxy's egress ranges and the header it uses for the client IP.

```ini
COMPOSE_FILE=compose.yaml:compose.edge.yaml
COMPOSE_PROFILES=with-mta,with-edge
EDGE_PROFILE=generic
EDGE_TRUSTED_CIDRS=198.51.100.0/24 2001:db8:1::/48   # the proxy's egress ranges
EDGE_REALIP_HEADER=X-Forwarded-For                   # header carrying the client IP
DOMAIN=postern.example.com
```

`generic` requires both `EDGE_TRUSTED_CIDRS` and `EDGE_REALIP_HEADER` non-empty (whitespace-only is rejected at start). nginx trusts the given ranges and reads the client IP from the named header. There is **no** auto-fetched range list, **no** proxied DNS management, and **no** Authenticated Origin Pull — the front and its trust boundary are yours to secure.

## Enabling ECH

ECH (Encrypted Client Hello) hides the SNI from the on-path network. It is a
**client-side, front-side** feature — Postern does no ECH itself and publishes no
ECH config; your front (Cloudflare, or any ECH-capable proxy) does.

ECH mode is set **per connection**, at creation time — there is no server-wide
toggle:

```bash
docker compose exec portal postern connection add alice@example.com "phone" --ech always
```

- `never` — never attempt ECH. Escape hatch for networks that drop ECH ClientHellos.
- `auto` — (default) opportunistic: use ECH if the front serves it, else fall
  back to plaintext. Fail-open.
- `always` — fail-closed: the downloaded client refuses to connect if ECH is
  unavailable. `connection add --ech always` self-checks the front over DoH
  before creating the connection and refuses if it confirms the front is not
  serving ECH.

`auto` and `always` both need `ECH_DOH_URL` set (default
`https://cloudflare-dns.com/dns-query`; any public DoH resolver works,
independent of your front) — the DoH resolver the plugin uses to fetch the ECH
config at connect time. Postern's part is to rewrite the **downloaded** client
config's `plugin_opts` with `;ech=<mode>;ech-doh=<url>` so the tunnel plugin
performs ECH. Requires plugin builds with ECH support (ex-ray ≥ v0.2.0,
galoshes ≥ v0.3.0). Use `always` only once the front is confirmed serving ECH
(for Cloudflare: orange-clouded + zone ECH enabled) — otherwise those clients
never connect.

### Batteries-included ECH front (Cloudflare)

Set `EDGE_CF_MANAGE_ZONE_ECH=true` (opt-in, off by default) alongside
`EDGE_PROFILE=cloudflare` and `DNS_PROVIDER=cloudflare`, and the provisioner
automatically enables Cloudflare's **zone-level ECH setting** so the front
actually serves ECH — otherwise `always` connections fail-closed and `auto`
connections silently fall back to plaintext. This closes the gap between
"Postern's clients request ECH" and "the front serves it."

- **Off by default:** the setting is **zone-wide** (it affects every proxied
  hostname in the Cloudflare zone) and requires a `Zone Settings:Edit` CF
  token, so on a shared root-domain zone — or with a narrower-scoped token —
  you may prefer to manage it yourself.
- **Never reverted:** disabling it later does **not** turn the zone setting back
  off — reverting a zone-wide toggle could break unrelated services. Turn it off
  in the Cloudflare dashboard if you need to.
- **If enablement fails** (wrong Cloudflare plan tier, API token missing
  `Zone Settings:Edit`, transient CF outage), the forcing function is a
  **signal**, in every deployment mode: the provisioner container goes
  **unhealthy**, logs the verbatim Cloudflare error every tick, and the
  `always` clients you handed out cannot connect — three converging cues that
  lead to the fix. Run `postern ech verify` / `postern ech show` to see the
  state and the last error. Under cert auto-renewal (`compose.cert.yaml`) that unhealthy provisioner
  *additionally* blocks nginx/mta startup (they `depends_on` it); under the default
  BYO-cert mode there is no such hard block — the signal is the mechanism.
- **Verify:** `postern ech verify` queries the apex HTTPS record over DoH and
  confirms an `ech=` SvcParam is present (exit 0 present, 1 absent, 2 inconclusive).
  `postern ech show` prints the settings, the provisioner state (incl. the last
  Cloudflare error), and the live DoH status.
- **Plan availability:** ECH is on by default on Free zones and toggleable on
  Pro/Business/Enterprise.

## Authenticated Origin Pull: what it proves (and what it doesn't)

Under `cloudflare`, AOP mTLS is **on by default** and does raise the bar: a naive `curl https://<origin-ip>` is rejected because it can't present Cloudflare's client certificate. Be precise about the guarantee, though:

- The certificate nginx trusts is Cloudflare's **global** origin-pull CA, shared across **all** Cloudflare tenants. AOP authenticates *"this connection came through Cloudflare"*, **not** *"this connection came through your zone."*
- So an attacker who discovers your origin IP can point **their own** Cloudflare zone at it and present the very same, valid origin-pull certificate. AOP alone does not stop them.

**The host firewall (`:443` restricted to Cloudflare ranges) is the real lockdown.** AOP is defence-in-depth on top of it, not a substitute. Per-hostname zone-scoped AOP would bind to your zone specifically. (Exception: running the built-in MTA requires `:443` open to the internet for MTA-STS — see the "Lock down the origin" section — so on those deployments AOP is the sole gate on the tunnel vhost.)

## Threat model: what Cloudflare sees

Orange-clouding routes the **tunnel itself** through Cloudflare, and Cloudflare **terminates the outer TLS**. Consequences:

- Cloudflare can observe per-connection path tokens (`/t/{token}`) and traffic **metadata** — timing, volume, connection counts.
- Cloudflare **cannot** read the tunnelled traffic: the Shadowsocks payload stays end-to-end encrypted between the client and the `ss-{token}` container; Cloudflare only relays the ciphertext.

This is inherent to CF-fronted ECH (Cloudflare must terminate TLS to decrypt the ECH-protected inner ClientHello) and to orange-cloud proxying in general. The trade is deliberate: **hide the SNI from the on-path network (the censor), in exchange for revealing connection metadata to Cloudflare** — a party outside the censor's jurisdiction. Choose the edge profile only where that trade favors your users.

The `/t/{token}` identification hardening makes tunnel responses uniform against *on-path* fingerprinting; it does **not** hide the tokens from Cloudflare, which sits inside the TLS.

## Caveats

- **ECH needs an ECH-capable front.** Cloudflare is the turnkey option in 2026, but ECH is a standard: `generic` **can** do ECH if your front publishes and serves an ECH config for your domain — you own that config publication. `generic` still gives real-IP recovery regardless.
- **The origin IP leaks via `mail.<domain>` when the built-in MTA is on.** SMTP can't be proxied, so the mail record is gray-clouded and resolves to your real address. The Cloudflare profile hides the SNI and fronts the tunnel, but does not hide the origin IP while the MTA runs. And because MTA-STS then needs `:443` open to the internet (see the "Lock down the origin" section), direct tunnel access to the origin is refused by AOP alone on those deployments, not the firewall.
- **`mta-sts.<domain>` is published gray, not proxied, under the edge.** Cloudflare's Universal SSL cannot authenticate a multi-level subdomain like `mta-sts.<domain>` (X.509 wildcards match a single left-most label), and MTA-STS mandates a valid publicly-trusted certificate for `https://mta-sts.<domain>/.well-known/mta-sts.txt`, not proxying — so the record stays **gray**, served directly by the origin's `*.<domain>` wildcard cert (the apex stays orange so Cloudflare can front it for ECH). The provisioner publishes and maintains it automatically; because senders reach it directly, `:443` must stay open to the internet when the MTA runs (see the "Lock down the origin" section).

```{warning}
Cloudflare's self-serve (free/pro) plans are scoped to serving websites; proxying general, non-HTML tunnel traffic can run afoul of §2.8 of the Self-Serve Subscription Agreement. On abuse reports, Cloudflare can reactively suspend the zone or terminate the account. Review the current ToS for your plan before relying on this in production.
```
