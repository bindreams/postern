# Email delivery

Postern sends exactly one kind of email: one-time login codes. You have two ways to deliver them:

- **Built-in MTA** (default, the `with-mta` Compose profile) — a self-hosted Postfix stack. No third party learns who your users are or when they log in. Requires real mail-server prerequisites (port 25, reverse DNS, DNS records); the bulk of this page walks through them.
- **Third-party SMTP relay** (Resend, SES, Mailgun, Postmark, etc.) — the fastest start, but the provider sees login metadata.

## Third-party SMTP relay

Comment out `COMPOSE_PROFILES=with-mta` in `.env` and set `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` to your provider's values (see [configuration](configuration.md)). The rest of this page doesn't apply.

```{note}
TLS mode is derived from the port: `465` → implicit TLS, `587` → STARTTLS, anything else → plaintext.
```

## Built-in MTA

The MTA is split across two containers, deliberately:

- **`mta`** — Postfix on public port 25 (in/out), submission on an internal-only port reached by the portal. Runs opendkim (signs outbound with DKIM — a cryptographic signature receivers verify against a public key in your DNS), Unbound (validates DNSSEC — cryptographic signing of DNS zones — which DANE outbound TLS requires), postsrsd (SRS rewriting for forwarded reports), and postfix-mta-sts-resolver (honors recipient MTA-STS policies). Holds the DKIM signing key.
- **`provisioner`** — generates DKIM keys, advances the rotation state machine, and talks to your DNS provider's API to publish/retire TXT records. Holds the DNS provider API token. Has zero inbound listeners.

The split is the threat-model story: a Postfix RCE on public port 25 cannot escalate to DNS-record hijack, because the credentials live in a different container.

The portal submits mail via the `mta-submit` network alias — [example.env](https://github.com/bindreams/postern/blob/main/example.env) already sets `SMTP_HOST=mta-submit`. Don't "simplify" this to the bare `mta` name: the `mta` service is multi-homed, and `mta` resolves to its default-network IP, which is outside Postfix's `mynetworks` and gets rejected. Only the alias lands on the internal submission network.

## Prerequisites

Five things to have in place before bringing up the stack.

### A VPS where port 25 outbound works

Most cloud providers block port 25 outbound by default to prevent spam from compromised tenants:

- **AWS, GCP, OVH, DigitalOcean (new accounts)**: blocked. AWS allows it after a request form; GCP doesn't allow it on Compute Engine at all.
- **Hetzner, Vultr, BuyVM, Linode, Scaleway**: usually allowed.

```{warning}
If your VPS blocks port 25 outbound, the built-in MTA cannot deliver mail. Use a third-party SMTP relay instead.
```

### Reverse DNS (PTR)

Set the reverse DNS for your public IP — the PTR record mapping the IP back to a hostname — to `mail.<your-domain>`. This is configured at the VPS provider's panel; there's no API for it from inside Postern. Verify:

```bash
dig -x <your-ip> +short
# expect: mail.<your-domain>.
```

### Three TLS certificates

- `<your-domain>` — used by nginx for the portal (already required).
- `mail.<your-domain>` — used by Postfix on port 25.
- `mta-sts.<your-domain>` — used by nginx to serve the MTA-STS policy file. RFC 8461 §3.3 mandates HTTPS with a publicly-trusted CA.

A single multi-SAN cert covering all three works (three separate certs work too):

```bash
certbot certonly --standalone \
    -d <your-domain> \
    -d mail.<your-domain> \
    -d mta-sts.<your-domain>
```

Alternatively, [auto-renewal](certificates.md) issues a wildcard cert that covers all three.

```{note}
Postern bind-mounts `/etc/letsencrypt` into the nginx and mta containers; whichever layout you pick must place the certs at the standard paths (`/etc/letsencrypt/live/<host>/fullchain.pem` etc).
```

### DNSSEC on your sending domain (strongly recommended)

Without DNSSEC, MTA-STS and DKIM records can be silently tampered with by anyone with upstream-DNS access. For a privacy-motivated VPN portal this is the single most impactful security control after eliminating the third-party relay.

Most modern registrars support DNSSEC for common TLDs:

- **Cloudflare Registrar, Gandi, Namecheap, Porkbun, Hover, INWX**: supported, manageable in the registrar UI.
- **GoDaddy, some others**: historically patchy. Transfer to a supported registrar if needed.

Verify:

```bash
dig +dnssec DS <your-domain>
# expect: a signed RRset, AD flag set
```

`MTA_REQUIRE_DNSSEC` is a tri-state with default `auto`:

- `auto` (default) — at startup, the mta probes whether your sending domain is DNSSEC-signed. If yes, the AD-bit check is enforced (mta refuses to start if the AD bit is missing). If no, the startup check is skipped, but Unbound continues to validate at runtime for DANE on outbound TLS. Most operators want this.
- `true` — always require. The mta refuses to start when the AD bit is missing, even on unsigned domains. Use this for fail-closed production where an unsigned-domain misconfiguration must be caught loudly.
- `false` — skip the startup check entirely. Use only for dev / CI.

### An external mailbox for technical reports

Postern is **outbound-only**. Inbound mail (postmaster, abuse, tls-rpt, bounces) is virtual-aliased to whatever you set as `MTA_ADMIN_EMAIL=`. Use a real mailbox you read — Proton, Fastmail, Gmail, etc. The mta refuses to start when `MTA_VERIFY_DNS=true` and this is missing.

Forwarded reports use SRS (Sender Rewriting Scheme) so they pass SPF on `<your-domain>` and don't get spam-flagged at the recipient.

## DNS records

Run this from the host once the stack is up to get the canonical record set with your actual DKIM public key:

```bash
docker compose exec portal postern mta show-dns
```

The full record set looks like this (parameterised by `<your-domain>` and `<your-server-ip>`):

```
<your-domain>.                                  IN MX     10 mail.<your-domain>.
mail.<your-domain>.                             IN A      <your-server-ip>
mta-sts.<your-domain>.                          IN A      <your-nginx-ip>
<reverse>.in-addr.arpa.                         IN PTR    mail.<your-domain>.

<your-domain>.                                  IN TXT    "v=spf1 mx -all"
_dmarc.<your-domain>.                           IN TXT    "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:<MTA_ADMIN_EMAIL>; ruf=mailto:<MTA_ADMIN_EMAIL>"
_mta-sts.<your-domain>.                         IN TXT    "v=STSv1; id=<unix-ts>"
_smtp._tls.<your-domain>.                       IN TXT    "v=TLSRPTv1; rua=mailto:<MTA_ADMIN_EMAIL>"
s1._domainkey.<your-domain>.                    IN TXT    "v=DKIM1; k=rsa; p=<base64-pubkey>"
```

```{note}
When `rua=`/`ruf=` point at a mailbox **outside** the policy's domain (i.e., your `MTA_ADMIN_EMAIL` is on a different domain), RFC 7489 §7.1 requires the receiving domain to publish an opt-in TXT record at `<your-domain>._report._dmarc.<receiver-domain>`. Most mainstream providers (Gmail, Outlook) work without it; if you don't see DMARC aggregate reports after a week, this is why.
```

## DKIM rotation

DKIM keys rotate every `MTA_DKIM_ROTATION_DAYS` (default 180 days). Selectors toggle between `s1` and `s2` across rotations (configurable base via `MTA_DKIM_SELECTOR_PREFIX`).

### Manual rotation (when `DNS_PROVIDER=none`)

The provisioner generates the initial key on first start, then exits. To rotate:

1. `docker compose run --rm provisioner` — generates a new selector and key, writes the next state.
1. Run `docker compose exec portal postern mta show-dns` to see the new TXT record.
1. Publish it at your DNS provider; wait for propagation (~24h max).
1. The mta auto-picks up the new key on its next reload trigger.
1. After ~7 days of overlap, retire the old TXT record manually.

### Auto rotation (when `DNS_PROVIDER=<provider>`)

Set `DNS_PROVIDER` to one of: `cloudflare`, `route53`, `gandi`, `digitalocean`, `ovh`, `hetzner`, `linode`, `namecheap`. Then set the provider's native env vars in `.env`:

```{list-table}
---
header-rows: 1
---
* - Provider
  - Env vars
  - Notes
* - cloudflare
  - `CLOUDFLARE_API_TOKEN`
  -
* - route53
  - `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
  -
* - gandi
  - `GANDI_API_TOKEN`
  - Must be a Gandi **Personal Access Token** generated at <https://account.gandi.net/personal-access-tokens>. The legacy "Gandi API key" (sent as `X-Api-Key`) is no longer supported.
* - digitalocean
  - `DO_AUTH_TOKEN`
  -
* - ovh
  - `OVH_ENDPOINT`, `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY`
  -
* - hetzner
  - `HETZNER_API_TOKEN`
  - Must be a **Hetzner Cloud** API token (zones in the new Hetzner Cloud Console). Tokens for the deprecated DNS Console at `dns.hetzner.com` are no longer supported.
* - linode
  - `LINODE_TOKEN`
  -
* - namecheap
  - `NAMECHEAP_API_KEY`, `NAMECHEAP_API_USER`, `NAMECHEAP_CLIENT_IP`
  -
```

```{tip}
Use a token scoped to **only** the DNS zone for `<your-domain>`. The token lives only in the provisioner container (zero inbound listeners), but tighter scope is still better.
```

The provisioner runs the state machine `STABLE → PROPAGATING → OVERLAP (7-day grace) → RETIRING → STABLE` automatically. To force a rotation step on demand:

```bash
docker compose exec portal postern mta rotate-dkim
docker compose exec portal postern mta rotation-status
```

## Post-deploy verification

After bringing up the stack and publishing the DNS records:

```bash
# Sanity check from inside the portal
docker compose exec portal postern mta verify-dns
docker compose exec portal postern mta dnssec-status

# External validation (sends a probe to a public auth-checker)
docker compose exec mta sh -c 'echo -e "Subject: probe\n" | sendmail check-auth@verifier.port25.com'

# Inbound TLS posture
nmap --script ssl-enum-ciphers -p 25 mail.<your-domain>

# MTA-STS policy reachable
curl https://mta-sts.<your-domain>/.well-known/mta-sts.txt

# Trigger an OTP send via /login -- watch logs
docker compose logs -f mta
```

After a few days of running you should see DMARC aggregate reports landing in your `MTA_ADMIN_EMAIL` inbox.

## Troubleshooting

**mta is in a restart loop on first deploy.** Expected — DNS verification fails until the records are published. Read `docker compose logs mta` for the missing-record list (the DKIM TXT value is in there). Publish, wait for propagation, and the next restart succeeds.

**`postern mta verify-dns` fails on DKIM.** The provisioner generates the key, but you must publish the TXT record. Run `postern mta show-dns` to see the line; copy it to your DNS provider.

**Provisioner warns about "possible leftover records" after upgrading Postern.** The pre-upgrade DNS state did not record which of `<your-domain>` / `*.<your-domain>` / `mail.<your-domain>` / `mta-sts.<your-domain>` an earlier configuration published, so the upgrade leaves the FQDNs named in the warning untouched. Check your zone: if A/AAAA records exist there and you did not create them yourself, delete them at your DNS provider. Records for currently-enabled subsystems are unaffected.

**Forwarded DMARC reports go to spam at the receiver.** SRS rewriting should handle SPF alignment for forwarded mail. If your `MTA_ADMIN_EMAIL` provider is still flagging, set up the receiver-side opt-in TXT (RFC 7489 §7.1) — see the DNS records section above.

**Local development.** Set `MTA_VERIFY_DNS=false` and use `mkcert` for `mail.<dev-domain>` and `mta-sts.<dev-domain>` certs. With auto-rotation off (`DNS_PROVIDER=none`), the provisioner generates the initial key and exits cleanly. Dev setup details live in the development docs.

```{dropdown} Threat-model rationale
Why these specific choices:

- **mta and provisioner split.** Postfix has had RCEs historically. Keeping the DNS provider API token out of the container exposed on port 25 means a hypothetical RCE leaks the DKIM signing key (an operator can rotate to recover) but cannot redirect MX records or hijack ACME issuance.
- **`mta-submit` internal /29 network.** Postfix `mynetworks` is scoped to this subnet, not the shared `default` bridge. Only the portal joins it. Other containers on `default` (nginx, docker-proxy) cannot relay through mta even if compromised. The portal reaches submission through the `mta-submit` network alias (`SMTP_HOST=mta-submit`), not the bare `mta` name: `mta` is multi-homed and resolves to its default-network IP, which is outside `mynetworks` and is rejected.
- **DANE outbound + DNSSEC.** DANE TLSA records published by recipient MTAs are only meaningful if your sender validates DNSSEC. The mta runs Unbound on 127.0.0.1 with auto-trust-anchor for exactly this reason.
- **MTA-STS enforce mode.** Recipient MTA-STS policies are honored via postfix-mta-sts-resolver. Outbound TLS is then either DANE-validated, MTA-STS-enforced, or opportunistic — strictest available.
- **`milter_default_action = tempfail`.** If opendkim is down, mail queues. Sending unsigned mail from an MTA whose entire purpose is auth-aligned outbound would defeat DMARC `p=reject`.
- **Forwarding-only inbound.** Postern doesn't host an inbox. The four named addresses (postmaster, abuse, tls-rpt, the bounce local-part) virtual-alias to `MTA_ADMIN_EMAIL`; everything else is rejected at SMTP RCPT TO with no backscatter.
- **DNSSEC at the sending domain.** Without it, your DKIM/MTA-STS records can be tampered with upstream of any consumer. With it, tampering breaks the signature chain. The default `MTA_REQUIRE_DNSSEC=auto` infers your domain's signing status at startup and enforces the AD-bit check when applicable, so this protection is on by default for any operator whose registrar supports DNSSEC.
```
