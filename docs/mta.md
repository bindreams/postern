# Built-in MTA

Postern ships a self-hosted email stack as the default `with-mta` Compose profile. It eliminates the third-party metadata leak that comes with using a relay like Resend or SES — no provider sees who your users are or when they log in.

This guide walks through what to set up before bringing up the stack, how the security posture is constructed, and the post-deploy checklist.

If you'd rather not run your own MTA: comment `COMPOSE_PROFILES=with-mta` in `.env` and set `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` to your provider. The rest of this document doesn't apply.

## Architecture

The MTA is split across two containers, deliberately:

- **`mta`** — Postfix on public port 25 (in/out), submission on internal-only port 587. Runs opendkim (signs outbound), Unbound (DNSSEC validation that DANE outbound requires), postsrsd (SRS rewriting for forwarded reports), and postfix-mta-sts-resolver (consumes recipient MTA-STS policies). Holds the DKIM signing key.
- **`provisioner`** — Generates DKIM keys, advances the rotation state machine, talks to your DNS provider's API to publish/retire TXT records. Holds the DNS provider API token. Has zero inbound listeners.

The split is the threat-model story: a Postfix RCE on public port 25 cannot escalate to DNS-record hijack because the credentials live in a different container.

## What you need before bringing up the stack

### 1. A VPS where port 25 outbound works

Most cloud providers block port 25 outbound by default to prevent spam from compromised tenants:

- **AWS, GCP, OVH, DigitalOcean (new accounts)**: blocked. AWS allows it after a request form; GCP doesn't allow it on Compute Engine at all.
- **Hetzner, Vultr, BuyVM, Linode, Scaleway**: usually allowed.

If your VPS blocks port 25 outbound, the built-in MTA cannot deliver mail. Use a third-party SMTP relay instead.

### 2. Reverse DNS (PTR) on your IP

Set the rDNS for your public IP to `mail.<your-domain>`. This is configured at the VPS provider's panel — there's no API for it from inside Postern.

Verify with:

```bash
dig -x <your-ip> +short
# expect: mail.<your-domain>.
```

### 3. Three TLS certificates

The MTA needs:

- `<your-domain>` — used by nginx for the portal (already required).
- `mail.<your-domain>` — used by Postfix on port 25 (smtpd_tls_cert_file).
- `mta-sts.<your-domain>` — used by nginx to serve the MTA-STS policy file. RFC 8461 §3.3 mandates HTTPS with a publicly-trusted CA.

A single multi-SAN cert covering all three works:

```bash
certbot certonly --standalone \
    -d <your-domain> \
    -d mail.<your-domain> \
    -d mta-sts.<your-domain>
```

Or three separate certs:

```bash
certbot certonly --standalone --cert-name <your-domain>           -d <your-domain>
certbot certonly --standalone --cert-name mail.<your-domain>      -d mail.<your-domain>
certbot certonly --standalone --cert-name mta-sts.<your-domain>   -d mta-sts.<your-domain>
```

Postern bind-mounts `/etc/letsencrypt` into the nginx and mta containers; whichever layout you pick must place the certs at the standard paths (`/etc/letsencrypt/live/<host>/fullchain.pem` etc).

### 4. DNSSEC on your sending domain (strongly recommended; auto-detected)

Without DNSSEC, MTA-STS and DKIM records can be silently tampered with by anyone with upstream-DNS access. For a privacy-motivated VPN portal this is the single most impactful security control after eliminating the third-party relay.

Most modern registrars support DNSSEC for common TLDs (including `.me`):

- **Cloudflare Registrar, Gandi, Namecheap, Porkbun, Hover, INWX**: supported, manageable in the registrar UI.
- **GoDaddy, some others**: historically patchy. Transfer to a supported registrar if needed.

Verify with:

```bash
dig +dnssec DS <your-domain>
# expect: a signed RRset, AD flag set
```

`MTA_REQUIRE_DNSSEC` is a tri-state with default `auto`:

- `auto` (default) — at startup, the mta probes whether your sending domain is DNSSEC-signed. If yes, the AD-bit check is enforced (mta refuses to start if the AD bit is missing). If no, the startup check is skipped, but Unbound continues to validate at runtime for DANE on outbound TLS. Most operators want this.
- `true` — always require. The mta refuses to start when the AD bit is missing, even on unsigned domains. Use this for fail-closed production where an unsigned-domain misconfiguration must be caught loudly.
- `false` — skip the startup check entirely. Use only for dev / CI.

### 5. An external mailbox for technical reports

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
postern-<YYYY-MM>._domainkey.<your-domain>.     IN TXT    "v=DKIM1; k=rsa; p=<base64-pubkey>"
```

Note on DMARC reports: when `rua=`/`ruf=` point at a mailbox **outside** the policy's domain (i.e., your `MTA_ADMIN_EMAIL` is on a different domain), RFC 7489 §7.1 requires the receiving domain to publish an opt-in TXT record at `<your-domain>._report._dmarc.<receiver-domain>`. Most mainstream providers (Gmail, Outlook) work without it; if you don't see DMARC aggregate reports after a week, this is why.

## DKIM rotation

DKIM keys rotate every `MTA_DKIM_ROTATION_DAYS` (default 180 days). Selectors are date-suffixed: `postern-2026-04`, `postern-2026-10`, etc.

### Manual rotation (when `MTA_DNS_PROVIDER=none`)

The provisioner generates the initial key on first start, then exits. To rotate:

1. `docker compose run --rm provisioner` — generates a new selector and key, writes the next state.
2. Run `docker compose exec portal postern mta show-dns` to see the new TXT record.
3. Publish it at your DNS provider; wait for propagation (~24h max).
4. The mta auto-picks up the new key on its next reload trigger.
5. After ~7 days of overlap, retire the old TXT record manually.

This is a once-per-six-months chore.

### Auto rotation (when `MTA_DNS_PROVIDER=<provider>`)

Set `MTA_DNS_PROVIDER` to one of: `cloudflare`, `route53`, `gandi`, `digitalocean`, `ovh`, `hetzner`, `linode`, `namecheap`. Then set the provider's native env vars in `.env`:

| Provider     | Env vars                                                                            |
| ------------ | ----------------------------------------------------------------------------------- |
| cloudflare   | `CLOUDFLARE_API_TOKEN`                                                              |
| route53      | `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`                          |
| gandi        | `GANDI_API_TOKEN`                                                                   |
| digitalocean | `DO_AUTH_TOKEN`                                                                     |
| ovh          | `OVH_ENDPOINT`, `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY` |
| hetzner      | `HETZNER_API_TOKEN`                                                                 |
| linode       | `LINODE_TOKEN`                                                                      |
| namecheap    | `NAMECHEAP_API_KEY`, `NAMECHEAP_API_USER`, `NAMECHEAP_CLIENT_IP`                    |

Use a token scoped to **only** the DNS zone for `<your-domain>`. The token lives only in the provisioner container (zero inbound listeners), but tighter scope is still better.

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

**Forwarded DMARC reports go to spam at the receiver.** SRS rewriting should handle SPF alignment for forwarded mail. If your `MTA_ADMIN_EMAIL` provider is still flagging, set up the receiver-side opt-in TXT (RFC 7489 §7.1) — see the DNS records section above.

**Local development.** Set `MTA_VERIFY_DNS=false` and use `mkcert` for `mail.<dev-domain>` and `mta-sts.<dev-domain>` certs (extends the mkcert pattern in [CONTRIBUTING.md](../CONTRIBUTING.md#running-the-stack-locally)). With auto-rotation off (`MTA_DNS_PROVIDER=none`), the provisioner generates the initial key and exits cleanly.

## Threat-model rationale

Why these specific choices:

- **mta and provisioner split.** Postfix has had RCEs historically. Keeping the DNS provider API token out of the container exposed on port 25 means a hypothetical RCE leaks the DKIM signing key (an operator can rotate to recover) but cannot redirect MX records or hijack ACME issuance.
- **`mta-submit` internal /29 network.** Postfix `mynetworks` is scoped to this subnet, not the shared `default` bridge. Only the portal joins it. Other containers on `default` (nginx, docker-proxy) cannot relay through mta even if compromised.
- **DANE outbound + DNSSEC.** DANE TLSA records published by recipient MTAs are only meaningful if your sender validates DNSSEC. The mta runs Unbound on 127.0.0.1 with auto-trust-anchor for exactly this reason.
- **MTA-STS enforce mode.** Recipient MTA-STS policies are honored via postfix-mta-sts-resolver. Outbound TLS is then either DANE-validated, MTA-STS-enforced, or opportunistic — strictest available.
- **`milter_default_action = tempfail`.** If opendkim is down, mail queues. Sending unsigned mail from an MTA whose entire purpose is auth-aligned outbound would defeat DMARC `p=reject`.
- **Forwarding-only inbound.** Postern doesn't host an inbox. The four named addresses (postmaster, abuse, tls-rpt, the bounce local-part) virtual-alias to `MTA_ADMIN_EMAIL`; everything else is rejected at SMTP RCPT TO with no backscatter.
- **DNSSEC at the sending domain.** Without it, your DKIM/MTA-STS records can be tampered with upstream of any consumer. With it, tampering breaks the signature chain. The default `MTA_REQUIRE_DNSSEC=auto` infers your domain's signing status at startup and enforces the AD-bit check when applicable, so this protection is on by default for any operator whose registrar supports DNSSEC.

## Testing the stack

### Hermetic e2e suite

The `e2e_mta` suite under [portal/tests/e2e/](../portal/tests/e2e/) boots the production `mta` + `provisioner` images alongside a mailpit "recipient MTA" — no real DNS, no port-25 outbound. It verifies DKIM signing + verification, postmaster forwarding, milter tempfail behavior, and a handful of architectural invariants (opendkim UID/GID, internal-network flag, Postfix listener health). Runs on every PR. See [CONTRIBUTING.md §End-to-end tests](../CONTRIBUTING.md#end-to-end-tests) for the bring-up command.

The hermetic suite is a working reference for `MTA_VERIFY_DNS=false` + `MTA_DNS_PROVIDER=none` deployments.

### Real-infra test-domain setup

The `e2e_mta_real` suite ([portal/tests/e2e/test_mta_real.py](../portal/tests/e2e/test_mta_real.py)) covers the two boundaries the hermetic suite cannot exercise:

1. **libdns round-trip** (`test_libdns_provider_round_trip`) — the provisioner's Go binary actually publishes and retires a TXT record via the configured provider, and the change becomes visible via public resolvers. Pins the libdns wrapper against API breakage.
2. **DNSSEC AD-bit detection** (`test_dnssec_status_detects_signed_domain`) — `postern.mta.dnssec.check()` returns clean against a known-signed zone (default `iana.org`).

End-to-end `mta_dns.verify()` against fully-configured baseline records (MX/SPF/DMARC/MTA-STS/TLS-RPT + a publicly-trusted MTA-STS HTTPS endpoint) is intentionally **not** in this tier. That much zone setup is incompatible with a CI job that runs on every PR; the full pipeline is exercised by the `e2e_mta_outbound` (VPS-only) suite.

To run the libdns round-trip you need a domain you control + provider creds. The test publishes and retires a single TXT record (`postern-e2e-test._domainkey.<domain>`) — no other records are required, and nothing else on the zone is touched.

Required env vars (each missing one produces a fail-loud message pointing back here):

| Var                                | Notes                                                                                                                                                                                                                                                                            | Default    |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `MTA_TEST_DOMAIN`                  | A domain you control. Only the `postern-e2e-test._domainkey.<domain>` TXT is published/retired during the test.                                                                                                                                                                  | (required) |
| `MTA_TEST_DNS_PROVIDER`            | One of: `cloudflare`, `route53`, `gandi`, `digitalocean`, `ovh`, `hetzner`, `linode`, `namecheap`.                                                                                                                                                                               | (required) |
| Provider creds                     | Provider-native env: `CLOUDFLARE_API_TOKEN` for cloudflare; `AWS_REGION` + `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` for route53; `GANDI_API_TOKEN`; `DO_AUTH_TOKEN`; etc. (See [provisioner/postern-dns/main.go](../provisioner/postern-dns/main.go) for the full mapping.) | (required) |
| `MTA_TEST_DNS_PROPAGATION_SECONDS` | Wait between `txt-set` and the public-resolver query.                                                                                                                                                                                                                            | `60`       |
| `MTA_TEST_DNSSEC_DOMAIN`           | The DNSSEC-status oracle for `test_dnssec_status_detects_signed_domain`. No env required for the default.                                                                                                                                                                        | `iana.org` |

Run:

```bash
docker build -f provisioner/Dockerfile -t local/postern-provisioner .
cd portal
uv run pytest -m e2e_mta_real -v --timeout=300
```

In CI: the `e2e-mta-real` job in [.github/workflows/test.yaml](../.github/workflows/test.yaml) runs on every PR and on push-to-main once the maintainer has populated the corresponding `vars.MTA_TEST_*` repo variables and `secrets.<provider>_*` repo secrets. Fork PRs see no secrets (GitHub default) and fail loud on the missing-env assertion — that's expected. The job has `concurrency: e2e-mta-real` so PRs serialize on the shared `postern-e2e-test` DKIM selector instead of racing on publish/cleanup.

### Outbound suite (VPS-only)

The `e2e_mta_outbound` suite ([portal/tests/e2e/test_mta_outbound.py](../portal/tests/e2e/test_mta_outbound.py)) does end-to-end OTP delivery over real outbound port 25 to a real recipient mailbox (polled via IMAP). Not run on GHA hosted runners (port 25 blocked); run locally on a VPS that allows outbound 25:

```bash
export MTA_TEST_DOMAIN=mta-test.example.com
export MTA_TEST_ADMIN_EMAIL=admin@something-else.example.com
export MTA_TEST_DNS_PROVIDER=cloudflare
export CLOUDFLARE_API_TOKEN=...
export MTA_TEST_RECIPIENT_EMAIL=test-mailbox@maintainer.example.com
export MTA_TEST_RECIPIENT_IMAP_HOST=imap.maintainer.example.com
export MTA_TEST_RECIPIENT_IMAP_USER=test-mailbox
export MTA_TEST_RECIPIENT_IMAP_PASS=...
export POSTERN_E2E_TLS_DIR=/etc/letsencrypt/live/${MTA_TEST_DOMAIN}
uv run pytest -m e2e_mta_outbound -v --timeout=600
```

A follow-up issue tracks adding a self-hosted GHA runner labeled `port25-ok` for this suite.

## Limitations / planned follow-ups

- **Ed25519 DKIM secondary keys** (RFC 8463). RSA-2048 is universally supported; a secondary Ed25519 key would help with newer receivers but isn't blocking.
- **Automatic Let's Encrypt cert renewal** for `mail.<domain>` and `mta-sts.<domain>` via the same provisioner + libdns providers. Tracked separately. For now, run certbot on the host.
- **DNSSEC TLSA on the sending side.** If your domain is DNSSEC-signed, you can additionally publish a TLSA record at `_25._tcp.mail.<domain>` so receivers can DANE-validate inbound mail to you. Not currently auto-managed.
