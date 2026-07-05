# Security model

This page maps Postern's security posture: what each layer defends, what it deliberately concedes, and which page carries the detailed threat-model discussion.

## Design principles

- **Single-tenant trust boundary.** One operator owns the host and everything on it; anyone with shell access to the host or any container is admin-equivalent. The model defends the perimeter — it does not defend containers from each other when the attacker *is* the operator. Cross-container isolation exists to contain external compromise (a Postfix RCE on port 25 must not yield the DNS provider token), not to police the operator.
- **Least privilege between components.** Each credential and capability lives in exactly one container: the DNS provider API token only in the provisioner, the DKIM signing key only in the mta, Docker API access only through a verb-scoped proxy. Internal networks are scoped the same way — only the portal sits on the mail-submission subnet that Postfix trusts for relaying.
- **Fail closed.** When a safety dependency is missing, Postern stops instead of degrading: outbound mail queues rather than leaving unsigned when the DKIM signer is down, the MTA refuses to start while required DNS records are absent, login cannot complete over plain HTTP, and a misconfigured edge profile is rejected at startup rather than discovered at runtime.

## Component posture

```{list-table}
---
header-rows: 1
---
* - Component
  - Exposure
  - Containment
* - nginx
  - Public `:443` / `:80`
  - TLS termination; per-IP rate limiting on the login routes; `Content-Security-Policy: default-src 'self'` on every portal response.
* - portal
  - Internal only (no published ports)
  - Distroless image with no shell; read-only filesystem plus tmpfs; `no-new-privileges`; Docker API reached only through a verb-scoped docker-proxy — never the raw socket.
* - `ss-*` tunnels
  - Reached only via nginx path tokens
  - One container per connection; deliberately logless.
* - mta
  - Public `:25`
  - All capabilities dropped except a minimal set; holds the DKIM key but no DNS credentials.
* - provisioner
  - Zero inbound listeners
  - Sole holder of the DNS provider token and the ACME account.
```

Runtime-hardening detail (distroless portal, read-only filesystem, tini as PID 1, the docker-proxy's exact permission set) lives in [architecture](development/architecture.md); the rationale for splitting the mta from the provisioner lives in [email delivery](deployment/email.md).

## Authentication

- Login is by emailed one-time code — no passwords to phish or reuse, and no self-serve signup: the operator creates every account via the [CLI](operations/cli.md).
- Codes are 6 digits, short-lived (10 minutes by default), invalidated after 5 wrong attempts, and rate-limited per email (3 active codes per 15-minute window), with nginx's per-IP rate limit in front.
- Codes are stored hashed and verified with a constant-time comparison ([auth.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/auth.py), [db.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/db.py)).
- Unknown emails get a dummy OTP row, so neither response timing nor rate-limit behavior reveals which addresses are registered.
- Sessions are secure-cookie only; login cannot complete over plain HTTP.
- There is no public API surface: OpenAPI endpoints are disabled, and connections cannot be created over HTTP at all.

## Tunnel identification resistance

Tunnels are ordinary WebSocket + TLS on `:443`, addressed by 24-hex-character path tokens (96 bits of entropy), and probes of wrong paths receive indistinguishable-by-design responses — an active scanner cannot confirm that `/t/` paths are special.

```{important}
The `/t/` uniformity work defends against on-path fingerprinting; it does **not** hide tokens from a TLS-terminating CDN. If you front Postern with Cloudflare, the tokens are visible to Cloudflare — see below.
```

## Email posture

The built-in MTA ships fail-closed mail authentication: DMARC `p=reject` with strict alignment, auto-rotated DKIM keys, MTA-STS and TLS-RPT, DANE-validating outbound TLS, and DNSSEC enforcement at startup on signed domains. If the DKIM signer is down, outbound mail queues rather than being sent unsigned. Setup and the full threat-model rationale: [email delivery](deployment/email.md).

## Edge fronting: what Cloudflare sees

Fronting with Cloudflare hides the SNI from the on-path network, but reveals connection metadata — path tokens, timing, volume — to Cloudflare, which terminates the outer TLS. The tunnel payload stays end-to-end encrypted between the client and its tunnel container; Cloudflare only relays ciphertext. The trade is deliberate and per-deployment: hide the domain from the censor in exchange for metadata visibility at a party outside the censor's jurisdiction. Details, caveats, and the origin-lockdown checklist: [fronting with a CDN edge](deployment/edge.md).

## Reporting a vulnerability

Report security issues by opening an issue in the [GitHub repository](https://github.com/bindreams/postern) or contacting the repository owner directly for sensitive reports; there is no formal bounty program.
