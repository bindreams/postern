# Security model

This page maps Postern's security posture: what each layer defends, what it deliberately concedes, and which page carries the detailed threat-model discussion.

## Design principles

- **Single-tenant trust boundary.** One operator owns the host and everything on it; anyone with shell access to the host or any container is admin-equivalent. The model defends the perimeter — it does not defend containers from each other when the attacker *is* the operator. Cross-container isolation exists to contain external compromise (a Postfix RCE on port 25 must not yield the DNS provider token), not to police the operator.
- **Least privilege between components.** Each credential and capability lives in exactly one container: the DNS provider API token only in the provisioner, the DKIM signing key only in the mta, Docker API access only through a default-deny allow-list proxy. Internal networks are scoped the same way — only the portal sits on the mail-submission subnet that Postfix trusts for relaying.
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
  - Distroless image with no shell; read-only filesystem plus tmpfs; `no-new-privileges`; Docker API reached only through the docker-proxy's allow-list, over a private socket — never the raw socket.
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

Runtime-hardening detail (distroless portal, read-only filesystem, tini as PID 1, the docker-proxy's exact allow-list) lives in [architecture](development/architecture.md); the rationale for splitting the mta from the provisioner lives in [email delivery](deployment/email.md).

## The Docker API proxy

The portal creates and removes the `ss-*` tunnel containers through the Docker API, so it needs a path to the daemon. That path is the `docker-proxy` container, the only container that mounts the Docker socket. It is a pinned HAProxy socket proxy running a default-deny allow-list ([docker-proxy/](https://github.com/bindreams/postern/tree/main/docker-proxy)); a request that matches no route exactly is refused with a `403` that names the reason.

What the proxy guarantees:

- **One create shape.** `POST /containers/create` is accepted only for a body that equals, key for key, what the reconciler sends: the configured shadowsocks image (an exact string, not a prefix or tag family), one `SS_CONFIG` environment variable, exactly the two `postern.*` labels, the configured shadowsocks network, and a fixed hardening profile (all capabilities dropped, `no-new-privileges`, read-only root filesystem, 512 MiB of memory, 1024 processes, two tmpfs mounts). Names must match `ss-<24 hex>`. No other key is accepted at any depth.
- **No image changes.** The only image route is the inspect of the configured image. Pulling, importing, building, tagging, loading, committing, pushing and deleting images are all refused, so the reference the portal creates containers from cannot be moved by a request through the proxy.
- **Containers addressed by id are proven first.** Inspect, start, stop and remove of a container are forwarded only after the daemon itself reports that exact id carrying this deployment's `postern.managed` and `postern.instance` labels. An id the daemon does not know is answered `404`, as the daemon would; an id that exists but is not this deployment's is `403`. Containers of the other Postern services and of other deployments are therefore out of reach.
- **No read of another container's configuration.** No route returns a container's `Env` unless the container carries this deployment's labels. The reconciler reads a container it may not own (a name conflict) from the label-scoped list payload, which carries no `Env`.
- **No route that is not named.** Exec, attach, archive, logs, kill, restart, rename, update, events, volumes, networks (other than inspecting the shadowsocks network), swarm, plugins and system endpoints are refused by default, not by a deny list. The API version in the path must equal the daemon's current one.
- **No network.** The proxy runs with `network_mode: none`, a read-only root filesystem, no capabilities beyond the two it needs to create its socket, and no published port. The portal reaches it through a unix socket in a volume that only the proxy and the portal mount (the portal read-only). No other container can send it a request.
- **Fail closed.** A policy error, an unreadable request body, a daemon that cannot be asked, a missing configuration value or an unparseable reply all mean the request is refused.

What it does not cover, stated as limits:

- **The tunnel configuration is the portal's.** The portal chooses the `SS_CONFIG` of each tunnel, which `ssserver` interprets inside a capability-less, read-only, memory- and process-bounded container of the pinned image on the shadowsocks network. The proxy does not inspect it.
- **Resource count.** Each tunnel container is bounded; their number is not. The reconciler's orphan sweep removes extras on its next pass.
- **The proxy holds the Docker socket.** A flaw in HAProxy or in the allow-list is a flaw in the isolation. The base image is pinned by digest, bumps are not merged automatically, and the policy has unit, wire-contract and end-to-end tests.
- **Reads that remain.** The portal can read the daemon version, the shadowsocks network (names, ids and addresses of attached containers, no environment), this deployment's own container list, and the labels, state and mounts of the one container with a given `ss-<24 hex>` name, including another deployment's tunnel; none of these returns an environment.
- **Instance identity.** Two Postern deployments on one Docker daemon are told apart by their instance id. With equal ids each treats the other's labelled containers as its own. The id is `INSTANCE_ID`, else the compose project name; the portal logs `Resolved own instance id to ...` at startup and the two deployments must show different values (see [operations](operations/index.md#instance-identity)).
- **Containers that already exist.** A container created by an older version is not detected or migrated. Ownership is the two labels alone: one without them is refused on every id route; one that carries them is served like any other, whatever its hardening, until it is replaced by hand.

This is an allow-list in front of the Docker API, not a sandbox.

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
