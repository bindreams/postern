# CLI reference

The `postern` admin CLI ships inside the portal image ([cli.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/cli.py)). There is no self-serve signup and no admin API — users and connections are managed here. Invoke every command as:

```bash
docker compose exec portal postern <command>
```

State-mutating commands (`connection add`/`enable`/`disable`, `user disable`/`delete`) write the reconcile trigger file (`/data/.reconcile-now`), so the reconciler applies the change within seconds instead of waiting for its next poll (default 60 s). Verification commands exit non-zero on failure, so they are safe to script.

## Users

Create and manage portal accounts, identified by email.

### postern user add

`postern user add NAME EMAIL` — creates a user and prints their id. Does not trigger a reconcile: a user with no connections needs no container.

### postern user list

Lists all users (id, name, email).

### postern user disable

`postern user disable EMAIL` — disables every connection belonging to the user (the user record and connections remain). Exits 1 if the email is unknown. Triggers a reconcile.

### postern user delete

`postern user delete EMAIL` — deletes the user and all their connections. Exits 1 if the email is unknown. Triggers a reconcile.

## Connections

Each connection is one tunnel: a 24-hex-character path token, a random password, and a plugin choice.

### postern connection add

`postern connection add USER_EMAIL LABEL` — creates a connection for an existing user (exits 1 if the email is unknown), generating the path token and password. Triggers a reconcile, which starts the tunnel container.

`--plugin` selects the SIP003 plugin: `v2ray-plugin` (default) or `galoshes`, which adds UDP support via yamux:

```bash
docker compose exec portal postern connection add alice@example.com "phone" --plugin galoshes
```

### postern connection list

Lists connections (id, label, plugin, enabled/disabled). `--user-email EMAIL` filters by user and exits 1 if the email is unknown.

### postern connection disable

`postern connection disable ID` — disables a connection; exits 1 if the id is unknown. Triggers a reconcile, which removes the tunnel container.

### postern connection enable

`postern connection enable ID` — re-enables a disabled connection; exits 1 if the id is unknown. Triggers a reconcile.

## Reconciler

The portal continuously reconciles tunnel containers against the database.

### postern reconcile

Wakes the reconciler immediately instead of waiting for the next poll, by creating the trigger file it watches. Equivalent to `touch /data/.reconcile-now`, but works in the distroless production image, which ships no shell or busybox.

## Built-in MTA

Inspect and drive the built-in mail subsystem — see [Email](../deployment/email.md) for setup.

### postern mta show-dns

Prints the DNS records to publish for the built-in MTA, covering every active DKIM selector. Warns on stderr for selectors whose key files are missing.

### postern mta verify-dns

Resolves and checks every required MTA DNS record; exits 1 if any check fails, including when no DKIM keys exist yet (bring the stack up first so the provisioner generates the initial keypair). DNSSEC is checked via external validating resolvers (the CLI has no local validating resolver): with `MTA_REQUIRE_DNSSEC=true` a DNSSEC failure fails the command; with `auto` the detected outcome (enforce or skip) is only reported.

### postern mta rotate-dkim

Requests a manual DKIM rotation step by writing the `.rotate-dkim` trigger file; the provisioner advances the rotation state machine on its next poll.

### postern mta rotation-status

Shows the DKIM rotation state machine: state, schema version, active selectors, retiring selector (if any), last and next rotation times, and consecutive failures (if any).

### postern mta dnssec-status

Checks whether the sending domain is DNSSEC-signed, using external validating resolvers; exits 1 if not signed. With `MTA_REQUIRE_DNSSEC=auto` it also reports whether enforcement would be applied or skipped at MTA startup.

## Certificates

Inspect and drive TLS certificates — see [Certificates](../deployment/certificates.md) for the two deployment modes (BYO and auto-renewal).

### postern cert show

Shows the installed certificate: path, issuer, SAN list, validity window, and days until expiry, plus the renewal state and last issuance time when `state.json` is present. Works in both BYO and auto-renewal modes; exits 1 if no certificate is installed yet.

### postern cert verify

Runs five checks and exits 1 on any failure: the cert file parses; the SAN set is exactly `{<domain>, *.<domain>}`; the cert nginx is serving on port 443 matches the on-disk cert; the domain's CAA record (if one exists) includes `letsencrypt.org`; and `state.json` (if present) agrees with the on-disk SANs.

### postern cert renew

Triggers an immediate renewal by writing the `.renew-cert` trigger file. Works only in auto-renewal mode (`CERT_RENEWAL=true` with the cert volume mounted); exits 1 otherwise.

### postern cert renewal-status

Prints the certificate renewal state machine: state, SANs, expiry, last issuance and attempt times, consecutive failures, ACME directory, and — when the state is `FAILED` — the state that failed.

## DNS records

Manage the A/AAAA/CAA records the cert-renewal DNS reconciler publishes.

### postern dns show

Shows the records the reconciler publishes — A/AAAA for `<domain>`, `*.<domain>`, and `mail.<domain>` (AAAA only when `PUBLIC_IPV6` is set) plus the `CAA 0 issue "letsencrypt.org"` record — alongside the last-published values and reconciliation status from `state.json`.

### postern dns verify

Checks live DNS against those expected records; requires `CERT_RENEWAL=true` and exits 1 on drift. The wildcard is probed through a synthetic sub-name (resolvers only expand wildcards for unmatched names). Also fails if the DNS reconciler has never completed a tick.

### postern dns publish

Triggers the MTA-records reconciler to publish on the next provisioner tick instead of waiting for its 1-hour cadence, by writing the `.publish-mta-dns` trigger file; the provisioner picks it up within `TRIGGER_POLL_SECONDS` (5 s by default).

## ECH

Check whether the front actually serves Encrypted Client Hello — see [Enabling ECH](../deployment/edge.md#enabling-ech). DoH-only; the portal holds no Cloudflare token.

### postern ech verify

Queries the apex HTTPS record over DoH and confirms an `ech=` SvcParam is present. Requires `ECH_ENABLED=true` (errors otherwise). Exits 0 when present, 1 when absent, 2 when inconclusive.

### postern ech show

Prints the ECH settings (`domain`, `ech_enabled`, `ech_doh_url`, `edge_profile`, `dns_provider`, `edge_cf_manage_zone_ech`), the provisioner-written zone-ECH state (last-enabled time, consecutive failures, and the verbatim last Cloudflare error), and the live DoH front-serving status.

## Edge

Inspect the Cloudflare edge's zone-wide settings that Postern manages — see [Zone-wide settings Postern manages](../deployment/edge.md#zone-wide-settings-postern-manages).

### postern edge ssl-status

Prints the SSL/TLS-mode settings (`edge_cf_manage_ssl_mode`, `edge_cf_ssl_mode` target) and the provisioner-written convergence state: when the zone `ssl-set` last succeeded, the actual mode Cloudflare left the zone in (`zone_ssl_current_mode`, which may sit below the target under raise-only), the consecutive-failure count, and the verbatim last Cloudflare error. Reads the shared state file only; the portal holds no Cloudflare token.

## Diagnostics

One command verifies the whole deployment end to end.

### postern doctor

Verifies operator prerequisites and live record state in three sections: **external** — records Postern cannot publish itself (DS at the registrar, PTR at the VPS provider); **postern-managed** — live DNS matches what Postern claims to publish; **connectivity** — port 443 serves a valid certificate and port 25 is reachable. `--external-only`, `--postern-only`, or `--connectivity-only` restricts the run to one section (at most one may be set; exits 2 otherwise); `--json` emits structured JSON instead of the human-readable table.

```{tip}
`postern doctor` exits non-zero on any failed check, so it works as a bring-up gate or a CI smoke step.
```
