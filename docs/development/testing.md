---
orphan: true
---

# Testing the stack

## Hermetic e2e suite

The `e2e_mta` suite under [portal/tests/e2e/](https://github.com/bindreams/postern/tree/main/portal/tests/e2e) boots the production `mta` + `provisioner` images alongside a mailpit "recipient MTA" — no real DNS, no port-25 outbound. It verifies DKIM signing + verification, postmaster forwarding, milter tempfail behavior, and a handful of architectural invariants (opendkim UID/GID, internal-network flag, Postfix listener health). Runs on every PR. See [CONTRIBUTING.md §End-to-end tests](https://github.com/bindreams/postern/blob/main/CONTRIBUTING.md) for the bring-up command.

The hermetic suite is a working reference for `MTA_VERIFY_DNS=false` + `DNS_PROVIDER=none` deployments.

## Real-infra test-domain setup

The `e2e_mta_real` suite ([portal/tests/e2e/test_mta_real.py](https://github.com/bindreams/postern/blob/main/portal/tests/e2e/test_mta_real.py)) covers the two boundaries the hermetic suite cannot exercise:

1. **libdns round-trip** (`test_libdns_provider_round_trip`) — the provisioner's Go binary actually publishes and retires a TXT record via the configured provider, and the change becomes visible via public resolvers. Pins the libdns wrapper against API breakage.
1. **DNSSEC AD-bit detection** (`test_dnssec_status_detects_signed_domain`) — `postern.mta.dnssec.check()` returns clean against a known-signed zone (default `iana.org`).

End-to-end `mta_dns.verify()` against fully-configured baseline records (MX/SPF/DMARC/MTA-STS/TLS-RPT + a publicly-trusted MTA-STS HTTPS endpoint) is intentionally **not** in this tier. That much zone setup is incompatible with a CI job that runs on every PR; the full pipeline is exercised by the `e2e_mta_outbound` (VPS-only) suite.

To run the libdns round-trip you need a domain you control + provider creds. The test publishes and retires a single TXT record (`postern-e2e-test._domainkey.<domain>`) — no other records are required, and nothing else on the zone is touched.

Required env vars (each missing one produces a fail-loud message pointing back here):

| Var                                | Notes                                                                                                                                                                                                                                                                                                                        | Default    |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `MTA_TEST_DOMAIN`                  | A domain you control. Only the `postern-e2e-test._domainkey.<domain>` TXT is published/retired during the test.                                                                                                                                                                                                              | (required) |
| `MTA_TEST_DNS_PROVIDER`            | One of: `cloudflare`, `route53`, `gandi`, `digitalocean`, `ovh`, `hetzner`, `linode`, `namecheap`.                                                                                                                                                                                                                           | (required) |
| Provider creds                     | Provider-native env: `CLOUDFLARE_API_TOKEN` for cloudflare; `AWS_REGION` + `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` for route53; `GANDI_API_TOKEN`; `DO_AUTH_TOKEN`; etc. (See [provisioner/postern-dns/main.go](https://github.com/bindreams/postern/blob/main/provisioner/postern-dns/main.go) for the full mapping.) | (required) |
| `MTA_TEST_DNS_PROPAGATION_SECONDS` | Wait between `txt-set` and the public-resolver query.                                                                                                                                                                                                                                                                        | `60`       |
| `MTA_TEST_DNSSEC_DOMAIN`           | The DNSSEC-status oracle for `test_dnssec_status_detects_signed_domain`. No env required for the default.                                                                                                                                                                                                                    | `iana.org` |

Run:

```bash
docker build -f provisioner/Dockerfile -t local/postern-provisioner .
cd portal
uv run pytest -m e2e_mta_real -v --timeout=300
```

In CI: the `e2e-mta-real` job in [.github/workflows/test.yaml](https://github.com/bindreams/postern/blob/main/.github/workflows/test.yaml) runs on every PR and on push-to-main once the maintainer has populated the corresponding `vars.MTA_TEST_*` repo variables and `secrets.<provider>_*` repo secrets. Fork PRs see no secrets (GitHub default) and fail loud on the missing-env assertion — that's expected. The job has `concurrency: e2e-mta-real` so PRs serialize on the shared `postern-e2e-test` DKIM selector instead of racing on publish/cleanup.

## Outbound suite (VPS-only)

The `e2e_mta_outbound` suite ([portal/tests/e2e/test_mta_outbound.py](https://github.com/bindreams/postern/blob/main/portal/tests/e2e/test_mta_outbound.py)) does end-to-end OTP delivery over real outbound port 25 to a real recipient mailbox (polled via IMAP). Not run on GHA hosted runners (port 25 blocked); run locally on a VPS that allows outbound 25:

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
