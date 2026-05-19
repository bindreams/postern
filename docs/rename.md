# Renaming the deployment hostname

Use this runbook when you need to change `DOMAIN` (e.g. moving from a production hostname to a staging one, or vice versa). The procedure preserves `postern-data` (portal DB), `postern-mta-data` (DKIM keys and rotation state), and `postern-mta-queue` (in-flight mail).

`DOMAIN` flows into nginx templates (rendered at container start), `mail.${DOMAIN}` MTA hostname, the wildcard TLS cert SAN set `{<domain>, *.<domain>}`, Traefik's `HostSNI(...)` label, and every DNS record the provisioner publishes (apex/wildcard A/AAAA/CAA, MX, SPF, DMARC, MTA-STS, TLS-RPT, TLSA, DKIM). Most of this is automatic on restart, but three things are not:

1. **Provisioner state files** keep `last_published_*` markers tied to the OLD FQDN. On domain change the reconcilers compute new FQDNs but their drift logic compares against stale `last_published_*` values, so they would not republish for the new domain. Reset:
   - `/etc/letsencrypt/state.json` (cert state)
   - `/etc/letsencrypt/dns_records_state.json` (apex/wildcard A/AAAA/CAA reconciler)
   - `/var/lib/opendkim/mta_records_state.json` (MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA reconciler)
2. **DKIM TXT for the new FQDN must be published by hand.** The rotation state machine in `provisioner/entrypoint.py` only publishes during `STABLE -> PROPAGATING` (i.e. on rotation). The MTA-records reconciler explicitly excludes DKIM. Mirror the first-deploy bootstrap and publish via `postern-dns txt-set`.
3. **OLD records at `*.<old-domain>`** are not auto-retired — the deletion logic compares record values, not FQDNs. Delete them via your DNS provider's API.

Reverse DNS (PTR) is set at the VPS provider control panel and has no API from inside Postern.

## Prerequisites

- DNS provider API token with zone DNS edit (publish + delete).
- VPS provider panel access for PTR.
- Acknowledged downtime window — there is no zero-downtime path for this.

## 0. Pre-flight (read-only)

Verify the token, resolve the zone id, and inventory every record at or below the OLD domain. These commands assume Cloudflare; substitute your provider's API.

```bash
cd <postern-checkout>
CLOUDFLARE_API_TOKEN=$(grep -E '^CLOUDFLARE_API_TOKEN=' .env | cut -d= -f2-)

curl -sS -X GET \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  | jq -e '.success == true and (.result.status == "active")'

OLD_DOMAIN=hole.binarydreams.me
NEW_DOMAIN=hole-stgn.binarydreams.me
ZONE=binarydreams.me

ZONE_ID=$(curl -sS -X GET \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  "https://api.cloudflare.com/client/v4/zones?name=${ZONE}" \
  | jq -r '.result[0].id')

mkdir -p .tmp/rename
curl -sS -X GET \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?per_page=500" \
  | jq -r --arg old "${OLD_DOMAIN}" '.result[]
      | select(.name == $old or (.name|endswith("." + $old)))
      | [.id, .type, .name, .content] | @tsv' \
  > .tmp/rename/old-records.tsv

# The DKIM TXT MUST be in the deletion list. If it is not, the public key
# stays in DNS signing nothing -- a confusing failure mode for the next
# deploy.
grep -F "_domainkey.${OLD_DOMAIN}" .tmp/rename/old-records.tsv \
  || { echo "ERROR: no _domainkey record for the old domain"; exit 1; }

# Save the current DKIM pubkey so step 5 can republish at the new FQDN
# without re-keying. Run as opendkim (uid 110) to read the 0600 .private
# sibling if needed; the .txt is world-readable.
docker compose exec provisioner \
  cat /var/lib/opendkim/$(docker compose exec provisioner sh -c \
    'jq -r ".active_selectors[0]" /var/lib/opendkim/state.json').txt \
  > .tmp/rename/dkim-pubkey.raw
```

## 1. Stop the stack

```bash
docker compose down   # no -v / --volumes; named volumes must survive
```

## 2. Reset provisioner state files

```bash
docker run --rm --network none -v postern-letsencrypt:/data alpine:3 sh -c \
  'rm -f /data/state.json /data/dns_records_state.json'

docker run --rm --network none -v postern-mta-data:/data alpine:3 sh -c \
  'rm -f /data/mta_records_state.json'
```

DKIM `state.json` and the `<selector>.private` / `<selector>.txt` files in `postern-mta-data` are intentionally not touched.

## 3. Delete OLD records

```bash
while IFS=$'\t' read -r rid rtype rname rcontent; do
  echo "DELETE ${rtype} ${rname} -> ${rcontent} (${rid})"
  curl -sS -X DELETE \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${rid}" \
    | jq -e '.success == true'
done < .tmp/rename/old-records.tsv
```

## 4. Update PTR at the VPS provider

```text
v4: <PUBLIC_IPV4> -> mail.<NEW_DOMAIN>.
v6: <PUBLIC_IPV6> -> mail.<NEW_DOMAIN>.
```

Wait for the change to land. The MTA's startup `MTA_VERIFY_DNS=true` check will fail if PTR still resolves to the old name.

## 5. Edit `.env` and bring the stack up

Edit `.env` on the host:

```
DOMAIN=<NEW_DOMAIN>
SMTP_FROM=<Brand> <noreply@<NEW_DOMAIN>>
```

Leave `MTA_DKIM_SELECTOR_PREFIX` and `PRODUCT_NAME` unchanged — both are brand-cosmetic and decoupled from `DOMAIN`.

```bash
docker compose up -d                                     # no --build needed
docker compose logs -f provisioner                        # watch for "cert: ... -> INSTALLED"
```

Then publish the DKIM TXT at the new FQDN:

```bash
SELECTOR=$(docker compose exec provisioner sh -c \
  'jq -r ".active_selectors[0]" /var/lib/opendkim/state.json' \
  | tr -d '\r')
DKIM_VAL=$(docker compose exec provisioner sh -c \
  "awk '/v=DKIM1/ { in_val=1 } in_val { gsub(/[\\\"\\(\\)]/, \"\"); gsub(/[ \\t]+/, \"\"); printf \"%s\", \$0 } /\\)/ { exit }' /var/lib/opendkim/${SELECTOR}.txt | sed -E 's/;----.*$//'" \
  | tr -d '\r')
docker compose exec provisioner \
  postern-dns txt-set "${SELECTOR}._domainkey.${NEW_DOMAIN}" "${DKIM_VAL}"

# Trigger the MTA-records reconciler to republish MX/SPF/DMARC/MTA-STS/
# TLS-RPT/TLSA at the new FQDN on the next 5s tick.
docker compose exec portal postern dns publish
```

## 6. Verify

```bash
docker compose ps
docker compose exec portal postern doctor
docker compose exec portal postern mta verify-dns
docker compose exec portal postern mta dnssec-status
docker compose exec portal postern cert verify

# Cert SAN must equal exactly {<NEW_DOMAIN>, *.<NEW_DOMAIN>}.
openssl s_client -servername ${NEW_DOMAIN} \
  -connect ${NEW_DOMAIN}:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName

# Public-recursor checks (bypass local cache).
for q in \
    "A ${NEW_DOMAIN}" \
    "AAAA ${NEW_DOMAIN}" \
    "A mail.${NEW_DOMAIN}" \
    "A mta-sts.${NEW_DOMAIN}" \
    "MX ${NEW_DOMAIN}" \
    "TXT ${NEW_DOMAIN}" \
    "TXT _dmarc.${NEW_DOMAIN}" \
    "TXT _mta-sts.${NEW_DOMAIN}" \
    "TLSA _25._tcp.mail.${NEW_DOMAIN}" \
    "TXT ${SELECTOR}._domainkey.${NEW_DOMAIN}"
do dig +short @1.1.1.1 $q | sed "s|^|$q -> |"; done

# Old records must be gone.
for r in "${OLD_DOMAIN}" "mail.${OLD_DOMAIN}" "mta-sts.${OLD_DOMAIN}" "_dmarc.${OLD_DOMAIN}"; do
  for t in A AAAA MX TXT TLSA; do dig +short @1.1.1.1 $t "$r"; done
done

curl -sS -X GET -I https://${NEW_DOMAIN}/login

# Final: send an OTP via /login to a mailbox you control and check the
# Authentication-Results header shows dkim=pass d=${NEW_DOMAIN}; spf=pass;
# dmarc=pass.
```

## Rollback

If anything goes wrong:

1. Revert `.env` on the host to the OLD `DOMAIN` and `SMTP_FROM`.
2. `docker compose down` and re-run step 2 (state files were cleared by the failed run; this re-clears any markers `docker compose up` wrote back).
3. Restore PTR to `mail.<OLD_DOMAIN>.` at the VPS provider.
4. `docker compose up -d`. The provisioner republishes the OLD apex/MTA records and re-issues the cert.

Volumes are never destroyed in either direction; bounded recovery time is dominated by DNS propagation (~5 min) plus one ACME issuance (~2 min).
