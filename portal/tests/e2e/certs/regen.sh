#!/usr/bin/env bash
# Regenerate the self-signed test CA and leaf cert for postern.test.
# Run from anywhere; the script uses its own directory as the output location.
#
# Output files (all PEM):
#   ca.pem         - self-signed root CA (trusted by the ssclient container)
#   privkey.pem    - leaf private key (nginx)
#   fullchain.pem  - leaf + CA (nginx)
#   chain.pem      - CA only (nginx reads for OCSP; we ship the CA itself)
#
# Validity: 1 year for both CA and leaf. Re-run yearly (or when CI fails TLS).
set -euo pipefail

cd "$(dirname "$0")"

# Git Bash on Windows mangles arguments that start with / into Windows paths.
# This breaks openssl's -subj /CN=... format. Disable that translation.
export MSYS_NO_PATHCONV=1

CA_KEY="ca.key"
CA_CERT="ca.pem"
CA_CONF="ca.conf"
LEAF_KEY="privkey.pem"
LEAF_CSR="leaf.csr"
LEAF_CERT="leaf.pem"
LEAF_EXT="leaf.ext"
FULLCHAIN="fullchain.pem"
CHAIN="chain.pem"

DAYS=365
SUBJ_CA="/CN=Postern Test Root CA"
SUBJ_LEAF="/CN=postern.test"

# OpenSSL 3+ requires basicConstraints + keyUsage on the CA cert; older clients
# are forgiving, Python's ssl module is not. v3_ca section below adds them.
cat > "$CA_CONF" <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
CN = Postern Test Root CA

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

# Root CA =================================================================
openssl genrsa -out "$CA_KEY" 4096
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$DAYS" \
    -config "$CA_CONF" -extensions v3_ca -out "$CA_CERT"

# Leaf key + CSR ==========================================================
openssl genrsa -out "$LEAF_KEY" 2048
openssl req -new -key "$LEAF_KEY" -subj "$SUBJ_LEAF" -out "$LEAF_CSR"

# Leaf cert (signed by our CA, with SANs) =================================
cat > "$LEAF_EXT" <<'EOF'
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = postern.test
DNS.2 = *.postern.test
EOF

openssl x509 -req -in "$LEAF_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$LEAF_CERT" -days "$DAYS" -sha256 \
    -extfile "$LEAF_EXT"

# Bundles for nginx =======================================================
cat "$LEAF_CERT" "$CA_CERT" > "$FULLCHAIN"
cp "$CA_CERT" "$CHAIN"

# Cleanup intermediate files
rm -f "$CA_KEY" "$CA_CONF" "$LEAF_CSR" "$LEAF_CERT" "$LEAF_EXT" ca.srl

echo "Regenerated test certs in $(pwd):"
ls -l ca.pem privkey.pem fullchain.pem chain.pem
