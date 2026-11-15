#!/usr/bin/env bash
# Émission manuelle d'un certificat utilisateur (démonstration OpenSSL).
# Usage : ./pki/issue_cert.sh alice@example.com
set -euo pipefail
EMAIL="${1:?usage: $0 email}"
cd "$(dirname "$0")"
mkdir -p issued
umask 077

openssl ecparam -name prime256v1 -genkey -noout -out "issued/$EMAIL.key.pem"
openssl req -new -key "issued/$EMAIL.key.pem" \
  -subj "/O=SecureShare/CN=$EMAIL" -out "issued/$EMAIL.csr.pem"

cat > "issued/$EMAIL.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyAgreement
extendedKeyUsage=emailProtection
subjectAltName=email:$EMAIL
EOF

openssl x509 -req -sha256 -days 365 -in "issued/$EMAIL.csr.pem" \
  -CA ca/ca.cert.pem -CAkey ca/ca.key.pem -CAcreateserial \
  -extfile "issued/$EMAIL.ext" -out "issued/$EMAIL.cert.pem"

# Vérification de la chaîne
openssl verify -CAfile ca/ca.cert.pem "issued/$EMAIL.cert.pem"
