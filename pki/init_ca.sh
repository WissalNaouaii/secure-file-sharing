#!/usr/bin/env bash
# Création de l'AC locale avec OpenSSL (courbe P-256).
# Usage : ./pki/init_ca.sh
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p ca
umask 077

# Clé privée de l'AC (chiffrée AES-256 : OpenSSL demandera une passphrase)
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl pkcs8 -topk8 -v2 aes-256-cbc -out ca/ca.key.pem

# Certificat auto-signé (10 ans) avec extensions d'AC
openssl req -new -x509 -sha256 -days 3650 -key ca/ca.key.pem \
  -subj "/C=TN/O=SecureShare/CN=SecureShare Local CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
  -out ca/ca.cert.pem

openssl x509 -in ca/ca.cert.pem -noout -subject -dates
echo "AC créée dans pki/ca/ (ne JAMAIS commiter ca.key.pem)"
