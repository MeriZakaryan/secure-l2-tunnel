#!/usr/bin/env bash
# Generate the long-term RSA-2048 key pairs of Device1 and Device2.
# Each device signs with its own private key and verifies the peer with the peer's public key.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p keys

for d in dev1 dev2; do
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "keys/${d}_priv.pem" 2>/dev/null
    chmod 600 "keys/${d}_priv.pem"                                   # owner-only access
    openssl pkey -in "keys/${d}_priv.pem" -pubout -out "keys/${d}_pub.pem"
done

echo "Keys generated:"
ls -l keys/