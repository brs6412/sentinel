#!/usr/bin/env bash
set -euo pipefail
mkdir -p docker/certs
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout docker/certs/privkey.pem -out docker/certs/fullchain.pem \
  -subj "/CN=localhost"
echo "Self-signed certs written to docker/certs"
