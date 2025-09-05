#!/usr/bin/env sh
set -e
CERT=/etc/nginx/certs/dev-cert.pem
KEY=/etc/nginx/certs/dev-key.pem
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "[nginx] generating self-signed cert"
  mkdir -p /etc/nginx/certs
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$KEY" -out "$CERT" \
    -subj "/CN=localhost"
else
  echo "[nginx] using existing certs"
fi
