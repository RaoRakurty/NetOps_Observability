#!/usr/bin/env bash
#
# gen-dev-cert.sh — generate a self-signed cert for dev use.
#
# DO NOT use this in production. For real deployments, terminate TLS
# at a load balancer or use Caddy/certbot to provision a Let's Encrypt
# cert. See docs/DEPLOY_LINUX.md.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERTS="$ROOT/deployment/docker/nginx/certs"
DOMAIN="${1:-netops.local}"

mkdir -p "$CERTS"

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$CERTS/privkey.pem" \
  -out    "$CERTS/fullchain.pem" \
  -subj "/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERTS/privkey.pem"

cat <<EOF

Self-signed cert written to:
  $CERTS/fullchain.pem
  $CERTS/privkey.pem  (mode 0600)

Next steps:
  1. cp deployment/docker/nginx/tls.conf.example \\
        deployment/docker/nginx/default.conf
  2. In docker-compose.yml under 'nginx:', add:
       ports:
         - "443:443"
       volumes:
         - ./nginx/certs:/etc/nginx/certs:ro
  3. docker compose up -d nginx
  4. Browse https://$DOMAIN  (accept the self-signed warning).

EOF
