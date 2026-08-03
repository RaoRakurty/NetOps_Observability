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

# Browsers match IP-address URLs against IP SANs, never DNS SANs — a cert for
# a bare-IP deployment (https://10.0.0.5:8443) must carry IP:<addr> or every
# browser rejects it as a name mismatch regardless of trust.
if [[ "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SAN="IP:$DOMAIN,DNS:localhost,IP:127.0.0.1"
else
  SAN="DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1"
fi

mkdir -p "$CERTS"

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$CERTS/privkey.pem" \
  -out    "$CERTS/fullchain.pem" \
  -subj "/CN=$DOMAIN" \
  -addext "subjectAltName=$SAN"

chmod 600 "$CERTS/privkey.pem"

cat <<EOF

Self-signed cert written to:
  $CERTS/fullchain.pem
  $CERTS/privkey.pem  (mode 0600)

Next steps:
  1. MOUNT the TLS front ALONGSIDE the existing config — do NOT replace it:
       deployment/docker/nginx/tls.conf.example
         -> /etc/nginx/conf.d/tls.conf
     NEVER copy it over default.conf. default.conf carries the auth_request
     gates that protect /metrics, /grafana/, /netbox/ and /search/ (Grafana
     runs with anonymous auth enabled and OpenSearch Dashboards with its
     security plugin off, so an ungated proxy publishes every tenant's
     dashboards and raw logs). The TLS front terminates TLS and proxies to
     that gated server, so the gates cannot be bypassed or drift out of sync.
  2. In docker-compose.yml under 'nginx:', add:
       ports:
         - "8443:8443"
       volumes:
         - ./nginx/tls.conf.example:/etc/nginx/conf.d/tls.conf:ro
         - ./nginx/certs:/etc/nginx/certs:ro
  3. Make the key readable by nginx (it runs as uid 101 in the container;
     the key above is 0600 owned by you, which fails with
     "cannot load certificate key ... Permission denied"):
       sudo chown 101 $CERTS/privkey.pem
  4. docker compose up -d nginx
  5. Browse https://$DOMAIN:8443  (accept the self-signed warning).

EOF
