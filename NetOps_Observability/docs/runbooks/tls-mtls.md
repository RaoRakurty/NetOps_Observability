# Runbook — enable end-to-end TLS + nginx↔API mTLS (#18 phase 2)

This turns on the internal mesh: the API serves HTTPS, requires a client cert
from nginx (mTLS), and the internal CA self-bootstraps every certificate — with
the CA private key sealed by the swtpm-backed Vault (#17). All of it is **opt-in
and fail-closed**; the default stack is unchanged (plaintext API behind nginx).

## What's automated vs manual

- **Automated (Go):** internal CA generation, CA-key sealing, issuing the API
  server SVID + nginx client SVID + the CA trust bundle on boot, hot cert reload,
  cert-expiry metric. (`tls_ca.go`, `tlsconfig`, `internalca` — all unit-tested;
  swtpm seal/unseal **live-validated**.)
- **Manual (ops):** point nginx at `https://` with a client cert, and mount the
  shared cert dir. nginx can't be env-conditional, so you swap its proxy config.

## Steps

### 1. Seal the root KEK (custody on)
```bash
docker compose --profile seal up -d secrets-seal          # software TPM sidecar
```

### 2. API: serve HTTPS + mTLS, self-bootstrap the CA
Set on the `api` service (all already in compose, dormant by default):
```bash
SEAL_PROVIDER=swtpm                 # seal the CA key (and all secrets) at rest
TLS_INTERNAL_CA=true                # generate CA + issue SVIDs on boot
TLS_TRUST_DOMAIN=netops             # SPIFFE trust domain
TLS_CERT_FILE=/data/tls/api.crt     # API server SVID (issued here on boot)
TLS_KEY_FILE=/data/tls/api.key
TLS_CLIENT_CA_FILE=/data/tls/ca.pem # CA bundle (written here); also nginx's verify root
TLS_CLIENT_ALLOWED_URIS=spiffe://netops/ns/default/sa/nginx   # only nginx may call the API
TLS_NGINX_CERT_DIR=/data/tls/nginx  # nginx client SVID issued here
TLS_SVID_TTL=24h                    # short-lived; re-issued each boot
```
On boot the API logs `internal CA bootstrapped` and writes `api.{crt,key}`,
`ca.pem`, and `nginx/nginx.{crt,key}` under the shared `/data/tls` dir. The API
now listens HTTPS and rejects any client without the nginx SVID.

### 3. nginx: present the client SVID over HTTPS
Mount the shared dir into nginx (`../../data/api/tls:/etc/nginx/tls:ro`) and change
each API upstream from `http://$up_api:8080` to `https://$up_api:8080` with:
```nginx
proxy_ssl_certificate         /etc/nginx/tls/nginx/nginx.crt;
proxy_ssl_certificate_key     /etc/nginx/tls/nginx/nginx.key;
proxy_ssl_trusted_certificate /etc/nginx/tls/ca.pem;
proxy_ssl_verify              on;
proxy_ssl_verify_depth        2;
proxy_ssl_name                api;          # SAN the API server SVID carries
proxy_ssl_server_name         on;
```
(Keep these in an included file you swap in, e.g. `nginx/api-mtls.conf`, so the
plaintext default stays the fallback.)

### 4. Verify
```bash
# API rejects a non-mTLS client (no cert) — fail-closed:
curl -sk https://<api-host>:8080/admin/healthz            # → TLS handshake / 400 (no client cert)
# Through nginx (which presents the SVID) it works:
curl -s http://localhost:8000/api/health                  # → 200
# Cert expiry is observable:
curl -s http://localhost:8000/metrics | grep netops_tls_cert_expiry_seconds
```

## Outbound backend TLS (phase 3)

The API's calls to OpenSearch / ClickHouse / VictoriaMetrics / correlation verify
against the mesh CA (not the system pool) once you set — on the `api` service:
```bash
TLS_BACKEND_CA_FILE=/data/tls/ca.pem        # the mesh CA (defaults to TLS_CLIENT_CA_FILE)
TLS_BACKEND_CERT_FILE=/data/tls/api.crt     # optional: present a client SVID for backend mTLS
TLS_BACKEND_KEY_FILE=/data/tls/api.key
```
Then point the backend URLs at `https://` (e.g. `CLICKHOUSE_URL=https://clickhouse:8123`).
Each datastore must serve TLS first (deployment config, not Go). Fail-closed: an
unloadable bundle aborts boot; plain `http://` URLs are unaffected.

### Postgres
pgx honors the DSN. For app-state over TLS set:
```
DATABASE_URL=postgres://app@postgres:5432/netops?sslmode=verify-full&sslrootcert=/data/tls/ca.pem
```
`verify-full` checks BOTH the chain and the hostname — do not use `require` (no
verification). The non-superuser/non-BYPASSRLS rule (RLS, #15) still applies.

## Rotation

- **Leaf SVIDs**: short TTL (`TLS_SVID_TTL`); re-issued on each API boot and
  hot-reloaded (`CertReloader`, no restart). For sub-TTL rotation, restart the API
  (or extend the bootstrap to a periodic re-issue loop — phase 4).
- **CA root**: long-lived (10y). To rotate, generate a new CA, publish BOTH roots
  in the bundle (`TrustBundle` carries multiple), roll services to certs from the
  new CA, then drop the old root.
- **KEK** (#17): rotation re-wraps the per-tenant DEKs; the CA key is just another
  sealed secret.

## Failure modes

- swtpm sidecar down at boot with `SEAL_PROVIDER=swtpm` → Vault won't unseal →
  **API refuses to start** (loud, by design).
- A broken/missing cert with TLS configured → **boot aborts** (`buildTLSServer` /
  `bootstrapInternalCA` fail-closed).
- nginx presents no/!wrong identity → API rejects the connection (mTLS +
  `TLS_CLIENT_ALLOWED_URIS` allowlist); audit/log the handshake failure.
- Alert on `netops_tls_cert_expiry_seconds` approaching zero.

## Validation status

- swtpm seal/unseal + Vault round-trip: **live-validated** (container, `TestSwtpm`
  PASS). See secret-custody.md.
- internal CA + Vault-sealed key + tlsconfig server/mTLS: unit-tested end to end.
- The nginx↔API hop above is config you apply per deployment; verify with step 4.
