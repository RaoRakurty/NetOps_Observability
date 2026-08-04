# Runbook — enable end-to-end TLS + nginx↔API mTLS (#18 phase 2)

> **BUILT ≠ ENABLED.** Following this runbook enables the ingress + nginx↔API
> (+ victoria scrape) edges only. The datastore, bus, and ingest-lane hops
> remain plaintext until their own SEC epics land — current truth per hop:
> `docs/security/transport-inventory.yaml`; programme: tracker #151.

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
Both halves ship committed — you swap files in the compose override, never edit
configs by hand. `nginx/default-mtls.conf` is the mTLS variant of `default.conf`
(identical except the seven api hops: `https://$up_api:8080` + an
`api-mtls.conf` include carrying the `proxy_ssl_*` client-SVID directives —
see `nginx/api-mtls.conf.example`). In `docker-compose.override.yml`, under
`nginx:`:
```yaml
volumes:
  - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
  - ./nginx/default-mtls.conf:/etc/nginx/conf.d/default.conf:ro
  - ./nginx/api-mtls.conf.example:/etc/nginx/conf.d/api-mtls.conf:ro
  - ../../data/tls:/etc/nginx/tls:ro
```
then `docker compose up -d nginx`. The base compose keeps mounting the
plaintext `default.conf` because a fresh install has no CA and a plaintext API —
mounting the mTLS variant without the include + certs stops nginx from booting
(`scripts/preflight-configs.sh` fresh-loads BOTH variants to pin this). Rollback
is the same swap in reverse.

### 4. Metrics scrape: victoria's client SVID (#149)

Once the API listens mTLS-only, the `netops-api` self-metrics scrape goes
`up==0` and every `netops_*` metric goes dark (this happened live 2026-08-04 —
`ScrapeTargetDown` critical for 12h). Three moves, all in the same override:

1. On `api`: `TLS_VICTORIA_CERT_DIR=/data/tls/victoria` (the CA then mints
   `victoria.{crt,key}` at boot and rotates them with the other SVIDs), and add
   `spiffe://<trust-domain>/ns/default/sa/victoria` to `TLS_CLIENT_ALLOWED_URIS`.
2. On `victoria`: mount `../../data/tls -> /etc/victoria/tls:ro` and point
   `--promscrape.config` at `src/config/vmscrape-mtls.yml` — the deploy-time
   variant of `vmscrape.yml` whose api job is `scheme: https` + `tls_config`
   (same two-variant pattern as `default-mtls.conf`; see the file headers for
   the mirror-editing rule).
3. `docker compose up -d api victoria`, then verify
   `up{instance="api:8080"} == 1`. No key-mode widening is needed: the stock
   victoria image runs as root, which reads the 0600 key.

### 5. Verify
```bash
# API rejects a non-mTLS client (no cert) — fail-closed:
curl -sk https://<api-host>:8080/admin/healthz            # → TLS handshake / 400 (no client cert)
# Through nginx (which presents the SVID) it works:
curl -s http://localhost:8000/api/health                  # → 200
# Cert expiry is observable:
curl -s http://localhost:8000/metrics | grep netops_tls_cert_expiry_seconds
# The self-metrics scrape survives mTLS (§4):
curl -s 'http://<victoria>/api/v1/query?query=up{instance="api:8080"}'  # value 1
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
