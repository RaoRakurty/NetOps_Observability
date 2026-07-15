# Cloud Connectors — Gap Analysis (as-built vs. target)

Status: **Phase 1 audit + Phases 2–4 foundation implemented** (this run). Live
per-provider token exchange (AWS STS / Azure Entra / GCP STS) is the documented
follow-up. Everything below reflects the ACTUAL repository, with `file:line`.

## 1. Current architecture (verified)

Correlix is a flat `package main` Go backend (`src/backend/`, ~1568 files) with a
runtime-selected store (`STORE_BACKEND=postgres` → pgx/`pgxpool`, else file/kv +
in-memory). Multi-tenancy, RLS, an envelope Vault, an audit trail, and SSO/OIDC
all already exist and are reused by this work — nothing here was greenfield except
the connector domain itself.

### 1.1 Existing cloud-collector credential reality (the "current connector")

Cloud telemetry is collected by a **Python sidecar**, not Go:
`deployment/docker/cloud-ingest/` (`poller.py`, `azure.py`, `gcp.py`,
`seam_aws.py`, `iam-policy-aws.json`, `CREDENTIALS.md`). Credentials today are
**environment variables / mounted files, NOT under the Vault**:

- **AWS** — `boto3.Session(region_name=REGION)` with no explicit keys
  (`poller.py:278`); relies on the boto3 default chain (env keys or a mounted
  `~/.aws`). Least-privilege policy in `iam-policy-aws.json` (read-only ec2/
  cloudwatch/cloudtrail/logs/s3). `CREDENTIALS.md:44-45` explicitly names the
  intended future: *"Prod shape replaces the env-var secret with the
  tenant-scoped connector store (encrypted Vault, Task #15)."* — i.e. THIS work.
- **Azure** — service-principal client-credentials via env `AZURE_TENANT_ID/
  CLIENT_ID/CLIENT_SECRET/SUBSCRIPTION_ID` (`azure.py:37-40`). Roles: Reader +
  Monitoring Reader.
- **GCP** — SA key file via `GOOGLE_APPLICATION_CREDENTIALS` + `GCP_PROJECT`
  (`gcp.py:40-41`). Roles: compute/monitoring/logging viewer.

**Gap:** all three are long-lived, shared, env-scoped secrets — none federated,
none tenant-scoped, none Vault-encrypted, none rotatable through the product.
This is exactly what the connector framework replaces.

### 1.2 Secret custody — the envelope Vault (REUSED, not rebuilt)

`secrets.go` — AES-256-GCM envelope Vault. Public API:
`(*Vault).Encrypt(tenant, fieldID, plaintext) (string,error)` (`secrets.go:130`)
and `Decrypt` (`secrets.go:148`). Root KEK from a `SealingProvider` (`swtpm`
sidecar, `secrets_swtpm.go`; env `SEAL_PROVIDER`), wraps a **per-tenant DEK**
(`secrets.go:172`); AAD binds ciphertext to `tenant|fieldID` (`secrets.go:311`).
Ciphertext format `v1:` + base64 (`secrets.go:40`). Dormant (no provider) →
plaintext passthrough, so encryption rolls out encrypt-on-next-write.

Two at-rest patterns exist: (A) inline ciphertext in a column (notify/SNMP/
integration webhook secrets), and (B) a **reference/handle** row that stores NO
ciphertext, only a `vault_ref` + `fields_set`
(`migrations/0020_nms_integrations.sql:38`, `integration_credentials_metadata`).

**Design used here:** a hybrid — a `cloud_secret_references` row holds the Vault
CIPHERTEXT + non-secret metadata, and the connector's `identity` references it by
opaque `csr_` handle. Only the Identity Broker decrypts (via the same Vault,
per-tenant DEK, field-id bound to `connector+kind`). **No second crypto system.**

**Gap closed:** cloud connector legacy secrets are now Vault-encrypted at rest
with per-tenant DEKs and audited access. (Migrating the *existing* Python sidecar
env-creds into this store is a later phase — see §5.)

### 1.3 Tenant isolation + RLS (REUSED)

`principalTenant(claims) (tenant, cross)` (`tenancy.go:62`); `withTenant`
sets the `app.tenant_id` GUC via `set_config` (`db.go:167`); every tenant table
carries the `tenant_iso` FORCE-RLS policy (template `0023_service_path_graph.sql`).
Opaque ids via `newOpaqueID(prefix)` (`identity_ids.go:48`). RBAC gates
`requirePerm/requireAdmin/requirePlatformAdmin` (`identity_handlers.go:18+`).
Isolation-test template `org_isolation_test.go`; route-governance backstop
`route_isolation_test.go` (`TestEveryRouteClassified`).

**Applied:** the connector tables mirror this exactly (0024 migration, RLS,
`withTenant`, opaque `ccn_/csr_` ids, isolation test, ledger entries).

### 1.4 Audit trail (REUSED)

`audit.go` / `audit_pg.go` — `AuditEvent{Actor,Tenant,Cross,Method,Path,Status,
Decision,Detail}`, PG table `audit_events` (`migrations/0001_app_state.sql:101`),
RLS `tenant_iso`, scoped read via `auditScopedList` (`audit.go:224`). Event "type"
is derived from Method+Path+Decision.

**Applied:** connector security events (CONNECTOR_CREATED, TRUST_VALIDATED,
CONNECTOR_ENABLED/DISABLED/REVOKED, SCOPE_CHANGED, TOKEN_ISSUED, SECRET_CREATED/
ACCESSED/ROTATED) are recorded through `s.audit.Record` / the broker's audit hook.
**No new audit table** (avoids a dead table; the existing trail is tenant-scoped).
Known limitation inherited: `AuditEvent` has no before/after-hash field yet
(`audit.go:24-26` defers it) — connector events carry before/after in `Detail`
where relevant, not as a hash.

### 1.5 Human auth (SSO/OIDC/SAML) — SEPARATE plane, untouched

`auth_config.go`, `oidc_config.go`, session/JWT layer already implement human
login. Per the mission this plane is **not** touched. The connector plane's
"OIDC" is machine **workload identity federation** to the cloud provider, a
different issuer/audience/subject entirely — see the architecture doc.

## 2. What this run implemented

- `cloudconn/` canonical contract package (provider/auth-method/scope/capability/
  lifecycle/ExternalId/CloudIdentityProvider + AWS/Azure/GCP adapters).
- `migrations/0024_cloud_connectors.sql` (+ rollback): `cloud_connectors`,
  `cloud_secret_references`, both tenant_iso FORCE-RLS.
- `cloud_connectors_store.go` / `_pg.go`: repo seam, in-memory + pg backends.
- `cloud_connectors_broker.go`: the Identity Broker (scoped tokens, cache
  isolation, max-lifetime, Vault secret custody, rotation).
- `cloud_connectors_handlers.go`: provider-neutral catalog + connector lifecycle
  APIs.
- Tests: `cloud_connectors_isolation_test.go`, `cloud_connectors_broker_test.go`,
  `cloudconn/*_test.go`; route ledger updated.

## 3. DB tables added

| Table | Purpose | Isolation |
|-------|---------|-----------|
| `cloud_connectors` | connector: identity metadata (no secrets), scopes, capability, state, identity+telemetry health | `tenant_iso` FORCE-RLS, PK `(tenant_id, connector_id)` |
| `cloud_secret_references` | Vault ciphertext + non-secret metadata for legacy secrets | `tenant_iso` FORCE-RLS, PK `(tenant_id, secret_ref)` |

Apply (DEFERRED to a live window — do NOT run against the live DB from here):

```
# migrations run automatically at API boot when STORE_BACKEND=postgres (db.go:112);
# to apply out-of-band against a running DB the operator runs the API build, or:
psql "$DATABASE_URL" -f src/backend/migrations/0024_cloud_connectors.sql
# then rely on the forward-only migrator to record it, or insert the version row.
```

## 4. Security / UX / provider gaps still open (honest)

- **Live token exchange is not wired** — AWS STS AssumeRole, Azure Entra federated
  token, GCP STS token-exchange all return `ErrProviderExchangeDeferred`. The
  broker, cache, storage, templates, validation and audit around them ARE done.
- **Live permission/scope validation deferred** — `validate-permissions` and
  `discover-scopes` return the declared required permissions / entered scopes with
  a `"live_check":"deferred"` marker (no provider round-trip yet).
- **Identity health is `config_validated`, never `live_verified`** this run — by
  design (identity health stays separate from telemetry health).
- **Wizard UI not built** — provider-neutral APIs + the wizard SHAPE are specified;
  the React wizard is a follow-up (reuse admin/integration primitives).
- **Existing Python sidecar not yet migrated** onto the broker (still env creds).

## 5. Phased plan for deferred work

See `cloud-connectors-architecture.md` §"Phased roadmap". Ordering: (P5) AWS STS
runtime + live permission validation → (P6) Azure Entra WIF + admin-consent OAuth
runtime → (P7) GCP WIF runtime → (P8) wizard UI → (P9) migrate the Python sidecar
to request broker tokens (retire env creds) → (P10) Service View / topology
integration of connector-sourced inventory.

## 6. Risks

- The broker's live exchange must enforce `DurationSeconds ≤ max lifetime` at the
  provider call (the cap is already enforced on the returned token).
- Rotation overlap requires the provider-side old credential to remain valid until
  the operator revokes it; the store tracks version + `rotated_at` but cannot force
  upstream revocation.
- RLS depends on the app DB role NOT having BYPASSRLS (`db.go:87 assertRLSCapable`
  already guards this at boot).
