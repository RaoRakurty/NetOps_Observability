# Phase 5 — Database-enforced isolation (PostgreSQL RLS + telemetry)

Status: **M0 storage layer IMPLEMENTED (decision A — normalize).** App-state now
persists as normalized, RLS-protected rows under `STORE_BACKEND=postgres`
(`db.go` + `pgstore.go` + `migrations/0001_app_state.sql`); verified by live
isolation + importer tests (`pgstore_test.go`, gated on `DATABASE_URL_TEST`).
Remaining: per-request tenant scoping (RLS is the backstop today, see below) and
the telemetry track. Owner: `docs/TRACKER.md` tasks #19/#15.

⚠️ **Operational requirement — handled three ways (defense in depth):**
`DATABASE_URL` must use a NON-superuser, non-BYPASSRLS role — superusers bypass
RLS even with FORCE, silently disabling isolation.
1. **Fail-closed runtime guard** (`db.go` `assertRLSCapable`): startup aborts if
   the connected role is a superuser or has BYPASSRLS, turning a silent breach
   into a loud error. Override for single-tenant: `STORE_PG_ALLOW_RLS_BYPASS=true`
   (downgrades to a warning).
2. **Correct-by-construction**: a least-privilege role is provisioned via
   `deployment/docker/postgres/netops-app-role.sql` (`CREATE ROLE … LOGIN
   NOSUPERUSER NOBYPASSRLS`, owns the app-state tables) and written into
   `DATABASE_URL` — never the `postgres` superuser. Opt-in compose wiring +
   step-by-step enablement in `docs/DEPLOY_POSTGRES_APPSTATE.md`. *(Auto-gen in
   `install.py` is a further follow-up; the manual path is documented.)*
3. **Test-proven**: `pgstore_test.go` provisions a non-superuser role to prove
   isolation, and asserts the guard rejects a superuser connection.

This is defense-in-depth *under* the application layer. The app already enforces
strict isolation at one chokepoint (`authz.go` `Authorize()`), proven by the
cross-tenant test matrix and recorded by the audit trail. RLS makes the database
refuse to return another tenant's rows even if an app-layer filter is ever
forgotten — "the developer cannot leak by omission."

## The blocker (why RLS isn't a config tweak here)

Today app-state persists as **JSON blobs**, not rows. The Postgres backend
(`pgkv.go`) is a single key/value table:

```sql
netops_kv(key TEXT PRIMARY KEY, data BYTEA, updated_at TIMESTAMPTZ)
```

Each store writes its *entire* collection as one blob: `key='users.json'` → a
BYTEA of **all** users across **all** tenants. RLS filters *rows* by a
`tenant_id` column; there is no per-tenant row to attach a policy to. So RLS
requires first **normalizing** the tenant-scoped stores from blob-kv into
per-row tables.

Decision required (see TRACKER): **(A)** normalize the data layer (sizeable
refactor of users/devices/saved/apikeys/snmp-credentials/tenants from
load/save-whole-blob to row-per-entity), then apply RLS; or **(B)** accept the
app-layer `Authorize()` + audit trail as the isolation guarantee for now and
defer RLS. Telemetry isolation (below) is independent of this choice.

## Target schema (when normalized)

Each tenant-scoped table carries `tenant_id` and enables RLS:

```sql
-- example: saved objects (repeat per tenant-scoped store)
CREATE TABLE saved_objects (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL,
  type       TEXT NOT NULL,
  name       TEXT NOT NULL,
  owner      TEXT,
  body       JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON saved_objects (tenant_id);

ALTER TABLE saved_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_objects FORCE ROW LEVEL SECURITY;

-- A scoped session sees only its tenant; the platform owner sets '*' to see all.
CREATE POLICY tenant_isolation ON saved_objects
  USING (
    current_setting('app.current_tenant', true) = '*'
    OR tenant_id = current_setting('app.current_tenant', true)
  )
  WITH CHECK (
    current_setting('app.current_tenant', true) = '*'
    OR tenant_id = current_setting('app.current_tenant', true)
  );
```

Notes:
- `current_setting('app.current_tenant', true)` — the `true` makes a missing GUC
  return NULL (deny) rather than erroring.
- `'*'` is the platform-owner sentinel. Alternatively give the platform owner a
  role with `BYPASSRLS`; the `'*'` policy keeps it in one connection pool.
- `FORCE ROW LEVEL SECURITY` so the table owner is also subject to policy.

## Session plumbing (the one new chokepoint)

Every request runs inside a transaction that first sets the tenant GUC from the
**already-resolved** `Principal` (never from request input):

```go
// pseudo — in the pg path, wrapping each store op in a tx
func (p *pgKV) withTenant(ctx context.Context, pr Principal, fn func(*sql.Tx) error) error {
    tx, err := p.db.BeginTx(ctx, nil)
    if err != nil { return err }
    defer tx.Rollback()
    scope := pr.Tenant
    if pr.cross { scope = "*" }
    // SET LOCAL is transaction-scoped; parameterize via set_config to avoid
    // string interpolation into SQL.
    if _, err := tx.ExecContext(ctx,
        `SELECT set_config('app.current_tenant', $1, true)`, scope); err != nil {
        return err
    }
    if err := fn(tx); err != nil { return err }
    return tx.Commit()
}
```

`set_config(name, value, is_local=true)` is the parameterized equivalent of
`SET LOCAL` — no SQL string interpolation, satisfying the zero-trust guardrail.
This binds the DB session to the resolved principal's tenant, so RLS does the
filtering even for any query that forgets a `WHERE tenant_id = …`.

This composes with Phase 4 (`TenantRouter`): `dedicated_db`/`dedicated_schema`
tenants resolve to a different DSN/schema *and* still get RLS within it.

## Telemetry isolation (independent sibling track)

RLS only covers data that lives in Postgres. The bulk of tenant data is
elsewhere and needs its own enforcement — **this does not depend on the
normalize-vs-defer decision above:**

| Store | Mechanism |
|-------|-----------|
| **OpenSearch** (logs) | Tag docs with `tenant_id` at ingest (Vector `applogs`/`flows` transforms); enforce with document-level security or per-tenant index patterns (`logs-<tenant>-*`). Today scoped indirectly via the device set. |
| **ClickHouse** (flows/findings) | Add `tenant_id` column at ingest; `CREATE ROW POLICY tenant_filter ON flows USING tenant_id = {tenant:String} TO ALL` with the tenant passed as a query setting. Today scoped via `flowTenantClause` (device addrs). |
| **VictoriaMetrics/Prometheus** | Per-tenant via label matchers or VM multitenancy (`/insert/<tenantID>/…`, `/select/<tenantID>/…`). |

The Vector ingest config (`deployment/docker/vector/vector.yaml`) is the single
place to stamp `tenant_id` once device→tenant mapping is authoritative.

## Sequencing

1. Decide A (normalize) vs B (defer) for app-state RLS.
2. If A: normalize one store at a time behind the `STORE_BACKEND=postgres` path,
   add the table + policy migration, wrap ops in `withTenant`. App-layer
   `Authorize()` stays as the first line; RLS becomes the backstop.
3. Telemetry track in parallel: Vector `tenant_id` tagging → ClickHouse row
   policy + OpenSearch DLS. Then flip the flow/log query-builders from
   device-set derivation to direct `tenant_id` filters.
4. Migration of existing blob data → normalized rows (one-time importer).

Until then, isolation rests on the (now-centralized, audited, test-covered)
application layer — which is a defensible posture, just not database-enforced.
