# Enabling the Postgres app-state backend (normalized rows + RLS)

By default the API stores app-state (users, tenants, API keys, saved objects,
SNMP credentials, audit) as JSON files on the data volume (`STORE_BACKEND=file`).
That is fine for a single-node dev/lab deployment and needs no database.

For multi-tenant / SaaS-grade isolation, switch to the Postgres backend: each
former blob becomes a normalized, per-row table with a `tenant_id` and
**PostgreSQL Row-Level Security**, so the database itself refuses another
tenant's rows even if an application filter is ever forgotten. The audit trail
also becomes a real per-row append/query log instead of a rewrite-whole blob.

This is **opt-in** — flipping it on does not change the default stack.

## Prerequisites

The stack already runs a `postgres` service. The `POSTGRES_USER`/`DB_USER` in it
is a **superuser**, which must NOT be used for app-state: superusers (and
`BYPASSRLS` roles) bypass RLS even with `FORCE ROW LEVEL SECURITY`, silently
disabling isolation. The API enforces this — it **refuses to start** when its
`DATABASE_URL` role can bypass RLS (override only for a deliberate single-tenant
deployment with `STORE_PG_ALLOW_RLS_BYPASS=true`).

So step 1 is creating a dedicated least-privilege role.

## Enable it

1. **Create the non-superuser app role** (idempotent; works on a fresh or
   existing volume):

   ```bash
   cd deployment/docker
   docker compose cp postgres/netops-app-role.sql postgres:/tmp/netops-app-role.sql
   docker compose exec -e PGPASSWORD="$DB_PASSWORD" postgres \
     psql -U "$DB_USER" -d "${DB_NAME:-netops}" \
          -v app_pw="'choose-a-strong-app-password'" \
          -f /tmp/netops-app-role.sql
   ```

2. **Point the API at it** — add to `deployment/docker/.env`:

   ```dotenv
   STORE_BACKEND=postgres
   DATABASE_URL=postgres://netops_app:choose-a-strong-app-password@postgres:5432/netops?sslmode=disable
   ```

3. **Restart the API** — it runs its schema migrations on boot:

   ```bash
   docker compose up -d api
   docker compose logs -f api    # expect "migration applied" then a clean start
   ```

   If the role can bypass RLS, the API aborts with a clear error instead of
   starting unprotected — fix the role and retry.

## Migrating existing file data

If you previously ran the legacy blob Postgres backend, its `netops_kv` table is
imported into the normalized tables automatically on first boot (idempotent —
only empty targets are filled). There is no automatic importer from the *file*
backend; for a fresh switch, recreate the bootstrap admin via
`ADMIN_USERNAME`/`ADMIN_INITIAL_PASSWORD` (seeded on an empty store) or
re-create objects through the UI.

## Verifying isolation

The RLS isolation, importer, superuser-rejection, and cross-backend conformance
behaviors are covered by tests gated on `DATABASE_URL_TEST`:

```bash
cd src/backend
docker run -d --name pgtest -e POSTGRES_PASSWORD=test -e POSTGRES_DB=netops \
  -p 55432:5432 postgres:16-alpine
DATABASE_URL_TEST="postgres://postgres:test@127.0.0.1:55432/netops?sslmode=disable" \
  go test -run 'TestPgStore|TestPgAudit|TestBackendConformance_Postgres' -v .
docker rm -f pgtest
```

## Reverting

Set `STORE_BACKEND=file` (or unset it) and restart the API. File and Postgres
backends are interchangeable from the API's perspective; only the persistence
layer differs.

---

## Why RLS here but not on telemetry (the "Zabbix question")

A fair critique (Zabbix makes it): RLS on a high-throughput SQL backend cripples
write performance, breaks background daemons, fights table partitioning, and
ties you to one DB's RLS syntax. All true — **for an architecture where one
high-volume SQL backend does everything.** Correlix is polyglot on purpose, so
the critique does not apply. The rule:

- **Control-plane (relational, low-volume) → Postgres FORCE-RLS.** Device
  inventory, ports, seams, incidents, integrations, roles/users, config,
  watchlists, compliance enablement/control catalog. Thousands-to-low-millions
  of rows, write-rare, read-per-request. RLS on an indexed `tenant_id` predicate
  the app query already carries costs ~nothing, and buys a database-level
  backstop: another tenant's control-plane rows never leak even if an
  app-authz check is missed.
- **Telemetry (high-volume time-series) → ClickHouse / OpenSearch /
  VictoriaMetrics, query-scoped (`chTenantScope` / `osTenantFilter` / VM label
  filter), NEVER Postgres RLS.** Flows, metrics, logs, correlation signals,
  and — importantly for the security build — findings/evidence at volume. This
  is the exact hot path Zabbix warns about; we keep RLS off it.

How the specific Zabbix objections are handled:
1. *Perf on billions of rows* — telemetry isn't in RLS tables; the soak proved
   1K devices / 100+ eps through CH/OS with zero PG-RLS in the path.
2. *Background daemons* — the `tenant_iso` policy has a `'*'` PLATFORM escape
   (`current_setting('app.tenant_id') = '*' OR tenant_id = …`); platform/
   background work runs cross-tenant via `withTenant(ctx, "", true)`, unblocked.
3. *App-level security* — we do BOTH: app-layer scoped queries (primary,
   indexed) PLUS RLS as defense-in-depth, not the primary filter.
4. *DB-engine agnosticism* — N/A: Postgres-only relational store (single driver,
   dependency allowlist).
5. *Partitioning conflicts* — N/A: partitioned time-series lives in ClickHouse,
   not the PG app-state tables.

**The discipline this imposes:** never let a firehose into a `tenant_iso`
table. High-volume → CH/OS/VM (query-scoped); control-plane → PG (RLS). The
security/compliance design follows this — findings/evidence go to CH/OS,
only low-volume config to PG.
