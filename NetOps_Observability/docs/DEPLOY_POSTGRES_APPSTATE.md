# The PostgreSQL app-state backend (normalized rows + RLS)

**PostgreSQL is the default persistent state backend for new normal Correlix
installations.** `scripts/install.py` generates `STORE_BACKEND=postgres` and a
`DATABASE_URL` for the non-superuser `netops_app` role, and provisions that role
before the API first starts. **The file backend is retained for explicitly
supported compatibility or PostgreSQL-less deployments.**

Two rules follow from that, and they are the whole reason this document exists:

* **Registries do not silently fall back to ephemeral memory** when a configured
  persistent backend is unsupported or unavailable. They say so.
* **A PostgreSQL outage does not trigger transparent failover to file or memory**
  for authoritative registry state. The backend is chosen once, at boot, and
  holds for the life of the process.

## The backend matrix

| `STORE_BACKEND` | Durability | When it is used |
|---|---|---|
| `postgres` | Durable | **Normal installation.** Normalized per-row tables, one `tenant_id` column per row, `FORCE ROW LEVEL SECURITY`. |
| `file` | Durable | Explicit compatibility / PostgreSQL-less mode. JSON collections on the data volume. |
| `memory` | **Ephemeral** | Development and test only. Explicit selection only; nothing survives a restart, and the API says so on every boot. |

Anything else (`postgress`, `sqlite`, …) is a configuration error that **aborts
the boot**. An unset variable resolves to `file`: an install whose configuration
is lost must keep reading the data it already has, never start serving an empty
database. New installs never rely on that — the installer writes the value.

### Not every registry exists on every backend

| Registry | `postgres` | `file` | `memory` |
|---|---|---|---|
| Applications (`/api/applications`) | supported | **unavailable** (no file implementation) | dev/test only |
| Service catalog (`/api/services`) | supported | **unavailable** | **unavailable** |
| Cloud business services | supported | **unavailable** | **unavailable** |
| Users, tenants, roles, API keys, SNMP credentials, saved objects, audit | supported | supported | dev/test only |

An unavailable registry answers `501` with a stable code
(`APPLICATION_REGISTRY_BACKEND_UNSUPPORTED`) and is shown as
*"Unavailable · configured storage: File"* on the Registries page. A registry
whose backend is configured but **unreachable** answers `503`
(`APPLICATIONS_STORAGE_UNAVAILABLE`) and is shown as *"PostgreSQL · Persistent ·
Unavailable"* — never relabelled as file or memory, because no write goes there.
`GET /api/registries/status` is the machine-readable form of the same truth:

```json
{"registry":"applications","configured_backend":"postgres","active_backend":"postgres",
 "persistence":"persistent","available":true,"healthy":true}
```

The same fact rides `/metrics` as
`netops_registry_storage_available{registry="applications",configured_backend="postgres",persistence="persistent"}`,
emitted on every scrape including as a zero, so unavailable storage is alertable
and not merely honest to whoever asks. `/api/stack/health` carries a
`state_backend` block for the platform owner: a green PostgreSQL TCP probe says a
server accepts connections, not that the API stores anything in it.

Before tracker 245 the Applications registry answered `200` with an in-memory
store on the file backend: applications could be created, listed, and were gone
after the next API restart, with nothing in the API or the UI able to say why.

## Fresh installs

Nothing to do. `python3 scripts/install.py` writes

```dotenv
STORE_BACKEND=postgres
DATABASE_URL=postgres://netops_app:<generated>@postgres:5432/netops?sslmode=disable
```

and, before starting the stack, provisions `netops_app` as a **non-superuser,
NOBYPASSRLS** role with that password (idempotent; a re-run re-aligns the live
role with whatever the DSN now says, which is also how you rotate it). A
superuser — or any `BYPASSRLS` role — ignores RLS even under `FORCE ROW LEVEL
SECURITY`, so the API **refuses to start** as one; the override
`STORE_PG_ALLOW_RLS_BYPASS=true` exists for a deliberate single-tenant
deployment and is **never** set by the installer.

On a `--tls` install the DSN is minted plaintext for phase A (the API is what
mints the mesh CA) and rewritten to
`?sslmode=verify-full&sslrootcert=/data/tls/ca.pem` in phase B, when postgres
becomes `hostssl`-only.

Pointing at an **external** database instead? Set `DATABASE_URL` yourself; the
installer detects a non-local host and leaves role provisioning to you
(`deployment/docker/postgres/netops-app-role.sql` is the same SQL it would run).

## Upgrades — read this before changing `STORE_BACKEND`

**An upgrade never changes an existing install's backend.** `install.py` does not
rewrite `STORE_BACKEND` in an existing `.env`; if the key is absent (a `.env`
older than the explicit key) it *appends* `STORE_BACKEND=file`, stamping the
backend the install's data actually lives on. Upgrading is therefore never
"the registry appeared empty".

That is deliberate, because **switching the backend does not move your data.**
The JSON files stay on the data volume, untouched, but the API stops reading
them: every registry then reads whatever is (or is not) in PostgreSQL.

### The one-time file → PostgreSQL importer

Set `IMPORT_FILE_STATE_DIR=/data` (already wired in compose) and the API imports
the durable configuration **once** on first boot of the PostgreSQL backend. It is
idempotent: each collection's decision is recorded as a marker row, so a
deliberately emptied collection is never re-filled from a stale snapshot, and a
target that already has rows is marked *skipped-populated* rather than clobbered.
An import failure **fails the boot** rather than letting a half-imported store
seed a fresh bootstrap admin over the real one.

**It covers exactly these collections:**

`tenants` · `roles` · `users` · `snmp_credentials` · `snmp_profiles` · `apikeys` ·
`saved` · `contact_points` · `notify_config` · `oidc_config` · `ldap_config` ·
`sso_idp_config` · `tacacs_config` · `token_policy` · `copilot_config` ·
`export_policy`

— i.e. logins, roles, tenants, API keys, saved objects, SNMP credentials, SSO and
notification configuration — plus the two pieces of **custody material** a
cutover cannot re-create:

`secrets_wrapped_keys.json` — the sealing vault's WRAPPED data-encryption keys.
Without them every value sealed on the file backend (SNMP credentials, connector
secrets) is undecryptable afterwards.

`tls_internal_ca_cert.pem` + `tls_internal_ca_key.enc` — the internal mesh CA.
Without them the API mints a NEW CA and every SVID issued by the old one stops
being trusted, which on a fail-closed TLS mesh is a stack outage.

Both are already sealed/encrypted at rest; the import moves the same bytes
between the platform's own stores, once, under the same marker gate — a re-run
never overwrites custody that has since been rotated in PostgreSQL
(`TestPgStoreImportsCustodyMaterial`).

Transient state (refresh tokens, the audit ring, ticket dedup) is intentionally
not imported; it rebuilds.

**It does NOT cover** the other file-backed collections. Everything below is
still on the data volume after a switch, but the API will not see it:

`devices.json` (+ `devices.json.d/`) · `orgs.json` · `role_bindings.json` ·
`discovery_config.json` · `itsm_config.json` · `ai_tenant_config.json` ·
`bgp_watchlist.json` · `dem_targets.json` · `iris_investigations.json` ·
`config_backup_versions.json` · `config_drift_state.json` ·
`security_settings.json` · `security_frameworks.json` ·
`security_control_plane.json` · `rca_promotions.json` ·
`rca_report_revisions.json` · `alert_episodes.json` · `alert_notify_state.json` ·
`ssh_known_hosts.json`

**Treat a backend switch on a populated install as a migration project, not a
configuration change:** inventory the list above, decide per collection whether
it is re-created or accepted as lost, and take a backup of `data/api/` first.

There is no automatic importer for those collections, and this document will not
pretend otherwise. The Applications registry needs none: it never had durable
file data to import (its file-backend records only ever lived in RAM).

### Switching a populated install deliberately

1. Back up `data/api/` and the `postgres` volume.
2. `STORE_BACKEND=postgres` + a `DATABASE_URL` in `deployment/docker/.env`.
3. Re-run `python3 scripts/install.py` (it provisions/aligns `netops_app`).
4. Optionally set `IMPORT_FILE_STATE_DIR=/data` for the covered collections.
5. `docker compose up -d api`, then check the boot log: `state backend selected
   backend=postgres`, `imported file-backend collection` lines, and
   `GET /api/registries/status`.
6. Re-create anything from the *not covered* list.

### Reverting

Set `STORE_BACKEND=file` and restart the API. The file collections are exactly
as they were left — but anything written while on PostgreSQL stays there.

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

Registry durability and the no-failover rule have their own tests on the same
gate — `TestApplicationsSurviveAnAPIRestartPG` (create for two tenants, restart
the store, both records and their isolation survive) and
`TestApplicationsPostgresOutageDoesNotFailOverPG` (with the database down the
registry answers 503, refuses the write, keeps naming PostgreSQL as its backend,
and the pre-outage record is the only one there after recovery). The
backend-selection invariants need no database:
`go test . -run 'TestApplication|TestInitStoreBackend|TestRegistriesStatus'`.

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
