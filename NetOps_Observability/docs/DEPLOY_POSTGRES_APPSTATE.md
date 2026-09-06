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

It moves state in **two phases**, both marker-gated and both able to fail the
boot:

**Phase 1 — blob-seam collections.** These stores persist through
`platformdb.Load/Save`: a file path on the file backend, an `app_kv` row key on
Postgres. The import is a verbatim byte move under the same key, so ids, tenant
ownership and timestamps survive by construction. Eight of them
(`users` · `tenants` · `roles` · `snmp_credentials` · `snmp_profiles` ·
`apikeys` · `saved` · `audit`) explode into normalized, RLS-protected tables
instead, because they have one.

The audit trail is in that list as of 2026-09-06. Before then a cutover started
the trail again from zero — an audit trail a configuration change can erase is
not an audit trail.

`tenants` · `roles` · `users` · `snmp_credentials` · `snmp_profiles` · `apikeys` ·
`saved` · `audit` · `contact_points` · `notify_config` · `oidc_config` ·
`ldap_config` · `sso_idp_config` · `tacacs_config` · `token_policy` ·
`copilot_config` · `export_policy` · `orgs` · `role_bindings` · `tenant_display` ·
`tenant_governance` · `devices` (**including the per-device
`devices.json.d/` subtree** — manual records, the `migrated` marker and the
`suppressed` tombstones) · `device_locations` · `device_sites` ·
`device_monitoring` · `sites` · `discovery_config` · `netbox_config` ·
`alert_episodes` · `alert_notify_state` · `user_rules` · `rca_promotions` ·
`rca_report_revisions` · `rca_action_items` · `security_settings` ·
`security_policies` · `ssh_known_hosts` · `itsm_config` · `tac_connectors` ·
`ai_tenant_config` · `cloud_monitors` · `cloud_slos` · `verify_config` ·
`verify_runs` · `wan_policy` · `timeintel_backfill_cursor`

— plus the **custody material** a cutover cannot re-create:

`secrets_wrapped_keys.json` — the sealing vault's WRAPPED data-encryption keys.
Without them every value sealed on the file backend (SNMP credentials, connector
secrets) is undecryptable afterwards.

`tls_internal_ca_cert.pem` + `tls_internal_ca_key.enc` — the internal mesh CA.
Without them the API mints a NEW CA and every SVID issued by the old one stops
being trusted, which on a fail-closed TLS mesh is a stack outage.

`cloud_workload_issuer_key.enc` — the cloud-connector workload issuer key.
Without it every workload identity it signed stops verifying.

All are already sealed/encrypted at rest; the import moves the same bytes
between the platform's own stores, once, under the same marker gate — a re-run
never overwrites custody that has since been rotated in PostgreSQL
(`TestPgStoreImportsCustodyMaterial`).

**Phase 2 — domain-table collections.** These have a *second* implementation:
the API reads a normalized, domain-shaped table on Postgres and never opens the
file. Each one's row shape belongs to its own package (`internal/platformdb`
must not import the packages that import it), so `main.domainImportCollections`
injects a `Count`/`Import` pair per collection and
`platformdb.ImportCollections` runs the same marker gate over them:

| Collection | File | PostgreSQL target |
|---|---|---|
| `dem_targets` | `dem_targets.json` | `dem_targets` |
| `dem_experience` | `dem_experience.json` | `dem_journeys`, `dem_change_events` |
| `iris_investigations` | `iris_investigations.json` | `iris_investigations` |
| `config_backup_versions` | `config_backup_versions.json` | `config_backup_versions` (golden mark included) |
| `config_drift_state` | `config_drift_state.json` | `config_drift_state` |
| `security_control_plane` | `security_control_plane.json` | `security_rule_state`, `security_saved_views` |
| `security_frameworks` | `security_frameworks.json` | `security_framework_state` |
| `bgp_watchlist` | `bgp_watchlist.json` | `bgp_watchlist` |
| `bgp_alert_policy` | `bgp_alert_policy.json` | `bgp_alert_policy` |
| `maintenance_windows` | `maintenance_windows.json` | `maintenance_windows` |
| `pcap_captures` | `pcap_captures.json` | `pcap_captures` |
| `pipeline_processors` | `pipeline_processors.json` | `pipeline_processors`, `processor_versions` |
| `rca_feedback` | `rca_feedback.json` | `rca_feedback` |
| `tac_templates` | `tac_templates.json` | `tac_templates` |
| `metering_daily` | `api/metering.json` | `metering_daily` |

Each phase-2 importer is **stricter than its file store**. A file store drops an
unreadable row and records `LoadErr` so a running install keeps serving; a
migration must not, because a dropped row is data the operator never gets back
and the boot log is the only place it could have been mentioned. Anything that
cannot be imported exactly — a malformed file, a non-concrete tenant bucket, a
row over a per-tenant cap, a duplicate primary key — **fails the boot naming the
collection**. Every import is verified by counting the target afterwards and
comparing it with what was written; the "done" marker is written **only** once
the count agrees, so a short import can never be frozen in place.

`TestEveryFileBackedPGPairIsImported` (root package) is the guard: adding a
file↔Postgres store pair without an importer fails CI.

### What is intentionally NOT imported

**Transient state — it goes through the store seam, so the switch DOES hide it,
and that is fine because it rebuilds:** `sessions.json` and `refresh_tokens.json`
(everyone re-logs in) and `report_artifact_*` (rendered report bodies, re-render
on demand).

**Unaffected: always-file.** These stores read their own file with `os.ReadFile`
and are **not selected by `STORE_BACKEND` at all**, so a backend switch does not
touch them and importing them would be wrong, not merely unnecessary:

| File | Owner | Why it stays a file |
|---|---|---|
| `api/licence.json` | `internal/licence` | The licence must be a FILE an operator can copy in, copy out, diff and verify offline with `correlix-licence verify`. A row in a database the customer cannot reach with an editor breaks that promise (stated in `internal/licence/store.go`). |
| `api/licence-report-key.json` | `internal/metering` | The per-installation report signing key, 0600 beside the licence. |
| `api/licence-overage.json` | `internal/licence` | The overage register (when has this install been over a ceiling), beside the licence — one operational object. |
| `backup-report.json`, `backup-drill.report.json`, `restore-drill.report.json`, `snapshot_verify.json`, `snapshot_operations.json`, `system_backup.json` | `internal/dataprotect` | Written by host scripts (`scripts/backup-drill.sh` …), read by the API. Host-side artifacts, not app state. |
| `system_network.json` | root | Host network facts, read with `os.ReadFile`. |
| `credential_overrides.json` | `internal/snmpcred` | The sentinel's learned bindings, re-learned on the next pass. |
| `report_runs.json` | root (`report_scheduler.go`) | The in-process scheduler's cadence state; the Postgres backend runs the durable report PIPELINE instead (`report_jobs` / `report_executions`), so this file is not its state at all. |
| `servicenow_tickets.json`, `jira_tickets.json`, `<system>_tickets_<tenant>.json` | `notify` (`ticket_state.go`) | ITSM ticket dedup state, written with `WriteFileAtomic` and read with `os.ReadFile`. |
| `enrichment/*.json`, `enrichment/device_tenant.csv` | root exporters | DERIVED exports the API regenerates on every pass, for the correlation engine to read off a shared volume. |
| `config-backups/`, `pcap/`, `tls/`, `processors/`, `appid-feeds/`, `cloud-fixtures/`, `cloud-runtime/`, `vuln/`, `tac/` | various | Blob/asset directories on the data volume. The *index* over them moves (see `config_backup_versions`, `pcap_captures`); the bytes stay where they are and are referenced by path. |

### Limits worth knowing before you run it

* The importer reads `<IMPORT_FILE_STATE_DIR>/<default basename>` and writes the
  **default** store key. A deployment that moved a store with its own env knob
  (`DEVICES_STORE_PATH`, `AUDIT_FILE`, …) is out of scope: copy that file to the
  default name first, or import it by hand.
* Phase 2 refuses a file that is **over a per-tenant cap** rather than silently
  truncating it. If that happens, prune the file to the cap and re-run — the
  cap is named in the error.

### Switching a populated install deliberately

1. Back up `data/api/` and the `postgres` volume.
2. `STORE_BACKEND=postgres` + a `DATABASE_URL` in `deployment/docker/.env`.
3. Re-run `python3 scripts/install.py` (it provisions/aligns `netops_app`).
4. Set `IMPORT_FILE_STATE_DIR=/data` — without it nothing moves.
5. `docker compose up -d api`, then check the boot log: `state backend selected
   backend=postgres`, `imported file-backend collection` lines, and
   `GET /api/registries/status`.
6. Re-create anything from the *not covered* list (transient state only).

The exact, ordered form of that — with the verification and rollback lines an
operator runs — is the runbook below.

---

## LAB CUTOVER RUNBOOK (file → PostgreSQL, populated install)

Run it in this order. Every step is either idempotent or reversible, and the
rollback at the end is one `.env` edit plus a restart because **the files are
never touched**: the importer only ever reads them.

### 0. Take the backups (non-negotiable)

```bash
cd NetOps_Observability
ts=$(date -u +%Y%m%dT%H%M%SZ)
sudo tar -C data -czf "/var/backups/correlix-data-api-$ts.tgz" api
sudo tar -C data -czf "/var/backups/correlix-postgres-$ts.tgz" postgres
ls -l /var/backups/correlix-*-"$ts".tgz     # both must be non-empty
```

`data/api` is the ONLY copy of the state being moved, and `data/postgres` is
what a rollback of a half-applied migration restores.

### 1. Provision the non-superuser application role

The API refuses to start as a superuser or any `BYPASSRLS` role — RLS would be
ignored and the tenant backstop would be off. Either

```bash
python3 scripts/install.py            # provision_app_state_role runs inside it
```

or, equivalently, by hand (the same SQL as
`deployment/docker/postgres/netops-app-role.sql`):

```bash
APP_PW='<generate one, 32+ chars>'
# The container's own superuser name — never hardcode it.
PGSU=$(docker exec netops-postgres-1 printenv POSTGRES_USER)
docker exec -i netops-postgres-1 psql -v ON_ERROR_STOP=1 -U "$PGSU" -d netops <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='netops_app') THEN
    CREATE ROLE netops_app LOGIN PASSWORD '$APP_PW' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  ELSE
    ALTER ROLE netops_app WITH LOGIN PASSWORD '$APP_PW' NOSUPERUSER NOBYPASSRLS;
  END IF;
END \$\$;
GRANT CONNECT ON DATABASE netops TO netops_app;
GRANT USAGE, CREATE ON SCHEMA public TO netops_app;
SQL
```

Verify it is NOT privileged — this is the check that keeps RLS armed:

```bash
docker exec netops-postgres-1 psql -U "$PGSU" -d netops -tAc \
  "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname='netops_app'"
# must print: f|f
```

### 2. Point the API at PostgreSQL

In `deployment/docker/.env`:

```dotenv
STORE_BACKEND=postgres
DATABASE_URL=postgres://netops_app:<pw>@postgres:5432/netops?sslmode=verify-full&sslrootcert=/data/tls/ca.pem
IMPORT_FILE_STATE_DIR=/data
```

`sslmode=verify-full` + `sslrootcert` because the lab's postgres is
**`hostssl`-only** — a plaintext DSN is refused at the server, not by us. Keep
the URL on ONE line and percent-encode any `@ : / ? # &` in the password.

### 3. Restart just the API

```bash
cd deployment/docker
docker compose up -d api
docker compose logs -f api | head -200
```

### 4. Verify the boot — the lines that matter

```bash
docker compose logs api | grep -F '"msg":"state backend selected"'
# → backend=postgres, persistent=true

docker compose logs api | grep -F 'imported file-backend collection'
# → one line per collection, each with its row count

docker compose logs api | grep -F 'imported file-backend app-state into Postgres'
docker compose logs api | grep -F 'imported file-backend domain collections into Postgres'
# → the two phase summaries

docker compose logs api | grep -Ei 'file-state import|import .*: ' | grep -i error
# → MUST be empty. An import failure ABORTS the boot; the api will not be up.
```

A collection whose target already had rows logs
`skipped file-backend collection (target already populated)` instead — that is
the correct answer on a re-run, not a failure.

### 5. Functional checks (in this order)

```bash
# a) Identity survived: log in with an EXISTING account, not the bootstrap admin.
curl -sk https://localhost:8000/api/health | head -c 200

# b) The registries say postgres/persistent/available
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://localhost:8000/api/registries/status | python3 -m json.tool
# applications → configured_backend=postgres, persistence=persistent, available=true

# c) Inventory and structure
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8000/api/devices | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("devices",[])))'
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8000/api/tenants  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d if isinstance(d,list) else d.get("tenants",[])))'
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8000/api/orgs     | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d if isinstance(d,list) else d.get("orgs",[])))'

# d) DEM targets — the count must match the pre-cutover file
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8000/api/dem/targets | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d if isinstance(d,list) else d.get("targets",[])))'

# e) Licence still installed (it is a FILE — it never moved)
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8000/api/system/licence | python3 -m json.tool | head -20

# f) TLS mesh healthy — proves the internal CA came across rather than being re-minted
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8000/api/stack/health | python3 -m json.tool | head -40

# g) A SEALED value still decrypts — proves the wrapped DEKs came across.
#    Open an SNMP credential in the UI (Admin → Credentials) and confirm the
#    bound profile resolves; or watch for a poll succeeding on a bound device.
docker compose logs api | grep -Ei 'vault|seal' | grep -i 'error|cannot' | head
# → empty

# h) Durability: create an application, restart the api, confirm it survives.
curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"cutover-probe"}' https://localhost:8000/api/applications
docker compose restart api && sleep 20
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8000/api/applications | grep -c cutover-probe
# → 1 (then delete it)
```

If (g) fails — sealed values will not open — **stop and roll back**: the vault's
wrapped keys did not arrive, and every write made since the cutover was sealed
under a key the old files do not know about.

### 6. Rollback (files are untouched, so this is cheap)

```bash
# deployment/docker/.env
STORE_BACKEND=file
# delete or comment out DATABASE_URL (and IMPORT_FILE_STATE_DIR)
```

```bash
cd deployment/docker && docker compose up -d api
docker compose logs api | grep -F '"msg":"state backend selected"'   # → backend=file
```

The JSON collections are exactly as they were left. **What does NOT come back is
anything written while the API was on PostgreSQL** — those rows stay in the
database. Roll back promptly, or treat the divergence as a merge.

Re-running the cutover after a rollback is safe: the markers live in PostgreSQL,
so a collection already imported is skipped and a collection that was never
reached imports on the next attempt.

### Rehearsing it first (recommended)

Never rehearse against the live database. Copy `data/api` (READ-ONLY source),
create a throwaway database, and run the real import path against it:

```bash
docker exec netops-postgres-1 psql -U "$PGSU" -d postgres \
  -c 'CREATE DATABASE netops_import_rehearsal'
cp -a data/api /tmp/cutover-rehearsal        # the copy is what gets imported
cd src/backend
IMPORT_REHEARSAL_DIR=/tmp/cutover-rehearsal \
DATABASE_URL_TEST="postgres://<superuser>:<pw>@<postgres-ip>:5432/netops_import_rehearsal?sslmode=require" \
  go test . -run TestImportRehearsalAgainstACopiedDataDir -count=1 -v
docker exec netops-postgres-1 psql -U "$PGSU" -d postgres \
  -c 'DROP DATABASE netops_import_rehearsal'
```

It prints a per-collection `FILE → PG → VERDICT` table and fails on any
mismatch. It counts rows and never prints a stored value: these files hold
sealed material and tokens.

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
