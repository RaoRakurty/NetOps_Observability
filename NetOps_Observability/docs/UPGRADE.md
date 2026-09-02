# Upgrading an existing deployment

This is the playbook for replacing the source tree on a running Linux
server. `scripts/update.sh` automates the safe steps; this doc tells
you what it's doing and how to handle the edge cases.

## The three-line happy path

```bash
cd /opt/netops/NetOps_Observability
git pull            # or rsync/scp the new tree in over the old one
bash scripts/update.sh
```

That's it for 95% of upgrades. Read on for the rest.

## What `update.sh` does

1. **Snapshots `data/` + `.env`** into `/var/backups/netops/pre-upgrade-<timestamp>.tar.zst`. This is your rollback point.
2. **Validates the new scaffold** — fails fast if required files are missing.
3. **Reconciles your `.env`** with the latest installer template. Existing values are never touched; only missing variables are appended (with random passwords generated for any new secret).
4. **Pulls pinned images** (`postgres:16-alpine`, `opensearch:2.16.0`, etc.) in case any were repinned.
5. **Rebuilds the local images** — the `api`, `frontend`, and `correlation` services are built from your source tree.
6. **Recreates containers** — `docker compose up -d --remove-orphans`. Services whose image or env didn't change keep running. Services that *did* change get rolled.
7. **Re-applies OpenSearch index templates** in case any were updated.

You can skip individual steps with `--no-backup` / `--no-build` if you know what you're doing.

## What is NOT migrated automatically

A few things sit outside Docker and need manual attention:

**ClickHouse schema changes.** `clickhouse/init.sql` only runs the first time the container starts (when `data/clickhouse/` is empty). If the upgrade adds a new table or column, apply it manually:

```bash
docker compose exec -T clickhouse clickhouse-client < deployment/docker/clickhouse/init.sql
```

The `CREATE TABLE IF NOT EXISTS` and `CREATE MATERIALIZED VIEW IF NOT EXISTS` patterns mean re-running is idempotent — existing tables aren't touched.

**Tenant at-rest partitioning (#20 Phase 3).** Fresh installs get `PARTITION BY (tenant_id, …)` from `init.sql`, but **existing** `flows`/`findings`/`tunnels` tables keep their old date-only partition key until you rebuild them. Run the idempotent migration (data preserved via `EXCHANGE TABLES`; safe to re-run — it skips already-migrated tables):

```bash
docker compose exec -T clickhouse sh -s < deployment/docker/clickhouse/migrate-tenant-partition.sh
```

> **Transition note (OpenSearch):** after Phase 3, telemetry is written to per-tenant indices (`netops-{signal}-{tenant}-{date}`, untagged → `…-untagged-…`). **Scoped tenants cannot read pre-Phase-3 `netops-{signal}-{date}` indices** (no tenant segment); the platform owner still sees them via `netops-{signal}-*`, and they age out within the ISM retention window (≤30d). No action needed — it self-heals as old indices roll off.

**Postgres schema changes.** Same story if/when we add tables there. The scaffold currently doesn't use Postgres for app state (the user store is JSON-backed), so there's nothing yet.

**User store format changes.** `data/api/users.json` is read on every API start. If the User struct grows fields, old entries get zero-valued defaults — no migration needed. If a field is removed, the old field is ignored. If a field is renamed (rare), you'd need a one-shot migration.

**The bootstrap admin.** Only seeded on first start with an empty user store. Upgrades never overwrite passwords. If you forgot the admin password and need a reset:

```bash
docker compose stop api
# edit data/api/users.json, remove the user(s)
docker compose start api    # api re-seeds from ADMIN_INITIAL_PASSWORD in .env
```

## Redpanda → Apache Kafka (2026-07)

The embedded event bus changed from Redpanda to Apache Kafka (single-node KRaft). Existing installs migrate by re-running the installer, which appends the new variables (`BROKER_URLS`, `KAFKA_CLUSTER_ID`, `COMPOSE_PROFILES`) to your `.env`, then recreating the stack:

```bash
python3 scripts/install.py
docker compose up -d --remove-orphans
```

The old redpanda container is removed automatically by `--remove-orphans`, and `data/redpanda/` can be deleted afterwards. In-flight bus data is transit-only (the durable copies live in OpenSearch / VictoriaMetrics / ClickHouse) and is not migrated.

## When `.env` reconciliation isn't enough

The reconciliation step appends new variables with safe defaults. It does **not** rotate existing secrets or change values you've set. To rotate (e.g. a known JWT_SECRET leak) there **is** a graceful path now — the installer alters the live store's credential and verifies it before touching `.env`:

```bash
python3 scripts/install.py --rotate-app-secrets
cd deployment/docker && docker compose up -d --force-recreate
```

That covers the application secrets and every store credential the tool can reconcile (`DB_PASSWORD`, `CLICKHOUSE_PASSWORD`, `NETBOX_DB_PASSWORD`, `GRAFANA_CH_PASSWORD`). It deliberately refuses to touch `KAFKA_CLUSTER_ID` (immutable once the broker volume is formatted) and the admin passwords seeded into Grafana / Keycloak / NetBox / the local user store on first boot — rotate those in the product itself and copy the value back into `.env`. Full matrix: **`docs/runbooks/secret-rotation.md`**.

A wipe-and-restore is no longer required for rotation, and `docker compose down -v` + `--reset-env` remains the destructive option of last resort:

```bash
# Take a backup, then dump
docker compose exec postgres pg_dumpall -U $DB_USER > pg.sql
docker compose down
# The stores are BIND MOUNTS under data/ — `down -v` does not remove them, and
# install.py detects them and refuses to pretend it rotated their credentials.
# A truly fresh install means deleting them:
sudo rm -rf data/postgres data/clickhouse data/kafka data/grafana data/api/users.json
python3 scripts/install.py --reset-env    # never-started install: rotates everything
# After install: restore pg dump
cat pg.sql | docker compose exec -T postgres psql -U $DB_USER
```

## Rolling back

The pre-upgrade backup tarball restores everything:

```bash
cd /opt/netops/NetOps_Observability
docker compose down
bash scripts/restore.sh /var/backups/netops/pre-upgrade-2026-05-27-141500.tar.zst
docker compose up -d
```

`restore.sh` puts `data/` back, restores `.env`, and lays the configs back in place. The next `up -d` is the rollback.

## If you're far behind (e.g., the original pre-bus scaffold)

Upgrades within a generation are easy. Crossing a major architecture change is not — between the early "Loki + Promtail" scaffold and the current "Kafka + OpenSearch + ClickHouse" stack, too many services were added/removed for an in-place upgrade to be safe. In that case:

1. Take the backup.
2. `docker compose down -v` (yes, the `-v` — orphan services from old stack go too).
3. Replace the source tree (`git pull` or rsync the new version in full).
4. `python3 scripts/install.py` — treats it as a fresh install. Generates a new `.env` (or keeps yours if you preserved it).
5. Apply any data you need from the backup manually — Postgres dump goes back, but old Loki/Promtail data is not portable to OpenSearch.

This is rare. Once you're on the current architecture, `update.sh` handles everything going forward.

## Recurring updates with systemd

If you're using `scripts/netops.service`:

```bash
sudo systemctl stop netops
bash scripts/update.sh
sudo systemctl start netops
```

`update.sh` itself doesn't touch the systemd unit; it talks directly to `docker compose`. The unit just wraps `compose up/down` for boot-time orchestration.

## One-time data migrations

### 2026-07-09 — correlation archive skip index

The API's boot self-heal adds a `bloom_filter` skip index on
`corr_signals_archive.archived_for` (per-object reads used to full-scan the
archive). New parts are indexed on write automatically; a deployment that
already has archive rows should materialize the index over the existing parts
once (safe to re-run, takes seconds even at tens of millions of rows):

```bash
docker compose exec clickhouse clickhouse-client -q \
  "ALTER TABLE netops.corr_signals_archive MATERIALIZE INDEX idx_archived_for"
```

Skipping this is not fatal — only reads over pre-upgrade parts stay slow until
their next natural merge.

### 2026-09-02 — optional modules (security lane, config backup)

Nothing to do by hand; this is what changes and what to check.

**New `.env` keys are reconciled for you.** `update.sh` appends any key its
template list is missing, and this release adds the optional-module knobs:
`FEATURE_SECURITY_LANE` / `SECURITY_SCAN_INTERVAL` /
`SECURITY_MAX_FINDINGS_PER_TENANT`, `FEATURE_CONFIG_BACKUP` /
`CONFIG_BACKUP_INTERVAL` / `CONFIG_BACKUP_KEEP_VERSIONS` /
`CONFIG_BACKUP_SSH_USER` / `CONFIG_BACKUP_SSH_PASSWORD` /
`CONFIG_BACKUP_SSH_KEY` / `CONFIG_BACKUP_SSH_PORT`, `PARSERCOV_MAX_LINES`,
`CORRELATION_REPLICA_URLS`, `FEATURE_PACKET_CAPTURE` / `PCAP_KEEP` /
`PCAP_SSH_USER` / `PCAP_SSH_PASSWORD` / `PCAP_SSH_KEY` / `PCAP_SSH_PORT`,
`CORR_SYSLOG_TOPIC` and `CORR_FIDELITY_WEIGHTING`. Every appended value equals the default compose
already interpolates, so the upgrade is behaviour-neutral: both feature flags
stay `false` until you flip them (see `docs/DEPLOY_LINUX.md` §5c for what each
one additionally needs). `CORR_EVIDENCE_TOPICS` is deliberately NOT appended —
for that variable unset ("every registered evidence class") and empty
("subscribe to none") are different contracts.

**Two new data directories.** `data/config-backups` and `data/pcap` are bind
mounts for the sealed configuration and packet-capture blobs, created `0700`
and owned by the api's runtime uid.
`update.sh` does not create it — run `python3 scripts/install.py --no-start`
(it is idempotent and only touches `.env` + `data/`) or
`sudo bash scripts/fix-permissions.sh` before enabling `FEATURE_CONFIG_BACKUP` or
`FEATURE_PACKET_CAPTURE`. Add `data/config-backups` to your backup rotation:
it is the only copy of a captured config.

**Postgres migrations apply on boot.** The api runs `0036_rca_feedback`,
`0037_security_control_plane` and `0038_config_backup` itself at startup on
the Postgres backend — no manual step, forward-only, serialised by an
advisory lock so two replicas booting together cannot both apply one. A
migration failure is fatal at boot, never a silently skipped table. Confirm
with:

```bash
docker compose exec postgres psql -U netops -c \
  "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 5"
```

On the file backend (`STORE_BACKEND` unset) there is nothing to apply — those
stores fall back to their tenant-keyed files.

## Quick sanity checks after every upgrade

```bash
docker compose ps                           # everything Running?
curl -fs http://localhost:8000/admin/health | jq
curl -fs http://localhost:8000/admin/version
docker compose logs --tail=50 api           # any startup errors?
```

If `/admin/health` returns 200 and `docker compose ps` is clean, the upgrade landed. Sign back into the dashboard with your existing admin credentials.
