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

**Postgres schema changes.** Same story if/when we add tables there. The scaffold currently doesn't use Postgres for app state (the user store is JSON-backed), so there's nothing yet.

**User store format changes.** `data/api/users.json` is read on every API start. If the User struct grows fields, old entries get zero-valued defaults — no migration needed. If a field is removed, the old field is ignored. If a field is renamed (rare), you'd need a one-shot migration.

**The bootstrap admin.** Only seeded on first start with an empty user store. Upgrades never overwrite passwords. If you forgot the admin password and need a reset:

```bash
docker compose stop api
# edit data/api/users.json, remove the user(s)
docker compose start api    # api re-seeds from ADMIN_INITIAL_PASSWORD in .env
```

## When `.env` reconciliation isn't enough

The reconciliation step appends new variables with safe defaults. It does **not** rotate existing secrets or change values you've set. If you want fresh secrets across the board (e.g., a known JWT_SECRET leak), there's no graceful path — rotating the DB password while Postgres has data, or rotating CLICKHOUSE_PASSWORD while ClickHouse has data, requires altering the running container's credentials first. The simplest path:

```bash
# Take a backup, then dump
docker compose exec postgres pg_dumpall -U $DB_USER > pg.sql
docker compose down -v                    # wipe data
python3 scripts/install.py --reset-env    # new secrets, new data dirs
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

## If you're far behind (e.g., the original pre-Redpanda scaffold)

Upgrades within a generation are easy. Crossing a major architecture change is not — between the early "Loki + Promtail" scaffold and the current "Redpanda + OpenSearch + ClickHouse" stack, too many services were added/removed for an in-place upgrade to be safe. In that case:

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

## Quick sanity checks after every upgrade

```bash
docker compose ps                           # everything Running?
curl -fs http://localhost:8000/admin/health | jq
curl -fs http://localhost:8000/admin/version
docker compose logs --tail=50 api           # any startup errors?
```

If `/admin/health` returns 200 and `docker compose ps` is clean, the upgrade landed. Sign back into the dashboard with your existing admin credentials.
