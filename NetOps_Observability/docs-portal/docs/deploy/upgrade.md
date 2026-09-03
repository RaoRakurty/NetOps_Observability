---
title: Upgrade a deployment
description: Replace the source tree, run update.sh, re-run the bootstraps a new lane needs, apply the one-time data migrations, and roll back if the upgrade lands badly.
page_type: task
sidebar_position: 10
---

# Upgrade a deployment

`scripts/update.sh` replaces the running deployment with a newer source tree while preserving `data/` and the secrets in `.env`. Three things sit outside it: the parts that are not migrated for you, the bootstraps a new release can require, and the rollback.

## Before you begin

- The new source tree, ready to place over the old one.
- Disk for the pre-upgrade snapshot. `update.sh` writes it to `/var/backups/netops/` unless you skip it.
- A maintenance window. Services whose image or environment changed are recreated.
- Read the release notes for one-time data migrations before you start.

## Steps

1. Stop the systemd unit, if you installed one.

   ```bash
   sudo systemctl stop netops
   ```

2. Replace the source tree in place, then run the upgrade.

   ```bash
   cd /opt/netops/NetOps_Observability
   git pull            # or rsync/scp the new tree in over the old one
   bash scripts/update.sh
   ```

   That is the whole upgrade for the large majority of releases.

3. Start the systemd unit again.

   ```bash
   sudo systemctl start netops
   ```

4. Re-run the bootstraps if this release adds or changes a lane. See [Bootstraps an upgrade must re-run](#bootstraps-an-upgrade-must-re-run).

5. Apply any one-time data migration the release notes call out. See [One-time data migrations](#one-time-data-migrations).

6. Qualify the deployment.

   ```bash
   bash scripts/deploy-qualify.sh
   ```

## Result

Every service is running on the new images, `data/` is untouched, and your existing admin credentials still work. Confirm with three reads:

```bash
docker compose ps
curl -fs http://localhost:8000/admin/health
curl -fs http://localhost:8000/admin/version
```

```json
{"status":"healthy"}
```

A 200 from `/admin/health` and a clean `docker compose ps` mean the containers landed. They do not mean the pipeline is working, which is why step 6 exists.

## What `update.sh` does

| Step | What it does |
|---|---|
| 1 | Snapshots `data/` and `.env` into `/var/backups/netops/pre-upgrade-<timestamp>.tar.zst`. This is the rollback point. |
| 2 | Validates the new scaffold and fails fast if a required file is missing. |
| 3 | Reconciles `.env` against the current installer template. Existing values are never touched; only missing variables are appended, with a random password generated for any new secret. |
| 4 | Pulls the pinned third-party images, in case the release repinned one. |
| 5 | Rebuilds the locally built images: `api`, `frontend` and `correlation`. |
| 6 | Recreates containers with `docker compose up -d --remove-orphans`. Services whose image and environment did not change keep running. |
| 7 | Re-applies the OpenSearch index templates. |

`--no-backup` skips step 1 and `--no-build` skips step 5. `--yes` skips the confirmation prompt.

`update.sh` talks directly to `docker compose` and does not touch the systemd unit. The unit only wraps `compose up` and `compose down` for boot-time orchestration.

## Bootstraps an upgrade must re-run

A lane is defined across four files applied by four different mechanisms, and `docker compose up` exiting 0 proves none of them. Run these after any upgrade that adds or changes a lane. All are idempotent and all are safe on a healthy stack.

| Bootstrap | What it applies | Skipped when |
|---|---|---|
| Kafka ACL matrix | Per-principal topic and group ACLs. | On a plaintext broker with no authorizer, or on an external broker, where it is the broker owner's job. |
| Kafka topics | The canonical topic list, partitions and retention. | On an external broker. |
| OpenSearch security configuration | The users, roles and role mappings. The role definition is the entry a release most often forgets. | On a non-TLS install. |
| Index templates | The per-lane field contract. | Never. Always run it. |
| ISM policies and snapshots | Retention policy patterns, replica posture, the snapshot repository and policy. | Never. Always run it. |

The deploy gate is the fastest correct way to run them. It applies the first, second and fifth as its phase-1 bootstraps. It audits the third and fourth read-only:

```bash
bash scripts/deploy-qualify.sh
```

To audit without changing anything:

```bash
bash scripts/bootstrap-opensearch.sh --verify
```

:::caution The file that gets forgotten is the role definition
A release that adds a lane touches the topic list, the ACL script, the router configuration, the index template, and the writer role. Miss the role and the router's bulk writes come back `403`, Vector treats `403` as non-retriable and drops the batch, and the lane produces no index, no consumer lag, no rejected-document counter and no red healthcheck. The surface reads as empty, which looks exactly like "nothing to report yet".
:::

## What is not migrated automatically

**ClickHouse schema changes.** `clickhouse/init.sql` runs only the first time the container starts, when `data/clickhouse/` is empty. Apply a new table or column by hand. The `CREATE TABLE IF NOT EXISTS` and `CREATE MATERIALIZED VIEW IF NOT EXISTS` patterns make re-running idempotent, and existing tables are not touched.

```bash
docker compose exec -T clickhouse clickhouse-client < deployment/docker/clickhouse/init.sql
```

**Tenant at-rest partitioning.** Fresh installs get the tenant-first partition key from `init.sql`. Existing `flows`, `findings` and `tunnels` tables keep their old date-only key until you rebuild them. The migration preserves data and skips tables that are already migrated, so it is safe to re-run.

```bash
docker compose exec -T clickhouse sh -s < deployment/docker/clickhouse/migrate-tenant-partition.sh
```

**Pre-partitioning OpenSearch indices.** Telemetry is written to per-tenant indices. A scoped tenant cannot read indices written before that change, because those index names carry no tenant segment. The platform owner still sees them, and they age out inside the retention window. No action is needed.

**User store format changes.** `data/api/users.json` is read on every API start. A new field gets a zero value on old entries, and a removed field is ignored. Only a renamed field would need a one-shot migration.

**The bootstrap admin.** It is seeded only on a first start with an empty user store. An upgrade never overwrites a password.

**Existing secrets.** `.env` reconciliation appends missing variables; it does not rotate what you already have. To rotate, use the installer, which alters the live store's credential and verifies it before touching `.env`:

```bash
python3 scripts/install.py --rotate-app-secrets
cd deployment/docker && docker compose up -d --force-recreate
```

That covers the application secrets and every store credential the installer can reconcile. It deliberately refuses to touch the Kafka cluster identifier, which is immutable once the broker volume is formatted, and the admin passwords seeded into the other components on their first boot. Rotate those in the product itself and copy the value back into `.env`.

## One-time data migrations

Releases occasionally ship a migration that runs once. These are the current ones.

**Correlation archive skip index (2026-07-09).** New parts are indexed on write automatically. A deployment that already holds archive rows should materialize the index over the existing parts once. It is safe to re-run and takes seconds even at tens of millions of rows.

```bash
docker compose exec clickhouse clickhouse-client -q \
  "ALTER TABLE netops.corr_signals_archive MATERIALIZE INDEX idx_archived_for"
```

Skipping it is not fatal. Reads over pre-upgrade parts stay slow until their next natural merge.

**Optional modules (2026-09-02).** Nothing to do by hand. `update.sh` appends the new `.env` keys for the security lane, configuration backup, packet capture and protocol diagnostics, and every appended value equals the default the compose file already interpolates, so the upgrade is behaviour-neutral. Both feature flags stay `false` until you turn them on. Two new bind mounts, `data/config-backups` and `data/pcap`, are created `0700` and owned by the API's runtime user; `update.sh` does not create them, so run `python3 scripts/install.py --no-start` or `sudo bash scripts/fix-permissions.sh` before turning either module on. Add `data/config-backups` to the backup rotation: it is the only copy of a captured configuration.

**PostgreSQL migrations.** On the PostgreSQL backend the API applies its own migrations at startup, forward-only, serialised by an advisory lock so two replicas booting together cannot both apply one. A migration failure is fatal at boot, never a silently skipped table. Confirm with:

```bash
docker compose exec postgres psql -U netops -c \
  "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 5"
```

On the file backend there is nothing to apply.

## Rolling back

The pre-upgrade tarball restores everything. `restore.sh` puts `data/` back, restores `.env`, and lays the configurations back in place. The next `up -d` is the rollback.

```bash
cd /opt/netops/NetOps_Observability
docker compose down
bash scripts/restore.sh /var/backups/netops/pre-upgrade-2026-05-27-141500.tar.zst
docker compose up -d
```

## If the deployment is very far behind

Upgrades within a generation are routine. Crossing a major architecture change is not. Too many services change between generations for an in-place upgrade to be safe. In that case: take the backup, run `docker compose down -v`, replace the source tree in full, run `python3 scripts/install.py` and let it treat the host as a fresh install, then restore the data you need by hand.

## Related

- [Verify a deployment is doing work](/deploy/verify-deployment) - the gate that catches a silent lane.
- [Back up and restore](/deploy/back-up-and-restore) - the backup the rollback depends on.
- [Turn on an optional module](/deploy/optional-modules) - what the new flags in a release need before they do anything.
