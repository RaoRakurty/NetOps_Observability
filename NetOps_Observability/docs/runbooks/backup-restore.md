# Backup, Snapshots & Restore — Operator Runbook

This is the operator guide to Correlix data protection: what runs automatically,
what you configure, and how to prove a restore works.

## TL;DR

| Store | What protects it | Automatic? | Where |
|---|---|---|---|
| OpenSearch (search: logs, flows) | daily incremental snapshots (`netops-daily`) | **Yes**, cluster-run | `data/opensearch-snapshots` |
| Postgres, ClickHouse, full `data/` | `scripts/backup.sh` → one tarball | **No** by default | wherever you point it |
| Everything, off-host | `BACKUP_REMOTE` push | only if configured | your remote |

The **restore drill** (`scripts/restore-drill.sh`) proves all three actually
restore, with content verified.

---

## 1. OpenSearch snapshots (automatic, cheap)

Registered by `opensearch-init` at install: a filesystem snapshot repository
(`netops-fs`) plus a Snapshot Management policy (`netops-daily`).

- **Schedule:** daily, 01:30 UTC. **Retention:** `OPENSEARCH_SNAPSHOT_KEEP` (default 14).
- **Cost:** incremental + deduplicated. Measured: first snapshot ≈ index size
  (~145 MB on a 164 MB index); a second same-day snapshot added **+1 MB**. Each
  daily snapshot only stores that day's new segments, so the repo stays bounded
  at roughly `index_size + N days of deltas`.
- **Daily vs weekly:** daily is the norm and correct here — because snapshots are
  incremental, weekly saves only a few days of tiny deltas at the cost of a worse
  RPO (up to 7 days lost vs 1). If space is tight, lower `OPENSEARCH_SNAPSHOT_KEEP`,
  don't reduce frequency.
- **Verify:**
  ```
  curl -s localhost:9200/_snapshot/netops-fs/_all | jq '.snapshots[-1] | {snapshot,state,end}'
  ```
  The `netops-fs` repository dir MUST be writable by uid 1000 (the opensearch
  user). If registration fails with `access_denied`, chown it:
  ```
  docker run --rm -v "$PWD/data/opensearch-snapshots:/s" alpine chown -R 1000:1000 /s
  docker compose up opensearch-init
  ```

> ⚠️ `data/opensearch-snapshots` lives inside `data/` — the tree it protects. It
> is real protection against index corruption / accidental delete, but NOT
> against losing the disk. For that you need the off-host copy below.

## 2. Full-stack backup (`backup.sh`) — configure per environment

`scripts/backup.sh <out.tar.zst>` captures Postgres (`pg_dumpall`), ClickHouse
(schema + `FORMAT Native` data), the OpenSearch snapshot, and `data/` + `.env`
into one tarball. It exits **non-zero** on any partial dump — a cron that ignores
that is worse than no backup.

**It is NOT scheduled by default**, on purpose: a nightly full backup on the same
disk fills the volume it needs (this is the F-55 disk-pressure failure). Enable
it only with an off-host destination.

### Lab / space-constrained

Leave it off. OpenSearch daily snapshots already give you real search-tier DR at
~a few hundred MB. The full backup is a prod concern — the code ships, disabled.

### Production

1. Provision an off-host destination (S3/MinIO, a NAS, another host).
2. Set it in the UI: **Settings → Data Protection** (platform admin), or directly:
   ```
   BACKUP_REMOTE="rsync://backup-host/correlix/"   # in deployment/docker/.env
   BACKUP_PUSH="rsync -a"                            # or "rclone copy" for object storage
   ```
3. Enable the schedule (UI toggle, or the applier writes the cron). The API and
   the applier both **refuse to schedule without `BACKUP_REMOTE`**.

## 3. Configuring it from the UI

**Settings → Data Protection** (platform-owner only) shows:

- **Live DR status** — snapshot repo health + newest snapshot age, whether an
  off-host remote is set, schedule state, and the last restore-drill result. It
  is honest by construction: an unregistered repo or an absent remote shows as a
  warning, never blank.
- **Config** — the off-host remote, push command, and the full-backup schedule.

The backend stores the intent (`/data/system_backup.json`); the host applier
(`scripts/apply-backup-config.sh`) enforces it — writes `BACKUP_REMOTE` into
`.env` and installs/removes the backup cron. This split exists because the
backend runs in a container and cannot write the host crontab. The applier is
invoked automatically by the stack watchdog cron whenever the stored intent is
newer than its last-applied stamp (`stack-watchdog.sh`, `apply_backup_intent`
— a GUI change is live on the host within a minute), and can be run by hand.

## 4. Prove a restore works — the drill

```
scripts/restore-drill.sh                 # all three stores, into disposable scratch
scripts/restore-drill.sh --stores pg     # one store
scripts/restore-drill.sh --keep          # leave scratch for inspection
```

It writes a canary into each live store, backs it up the real way, restores into
an **empty disposable container** (never a live volume), and asserts the canary
(magic + exact timestamp) came back. Emits JSON to
`data/api/restore-drill.report.json` — the api container's `/data` mount, so
the Data Protection page surfaces the last drill result — and exits non-zero
on any failed assertion (`RESTORE_DRILL_REPORT` overrides the path).

Proven: 17/17 assertions, RTO pg ~21s / ch ~9s / os ~52s.

Run it after any change to the backup path, and periodically as a DR drill — a
backup that has never been restored is a hypothesis.

## 5. Restore for real (disaster)

1. Fetch the latest tarball from `BACKUP_REMOTE`.
2. `tar --zstd -xf backup.tar.zst -C /restore`
3. Postgres: `psql < /restore/postgres.sql` into a fresh instance.
4. ClickHouse: recreate schema from `clickhouse-schema.sql`, load each
   `clickhouse-data/<table>.native.gz` with `INSERT … FORMAT Native`.
5. OpenSearch: restore from the `netops-fs` snapshot (or the copied repo dir).
6. Bring the stack up against the restored volumes and run the drill to confirm.

## Known gaps (need infrastructure, not code)

- Off-host storage must be **provisioned** (the push hook is ready).
- `data/opensearch-snapshots` `path.repo` still lives on the data volume — move
  it to separate storage, or ensure the off-host copy captures it independently.
- The primary `data/` volume is small (see F-55). A separate/larger volume is a
  hypervisor decision. Retention + monitoring are already in place.

See `docs/audit/BACKUP-FAILURE-DOMAIN.md` for the failure-domain analysis.
