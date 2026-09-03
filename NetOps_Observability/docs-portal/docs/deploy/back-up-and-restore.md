---
title: Back up and restore
description: Configure search-tier snapshots and an off-host full backup from the Data Protection page, prove a restore works with the drill, and restore for real.
page_type: task
sidebar_position: 11
---

# Back up and restore

Correlix protects two different things in two different ways. The search tier is snapshotted by the cluster itself, daily and incrementally, out of the box. Everything else, which is PostgreSQL, ClickHouse and the whole `data/` tree, is covered by a full backup that ships disabled and stays disabled until you give it somewhere off-host to write.

That default is deliberate. A nightly full backup on the same disk fills the volume it needs.

## Before you begin

- Platform administrator rights. The data-protection surface is platform-global, not per tenant.
- An off-host destination: an absolute path to a separately mounted device, or an `rsync://`, `s3://`, `gs://`, `file://`, `b2://` or `azure://` URL.
- A transport the host can run: `rsync`, `rclone`, `scp`, `aws`, `gsutil`, `b2`, `azcopy` or `cp`, with bare flags only.
- Shell access on the host for the restore drill.

## Steps

1. Go to **Administration → Settings** and find the **Data Protection** card.

2. Read **Disaster-recovery status** before changing anything. It is computed live, never stored, so an unregistered repository or an absent remote reads as a problem rather than as a blank.

3. Check the search-tier snapshot policy. Snapshots are on by default, daily, with a retention count. Disabling them is an explicit act and the page says so.

4. Set the off-host remote and the push command.

   ```
   BACKUP_REMOTE="rsync://backup.example.com/correlix/"
   BACKUP_PUSH="rsync -a"
   ```

   You can set the same values directly in `deployment/docker/.env`.

5. Enable the scheduled full backup. The default schedule is `30 2 * * *`, which is 02:30 daily.

6. Prove the restore works. The drill writes a canary into each live store, backs it up through the real path, restores into a disposable empty container, and asserts the canary came back with the correct content.

   ```bash
   scripts/restore-drill.sh
   ```

   Restrict it to one store with `--stores pg`, and keep the scratch containers for inspection with `--keep`.

7. Re-run the drill after any change to the backup path, and periodically as a disaster-recovery exercise. A backup that has never been restored is a hypothesis.

## Result

The Data Protection page shows the off-host copy as configured, the schedule as enabled, and the last drill result with its timestamp. The snapshot policy reads back through the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/system/backup/snapshots
```

```json
{
  "enabled": true,
  "schedule_cron": "30 1 * * *",
  "retention_max_count": 14,
  "retention_max_age_days": 0,
  "last_run": {
    "status": "FAILED",
    "time": "2026-09-02T01:31:27Z",
    "duration_seconds": 59
  },
  "next_run": "2026-09-04T01:30:00Z"
}
```

The live posture reads back from the companion route:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/system/backup
```

```json
{
  "config": {
    "remote_url": "",
    "schedule_enabled": false,
    "updated_at": "0001-01-01T00:00:00Z"
  },
  "status": {
    "remote_configured": false,
    "schedule_enabled": false,
    "os_snapshot_repo_ok": true,
    "os_last_snapshot_age_hours": 184,
    "os_snapshot_detail": "newest successful snapshot 184h ago",
    "on_host_only_warning": true
  }
}
```

That response is an honest one, and worth reading closely. The search tier has a registered repository and a snapshot, but the newest is 184 hours old, there is no off-host copy, and `on_host_only_warning` is true. Backups and primary data share a disk, so one disk failure loses both.

## Two behaviours that will surprise you if nobody says them

**A schedule with no off-host remote is refused with a `400`.** Both the API and the host-side applier refuse it. The error names the reason:

```
cannot enable the scheduled backup without an off-host remote — a local-only nightly backup fills the disk it needs
```

Set `BACKUP_REMOTE` first, then enable the schedule.

**A scheduled backup with no run report renders as "never ran / not reporting", never as blank.** The status carries the full-backup component's last run, read from the report the backup script writes. When the schedule is enabled and no report exists, the page says so:

```
no run report — never ran, or the host cron is not reporting
```

That is two facts, not one: the job may never have run, or it ran on a host whose cron is not reporting back. Both need investigation, and neither is "fine".

## What protects what

| Store | Protected by | Automatic | Where it lands |
|---|---|---|---|
| OpenSearch (logs, flows) | Daily incremental cluster snapshots | Yes | `data/opensearch-snapshots` |
| PostgreSQL, ClickHouse, the whole `data/` tree | `scripts/backup.sh`, one tarball | No, by default | Wherever you point it |
| Everything, off-host | The `BACKUP_REMOTE` push | Only when configured | Your remote |

Snapshots are incremental and deduplicated: the first is about the size of the index, and a second same-day snapshot adds a fraction of it. Daily is the right frequency for exactly that reason. If space is tight, lower the retention count rather than reducing the frequency, because a weekly schedule saves a few days of small deltas at the cost of up to seven days of recovery point.

:::caution The snapshot repository lives inside the tree it protects
`data/opensearch-snapshots` sits under `data/`. It is real protection against index corruption and accidental deletion, and it is no protection at all against losing the disk. Only the off-host copy covers that.
:::

## The full backup

`scripts/backup.sh <out.tar.zst>` captures a PostgreSQL dump, the ClickHouse schema and data, the OpenSearch snapshot, and `data/` plus `.env`, into one tarball.

```bash
scripts/backup.sh /var/backups/netops/$(date +%F).tar.zst
```

It records `PASS` or `FAIL` per component in a manifest inside the tarball and exits non-zero if any component failed. A backup job that cannot fail is not a backup job. `--verify` re-reads a tarball's manifest and fails if it records a failure or is missing an artifact.

The backend stores your intent in its own state, and a host-side applier enforces it: it writes `BACKUP_REMOTE` into `.env` and installs or removes the backup cron entry. The split exists because the backend runs in a container and cannot write the host crontab. The applier runs automatically from the watchdog cron whenever the stored intent is newer than its last-applied stamp, so a change made in the console is live on the host within a minute.

## Restoring for real

1. Fetch the latest tarball from the off-host remote.
2. Extract it: `tar --zstd -xf backup.tar.zst -C /restore`.
3. Load the PostgreSQL dump into a fresh instance.
4. Recreate the ClickHouse schema, then load each table's native-format data file.
5. Restore OpenSearch from the snapshot repository, or from the copied repository directory.
6. Bring the stack up against the restored volumes.
7. Run `scripts/restore-drill.sh` to confirm the result, and `bash scripts/deploy-qualify.sh` to confirm the pipeline is working.

## Known gaps, stated rather than hidden

- The off-host destination has to be provisioned by you. The push hook is ready; the storage is not.
- The snapshot repository path still lives on the data volume. Move it to separate storage, or make sure the off-host copy captures it independently.
- `.env` holds the credentials for every store. A restore that recovers `data/` without `.env` recovers data nothing can open.

## Related

- [Upgrade a deployment](/deploy/upgrade) - the pre-upgrade snapshot, and the rollback that uses it.
- [Verify a deployment is doing work](/deploy/verify-deployment) - run it after a restore.
- [Administration](/administration/overview) - where the Data Protection page lives.
