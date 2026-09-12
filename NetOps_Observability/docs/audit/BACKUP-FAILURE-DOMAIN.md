# Backup Failure-Domain Analysis (Phase 10)

> Measured 2026-07-23 on the current deployment host. This is the "is a copy on
> the same disk a backup?" question. The answer here is no, at every level.

## What was measured

| Artifact | Location | Filesystem | Block device | Host |
|---|---|---|---|---|
| **Primary data** (`data/`: PG, ClickHouse, OpenSearch, Kafka, …) | `/home/.../data` | `/dev/mapper/ubuntu--vg-ubuntu--lv` → `/` | one LVM LV | this host |
| `backup.sh` tarball | caller-supplied path (no default off-host) | same `/` unless told otherwise | same | this host |
| `update.sh` pre-upgrade snapshot | `/var/backups/netops` | same `/` | same | this host |
| **OpenSearch snapshots** | `data/opensearch-snapshots` | same `/` — *inside the data tree it protects* | same | this host |

## The finding

**Every backup shares the primary data's failure domain — filesystem, block
device, host, and credentials.** The 3-2-1 rule (3 copies, 2 media, 1 offsite)
is violated at step one:

1. **Same filesystem / block device.** A filesystem corruption, an LVM/disk
   failure, or the OpenSearch 95% flood-stage that sets every index read-only
   takes primary AND backup at once. The disk sat at **91%** earlier this session
   (F-55: six stores on one 77 GB volume, ~7 GB margin) — the exact condition
   under which a shared-domain copy is worthless.
2. **OpenSearch snapshots live *inside* `data/`.** The snapshot repository
   (`path.repo → data/opensearch-snapshots`) is in the very tree it is meant to
   recover. `data/` loss loses the snapshots with it. The compose file already
   admits this: *"Copy/rsync data/opensearch-snapshots off-host to make it one."*
3. **No automated backups run at all.** `backup.sh` is **not in any crontab**.
   Backups are produced only when a human runs the script. There is no schedule,
   so there is no RPO in practice — the last backup is "whenever someone last
   thought of it."
4. **Same host / credentials.** Ransomware, a compromised host account, or an
   `rm -rf` reaches primary and backup with the same permissions.

## Severity

High. It compounds with two known items: F-55 (the volume is small and has hit
flood stage once) and the fact that the restore drill (`restore-drill.sh`) can
now *prove* a restore works — which makes it worse, not better, that the artifact
being restored lives on the disk most likely to fail.

## Mechanism now in place (2026-07-23)

`backup.sh` gained a `BACKUP_REMOTE` off-host push (rsync/rclone/NFS — the
operator's transport via `BACKUP_PUSH`). When set, the artifact is copied to a
separate failure domain and a push failure is FATAL; when unset, the script WARNS
that the backup is on-host-only and not DR (never a silent pass). This closes the
*code* half. The remaining half needs infrastructure authorization:

## What still needs infra authorization

- **Provision the off-host destination** and set `BACKUP_REMOTE` (the push hook
  is ready). S3/MinIO/NAS on a different host; write-once or separately
  credentialed storage also addresses the ransomware / same-credentials axis.
- **Schedule `backup.sh` ONLY AFTER `BACKUP_REMOTE` is set.** A local-only
  nightly backup on the current 68%-full 77 GB volume would *cause* F-55 — it is
  deliberately NOT scheduled until the artifact goes off-host. The script already
  exits non-zero on a partial dump; the cron must surface that per §16.1.
- **Move the OpenSearch `path.repo` off the data volume**, or at minimum ensure
  the off-host copy captures it independently.
- **Then extend `restore-drill.sh`** to pull from the off-host copy, so the drill
  proves the DR path, not just the local-copy path.

These require provisioning storage/credentials on infrastructure this audit
cannot modify without explicit authorization, so they are documented as the
required remediation rather than silently half-done.
