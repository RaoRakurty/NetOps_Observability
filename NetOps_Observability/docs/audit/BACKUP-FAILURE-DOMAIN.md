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

## What would fix it (not provisioned here — needs infra authorization)

- **Off-host destination with retention.** `backup.sh` output and
  `data/opensearch-snapshots` rsync'd to a different host / object store (S3,
  MinIO, a NAS) on a schedule. Object storage also addresses the ransomware /
  same-credentials axis if it is write-once or separately credentialed.
- **Schedule `backup.sh`** (daily, off-peak) so an RPO actually exists — with
  the §16.1 discipline: it already exits non-zero on a partial dump; the cron
  must surface that, not `|| true` it.
- **Move the OpenSearch `path.repo` off the data volume**, or at minimum ensure
  the off-host copy captures it independently.
- **Then extend `restore-drill.sh`** to pull from the off-host copy, so the drill
  proves the DR path, not just the local-copy path.

These require provisioning storage/credentials on infrastructure this audit
cannot modify without explicit authorization, so they are documented as the
required remediation rather than silently half-done.
