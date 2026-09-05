---
title: Manage snapshots
description: Take, list, verify, restore and delete search-tier snapshots, and change the daily schedule and its retention.
page_type: task
sidebar_position: 12
---

# Manage snapshots

Correlix snapshots the search tier into the `netops-fs` repository once a day, on the `netops-daily` schedule. You work with that schedule from the **Data Protection** card and from the API: read what restore points exist, take one on demand, prove one can be restored, restore it, delete it, and retune the window and the retention.

Read [Back up and restore](/deploy/back-up-and-restore) first for how the search tier and the full off-host backup differ. Snapshots protect against index corruption and accidental deletion. They do not protect against losing the disk, because the repository sits on it.

## Before you begin

- Platform administrator rights. Data Protection is platform-global configuration, not per-tenant data. A tenant administrator receives a `403`.
- An API token in `$TOKEN`. Every route below is audited under the calling operator.
- The index names you intend to restore. A restore acts on named indices, not on the whole cluster.
- Free disk for a restore. A restored index is a second full copy of the data it holds.
- Shell access on the host, for the appendix that applies when the API is unreachable.

## Steps

**To read the snapshot inventory:**

1. Go to **Administration → Settings** and open the **Data Protection** card.
2. Read **Disaster-recovery status**. It is computed live at request time, so an unregistered repository or a missing off-host copy reads as a problem rather than as a blank.
3. Read the same state from the command line:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/system/backup/snapshots/list
   ```

   Each entry carries the snapshot name, its state, its shard counts, and the restorable-verified verdict. An entry that has never been probed reports as unverified. Unverified is a different fact from good, and the page never collapses the two.

4. Read the policy and the repository state with the companion route:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/system/backup/snapshots
   ```

5. Read which engine each restore point covers:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/system/backup/coverage
   ```

**To take a snapshot now:**

1. Post an empty body. Correlix generates the snapshot name, so two operators cannot collide on one.

   ```bash
   curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{}' \
     http://localhost:8000/api/system/backup/snapshots/create
   ```

2. The route answers `202` with an `operation` id, because a snapshot outlives an HTTP request. Poll it:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/api/system/backup/operations/<id>
   ```

3. Wait for the operation to leave its running state, then read the shard counts. On a validation host holding 3.1 GiB across 51 indices, a full snapshot took 8.2 minutes. Size a maintenance window from a measurement on your own data.

**To prove a snapshot can be restored:**

1. Run the restorability probe. With an empty body it probes the newest successful snapshot:

   ```bash
   curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{}' \
     http://localhost:8000/api/system/backup/snapshots/verify
   ```

2. Name a snapshot to probe that one instead:

   ```bash
   curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"snapshot":"<name>"}' \
     http://localhost:8000/api/system/backup/snapshots/verify
   ```

3. Poll the returned operation. The probe restores the smallest index under a temporary name, compares the document count against the source, and deletes the temporary copy. The count comparison is the assertion. A restore that returns a different count is a failed restore even though every call returned `200`.

**To restore a snapshot:**

1. Restore under a new name first. The restored indices land beside the live ones and nothing in production is touched:

   ```bash
   curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"snapshot":"<name>","indices":["<idx>"],"mode":"renamed","rename_prefix":"restored-"}' \
     http://localhost:8000/api/system/backup/snapshots/restore
   ```

2. Check the restored copy holds what you expect before you act on it.

3. Restore in place only when the live index is to be replaced. The mode requires the type-to-confirm field as well, and it closes and overwrites the live index:

   ```bash
   curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"snapshot":"<name>","indices":["<idx>"],"mode":"in_place","confirm":"<name>"}' \
     http://localhost:8000/api/system/backup/snapshots/restore
   ```

4. Delete the `restored-` copies once you are finished with them. Each one holds a full second copy of the data and consumes the disk the repository shares.

**To delete a snapshot:**

1. Send the name twice. The `confirm` field must equal `snapshot`, which is what stops a mistyped name from removing a restore point you meant to keep.

   ```bash
   curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"snapshot":"<name>","confirm":"<name>"}' \
     http://localhost:8000/api/system/backup/snapshots/delete
   ```

2. Deleting through this route is safe. OpenSearch removes only the blobs that no remaining snapshot references.

:::danger Never delete files inside the repository directory
Removing files under `data/opensearch-snapshots` while the repository is registered destroys every restore point that references them, including snapshots taken months earlier. The repository keeps reporting healthy afterwards and the failure appears only at restore time. Delete snapshots through the API, or unregister the repository first.
:::

**To change the schedule or the retention:**

1. Set the daily window as a cron expression in UTC:

   ```bash
   curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"schedule_cron":"30 1 * * *"}' \
     http://localhost:8000/api/system/backup/snapshots
   ```

2. Set how many restore points to keep, and how old the oldest may become:

   ```bash
   curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"retention_max_count":3,"retention_max_age_days":7}' \
     http://localhost:8000/api/system/backup/snapshots
   ```

3. Stop the schedule only as a deliberate act, and record why:

   ```bash
   curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"enabled":false}' \
     http://localhost:8000/api/system/backup/snapshots
   ```

   While `enabled` is `false`, no new restore points are created. Every hour it stays off is an hour of indexed logs, traps and flows with no backup.

## Result

The policy reads back with the values you set, and with the last and next run:

```json
{
  "enabled": true,
  "schedule_cron": "30 1 * * *",
  "retention_max_count": 3,
  "retention_max_age_days": 7,
  "last_run": {
    "status": "SUCCESS",
    "time": "2026-09-03T01:31:27Z",
    "duration_seconds": 492
  },
  "next_run": "2026-09-04T01:30:00Z"
}
```

A healthy snapshot in the inventory reports every shard successful and none failed: 51 indices, 51 successful shards, 0 failed, 51 total. A verified snapshot additionally carries the timestamp at which the restore probe last returned a verdict.

## How to read a snapshot's state

**`PARTIAL`, or any non-zero failed-shard count, is a broken restore point.** It is not a warning and not a degraded success. The shards that failed are absent from the snapshot, and no later snapshot backfills them. Treat the entry as though it were not there, and find out why the shards failed before the next scheduled run.

**A snapshot that has never been verified is not a proven backup.** Repository verification proves only that the cluster can write to the repository path. It says nothing about whether any byte of any snapshot is readable. On one deployment, eight consecutive snapshots reported success for seven days while the repository's files had been deleted underneath it, and every restore would have failed. The restorability probe is what separates a restore point from a row in a table, so run it after any change to the repository and let the schedule keep proving it afterwards.

**Retention costs disk on the same volume as the data.** A filesystem repository holds the union of the segments its snapshots reference, so a 14-count retention holds roughly twice the live store in addition to the live store. Raise the retention only after the repository ships off-host. Until then, lower retention is the safer setting, and the shipped default reflects that.

## If the API is unreachable

Every operation above exists as a direct call to OpenSearch. Use this form when the API is the component that is down. The transport uses the admin client certificate, and the hostname has to match that certificate, which is what `--resolve` provides:

```bash
OS_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' netops-opensearch-1)
curl -s --cacert data/tls/ca.pem --cert data/tls/admin/admin.crt --key data/tls/admin/admin.key \
     --resolve opensearch:9200:"$OS_IP" https://opensearch:9200/_cat/snapshots/netops-fs?v
```

`<OS_IP>` is the container address that command reads. The key is a file path, and its contents are never printed, pasted into a ticket, or sent to support.

| What you want | Direct call |
|---|---|
| List repositories | `GET /_snapshot/_all` |
| List snapshots | `GET /_cat/snapshots/netops-fs?v` |
| Read the policy | `GET /_plugins/_sm/policies/netops-daily` |
| Take a snapshot | `PUT /_snapshot/netops-fs/<name>?wait_for_completion=false` |
| Delete a snapshot | `DELETE /_snapshot/netops-fs/<name>` |
| Restore under a new name | `POST /_snapshot/netops-fs/<name>/_restore` with `rename_pattern` and `rename_replacement` |
| Check the repository is writable | `POST /_snapshot/netops-fs/_verify` |
| Stop or start the schedule | `POST /_plugins/_sm/policies/netops-daily/_stop` or `/_start` |

A `PUT` that takes a snapshot answers `{"accepted":true}`, which is acceptance rather than completion. Poll `_cat/snapshots/netops-fs?v` until the row leaves `IN_PROGRESS`, then read its failed-shard count.

Two behaviours of the policy API are worth knowing before you edit it by hand. A create is a bare `POST`, while an update is a `PUT` carrying `if_seq_no` and `if_primary_term` read from a preceding `GET`. An update body that omits `"enabled"` defaults the policy to enabled, which silently restarts a schedule an operator stopped on purpose. Always send the current value of `enabled` with any hand-written update.

The full operator recipes, including the emergency repository recreate, are in the `storage-and-volume-operations` runbook that ships with the deployment.

## Related

- [Back up and restore](/deploy/back-up-and-restore) - the off-host full backup and the restore drill that covers the stores snapshots do not.
- [Verify a deployment is doing work](/deploy/verify-deployment) - run it after any restore.
- [Upgrade a deployment](/deploy/upgrade) - the pre-upgrade snapshot and the rollback that uses it.
- [Alert rules](/reference/alert-rules) - the storage alerts that fire when a repository stops being restorable.
