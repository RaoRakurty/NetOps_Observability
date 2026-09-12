data/opensearch-snapshots/ IS A LIVE OPENSEARCH SNAPSHOT REPOSITORY.
Do not delete anything inside it. Not even to free disk. Especially to free disk.

WHAT HAPPENS IF YOU DO (this is not hypothetical — it happened here)
  2026-08-26/27: `rm -rf data/opensearch-snapshots/indices` was run from a shell
  during a disk crunch while the repository was still registered. OpenSearch
  re-created the empty directories at 2026-08-27T01:30:46Z, the instant the next
  scheduled snapshot started, and from then on every shard failed with
    java.nio.file.NoSuchFileException: .../snapshots/indices/<id>/0/index-<gen>
  Eight snapshots that still read SUCCESS in `_cat/snapshots` were silently
  UNRESTORABLE. Nobody noticed for seven days. `_snapshot/netops-fs/_cleanup`
  cannot repair it: it returns deleted_bytes 0, because the older snapshots
  still reference the blobs that are gone.

IF YOU NEED THE SPACE, DO THIS INSTEAD (in this order)
  1. curl -X DELETE .../_snapshot/netops-fs          # unregister FIRST
  2. then, and only then, delete files on disk
  3. re-register + take a fresh snapshot + PROVE it restores
  The exact commands: docs/runbooks/storage-and-volume-operations.md#managing-snapshots

TO DELETE A SINGLE RESTORE POINT, USE THE API, NEVER THE FILESYSTEM
  curl -X DELETE .../_snapshot/netops-fs/<snapshot-name>
  or the Data Protection page in the UI (Settings -> Data Protection).

A BACKUP THAT HAS NEVER BEEN RESTORED IS NOT A BACKUP.
  `_verify` only proves the node can write here. Only a restore-and-compare
  proves a restore point. The api runs that probe nightly and exports
  netops_opensearch_snapshot_restorable; if it reads 0, restorability is
  unproven or broken — treat it as no backup at all.
