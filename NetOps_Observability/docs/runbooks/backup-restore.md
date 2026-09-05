# Backup, Snapshots & Restore — Operator Runbook

This is the operator guide to Correlix data protection: what runs automatically,
what you configure, and how to prove a restore works.

## TL;DR

| Store | What protects it | Automatic? | Where |
|---|---|---|---|
| OpenSearch (search: logs, flows) | daily incremental snapshots (`netops-daily`) | **Yes**, cluster-run | `data/opensearch-snapshots` |
| Postgres, ClickHouse, full `data/` | `scripts/backup.sh` → one tarball | **No** by default | wherever you point it |
| VictoriaMetrics (time series) | `scripts/backup.sh` calls VM's own `/snapshot/create`, copies it out, deletes it | inside the bundle | `./victoriametrics/<snap>` in the tarball |
| Sealed custody material (`data/swtpm`, `data/tls`, wrapped keys) | `scripts/backup.sh` — a SEPARATELY ENCRYPTED member, **fail-closed** | inside the bundle | `./sealed/` in the tarball |
| Everything, off-host | `BACKUP_REMOTE` push (+ `BACKUP_REMOTE_VERIFY=1` to re-checksum at the far end) | only if configured | your remote |
| A second OpenSearch repository, off this disk | `docker-compose.snapshot-repo2.yml` overlay | **No**, opt-in | your separate mount |

Two drills, and they prove different things:

* `scripts/restore-drill.sh` proves the **mechanism** — canary into the live
  stores, dump, restore into scratch, canary comes back.
* `scripts/backup-drill.sh` proves **a real bundle artifact** restores: the
  Postgres dump, the ClickHouse export, the VictoriaMetrics snapshot and the
  sealed custody envelope, out of the file you actually hold. See
  `storage-and-volume-operations.md#bundle-restore-drill`.

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
(schema + `FORMAT Native` data), the OpenSearch snapshot, a VictoriaMetrics
snapshot, the sealed custody material and `data/` + `.env` into one tarball. It
exits **non-zero** on any partial dump — a cron that ignores that is worse than
no backup.

### The knobs, and what each one costs you if you get it wrong

| Variable | Default | What it does |
|---|---|---|
| `BACKUP_REMOTE` | unset | off-host destination. Unset = the copy shares the primary data's failure domain, and the run says so. |
| `BACKUP_PUSH` | `rsync -a` | the transport. Word-split, so use `RSYNC_RSH` for a custom ssh rather than embedding `-e "..."`. |
| `BACKUP_REMOTE_VERIFY` | `0` | `1` re-runs `sha256sum -c SHA256SUMS` **at the destination** over `BACKUP_SSH`. This is the only thing that turns "pushed" into **proven**, and the Data Protection page reserves that word for it. |
| `BACKUP_SSH` | `ssh` | transport for the verification call. Word-split like `BACKUP_PUSH`. |
| `BACKUP_SIGN_KEY` | unset | HMAC key for `$OUT.sig`. Unset = corruption is detectable, tampering is not. |
| `BACKUP_SEALED_PASSPHRASE` | unset | passphrase for the custody envelope. **Fail-closed**: with custody material present and no passphrase, the component FAILS. It never degrades to plaintext. |
| `BACKUP_SEALED_MATERIAL` | `1` | `0` is the deliberate opt-out — a loud SKIP, not a failure. A bundle restored onto a host without `data/swtpm` decrypts nothing. |
| `BACKUP_VICTORIA` | `1` | `0` skips the time-series snapshot. |
| `BACKUP_CH_MAX_TABLE_MB` | `512` | per-table ceiling on the ClickHouse `FORMAT Native` export. Larger tables ship as **schema only** and the component reports `partial`, never `pass`; their rows belong in the cold Parquet tier (`scripts/ch-cold-export.sh`). `0` disables the ceiling. |
| `BACKUP_EXCLUDE` | unset | extra rsync excludes for the `data/` copy, space-separated and anchored at `data/` (e.g. `"/kafka /opensearch"`). Recorded in the MANIFEST **and** the run report, so a narrowed bundle can never be presented as a full one. |
| `BACKUP_KEEP` | `7` | artifacts to keep. `0` disables pruning, loudly. |
| `OPENSEARCH_ADMIN_CERT_DIR` | `data/tls/admin` | when `admin.crt`/`admin.key`/`ca.pem` are there, the OpenSearch snapshot call is made over the compose network with that client certificate — which is the only way it works on a stack with the security plugin enabled. |

**Where the custody passphrase must NOT live:** on the backup host, next to the
artifact. The whole point of the separate envelope is that the tarball plus the
`.env` inside it still cannot unseal the vault. Keep it where the KEK ceremony
keeps its material.

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
