#!/usr/bin/env bash
#
# backup.sh — snapshot the full NetOps Observability data directory
# plus per-engine logical dumps into one compressed tarball.
#
# Usage:
#   ./backup.sh /path/to/output-file.tar.zst
#
# Designed to run with the stack RUNNING. We take Postgres / ClickHouse /
# OpenSearch backups via their own clients first (they're consistent) and then
# snapshot the rest of data/ with rsync to a scratch dir before tarring
# — that minimises the window where files are mutating mid-copy. For
# absolute consistency, stop the stack first.
#
# Safe to run BEFORE a first successful install: when a container isn't
# running, its logical dump is skipped and only the on-disk data/
# directory is captured.
#
# ---------------------------------------------------------------------------
# F-59 (2026-07-22) — WHAT THIS USED TO DO, AND WHY IT WAS NOT A BACKUP
#
# The audit found: `GET _snapshot` = {} (no OpenSearch snapshot repository had
# ever existed), the "ClickHouse dump" was `SHOW CREATE TABLE` for 2 of 16
# tables — schema text, zero rows — and every one of those commands ended in
# `|| true`, so a total failure produced a tarball and an exit code of 0.
# `scripts/backup.sh` was also not in any crontab, so none of it ran anyway.
# The result was a system that looked backed up and was not, which is strictly
# worse than one that knows it isn't.
#
# What changed:
#   * OpenSearch is backed up with a real SNAPSHOT (the only consistent backup
#     it has — rsync of a live Lucene directory is a torn copy), via the
#     netops-fs repository registered by opensearch/apply-ism.sh.
#   * ClickHouse dumps the SCHEMA OF EVERY TABLE, not two, and states plainly
#     that row data lives in the (snapshot-consistent) data/ copy plus the
#     cold Parquet export.
#   * Nothing is `|| true`. Every component records PASS/FAIL in a MANIFEST
#     inside the tarball, and the script EXITS NON-ZERO if any of them failed.
#     A backup job that cannot fail is not a backup job.
#   * --verify re-reads a tarball's MANIFEST and fails if it records a failure
#     or is missing an artifact — the restore-side check that was absent.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# RETENTION (2026-07-27) — the other half of "this is a real backup".
#
# apply-backup-config.sh installs a DAILY cron writing
# data/backups/correlix-YYYYMMDD.tar.zst, and NOTHING ever pruned them, while
# docs/runbooks/backup-restore.md claimed "retention + monitoring are already in
# place". The only retention that existed was OpenSearch snapshots
# (OPENSEARCH_SNAPSHOT_KEEP). A daily full backup with no retention fills the
# disk it needs — the same failure mode as the bundle-autoupdate incident
# (CLAUDE.md §16.4) — and a full disk takes the primary data with it.
#
#   BACKUP_KEEP=<N>   keep the N newest managed artifacts, prune the rest
#                     (default 7; mirrors the OPENSEARCH_SNAPSHOT_KEEP convention)
#   BACKUP_KEEP=0     pruning DISABLED — loud warning, never a silent default
#
# Rules the prune obeys (§16.1/§16.3):
#   * it runs only after a SUCCESSFUL backup — a failed run never gets to delete
#     history on the strength of an artifact that may be incomplete;
#   * it NEVER deletes the newest artifact, at any value of BACKUP_KEEP;
#   * it only touches the managed `correlix-*.tar.zst` naming scheme, in the
#     directory the new artifact was written to — never a directory it was not
#     pointed at;
#   * a delete failure is FATAL (no `|| true`): a prune that cannot prune must be
#     as visible as the disk it is protecting.
#
#   scripts/backup.sh --prune <dir> [--dry-run]   exercises it standalone.
# ---------------------------------------------------------------------------

# -E (errtrace): the ERR trap below must fire inside functions/subshells too,
# so an abort's failing command lands in the report's reason.
set -Eeuo pipefail

# §16.2 — cron gives us PATH=/usr/bin:/bin only, and docker/zstd/rsync commonly
# live in /usr/local/bin. This script IS a cron job now, so it states its PATH.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --verify <file>: check a previously written backup instead of taking one.
if [[ "${1:-}" == "--verify" ]]; then
  IN="${2:-}"
  if [[ -z "$IN" || ! -f "$IN" ]]; then
    echo "usage: $0 --verify <backup.tar.zst>" >&2
    exit 2
  fi
  MAN=$(zstd -dc "$IN" | tar -xO ./MANIFEST 2>/dev/null || true)
  if [[ -z "$MAN" ]]; then
    echo "VERIFY FAILED: $IN has no MANIFEST — it predates F-59 or is truncated." >&2
    exit 1
  fi
  echo "$MAN"
  if grep -q '^FAIL' <<<"$MAN"; then
    echo "VERIFY FAILED: the manifest records at least one failed component." >&2
    exit 1
  fi
  echo "VERIFY OK: $IN"
  exit 0
fi

SCRIPT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$SCRIPT_ROOT/deployment/docker/.env"

# load_env_default <VAR> — §16.2: cron does NOT source a shell profile and does
# NOT read deployment/docker/.env, so BACKUP_REMOTE/BACKUP_PUSH/BACKUP_KEEP set
# by apply-backup-config.sh were invisible to the nightly run: the off-host copy
# silently never happened and retention would have been unconfigurable. Read the
# value out of .env when the environment does not already provide it. Parsed with
# a strict `^VAR=` match — never `source`d, so a stray line in .env cannot execute.
load_env_default() {
    local var="$1" line
    [[ -n "${!var:-}" ]] && return 0          # an explicit environment value wins
    [[ -f "$ENV_FILE" ]] || return 0
    line="$(grep -m1 "^${var}=" "$ENV_FILE" || true)"   # absent key is not an error
    [[ -z "$line" ]] && return 0
    line="${line#*=}"
    line="${line%\"}"; line="${line#\"}"
    line="${line%\'}"; line="${line#\'}"
    export "${var}=${line}"
}
load_env_default BACKUP_REMOTE
load_env_default BACKUP_PUSH
load_env_default BACKUP_KEEP

BACKUP_KEEP="${BACKUP_KEEP:-7}"
if ! [[ "$BACKUP_KEEP" =~ ^[0-9]+$ ]]; then
    echo "backup: BACKUP_KEEP=${BACKUP_KEEP} is not a non-negative integer" >&2
    exit 2
fi

# prune_backups <dir> — keep the $BACKUP_KEEP newest managed artifacts in <dir>,
# delete the rest. Prints exactly what it will touch BEFORE touching it (§16.3).
# Returns non-zero if any delete failed; the caller records that as a FAILURE.
prune_backups() {
    local dir="$1" dry="${2:-0}" rc=0 idx=0 kept=0 removed=0
    if [[ ! -d "$dir" ]]; then
        echo "  prune: $dir does not exist — nothing to prune"
        return 0
    fi
    if [[ "$BACKUP_KEEP" -eq 0 ]]; then
        echo "!! WARNING: BACKUP_KEEP=0 — retention is DISABLED. Backups will" >&2
        echo "!!          accumulate until they fill the disk the stack needs." >&2
        return 0
    fi

    # Newest first, by mtime. NUL-delimited end to end so a hostile filename in
    # the backup directory cannot split a record and misdirect a delete.
    local -a entries=()
    mapfile -d '' -t entries < <(
        find "$dir" -maxdepth 1 -type f -name 'correlix-*.tar.zst' \
             -printf '%T@\t%p\0' 2>/dev/null | sort -z -rn
    )
    if [[ ${#entries[@]} -eq 0 ]]; then
        echo "  prune: no managed backups (correlix-*.tar.zst) in $dir"
        return 0
    fi

    echo "  prune: ${#entries[@]} managed backup(s) in $dir, keeping the $BACKUP_KEEP newest"
    local entry path
    for entry in "${entries[@]}"; do
        path="${entry#*$'\t'}"
        idx=$((idx + 1))
        # The newest is protected UNCONDITIONALLY, independent of the arithmetic
        # above: a retention bug must never be able to leave us with no backup.
        if [[ $idx -eq 1 || $idx -le $BACKUP_KEEP ]]; then
            kept=$((kept + 1))
            continue
        fi
        if [[ "$dry" == "1" ]]; then
            echo "    [dry-run] would delete $path"
            removed=$((removed + 1))
            continue
        fi
        if rm -f -- "$path" 2>"$dir/.prune.err"; then
            echo "    deleted $path"
            removed=$((removed + 1))
        else
            echo "    !! FAILED to delete $path: $(tail -1 "$dir/.prune.err" 2>/dev/null)" >&2
            rc=1
        fi
    done
    rm -f -- "$dir/.prune.err" 2>/dev/null || true  # optional: cleanup of our own temp
    echo "  prune: kept $kept, removed $removed"
    return $rc
}

# --prune <dir> [--dry-run]: run ONLY the retention sweep (the documented dry-run
# / test seam; the nightly path calls the same function).
if [[ "${1:-}" == "--prune" ]]; then
    PDIR="${2:-}"
    if [[ -z "$PDIR" ]]; then
        echo "usage: $0 --prune <dir> [--dry-run]" >&2
        exit 2
    fi
    PDRY=0
    [[ "${3:-}" == "--dry-run" ]] && PDRY=1
    prune_backups "$PDIR" "$PDRY"
    exit $?
fi

OUT="${1:-}"
if [[ -z "$OUT" ]]; then
  echo "usage: $0 <output.tar.zst>" >&2
  echo "       $0 --verify <backup.tar.zst>" >&2
  echo "       $0 --prune  <dir> [--dry-run]" >&2
  exit 1
fi

ROOT="$SCRIPT_ROOT"
COMPOSE_DIR="$ROOT/deployment/docker"
DATA_DIR="$ROOT/data"
STAGE="$(mktemp -d -t netops-backup-XXXXXX)"
START_EPOCH="$(date +%s)"

# ---------------------------------------------------------------------------
# Honest run report on EVERY exit path (2026-08-14). The report used to be
# written only by straight-line code at the end of the run, so any set -e
# abort (rsync of the live tree, zstd refusing an overwrite, an unexpected
# failure anywhere) skipped it — and the GUI (system_backup.go reads
# data/api/backup-report.json) kept rendering the PREVIOUS run's green
# "success" pill as current truth. Now:
#   * write_report is the single writer (atomic tmp+rename, both outcomes);
#   * the EXIT trap writes a status=failed report — naming the aborted step
#     and the failing command — whenever the run dies before the normal
#     report write (REPORT_DONE guards double writes);
#   * a report-write failure stays a WARNING, never a masked backup error.
# ---------------------------------------------------------------------------
CURRENT_STEP="startup"
REPORT_DONE=0
ERR_CMD=""
trap 'ERR_CMD=$BASH_COMMAND' ERR

write_report() { # <status> <reason>  (reason may be empty)
    local status="$1" reason="$2" size rdir="$DATA_DIR/api"
    size=$(stat -c%s -- "$OUT" 2>/dev/null || echo 0)
    # JSON-safety: the reason can carry a shell command line — strip quotes,
    # backslashes and control chars, and bound it.
    reason=$(printf '%s' "$reason" | tr -d '\042\134' | tr -s '[:cntrl:]' ' ' | cut -c1-300)  # \042="  \134=backslash
    if [[ ! -d "$rdir" ]] \
       || ! printf '{"status":"%s","ended":"%s","size_bytes":%s,"duration_seconds":%s,"failures":%s,"artifact":"%s","reason":"%s"}\n' \
            "$status" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$size" \
            "$(( $(date +%s) - START_EPOCH ))" "${FAILURES:-0}" "$(basename -- "$OUT")" "$reason" \
            > "$rdir/backup-report.json.tmp" \
       || ! mv -f -- "$rdir/backup-report.json.tmp" "$rdir/backup-report.json"; then
        echo "!! WARNING: could not write $rdir/backup-report.json — the GUI will show a stale last-run" >&2
        return 0
    fi
    REPORT_DONE=1
}

# Single-quoted trap body (SC2064): everything resolves when the trap FIRES,
# and a staging path with a space can never word-split into `rm -rf /`.
finish() {
    local rc=$?
    rm -rf -- "$STAGE"
    if [[ $rc -ne 0 && ${REPORT_DONE:-0} -eq 0 ]]; then
        echo "!! backup ABORTED during: ${CURRENT_STEP:-startup} (exit $rc)" >&2
        write_report "failed" "aborted during ${CURRENT_STEP:-startup} (exit $rc)${ERR_CMD:+ — failed command: $ERR_CMD}"
    fi
    return "$rc"
}
trap finish EXIT

# is_running <service>  → returns 0 if the named compose service has a
# container currently in Running state, non-zero otherwise.
is_running() {
    local svc="$1"
    docker compose -f "$COMPOSE_DIR/docker-compose.yml" ps --status running --services 2>/dev/null \
        | grep -qx "$svc"
}

# MANIFEST is the honesty record. Every component appends exactly one line;
# a FAIL line makes this script exit non-zero and `--verify` reject the file.
MANIFEST="$STAGE/MANIFEST"
FAILURES=0
: > "$MANIFEST"
note()  { echo "PASS $*" >> "$MANIFEST"; }
fail()  { echo "FAIL $*" >> "$MANIFEST"; FAILURES=$((FAILURES + 1)); echo "  !! $*" >&2; }
skip()  { echo "SKIP $*" >> "$MANIFEST"; }

# ---- Postgres -------------------------------------------------------------

CURRENT_STEP="postgres dump"
if is_running postgres; then
    echo "→ Postgres dump"
    DB_USER_VAL="${DB_USER:-netops}"
    if docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T postgres \
        pg_dumpall -U "$DB_USER_VAL" > "$STAGE/postgres.sql" 2>"$STAGE/postgres.err"; then
        # An empty dump is a FAILED dump. pg_dumpall can exit 0 having written
        # nothing if it is pointed at the wrong socket; a 0-byte postgres.sql
        # inside a green backup is the exact shape this finding is about.
        if [[ -s "$STAGE/postgres.sql" ]]; then
            note "postgres pg_dumpall $(wc -c < "$STAGE/postgres.sql") bytes"
        else
            fail "postgres pg_dumpall produced an EMPTY dump"
        fi
    else
        fail "postgres pg_dumpall failed: $(tail -1 "$STAGE/postgres.err" 2>/dev/null)"
    fi
else
    skip "postgres not running (data/postgres still in the snapshot)"
fi

# ---- ClickHouse -----------------------------------------------------------
#
# Schema for EVERY table, not two. Row data is captured by the data/ snapshot
# below plus scripts/ch-cold-export.sh (Parquet, the durable tier); the schema
# dump is what makes an empty-volume restore reproducible.

CURRENT_STEP="clickhouse dump"
if is_running clickhouse; then
    echo "→ ClickHouse schema dump (all tables)"
    CH_TABLES=$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
        clickhouse-client --query \
        "SELECT name FROM system.tables WHERE database='netops' AND engine NOT LIKE '%View' ORDER BY name" \
        2>"$STAGE/clickhouse.err" || true)
    if [[ -z "$CH_TABLES" ]]; then
        fail "clickhouse table list empty: $(tail -1 "$STAGE/clickhouse.err" 2>/dev/null)"
    else
        : > "$STAGE/clickhouse-schema.sql"
        CH_OK=0; CH_BAD=0
        while read -r tbl; do
            [[ -z "$tbl" ]] && continue
            if docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
                clickhouse-client --query "SHOW CREATE TABLE netops.$tbl" \
                >> "$STAGE/clickhouse-schema.sql" 2>>"$STAGE/clickhouse.err"; then
                printf ';\n\n' >> "$STAGE/clickhouse-schema.sql"
                CH_OK=$((CH_OK + 1))
            else
                CH_BAD=$((CH_BAD + 1))
            fi
        done <<< "$CH_TABLES"
        if [[ $CH_BAD -gt 0 ]]; then
            fail "clickhouse schema dump: $CH_BAD of $((CH_OK + CH_BAD)) tables failed"
        else
            note "clickhouse schema $CH_OK tables"
        fi

        # ---- ClickHouse DATA (2026-07-23) --------------------------------------
        # Until now this captured SCHEMA ONLY — SHOW CREATE TABLE, zero rows — and
        # relied on the data/clickhouse filesystem rsync for the rows. A live-CH
        # data-dir copy is not guaranteed consistent (parts merge mid-copy), so
        # the OLAP store holding signals/objects/edges/evidence/flows had no
        # RELIABLE row backup. Dump each table as FORMAT Native — ClickHouse's own
        # binary, exactly type-preserving and re-ingestible with INSERT … FORMAT
        # Native — which restore-drill.sh exercises. Compressed; skips *View
        # engines (materialised from their sources).
        echo "→ ClickHouse data dump (Native, all tables)"
        mkdir -p "$STAGE/clickhouse-data"
        CH_D_OK=0; CH_D_BAD=0
        while read -r tbl; do
            [[ -z "$tbl" ]] && continue
            if docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
                clickhouse-client --query \
                "SELECT * FROM netops.$tbl FORMAT Native SETTINGS tenant_scope='__all__'" \
                2>>"$STAGE/clickhouse.err" | gzip > "$STAGE/clickhouse-data/$tbl.native.gz"; then
                CH_D_OK=$((CH_D_OK + 1))
            else
                CH_D_BAD=$((CH_D_BAD + 1))
            fi
        done <<< "$CH_TABLES"
        if [[ $CH_D_BAD -gt 0 ]]; then
            fail "clickhouse data dump: $CH_D_BAD of $((CH_D_OK + CH_D_BAD)) tables failed"
        else
            note "clickhouse data $CH_D_OK tables (Native)"
        fi
    fi
else
    skip "clickhouse not running"
fi

# ---- OpenSearch -----------------------------------------------------------
#
# A SNAPSHOT, not an rsync. Lucene segments are written continuously, so a
# file-level copy of a live index directory is torn and may not open at all;
# a snapshot is the only consistent backup OpenSearch offers. It is incremental
# against the netops-fs repository, so this costs roughly the day's new
# segments. data/opensearch-snapshots is picked up by the data/ copy below.

CURRENT_STEP="opensearch snapshot"
if is_running opensearch; then
    SNAP="backup-$(date -u +%Y%m%d-%H%M%S)"
    echo "→ OpenSearch snapshot $SNAP"
    OS_RESP=$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T opensearch \
        curl -s -X PUT "http://localhost:9200/_snapshot/netops-fs/$SNAP?wait_for_completion=true" \
        -H 'Content-Type: application/json' \
        -d '{"indices":"netops-*","ignore_unavailable":true,"include_global_state":false}' 2>&1 || true)
    case "$OS_RESP" in
        *'"state":"SUCCESS"'*) note "opensearch snapshot $SNAP" ;;
        *'"state":"PARTIAL"'*) fail "opensearch snapshot $SNAP is PARTIAL — some shards were not captured" ;;
        *repository_missing*|*RepositoryMissingException*)
            fail "opensearch snapshot repository netops-fs is NOT registered — the search tier has NO backup (run opensearch-init / apply-ism.sh)" ;;
        *) fail "opensearch snapshot failed: ${OS_RESP:0:300}" ;;
    esac
else
    skip "opensearch not running — NO consistent search-tier backup in this file"
fi

# ---- data dir snapshot ----------------------------------------------------

echo "→ Snapshotting data/"
CURRENT_STEP="data/ snapshot (rsync)"
mkdir -p "$STAGE/data"
if [[ -d "$DATA_DIR" ]]; then
    # rsync of the LIVE, mutating data/ tree. rc=24 ("some files vanished
    # before they could be transferred") is the EXPECTED outcome on a running
    # stack — files legitimately appear and disappear mid-scan — and is a
    # warning, not a failure: the stores whose consistency matters (PG/CH/OS)
    # were dumped with their own consistent mechanisms above; this copy only
    # minimises the mutation window for the rest. Before 2026-08-14 this was a
    # bare statement under set -e, so rc=24 killed the whole run with no
    # report. Any OTHER rc (23 = partial transfer from real errors, I/O,
    # permissions) is a genuine failure and is recorded as one.
    rsync_rc=0
    rsync -a --delete --info=stats1 "$DATA_DIR/" "$STAGE/data/" || rsync_rc=$?
    case "$rsync_rc" in
        0)  note "data/ snapshot (rsync)" ;;
        24) note "data/ snapshot (rsync rc=24: vanished files — expected on a live stack)" ;;
        *)  fail "data/ snapshot rsync failed (rc=$rsync_rc)" ;;
    esac
else
    echo "  (no data/ directory yet)"
    skip "no data/ directory yet"
fi

# ---- .env + configs --------------------------------------------------------

echo "→ Snapshotting .env and configs"
CURRENT_STEP=".env + config snapshot"
if [[ -f "$COMPOSE_DIR/.env" ]]; then
    cp "$COMPOSE_DIR/.env" "$STAGE/env.backup"   # 0600 preserved by tar
fi
mkdir -p "$STAGE/src-config"
if [[ -d "$ROOT/src/config" ]]; then
    # Near-static source configs: any rsync failure here is real (no vanished-
    # file tolerance needed) — record it instead of aborting reportless.
    if ! rsync -a "$ROOT/src/config/" "$STAGE/src-config/"; then
        fail "src/config snapshot rsync failed"
    fi
fi

# ---- tar + zstd ------------------------------------------------------------

echo "→ Tar + zstd"
CURRENT_STEP="tar+zstd archive write"
# -f: the cron names its artifact correlix-YYYYMMDD.tar.zst, so a same-day
# re-run (manual retry after a failure) targets an EXISTING file — without -f
# zstd refuses the overwrite and the whole run aborted (found 2026-08-14).
# Overwriting the same-day artifact with a fresh complete one is the intent.
tar -C "$STAGE" -cf - . | zstd -T0 -19 -f -o "$OUT"

echo
echo "─── MANIFEST ───"
cat "$MANIFEST"
echo "────────────────"
echo "→ Done: $OUT ($(du -h "$OUT" | cut -f1))"

# ---- off-host copy (DR failure-domain, BACKUP-FAILURE-DOMAIN.md) -----------
#
# A backup on the same disk/host as primary data is not disaster recovery: one
# LVM/filesystem failure or the 95% flood-stage takes both. When BACKUP_REMOTE
# is set, push the artifact to a DIFFERENT failure domain. The transport is the
# operator's choice — anything that takes "<src> <dest>" works:
#
#   BACKUP_REMOTE="rsync://backup-host/correlix/"          # + rsync
#   BACKUP_REMOTE="s3://correlix-dr/"   BACKUP_PUSH="rclone copy"
#   BACKUP_REMOTE="/mnt/nas/correlix/"  (a separately-mounted device/NFS)
#
# UNSET is reported as a WARNING, never a silent pass: an operator who thinks
# they have DR and does not is the exact looks-backed-up-but-isnt state F-59 was
# about. A push FAILURE is fatal (the off-host copy is the whole point).
CURRENT_STEP="off-host copy"
if [[ -n "${BACKUP_REMOTE:-}" ]]; then
    PUSH_CMD="${BACKUP_PUSH:-rsync -a}"
    echo "→ Off-host copy: $PUSH_CMD $OUT $BACKUP_REMOTE"
    if $PUSH_CMD "$OUT" "$BACKUP_REMOTE" 2>"$STAGE/push.err"; then
        note "off-host copy → $BACKUP_REMOTE"
    else
        fail "off-host copy FAILED: $(tail -1 "$STAGE/push.err" 2>/dev/null) — the artifact is ON-HOST ONLY (no DR)"
    fi
else
    echo "!! WARNING: BACKUP_REMOTE unset — this backup shares the primary data's" >&2
    echo "!!          failure domain (same disk/host). It is NOT disaster recovery." >&2
    echo "!!          See docs/audit/BACKUP-FAILURE-DOMAIN.md. Set BACKUP_REMOTE to fix." >&2
fi

# ---- retention sweep -------------------------------------------------------
#
# LAST, and only on a clean run. Ordering is deliberate: we prune history only
# once THIS artifact exists, is non-empty, and every component reported PASS —
# otherwise a broken night would delete good backups to make room for a bad one.
CURRENT_STEP="retention prune"
echo "→ Retention (BACKUP_KEEP=$BACKUP_KEEP)"
if [[ $FAILURES -gt 0 ]]; then
    echo "  prune SKIPPED: this run recorded $FAILURES failure(s) — refusing to delete" >&2
    echo "  older backups on the strength of an incomplete artifact." >&2
elif [[ ! -s "$OUT" ]]; then
    fail "prune SKIPPED: $OUT is missing or empty after tar — refusing to prune"
elif ! prune_backups "$(dirname -- "$OUT")" "${BACKUP_PRUNE_DRY_RUN:-0}"; then
    fail "backup retention prune failed — old artifacts are accumulating on the backup disk"
fi

# Machine-readable run report (#150): the api's Backup & DR page reads this
# (BACKUP_REPORT, default /data/backup-report.json inside the container; the
# api's /data maps to data/api on the host — the same mapping
# apply-backup-config.sh documents for system_backup.json) to show the
# full-backup component's last_run {status,time,size,duration} — the host
# cron's outcome is otherwise invisible to the GUI. Written on EVERY outcome
# (write_report is also the EXIT trap's abort path — see its header); a
# report-write failure is a warning, never a masked backup error.
CURRENT_STEP="run report"
REPORT_STATUS="success"; REPORT_REASON=""
if [[ $FAILURES -gt 0 ]]; then
    REPORT_STATUS="failed"
    REPORT_REASON="$FAILURES component(s) failed — see MANIFEST in the archive"
fi
write_report "$REPORT_STATUS" "$REPORT_REASON"

# Exit non-zero when any component failed. THIS IS THE POINT: a cron entry
# whose script always exits 0 cannot alert, so `backup.sh` silently producing
# an empty backup every night is indistinguishable from success. Verify a
# written file later with:  scripts/backup.sh --verify <file>
if [[ $FAILURES -gt 0 ]]; then
    echo "!! $FAILURES component(s) FAILED — this archive is INCOMPLETE." >&2
    exit 1
fi
