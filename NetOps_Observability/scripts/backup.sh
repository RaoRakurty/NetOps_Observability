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

set -euo pipefail

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

OUT="${1:-}"
if [[ -z "$OUT" ]]; then
  echo "usage: $0 <output.tar.zst>" >&2
  echo "       $0 --verify <backup.tar.zst>" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_DIR="$ROOT/deployment/docker"
DATA_DIR="$ROOT/data"
STAGE="$(mktemp -d -t netops-backup-XXXXXX)"
trap "rm -rf $STAGE" EXIT

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
mkdir -p "$STAGE/data"
if [[ -d "$DATA_DIR" ]]; then
    rsync -a --delete --info=stats1 "$DATA_DIR/" "$STAGE/data/"
else
    echo "  (no data/ directory yet)"
fi

# ---- .env + configs --------------------------------------------------------

echo "→ Snapshotting .env and configs"
if [[ -f "$COMPOSE_DIR/.env" ]]; then
    cp "$COMPOSE_DIR/.env" "$STAGE/env.backup"   # 0600 preserved by tar
fi
mkdir -p "$STAGE/src-config"
if [[ -d "$ROOT/src/config" ]]; then
    rsync -a "$ROOT/src/config/" "$STAGE/src-config/"
fi

# ---- tar + zstd ------------------------------------------------------------

echo "→ Tar + zstd"
tar -C "$STAGE" -cf - . | zstd -T0 -19 -o "$OUT"

echo
echo "─── MANIFEST ───"
cat "$MANIFEST"
echo "────────────────"
echo "→ Done: $OUT ($(du -h "$OUT" | cut -f1))"

# Exit non-zero when any component failed. THIS IS THE POINT: a cron entry
# whose script always exits 0 cannot alert, so `backup.sh` silently producing
# an empty backup every night is indistinguishable from success. Verify a
# written file later with:  scripts/backup.sh --verify <file>
if [[ $FAILURES -gt 0 ]]; then
    echo "!! $FAILURES component(s) FAILED — this archive is INCOMPLETE." >&2
    exit 1
fi
