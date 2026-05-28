#!/usr/bin/env bash
#
# backup.sh — snapshot the full NetOps Observability data directory
# plus per-engine logical dumps into one compressed tarball.
#
# Usage:
#   ./backup.sh /path/to/output-file.tar.zst
#
# Designed to run with the stack RUNNING. We take Postgres / ClickHouse
# dumps via their own clients first (they're transactional) and then
# snapshot the rest of data/ with rsync to a scratch dir before tarring
# — that minimises the window where files are mutating mid-copy. For
# absolute consistency, stop the stack first.
#
# Safe to run BEFORE a first successful install: when a container isn't
# running, its logical dump is skipped and only the on-disk data/
# directory is captured.

set -euo pipefail

OUT="${1:-}"
if [[ -z "$OUT" ]]; then
  echo "usage: $0 <output.tar.zst>" >&2
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

# ---- Postgres -------------------------------------------------------------

if is_running postgres; then
    echo "→ Postgres dump"
    DB_USER_VAL="${DB_USER:-netops}"
    docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T postgres \
        pg_dumpall -U "$DB_USER_VAL" > "$STAGE/postgres.sql"
else
    echo "→ postgres not running — skipping logical dump (data/postgres still in snapshot)"
fi

# ---- ClickHouse -----------------------------------------------------------

if is_running clickhouse; then
    echo "→ ClickHouse dump (schemas only — flow data lives in data/clickhouse)"
    docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
        clickhouse-client --query "SHOW CREATE TABLE netops.flows" \
        > "$STAGE/clickhouse-flows.sql" 2>/dev/null || true
    docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
        clickhouse-client --query "SHOW CREATE TABLE netops.findings" \
        > "$STAGE/clickhouse-findings.sql" 2>/dev/null || true
else
    echo "→ clickhouse not running — skipping logical dump"
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

echo "→ Done: $OUT ($(du -h "$OUT" | cut -f1))"
