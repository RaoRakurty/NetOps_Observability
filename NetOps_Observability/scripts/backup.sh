#!/usr/bin/env bash
#
# backup.sh — snapshot the full NetOps Observability data directory
# plus per-engine logical dumps into one compressed tarball.
#
# Usage:
#   ./backup.sh /path/to/output-file.tar.zst
#
# Designed to run from cron with the stack RUNNING. We take the
# Postgres / ClickHouse dumps via their own clients first (they're
# transactional) and then snapshot the rest of data/ with rsync to a
# scratch dir before tarring — that minimises the window where files
# are mutating mid-copy. For absolute consistency, stop the stack
# first.

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

echo "→ Postgres dump"
docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T postgres \
  pg_dumpall -U "${DB_USER:-netops}" > "$STAGE/postgres.sql"

echo "→ ClickHouse dump (schemas only — flow data lives in data/clickhouse)"
docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
  clickhouse-client --query "SHOW CREATE TABLE netops.flows" \
  > "$STAGE/clickhouse-flows.sql"
docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
  clickhouse-client --query "SHOW CREATE TABLE netops.findings" \
  > "$STAGE/clickhouse-findings.sql"

echo "→ Snapshotting data/"
mkdir -p "$STAGE/data"
rsync -a --delete --info=stats1 "$DATA_DIR/" "$STAGE/data/"

echo "→ Snapshotting .env and configs"
cp "$COMPOSE_DIR/.env" "$STAGE/env.backup"  # 0600 preserved by tar
mkdir -p "$STAGE/src-config"
rsync -a "$ROOT/src/config/" "$STAGE/src-config/"

echo "→ Tar + zstd"
tar -C "$STAGE" -cf - . | zstd -T0 -19 -o "$OUT"

echo "→ Done: $OUT ($(du -h "$OUT" | cut -f1))"
