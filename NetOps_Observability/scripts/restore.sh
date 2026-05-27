#!/usr/bin/env bash
#
# restore.sh — restore a backup produced by scripts/backup.sh.
#
# This is destructive: it overwrites data/, .env, and the postgres /
# clickhouse logical dumps. Run with the stack STOPPED.
#
# Usage:
#   docker compose down
#   ./restore.sh /path/to/backup.tar.zst
#   docker compose up -d

set -euo pipefail

IN="${1:-}"
if [[ -z "$IN" || ! -f "$IN" ]]; then
  echo "usage: $0 <backup.tar.zst>" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_DIR="$ROOT/deployment/docker"
DATA_DIR="$ROOT/data"
STAGE="$(mktemp -d -t netops-restore-XXXXXX)"
trap "rm -rf $STAGE" EXIT

echo "→ Unpacking"
zstd -dc "$IN" | tar -C "$STAGE" -xf -

echo "→ Restoring data/"
rsync -a --delete "$STAGE/data/" "$DATA_DIR/"

if [[ -f "$STAGE/env.backup" ]]; then
  echo "→ Restoring .env"
  install -m 0600 "$STAGE/env.backup" "$COMPOSE_DIR/.env"
fi

if [[ -d "$STAGE/src-config" ]]; then
  echo "→ Restoring src/config (in-place merge)"
  rsync -a "$STAGE/src-config/" "$ROOT/src/config/"
fi

echo
echo "→ Done. Now: cd $COMPOSE_DIR && docker compose up -d"
echo
echo "Postgres + ClickHouse data restored as data-directory snapshots."
echo "If you need a transactional re-apply, also run:"
echo "   docker compose exec -T postgres psql -U \$DB_USER < $STAGE/postgres.sql"
echo "(That dump is included in the tarball but not auto-applied.)"
