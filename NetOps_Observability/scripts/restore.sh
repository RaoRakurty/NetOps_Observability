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
# F-59: the staging dir used to be removed on EXIT while the closing message
# told the operator to run `psql < $STAGE/postgres.sql` — a path that no longer
# existed by the time they read it. Keep the extracted dump somewhere durable
# and print THAT path.
KEEP="${RESTORE_KEEP_DIR:-$ROOT/data/restore-staging}"
trap 'rm -rf "$STAGE"' EXIT

echo "→ Unpacking"
zstd -dc "$IN" | tar -C "$STAGE" -xf -

# F-59: refuse an archive that records its own failure. backup.sh writes a
# MANIFEST with one PASS/FAIL/SKIP line per component precisely so a restore
# does not have to guess whether the file is complete.
if [[ -f "$STAGE/MANIFEST" ]]; then
  echo "→ Backup manifest:"
  sed 's/^/    /' "$STAGE/MANIFEST"
  if grep -q '^FAIL' "$STAGE/MANIFEST" && [[ "${RESTORE_FORCE:-0}" != "1" ]]; then
    echo >&2
    echo "!! This archive records FAILED components (above). Restoring from it will" >&2
    echo "   silently leave those stores empty. Re-run with RESTORE_FORCE=1 to proceed" >&2
    echo "   anyway, or take a fresh backup." >&2
    exit 1
  fi
else
  echo "!! No MANIFEST in this archive — it predates F-59, so which components it" >&2
  echo "   actually contains is unknown. Check the contents before relying on it." >&2
fi

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

# Keep the logical dumps somewhere that still exists after this script exits.
mkdir -p "$KEEP"
for f in postgres.sql clickhouse-schema.sql MANIFEST; do
  [[ -f "$STAGE/$f" ]] && install -m 0600 "$STAGE/$f" "$KEEP/$f"
done

echo
echo "→ Done. Now: cd $COMPOSE_DIR && docker compose up -d"
echo
echo "Postgres + ClickHouse data restored as data-directory snapshots."
echo "Logical dumps kept at: $KEEP"
echo "If you need a transactional re-apply, also run:"
echo "   docker compose exec -T postgres psql -U \$DB_USER < $KEEP/postgres.sql"
echo "(That dump is included in the tarball but not auto-applied.)"
echo
echo "OpenSearch: the data/ copy includes data/opensearch-snapshots (the netops-fs"
echo "repository). If the search indices themselves are damaged, restore them from"
echo "a snapshot rather than the copied data dir — a file-level copy of a live"
echo "Lucene directory can be torn:"
echo "   docker compose exec -T opensearch curl -s \\"
echo "     -X POST 'http://localhost:9200/_snapshot/netops-fs/<snapshot>/_restore' \\"
echo "     -H 'Content-Type: application/json' -d '{\"indices\":\"netops-*\"}'"
echo "   (list them: curl 'http://localhost:9200/_cat/snapshots/netops-fs?v')"
