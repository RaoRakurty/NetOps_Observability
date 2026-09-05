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
# §16.2: state the PATH — this may run from a minimal recovery shell.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

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

# ---------------------------------------------------------------------------
# H4: authenticate the artifact BEFORE extracting a byte. backup.sh writes a
# $OUT.sig sidecar (sha256 + optional HMAC-SHA256 keyed with BACKUP_SIGN_KEY);
# a restore is the single most credulous moment in the system's life — it
# overwrites data/ and .env with whatever the file says — so an artifact that
# cannot prove what it is gets refused, not extracted.
#
#   * sidecar missing            → refuse (RESTORE_FORCE=1 for pre-H4 files)
#   * sha256 mismatch            → refuse, NO override (corrupt/tampered)
#   * HMAC present, no local key → refuse (RESTORE_FORCE=1 if you accept
#                                  integrity-only)
#   * HMAC mismatch              → refuse, NO override (tampered or wrong key)
#   * HMAC absent but we HOLD a key → refuse (a stripped MAC is exactly what a
#                                  downgrade attack looks like; RESTORE_FORCE=1)
# ---------------------------------------------------------------------------
hmac_file() {  # HMAC-SHA256 of $1, keyed via the environment — never argv
  python3 - "$1" <<'PY'
import hashlib, hmac, os, sys
h = hmac.new(os.environ["BACKUP_SIGN_KEY"].encode(), digestmod=hashlib.sha256)
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
PY
}

SIG="$IN.sig"
SIGN_KEY="${BACKUP_SIGN_KEY:-}"
if [[ -z "$SIGN_KEY" && -f "$COMPOSE_DIR/.env" ]]; then
  SIGN_KEY="$(sed -n 's/^BACKUP_SIGN_KEY=//p' "$COMPOSE_DIR/.env" | head -1)"
  # Match backup.sh's load_env_default: strip ONE surrounding pair of quotes so a
  # quoted .env value (BACKUP_SIGN_KEY="k") verifies — else the HMAC keys differ
  # and a legitimately-signed backup is refused at DR time (review 2026-08-16).
  SIGN_KEY="${SIGN_KEY%\"}"; SIGN_KEY="${SIGN_KEY#\"}"
  SIGN_KEY="${SIGN_KEY%\'}"; SIGN_KEY="${SIGN_KEY#\'}"
fi
if [[ ! -f "$SIG" ]]; then
  if [[ "${RESTORE_FORCE:-0}" != "1" ]]; then
    echo "!! REFUSING: $IN has no signature sidecar ($SIG)." >&2
    echo "   Without it, integrity and provenance are unverifiable (H4). If this is" >&2
    echo "   a pre-signature backup you trust, re-run with RESTORE_FORCE=1." >&2
    exit 1
  fi
  echo "!! RESTORE_FORCE=1: proceeding WITHOUT signature verification." >&2
else
  echo "→ Verifying signature"
  WANT_SHA="$(sed -n 's/^sha256 //p' "$SIG" | head -1)"
  HAVE_SHA="$(sha256sum -- "$IN" | cut -d' ' -f1)"
  if [[ -z "$WANT_SHA" || "$WANT_SHA" != "$HAVE_SHA" ]]; then
    echo "!! REFUSING: sha256 mismatch against $SIG — the artifact was modified or" >&2
    echo "   corrupted after it was written. There is no override for this: restore" >&2
    echo "   from a known-good copy instead." >&2
    exit 1
  fi
  WANT_MAC="$(sed -n 's/^hmac-sha256 //p' "$SIG" | head -1)"
  if [[ -n "$WANT_MAC" ]]; then
    if [[ -z "$SIGN_KEY" ]]; then
      if [[ "${RESTORE_FORCE:-0}" != "1" ]]; then
        echo "!! REFUSING: $SIG carries an HMAC but no BACKUP_SIGN_KEY is available" >&2
        echo "   (environment or $COMPOSE_DIR/.env) — authenticity cannot be checked." >&2
        echo "   Provide the key, or RESTORE_FORCE=1 to accept sha256-only integrity." >&2
        exit 1
      fi
      echo "!! RESTORE_FORCE=1: HMAC present but unverifiable (no key) — sha256 only." >&2
    else
      if ! command -v python3 >/dev/null 2>&1; then
        echo "!! REFUSING: python3 is required to verify the HMAC and is not on PATH." >&2
        exit 1
      fi
      HAVE_MAC="$(BACKUP_SIGN_KEY="$SIGN_KEY" hmac_file "$IN")"
      if [[ "$WANT_MAC" != "$HAVE_MAC" ]]; then
        echo "!! REFUSING: HMAC mismatch — the artifact does NOT authenticate against" >&2
        echo "   BACKUP_SIGN_KEY (tampered, or signed with a different key). No override." >&2
        exit 1
      fi
      echo "   signature OK (sha256 + HMAC)"
    fi
  else
    if [[ -n "$SIGN_KEY" ]]; then
      if [[ "${RESTORE_FORCE:-0}" != "1" ]]; then
        echo "!! REFUSING: this host holds BACKUP_SIGN_KEY but $SIG has no HMAC line —" >&2
        echo "   a stripped MAC is exactly what a downgrade attack looks like." >&2
        echo "   RESTORE_FORCE=1 to accept sha256-only integrity anyway." >&2
        exit 1
      fi
      echo "!! RESTORE_FORCE=1: accepting MAC-less sidecar (sha256 verified)." >&2
    else
      echo "   sha256 OK (no HMAC in sidecar, no local key — integrity only)"
    fi
  fi
fi

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
# H4/H5: backup.sh EXCLUDES the custody root (data/swtpm, data/secrets-seal)
# and the generated dirs (data/backups, data/restore-staging) from the
# archive. The excludes here MUST match: without them, --delete would read the
# archive's absence of data/swtpm as "delete the live swtpm state" — i.e. a
# routine restore would destroy the host's KEK. The custody root is restored
# only by the operator key ceremony, never by this script.
declare -a RESTORE_EXCLUDES=(
    --exclude=/swtpm --exclude=/secrets-seal
    --exclude=/backups --exclude=/restore-staging
)
# THE SAME RULE, GENERALISED (S4, 2026-09-04). The hard-coded list above was
# safe only while the archive's exclude set was hard-coded too. It is not any
# more: backup.sh drops data/victoria whenever it captured the consistent
# VictoriaMetrics snapshot instead, and BACKUP_EXCLUDE lets an operator narrow
# the data/ copy further on a space-constrained host. Every one of those paths
# is present on the LIVE host and absent from the archive — exactly the shape
# that made the swtpm exclude necessary — so a bare `--delete` would DELETE the
# live copy of a store the archive simply chose not to carry.
#
# So the excludes are DERIVED from the archive: any top-level entry that exists
# under the live data/ and not under the archive's is protected, and named. A
# restore must never destroy something merely because the backup did not carry
# it.
if [[ -d "$DATA_DIR" ]]; then
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        [[ -e "$STAGE/data/$entry" ]] && continue
        case "/$entry" in
            /swtpm|/secrets-seal|/backups|/restore-staging) continue ;;  # already excluded above
        esac
        RESTORE_EXCLUDES+=("--exclude=/$entry")
        echo "   protecting live data/$entry — this archive does not carry it (BACKUP_EXCLUDE, or a store captured by another mechanism); it is left UNTOUCHED, not deleted"
    done < <(cd "$DATA_DIR" && ls -1A 2>/dev/null)
fi
rsync -a --delete "${RESTORE_EXCLUDES[@]}" "$STAGE/data/" "$DATA_DIR/"

if [[ -f "$STAGE/env.backup" ]]; then
  echo "→ Restoring .env"
  # backup.sh strips BACKUP_SIGN_KEY out of env.backup on purpose (the archive
  # must not carry the key that authenticates it). Carry the live host's key
  # forward so the NEXT backup is still signed after this restore.
  CUR_SIGN_KEY=""
  if [[ -f "$COMPOSE_DIR/.env" ]]; then
    CUR_SIGN_KEY="$(sed -n 's/^BACKUP_SIGN_KEY=//p' "$COMPOSE_DIR/.env" | head -1)"
    CUR_SIGN_KEY="${CUR_SIGN_KEY%\"}"; CUR_SIGN_KEY="${CUR_SIGN_KEY#\"}"
    CUR_SIGN_KEY="${CUR_SIGN_KEY%\'}"; CUR_SIGN_KEY="${CUR_SIGN_KEY#\'}"
  fi
  install -m 0600 "$STAGE/env.backup" "$COMPOSE_DIR/.env"
  if [[ -n "$CUR_SIGN_KEY" ]] && ! grep -q '^BACKUP_SIGN_KEY=' "$COMPOSE_DIR/.env"; then
    printf 'BACKUP_SIGN_KEY=%s\n' "$CUR_SIGN_KEY" >> "$COMPOSE_DIR/.env"
  fi
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
# S4 members: the per-table ClickHouse data export, the consistent
# VictoriaMetrics snapshot and the sealed custody envelope. None of the three is
# auto-applied — each replaces a live store wholesale, which is an operator
# decision, not a side effect of running this script.
for d in clickhouse-data victoriametrics sealed; do
  if [[ -d "$STAGE/$d" ]]; then
    rm -rf -- "${KEEP:?}/$d"
    cp -a -- "$STAGE/$d" "$KEEP/$d"
    chmod -R go-rwx -- "$KEEP/$d"
  fi
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
echo
if [[ -d "$KEEP/clickhouse-data" ]]; then
  echo "ClickHouse ROW DATA is in this archive as per-table FORMAT Native dumps, kept at"
  echo "   $KEEP/clickhouse-data/. The data/ copy above restores the data DIRECTORY;"
  echo "if you need a clean re-ingest instead, replay the schema and then each table:"
  echo "   docker compose exec -T clickhouse clickhouse-client --multiquery < $KEEP/clickhouse-schema.sql"
  echo "   gzip -dc $KEEP/clickhouse-data/<table>.native.gz | docker compose exec -T clickhouse \\"
  echo "     clickhouse-client --query 'INSERT INTO netops.<table> FORMAT Native'"
  echo "Tables over BACKUP_CH_MAX_TABLE_MB ship as SCHEMA ONLY — read the MANIFEST above"
  echo "for the names; their rows are in the cold Parquet tier (scripts/ch-cold-export.sh)."
  echo
fi

if [[ -d "$KEEP/victoriametrics" ]]; then
  echo "VICTORIAMETRICS: a consistent snapshot is in this archive, kept at"
  echo "   $KEEP/victoriametrics/<snapshot>/. It is NOT applied automatically —"
  echo "replacing the time-series store is destructive and deliberate. To use it:"
  echo "   docker compose stop victoria"
  echo "   mv $DATA_DIR/victoria $DATA_DIR/victoria.before-restore"
  echo "   mkdir -p $DATA_DIR/victoria && cp -a $KEEP/victoriametrics/*/. $DATA_DIR/victoria/"
  echo "   docker compose start victoria"
  echo "Verify BEFORE deleting the .before-restore copy:"
  echo "   docker compose exec -T victoria wget -qO- 'http://127.0.0.1:8428/api/v1/label/__name__/values'"
  echo
fi

echo "CUSTODY: data/swtpm and data/secrets-seal were NOT restored and were NOT"
echo "touched — deliberate. swtpm state re-derives the KEK, so putting it back is"
echo "an operator decision, never a side effect of a routine restore."
if [[ -f "$KEEP/sealed/sealed-material.tar.gz.enc" ]]; then
  echo
  echo "This archive DOES carry the custody material, as a separately encrypted"
  echo "member kept at $KEEP/sealed/. It needs BACKUP_SEALED_PASSPHRASE, which is"
  echo "deliberately NOT in the archive and must NOT live on the backup host:"
  echo "   cd $KEEP/sealed"
  echo "   BACKUP_SEALED_PASSPHRASE=... openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \\"
  echo "     -pass env:BACKUP_SEALED_PASSPHRASE -in sealed-material.tar.gz.enc \\"
  echo "     | tar -xzf - -C <a scratch dir>"
  echo "   cd <that scratch dir> && sha256sum -c $KEEP/sealed/sealed-material.manifest"
  echo "Only after the manifest verifies, and with the stack STOPPED, copy swtpm/"
  echo "and tls/ into $DATA_DIR/. See $KEEP/sealed/README."
else
  echo "This archive carries NO custody envelope (BACKUP_SEALED_MATERIAL=0, or the"
  echo "component failed when it was taken). If this host's custody root is lost,"
  echo "restore it from the key ceremony's media BEFORE starting the stack, or the"
  echo "vault cannot unwrap its DEKs."
fi
