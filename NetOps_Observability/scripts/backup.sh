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
# CUSTODY + SIGNATURE (H4/H5, 2026-08-15) — what this archive deliberately
# DOES NOT contain, and how it proves it was not tampered with.
#
# The archive used to rsync ALL of data/ and then ship plaintext + unsigned:
#   * data/swtpm — the software TPM's persistent state. That state
#     deterministically re-derives the root KEK, so a copy of it IS the KEK.
#   * data/secrets-seal — the sealed-KEK blobs (seal.pub/seal.priv).
#   * data/api/secrets_wrapped_keys.json — every wrapped DEK.
#   * env.backup — the full .env, every stack credential.
# One file on a backup host therefore held the KEK, the DEKs it wraps and the
# service credentials: the entire custody model, collapsed. Now:
#   * the CUSTODY ROOT (data/swtpm + data/secrets-seal) is EXCLUDED from the
#     plaintext data/ copy. swtpm state == the KEK: it must never sit in the
#     clear next to the data it unlocks.
#     Wrapped DEKs still ship — they are ciphertext without the KEK.
#
# SEALED MATERIAL AS A SEPARATELY ENCRYPTED MEMBER (S4, 2026-09-04). Excluding
# the custody root closed the "one file holds everything" hole and opened a
# different one: `data/swtpm` was then in NO copy at all, and losing it makes
# every vault secret unrecoverable even from a perfect data backup — the
# coverage table has reported that as covered=no ever since. Both facts are now
# true at once, because the material rides in its OWN encryption envelope:
#   * ./sealed/sealed-material.tar.gz.enc — data/swtpm (minus the lock file),
#     data/tls and data/api/secrets_wrapped_keys.json, tarred and encrypted with
#     `openssl enc -aes-256-cbc -pbkdf2` under BACKUP_SEALED_PASSPHRASE (age is
#     not available in this stack's base images). The passphrase crosses to
#     openssl through the ENVIRONMENT (`-pass env:`), never argv, and is never
#     echoed, logged or written into the archive.
#   * FAIL-CLOSED: when the material exists and BACKUP_SEALED_PASSPHRASE is
#     unset, the component FAILS. It never degrades to plaintext, and it never
#     silently omits the one thing whose absence is unrecoverable. The explicit
#     opt-out is BACKUP_SEALED_MATERIAL=0 (loud warning, recorded as SKIP).
#   * BACKED UP ON CHANGE: a sha256 manifest of the material decides. Unchanged
#     material re-uses the previously encrypted archive out of
#     data/backups/sealed/ (itself excluded from the data/ copy) so every bundle
#     stays self-contained without re-encrypting a static custody root nightly.
#   * The passphrase is NOT the KEK and NOT in the archive: an attacker with the
#     tarball still needs it, which is what keeps the custody model intact.
#     Keep it where the KEK ceremony keeps its material, not on the backup host.
#   * data/backups and data/restore-staging are EXCLUDED: the artifact is
#     written INTO data/backups, so including it nested every previous backup
#     inside tonight's (night N contained nights 1..N-1 — exponential growth).
#   * the artifact is SIGNED: $OUT.sig carries a sha256 and, when
#     BACKUP_SIGN_KEY is set (environment or .env — never from data/), an
#     HMAC-SHA256. restore.sh verifies BEFORE extracting and refuses a
#     missing/wrong signature; BACKUP_SIGN_KEY is stripped out of env.backup
#     so the archive never carries the key that authenticates it.
#   * everything this run writes is private: umask 077, artifact + sidecar
#     chmod 0600, backup dir 0700 (M26).
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

# M26: nothing about a backup is world-readable — the artifact is whole-store
# dumps plus (signed) config. Every file this run creates (stage contents,
# artifact, sidecar, report) starts life owner-only; cron's umask never widens it.
umask 077

# hmac_file <file> — HMAC-SHA256 of <file> keyed with $BACKUP_SIGN_KEY, hex on
# stdout. The key crosses to python through the ENVIRONMENT (exported by
# load_env_default / the caller), never argv — argv is world-readable in /proc
# for as long as the hash runs.
hmac_file() {
    python3 - "$1" <<'PY'
import hashlib, hmac, os, sys
h = hmac.new(os.environ["BACKUP_SIGN_KEY"].encode(), digestmod=hashlib.sha256)
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
PY
}

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
load_env_default BACKUP_SIGN_KEY
# S4 additions. The passphrase follows BACKUP_SIGN_KEY exactly: the environment
# wins, .env is the cron fallback, and neither is ever printed or archived.
load_env_default BACKUP_SEALED_PASSPHRASE
load_env_default BACKUP_SEALED_MATERIAL
load_env_default BACKUP_EXCLUDE
load_env_default BACKUP_VICTORIA
load_env_default BACKUP_REMOTE_VERIFY

# --verify <file>: check a previously written backup instead of taking one.
# Lives AFTER load_env_default so the HMAC check finds BACKUP_SIGN_KEY in .env
# the same way the writer did.
if [[ "${1:-}" == "--verify" ]]; then
  IN="${2:-}"
  if [[ -z "$IN" || ! -f "$IN" ]]; then
    echo "usage: $0 --verify <backup.tar.zst>" >&2
    exit 2
  fi
  # H4: signature sidecar first — a tampered archive must be named as
  # tampered, not merely "manifest unreadable".
  if [[ -f "$IN.sig" ]]; then
    WANT_SHA=$(sed -n 's/^sha256 //p' "$IN.sig" | head -1)
    HAVE_SHA=$(sha256sum -- "$IN" | cut -d' ' -f1)
    if [[ -z "$WANT_SHA" || "$WANT_SHA" != "$HAVE_SHA" ]]; then
      echo "VERIFY FAILED: sha256 mismatch against $IN.sig — the artifact was modified or corrupted." >&2
      exit 1
    fi
    WANT_MAC=$(sed -n 's/^hmac-sha256 //p' "$IN.sig" | head -1)
    if [[ -n "$WANT_MAC" ]]; then
      if [[ -z "${BACKUP_SIGN_KEY:-}" ]]; then
        echo "VERIFY FAILED: $IN.sig carries an HMAC but BACKUP_SIGN_KEY is not available (environment or .env) — authenticity cannot be checked." >&2
        exit 1
      fi
      HAVE_MAC=$(hmac_file "$IN")
      if [[ "$WANT_MAC" != "$HAVE_MAC" ]]; then
        echo "VERIFY FAILED: HMAC mismatch — the artifact does NOT authenticate against BACKUP_SIGN_KEY (tampered, or signed with a different key)." >&2
        exit 1
      fi
    fi
  else
    echo "VERIFY WARNING: no signature sidecar ($IN.sig) — integrity is unauthenticated (pre-H4 artifact?). restore.sh refuses it without RESTORE_FORCE=1." >&2
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
            echo "    [dry-run] would delete $path (+ its .sig sidecar, if any)"
            removed=$((removed + 1))
            continue
        fi
        if rm -f -- "$path" 2>"$dir/.prune.err"; then
            echo "    deleted $path"
            removed=$((removed + 1))
            # H4: the signature sidecar travels with its artifact — an orphaned
            # .sig is noise at best and a re-signing aid at worst. A sidecar
            # delete failure is as fatal as an artifact delete failure.
            if [[ -e "$path.sig" ]] && ! rm -f -- "$path.sig" 2>"$dir/.prune.err"; then
                echo "    !! FAILED to delete sidecar $path.sig: $(tail -1 "$dir/.prune.err" 2>/dev/null)" >&2
                rc=1
            fi
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

# PER-COMPONENT outcomes (S4). The report used to carry one whole-run status,
# so the Data Protection page could only say "the bundle failed" — never WHICH
# store lost its copy. Postgres, ClickHouse, VictoriaMetrics and the sealed
# custody material each own a coverage row in that table, and a row that
# inherits the bundle's verdict wholesale reports a green Postgres dump on a
# night when only the VM snapshot failed. Every component records its own
# verdict here, in declaration order, and internal/dataprotect reads them.
COMPONENT_KEYS=()
COMPONENT_VALS=()
comp() { COMPONENT_KEYS+=("$1"); COMPONENT_VALS+=("$2"); }
# comp_status <key> — the verdict already recorded for a component, or the empty
# string when it has not run yet. Later legs branch on earlier ones (the data/
# copy drops data/victoria only once the snapshot actually succeeded), and
# re-deriving that from a second variable is how the two drift apart.
comp_status() {
    local i
    for i in "${!COMPONENT_KEYS[@]}"; do
        [[ "${COMPONENT_KEYS[$i]}" == "$1" ]] && { printf '%s' "${COMPONENT_VALS[$i]}"; return 0; }
    done
    return 0
}

# json_str — minimal JSON string escaping for values this script composes
# (paths, rsync patterns, a failing command line). Quotes and backslashes are
# removed rather than escaped, control chars collapse to spaces: the report is
# machine-read by the api, so a value that breaks the parse blinds the page.
json_str() { printf '%s' "$1" | tr -d '\042\134' | tr -s '[:cntrl:]' ' '; }

# components_json renders {"postgres":"pass",...}. Empty renders {} — an absent
# component map is "this report predates per-component reporting", not "every
# component passed", and the reader must be able to tell those apart.
components_json() {
    local i out=""
    for i in "${!COMPONENT_KEYS[@]}"; do
        [[ -n "$out" ]] && out+=","
        out+="\"$(json_str "${COMPONENT_KEYS[$i]}")\":\"$(json_str "${COMPONENT_VALS[$i]}")\""
    done
    printf '{%s}' "$out"
}

# remote_json is the off-host transfer's own record: configured / pushed /
# when the REMOTE copy was last checksum-verified. Deliberately WITHOUT the
# destination string — BACKUP_PUSH can carry credentials (an `-e "sshpass -p …"`
# transport), and §8 keeps those out of every file the api reads. The api
# already has the destination from the stored intent and redacts it there.
REMOTE_PUSHED=0
REMOTE_VERIFIED_AT=""
remote_json() {
    local configured=false pushed=false
    [[ -n "${BACKUP_REMOTE:-}" ]] && configured=true
    [[ "$REMOTE_PUSHED" == "1" ]] && pushed=true
    printf '{"configured":%s,"pushed":%s,"verified_at":"%s"}' \
        "$configured" "$pushed" "$(json_str "$REMOTE_VERIFIED_AT")"
}

write_report() { # <status> <reason>  (reason may be empty)
    local status="$1" reason="$2" size rdir="$DATA_DIR/api"
    size=$(stat -c%s -- "$OUT" 2>/dev/null || echo 0)
    # JSON-safety: the reason can carry a shell command line — strip quotes,
    # backslashes and control chars, and bound it.
    reason=$(json_str "$reason" | cut -c1-300)
    if [[ ! -d "$rdir" ]] \
       || ! printf '{"status":"%s","ended":"%s","size_bytes":%s,"duration_seconds":%s,"failures":%s,"artifact":"%s","reason":"%s","components":%s,"remote":%s,"data_excludes":"%s"}\n' \
            "$status" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$size" \
            "$(( $(date +%s) - START_EPOCH ))" "${FAILURES:-0}" "$(basename -- "$OUT")" "$reason" \
            "$(components_json)" "$(remote_json)" "$(json_str "${BACKUP_EXCLUDE:-}" | cut -c1-300)" \
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
            comp postgres pass
        else
            fail "postgres pg_dumpall produced an EMPTY dump"
            comp postgres fail
        fi
    else
        fail "postgres pg_dumpall failed: $(tail -1 "$STAGE/postgres.err" 2>/dev/null)"
        comp postgres fail
    fi
else
    skip "postgres not running (data/postgres still in the snapshot)"
    comp postgres skip
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
        comp clickhouse fail
    else
        : > "$STAGE/clickhouse-schema.sql"
        CH_OK=0; CH_BAD=0
        # `< /dev/null` on EVERY exec inside these loops (2026-09-04). Without
        # it `docker compose exec -T` inherits — and CONSUMES — the loop's stdin,
        # which is the table list: the first iteration swallowed the remaining
        # names and the loop ended after ONE table. This backup captured exactly
        # one of 26 ClickHouse tables, silently, and reported "clickhouse schema
        # 1 tables" as a PASS. Found by the first proof run of the S4 wave.
        while read -r tbl; do
            [[ -z "$tbl" ]] && continue
            # FORMAT TabSeparatedRaw is LOAD-BEARING. clickhouse-client's
            # default output format escapes the DDL's newlines to a literal
            # `\n` and its quotes to `\'`, so the schema this script had been
            # writing since it was born was not valid SQL and could not be
            # replayed at all — every ClickHouse restore would have failed at
            # the first statement. Found by the first bundle restore drill
            # (S4, 2026-09-04). Raw preserves the real statement.
            if docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
                clickhouse-client --query "SHOW CREATE TABLE netops.$tbl FORMAT TabSeparatedRaw" < /dev/null \
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
        # PER-TABLE SIZE CEILING (2026-09-04). A FORMAT Native dump of every
        # table is the right shape and the wrong SIZE on a real OLAP store: this
        # host's netops.corr_signals_archive alone is 3.5 GiB on disk / 710M
        # rows, and a nightly full export of it would fill the disk the stack
        # needs — the §16.4 failure mode, with the primary data as collateral.
        # (The stdin bug fixed above hid this: the loop had been ending after
        # ONE table since it was written, so nobody had ever seen the real cost.)
        #
        # Tables above BACKUP_CH_MAX_TABLE_MB are SKIPPED, by name, loudly:
        #   * their SCHEMA is still captured, so an empty-volume restore is
        #     reproducible;
        #   * their ROW HISTORY belongs in the cold Parquet tier
        #     (scripts/ch-cold-export.sh), which is where a multi-GiB append-only
        #     archive should live anyway;
        #   * the component reports PARTIAL, never pass. A ClickHouse backup
        #     missing its largest tables is not a covered store, and the coverage
        #     row says which tables and why rather than rounding up to green.
        # Set BACKUP_CH_MAX_TABLE_MB=0 to dump everything regardless of size.
        CH_MAX_MB="${BACKUP_CH_MAX_TABLE_MB:-512}"
        if ! [[ "$CH_MAX_MB" =~ ^[0-9]+$ ]]; then
            fail "BACKUP_CH_MAX_TABLE_MB=$CH_MAX_MB is not a non-negative integer"
            CH_MAX_MB=512
        fi
        CH_BIG=""
        if [[ "$CH_MAX_MB" -gt 0 ]]; then
            CH_BIG=$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
                clickhouse-client --query \
                "SELECT table FROM system.parts WHERE database='netops' AND active GROUP BY table HAVING sum(bytes_on_disk) > ${CH_MAX_MB} * 1024 * 1024" \
                < /dev/null 2>>"$STAGE/clickhouse.err" || true)
        fi
        # DICTIONARY engines hold no rows of their own: they are LOADED from an
        # external source (netops.geoip_country from the MaxMind extract that
        # scripts/geoip-prepare.py stages). `SELECT * … FORMAT Native` against
        # one fails outright when that source file is absent — Code 107,
        # FILE_DOESN'T_EXIST — which is what made this component FAIL on the
        # first full-table run. The DDL still ships in the schema dump, so a
        # restored stack re-creates the dictionary and reloads it from source;
        # dumping its contents would be backing up a cache.
        CH_DICTS=$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
            clickhouse-client --query \
            "SELECT name FROM system.tables WHERE database='netops' AND engine='Dictionary'" \
            < /dev/null 2>>"$STAGE/clickhouse.err" || true)
        echo "→ ClickHouse data dump (Native; per-table ceiling ${CH_MAX_MB} MB)"
        mkdir -p "$STAGE/clickhouse-data"
        CH_D_OK=0; CH_D_BAD=0; CH_D_SKIP=0; CH_SKIPPED=""
        while read -r tbl; do
            [[ -z "$tbl" ]] && continue
            if [[ -n "$CH_DICTS" ]] && grep -qx -- "$tbl" <<< "$CH_DICTS"; then
                # Not counted as skipped-for-size: a dictionary has no rows to
                # miss, so its absence does not make the export partial.
                echo "  skipping $tbl: Dictionary engine — reloaded from its source on restore, not backed up"
                continue
            fi
            if [[ -n "$CH_BIG" ]] && grep -qx -- "$tbl" <<< "$CH_BIG"; then
                CH_D_SKIP=$((CH_D_SKIP + 1)); CH_SKIPPED="$CH_SKIPPED $tbl"
                echo "  skipping $tbl: larger than ${CH_MAX_MB} MB on disk (schema captured; rows belong in the cold Parquet tier)"
                continue
            fi
            if docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
                clickhouse-client --query \
                "SELECT * FROM netops.$tbl FORMAT Native SETTINGS tenant_scope='__all__'" < /dev/null \
                2>>"$STAGE/clickhouse.err" | gzip > "$STAGE/clickhouse-data/$tbl.native.gz"; then
                CH_D_OK=$((CH_D_OK + 1))
            else
                CH_D_BAD=$((CH_D_BAD + 1))
            fi
        done <<< "$CH_TABLES"
        if [[ $CH_D_BAD -gt 0 ]]; then
            fail "clickhouse data dump: $CH_D_BAD of $((CH_D_OK + CH_D_BAD)) attempted tables failed"
            comp clickhouse fail
        elif [[ $CH_D_SKIP -gt 0 ]]; then
            # NOT a failure — the dump did what it was told — but emphatically
            # not a pass either. SKIP lines do not make --verify reject the
            # archive; the PARTIAL component verdict is what stops the coverage
            # page calling this store covered.
            skip "clickhouse data $CH_D_OK tables (Native); $CH_D_SKIP table(s) over ${CH_MAX_MB} MB NOT dumped:${CH_SKIPPED} — schema only, rows are in the cold Parquet tier"
            echo "!! WARNING: ${CH_D_SKIP} ClickHouse table(s) exceed BACKUP_CH_MAX_TABLE_MB=${CH_MAX_MB}" >&2
            echo "!!         and are in this archive as SCHEMA ONLY:${CH_SKIPPED}" >&2
            echo "!!         Their rows are recoverable only from scripts/ch-cold-export.sh output." >&2
            if [[ $CH_BAD -eq 0 ]]; then comp clickhouse partial; else comp clickhouse fail; fi
        else
            note "clickhouse data $CH_D_OK tables (Native)"
            # Schema and data are ONE coverage row: a schema-only capture is
            # not a restorable ClickHouse backup, so the row is pass only when
            # neither half recorded a failure.
            if [[ $CH_BAD -eq 0 ]]; then comp clickhouse pass; else comp clickhouse fail; fi
        fi
    fi
else
    skip "clickhouse not running"
    comp clickhouse skip
fi

# ---- OpenSearch -----------------------------------------------------------
#
# A SNAPSHOT, not an rsync. Lucene segments are written continuously, so a
# file-level copy of a live index directory is torn and may not open at all;
# a snapshot is the only consistent backup OpenSearch offers. It is incremental
# against the netops-fs repository, so this costs roughly the day's new
# segments. data/opensearch-snapshots is picked up by the data/ copy below.

# os_snapshot_put <snapshot-name> — take one snapshot, over whatever transport
# THIS deployment actually exposes. Two facts made the old one-liner unable to
# work at all on a TLS-enabled stack, and both were found by the S4 proof run
# (2026-09-04), after which the OpenSearch component had never once succeeded on
# this host:
#
#   1. it dialled `localhost`, and curl resolves that to ::1 first. OpenSearch
#      accepts the IPv6 connection and then answers nothing, so curl reports
#      "Empty reply from server" — the same IPv6-first hazard the compose file
#      already documents on the victoria healthcheck. 127.0.0.1 is explicit.
#   2. it spoke PLAIN HTTP from inside the server container. With the security
#      plugin enabled (DISABLE_SECURITY_PLUGIN=false, which is what the TLS
#      programme leaves behind) the REST layer is HTTPS with client-certificate
#      auth, and the server container does not even hold the admin certificate —
#      only the security bootstrap does.
#
# So: when the deployment's admin certificate is on the host, reach the cluster
# the way the platform's own bootstraps do — over the compose network, from the
# pinned curl image, with that client certificate. No credential ever reaches
# argv: the authentication is FILES, mounted read-only. Otherwise fall back to
# the in-container plain-HTTP path, which is correct for a scaffold-grade stack.
#
# Both paths write curl's stderr to $STAGE/opensearch.err and its exit code to
# $OS_CURL_RC, because "opensearch snapshot failed: " with nothing after the
# colon is not a diagnosis (§16.1).
OS_ADMIN_DIR="${OPENSEARCH_ADMIN_CERT_DIR:-$DATA_DIR/tls/admin}"
OS_CURL_IMAGE="${OPENSEARCH_CURL_IMAGE:-curlimages/curl:8.10.1}"
OS_CURL_RC=0
os_snapshot_put() {
    local snap="$1" body='{"indices":"netops-*","ignore_unavailable":true,"include_global_state":false}'
    local rc=0 net=""
    if [[ -r "$OS_ADMIN_DIR/admin.crt" && -r "$OS_ADMIN_DIR/admin.key" && -r "$OS_ADMIN_DIR/ca.pem" ]]; then
        net=$(docker inspect "$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" ps -q opensearch)" \
                --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>>"$STAGE/opensearch.err" \
              | awk '{print $1}')
        if [[ -z "$net" ]]; then
            echo "opensearch: could not determine the compose network for the mTLS call" >>"$STAGE/opensearch.err"
            OS_CURL_RC=1
            return 1
        fi
        timeout 1800 docker run --rm --network "$net" -v "$OS_ADMIN_DIR:/certs:ro" "$OS_CURL_IMAGE" \
            -s --max-time 1750 \
            --cacert /certs/ca.pem --cert /certs/admin.crt --key /certs/admin.key \
            -X PUT "${OPENSEARCH_SNAPSHOT_URL:-https://opensearch:9200}/_snapshot/netops-fs/$snap?wait_for_completion=true" \
            -H 'Content-Type: application/json' -d "$body" 2>>"$STAGE/opensearch.err" || rc=$?
    else
        timeout 1800 docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T opensearch \
            curl -s --max-time 1750 \
            -X PUT "${OPENSEARCH_SNAPSHOT_URL:-http://127.0.0.1:9200}/_snapshot/netops-fs/$snap?wait_for_completion=true" \
            -H 'Content-Type: application/json' -d "$body" < /dev/null 2>>"$STAGE/opensearch.err" || rc=$?
    fi
    OS_CURL_RC=$rc
    return 0
}

CURRENT_STEP="opensearch snapshot"
if is_running opensearch; then
    SNAP="backup-$(date -u +%Y%m%d-%H%M%S)"
    echo "→ OpenSearch snapshot $SNAP"
    : > "$STAGE/opensearch.err"
    # NOT a command substitution: $OS_CURL_RC is set inside the function, and a
    # subshell would discard it — leaving the diagnosis-free "failed: " message
    # this rewrite exists to remove. Redirection keeps the current shell.
    os_snapshot_put "$SNAP" > "$STAGE/opensearch.out"
    OS_RESP=$(cat "$STAGE/opensearch.out")
    case "$OS_RESP" in
        *'"state":"SUCCESS"'*) note "opensearch snapshot $SNAP"; comp opensearch pass ;;
        *'"state":"PARTIAL"'*) fail "opensearch snapshot $SNAP is PARTIAL — some shards were not captured"; comp opensearch fail ;;
        *repository_missing*|*RepositoryMissingException*)
            fail "opensearch snapshot repository netops-fs is NOT registered — the search tier has NO backup (run opensearch-init / apply-ism.sh)"
            comp opensearch fail ;;
        *Unauthorized*|*'"status":401'*|*'"status":403'*)
            fail "opensearch snapshot REFUSED (unauthenticated): the security plugin is enabled on this cluster and this call was not authorised. Put the deployment's admin certificate at $OS_ADMIN_DIR (admin.crt, admin.key, ca.pem) or point OPENSEARCH_ADMIN_CERT_DIR at it"
            comp opensearch fail ;;
        "")
            # An EMPTY body is the shape both historical faults produced, and it
            # is the one that used to print a colon and nothing else.
            fail "opensearch snapshot produced NO response (curl rc=$OS_CURL_RC): $(tail -1 "$STAGE/opensearch.err" 2>/dev/null). curl rc=52 here means the cluster accepted the connection and answered nothing — usually plain HTTP against a TLS listener, or an IPv6-first ::1 connection"
            comp opensearch fail ;;
        *) fail "opensearch snapshot failed (curl rc=$OS_CURL_RC): ${OS_RESP:0:300} $(tail -1 "$STAGE/opensearch.err" 2>/dev/null)"; comp opensearch fail ;;
    esac
else
    skip "opensearch not running — NO consistent search-tier backup in this file"
    comp opensearch skip
fi

# ---- VictoriaMetrics ------------------------------------------------------
#
# The time-series tier held EVERY metric this platform alerts on — including the
# ones on the Data Protection page itself — and had no copy of any kind: its
# only protection was in-place -retentionPeriod, which bounds how long data
# survives, not whether it survives losing the disk. The coverage table has said
# so ("no VictoriaMetrics snapshot caller exists in this platform") since it was
# built. This is the caller.
#
# VM's own consistent mechanism is /snapshot/create: it hardlinks a
# point-in-time view of the parts under <storageDataPath>/snapshots/<name>. An
# rsync of the live /victoria tree is a torn copy for the same reason a live
# Lucene copy is. The sequence is therefore create -> copy -> DELETE, and the
# delete must happen even when the copy failed: a snapshot left behind pins the
# parts it references and grows the disk the stack needs.
#
# The API is reached from INSIDE the compose network (docker compose exec on the
# vm container itself, busybox wget), so nothing has to be published on the
# host and no credential crosses a command line.

CURRENT_STEP="victoriametrics snapshot"
VM_SERVICE="${VICTORIA_SERVICE:-victoria}"
VM_SNAP=""
# vm_api <path> — one bounded call to VM's own HTTP API from inside its
# container. Output on stdout, stderr captured by the caller.
vm_api() {
    timeout 120 docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T "$VM_SERVICE" \
        wget -q -T 30 -O - "http://127.0.0.1:8428$1"
}
# vm_snapshot_delete — best-effort-but-LOUD teardown. Never `|| true` silently:
# a snapshot we created and could not delete is disk we are leaking, so it is
# reported as a failure of this component even when the copy itself worked.
vm_snapshot_delete() {
    local name="$1" resp=""
    resp=$(vm_api "/snapshot/delete?snapshot=$name" 2>"$STAGE/vm-delete.err") || resp=""
    case "$resp" in
        *'"status":"ok"'*) return 0 ;;
        *) echo "  !! VictoriaMetrics snapshot $name could NOT be deleted: ${resp:-$(tail -1 "$STAGE/vm-delete.err" 2>/dev/null)}" >&2
           return 1 ;;
    esac
}
if [[ "${BACKUP_VICTORIA:-1}" != "1" ]]; then
    echo "!! WARNING: BACKUP_VICTORIA=${BACKUP_VICTORIA} — the time-series tier is NOT in this archive." >&2
    skip "victoriametrics snapshot disabled by BACKUP_VICTORIA=${BACKUP_VICTORIA}"
    comp victoriametrics skip
elif is_running "$VM_SERVICE"; then
    echo "→ VictoriaMetrics snapshot"
    VM_CREATE=$(vm_api "/snapshot/create" 2>"$STAGE/vm.err") || VM_CREATE=""
    VM_SNAP=$(sed -n 's/.*"snapshot"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$VM_CREATE" | head -1)
    if [[ "$VM_CREATE" != *'"status":"ok"'* || -z "$VM_SNAP" ]]; then
        fail "victoriametrics /snapshot/create failed: ${VM_CREATE:0:200}${VM_CREATE:+ }$(tail -1 "$STAGE/vm.err" 2>/dev/null)"
        comp victoriametrics fail
    else
        VM_SNAP_DIR="$DATA_DIR/victoria/snapshots/$VM_SNAP"
        vm_rc=0
        mkdir -p "$STAGE/victoriametrics"
        if [[ ! -d "$VM_SNAP_DIR" ]]; then
            # The snapshot exists inside the container but not where we expect it
            # on the host: the storageDataPath is not the bind mount this script
            # assumes. Say exactly that instead of shipping an empty directory.
            fail "victoriametrics snapshot $VM_SNAP is not visible at $VM_SNAP_DIR — is --storageDataPath still bound to data/victoria?"
            vm_rc=1
        else
            # -L (--copy-links) is LOAD-BEARING, not a style choice. A
            # VictoriaMetrics snapshot is a tree of SYMLINKS into the live
            # storage — `indexdb` points at ../../indexdb/snapshots/<name> and
            # every part under data/ is a link to the live part directory. A
            # plain `rsync -a` copies the links AS LINKS, so the archived
            # "snapshot" is 20 KB of dangling pointers: a throwaway vmsingle
            # started on it panics with `mkdir /victoria/indexdb: file exists`
            # and not one sample is recoverable. Found by the first bundle
            # restore drill (S4, 2026-09-04) — the leg failed, which is exactly
            # what a drill is for. -L follows them and writes the real bytes.
            # No --delete and no --hard-links, both deliberate.
            if rsync -aL --info=stats1 "$VM_SNAP_DIR/" "$STAGE/victoriametrics/$VM_SNAP/"; then
                note "victoriametrics snapshot $VM_SNAP ($(du -sh "$STAGE/victoriametrics/$VM_SNAP" | cut -f1))"
            else
                fail "victoriametrics snapshot copy failed (rsync of $VM_SNAP_DIR)"
                vm_rc=1
            fi
        fi
        # DELETE ALWAYS — including on the failure paths above.
        if ! vm_snapshot_delete "$VM_SNAP"; then
            fail "victoriametrics snapshot $VM_SNAP was left on disk — it pins parts and grows data/victoria until removed by hand"
            vm_rc=1
        fi
        VM_SNAP=""
        if [[ $vm_rc -eq 0 ]]; then comp victoriametrics pass; else comp victoriametrics fail; fi
    fi
else
    skip "victoriametrics ($VM_SERVICE) not running — NO time-series backup in this file"
    comp victoriametrics skip
fi

# ---- sealed custody material ----------------------------------------------
#
# See the CUSTODY block at the top for WHY this is a separate envelope. This is
# the mechanics.

CURRENT_STEP="sealed custody material"
SEALED_STORE="$DATA_DIR/backups/sealed"          # excluded from the data/ copy (/backups)
SEALED_ENC="$SEALED_STORE/sealed-material.tar.gz.enc"
SEALED_MAN="$SEALED_STORE/sealed-material.manifest"
# The members, relative to data/. data/secrets-seal is deliberately absent: it
# holds only the sidecar's unix socket, which is runtime state, not custody.
SEALED_MEMBERS=(swtpm tls api/secrets_wrapped_keys.json)

# sealed_existing — the members that actually EXIST on this host, as an array in
# $SEALED_PRESENT. A member that is absent (a stack with no data/tls yet, or a
# pre-install host) must be dropped from the tar and the manifest rather than
# passed to `find`/`tar` and turned into a component failure: "this host has no
# TLS material" is not "the custody backup broke".
SEALED_PRESENT=()
sealed_existing() {
    local m
    SEALED_PRESENT=()
    for m in "${SEALED_MEMBERS[@]}"; do
        [[ -e "$DATA_DIR/$m" ]] && SEALED_PRESENT+=("$m")
    done
}

# sealed_present — is there anything to protect on this host at all?
sealed_present() {
    sealed_existing
    [[ ${#SEALED_PRESENT[@]} -gt 0 ]]
}

# sealed_manifest — sha256 of every file in the members, path-sorted. This is
# the "backed up on change" decision AND the integrity manifest the drill
# checks the decrypted archive against.
sealed_manifest() {
    ( cd "$DATA_DIR" && find "${SEALED_PRESENT[@]}" -type f ! -name '.lock' -print0 \
        | LC_ALL=C sort -z | xargs -0 -r sha256sum )
}

# sealed_tar — tar the members to stdout. data/swtpm is written by the swtpm
# sidecar as root (0660 root:root), and this script runs as the crontab's owner,
# which on most installs is NOT root: a straight host-side tar then fails with
# permission errors on the ONE component whose absence is unrecoverable. When
# the host read fails, fall back to a pinned helper container with data/ mounted
# read-only — the same idiom scripts/clean-slate.sh uses, and the same trust
# boundary the rest of this script already relies on (docker compose exec).
SEALED_HELPER_IMAGE="${BACKUP_SEALED_HELPER_IMAGE:-alpine:3.20}"
SEALED_TAR_PATH="host"
sealed_tar() {
    if [[ "$SEALED_TAR_PATH" == "host" ]]; then
        tar -C "$DATA_DIR" --exclude=swtpm/.lock -czf - "${SEALED_PRESENT[@]}"
    else
        docker run --rm --user 0:0 -v "$DATA_DIR:/data:ro" "$SEALED_HELPER_IMAGE" \
            tar -C /data --exclude=swtpm/.lock -czf - "${SEALED_PRESENT[@]}"
    fi
}

if [[ "${BACKUP_SEALED_MATERIAL:-1}" != "1" ]]; then
    echo "!! WARNING: BACKUP_SEALED_MATERIAL=${BACKUP_SEALED_MATERIAL} — the sealed custody root is" >&2
    echo "!!          NOT in this archive. A restore of this bundle onto a host without" >&2
    echo "!!          data/swtpm decrypts NOTHING: every vault secret stays unrecoverable." >&2
    skip "sealed custody material disabled by BACKUP_SEALED_MATERIAL=${BACKUP_SEALED_MATERIAL}"
    comp sealed_material skip
elif ! sealed_present; then
    skip "no sealed custody material on this host (${SEALED_MEMBERS[*]} absent — pre-install?)"
    comp sealed_material skip
elif [[ -z "${BACKUP_SEALED_PASSPHRASE:-}" ]]; then
    # FAIL, not skip. Skipping would produce a green bundle that silently omits
    # the one thing whose loss cannot be recovered from any other copy.
    fail "sealed custody material NOT captured: BACKUP_SEALED_PASSPHRASE is unset, and this script will never write custody material in the clear. Set it (environment or .env), or opt out deliberately with BACKUP_SEALED_MATERIAL=0"
    comp sealed_material fail
else
    echo "→ Sealed custody material"
    sealed_rc=0
    install -d -m 0700 -- "$SEALED_STORE"
    # Readability decides the transport, and the choice is REPORTED — a bundle
    # whose custody member came from a helper container is a different fact from
    # one taken as root, and an operator debugging a restore needs to know which.
    if ! ( cd "$DATA_DIR" && find "${SEALED_PRESENT[@]}" -type f ! -name '.lock' ! -readable -print | grep -q . ); then
        SEALED_TAR_PATH="host"
    elif command -v docker >/dev/null 2>&1; then
        SEALED_TAR_PATH="helper"
        echo "  (some custody files are not readable as $(id -un); using the $SEALED_HELPER_IMAGE helper with data/ mounted read-only)"
    else
        fail "sealed custody material unreadable as $(id -un) and docker is unavailable for the read-only helper — run this as root or install docker"
        sealed_rc=1
    fi

    if [[ $sealed_rc -eq 0 ]]; then
        SEALED_MAN_NEW="$STAGE/sealed-material.manifest.new"
        if [[ "$SEALED_TAR_PATH" == "helper" ]]; then
            # The same permission wall applies to hashing; take the manifest out
            # of the archive we are about to write instead of off the live tree.
            if sealed_tar > "$STAGE/sealed-material.tar.gz" 2>"$STAGE/sealed.err" \
               && tar -tzf "$STAGE/sealed-material.tar.gz" >/dev/null 2>>"$STAGE/sealed.err"; then
                :   # archive written and re-readable
            else
                fail "sealed custody material: helper tar failed: $(tail -1 "$STAGE/sealed.err" 2>/dev/null)"
                sealed_rc=1
            fi
            if [[ $sealed_rc -eq 0 ]]; then
                # Manifest over the ARCHIVE MEMBERS, which is what the drill can
                # re-derive after decrypting: <sha256>  <path>, path-sorted.
                ( cd "$STAGE" && mkdir -p sealed-extract && tar -xzf sealed-material.tar.gz -C sealed-extract \
                  && cd sealed-extract && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum \
                     | sed 's|\./||' ) > "$SEALED_MAN_NEW" 2>>"$STAGE/sealed.err" \
                  || { fail "sealed custody material: manifest could not be derived from the helper archive"; sealed_rc=1; }
                rm -rf -- "$STAGE/sealed-extract"
            fi
        else
            sealed_manifest > "$SEALED_MAN_NEW" 2>"$STAGE/sealed.err" \
                || { fail "sealed custody material: manifest could not be computed: $(tail -1 "$STAGE/sealed.err" 2>/dev/null)"; sealed_rc=1; }
        fi
    fi

    if [[ $sealed_rc -eq 0 ]]; then
        if [[ ! -s "$SEALED_MAN_NEW" ]]; then
            fail "sealed custody material: the manifest is EMPTY — nothing was hashed, so nothing would be verifiable"
            sealed_rc=1
        elif [[ -f "$SEALED_ENC" && -f "$SEALED_MAN" ]] && cmp -s "$SEALED_MAN_NEW" "$SEALED_MAN"; then
            # UNCHANGED: re-use the existing envelope rather than re-encrypting a
            # static custody root every night. The bundle still carries it, so it
            # is still self-contained.
            note "sealed custody material UNCHANGED since $(date -u -r "$SEALED_ENC" +%Y-%m-%dT%H:%M:%SZ) — re-using the existing encrypted envelope"
        else
            # CHANGED (or first run): encrypt now. -pass env: keeps the
            # passphrase out of argv, which is world-readable in /proc.
            if [[ "$SEALED_TAR_PATH" == "helper" ]]; then
                BACKUP_SEALED_PASSPHRASE="$BACKUP_SEALED_PASSPHRASE" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
                    -pass env:BACKUP_SEALED_PASSPHRASE -in "$STAGE/sealed-material.tar.gz" -out "$SEALED_ENC.tmp" 2>"$STAGE/sealed.err" \
                    || { fail "sealed custody material: openssl enc failed: $(tail -1 "$STAGE/sealed.err" 2>/dev/null)"; sealed_rc=1; }
            else
                sealed_tar 2>"$STAGE/sealed.err" \
                    | BACKUP_SEALED_PASSPHRASE="$BACKUP_SEALED_PASSPHRASE" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
                        -pass env:BACKUP_SEALED_PASSPHRASE -out "$SEALED_ENC.tmp" 2>>"$STAGE/sealed.err" \
                    || { fail "sealed custody material: tar|openssl failed: $(tail -1 "$STAGE/sealed.err" 2>/dev/null)"; sealed_rc=1; }
            fi
            if [[ $sealed_rc -eq 0 && -s "$SEALED_ENC.tmp" ]]; then
                chmod 0600 -- "$SEALED_ENC.tmp"
                mv -f -- "$SEALED_ENC.tmp" "$SEALED_ENC"
                cp -f -- "$SEALED_MAN_NEW" "$SEALED_MAN"
                chmod 0600 -- "$SEALED_MAN"
                note "sealed custody material RE-ENCRYPTED ($(wc -l < "$SEALED_MAN") files, $(stat -c%s -- "$SEALED_ENC") bytes ciphertext)"
            else
                rm -f -- "$SEALED_ENC.tmp"
                [[ $sealed_rc -eq 0 ]] && { fail "sealed custody material: the encrypted archive is EMPTY"; sealed_rc=1; }
            fi
        fi
        rm -f -- "$STAGE/sealed-material.tar.gz"
    fi

    if [[ $sealed_rc -eq 0 ]]; then
        mkdir -p "$STAGE/sealed"
        if cp -f -- "$SEALED_ENC" "$STAGE/sealed/sealed-material.tar.gz.enc" \
           && cp -f -- "$SEALED_MAN" "$STAGE/sealed/sealed-material.manifest"; then
            cat > "$STAGE/sealed/README" <<'SEALED_README'
sealed-material.tar.gz.enc — data/swtpm (minus .lock), data/tls and
data/api/secrets_wrapped_keys.json, gzip-tarred and then encrypted with:

    openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_SEALED_PASSPHRASE

Decrypt with the SAME passphrase (which is NOT in this archive, by design):

    BACKUP_SEALED_PASSPHRASE=... openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
        -pass env:BACKUP_SEALED_PASSPHRASE \
        -in sealed-material.tar.gz.enc | tar -xzf - -C <restore-root>

sealed-material.manifest is `sha256sum` over the archive members, path-sorted
and relative to data/. Verify a decrypted tree against it before trusting it:

    cd <restore-root> && sha256sum -c sealed-material.manifest

scripts/backup-drill.sh does exactly that, unattended, as one of its legs.

WHY THIS IS SEPARATE FROM THE REST OF THE BUNDLE: data/swtpm deterministically
re-derives the root KEK, so a copy of it IS the KEK. Keeping it in its own
envelope means the tarball plus the .env inside it still cannot unseal the
vault without a secret held outside the backup host.
SEALED_README
            note "sealed custody material included as ./sealed/sealed-material.tar.gz.enc (separately encrypted)"
            comp sealed_material pass
        else
            fail "sealed custody material could not be staged into the archive"
            comp sealed_material fail
        fi
    else
        comp sealed_material fail
    fi
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
    # H4/H5: what the data/ snapshot must NOT carry (all paths anchored at the
    # transfer root, i.e. directly under data/):
    #   /swtpm, /secrets-seal — the CUSTODY ROOT (swtpm state re-derives the
    #     KEK; secrets-seal holds the sealed blobs). Never in the same file as
    #     the wrapped DEKs + .env it would unlock — see the header block.
    #   /backups — where THIS artifact lands; including it nests every
    #     previous backup inside tonight's (exponential growth).
    #   /restore-staging — restore.sh's durable extraction of a previous
    #     restore (a full postgres.sql); same nesting problem.
    # restore.sh carries the MATCHING excludes so its --delete can never
    # remove the live custody root just because the archive lacks it.
    #
    # S4 additions to the exclude set:
    #   /victoria/snapshots — never carry a stale VM snapshot directory; the
    #     one this run took is staged under ./victoriametrics as real bytes.
    #   /victoria — excluded ONLY when the consistent snapshot above succeeded.
    #     A live VM data-dir copy is torn for the same reason a live Lucene copy
    #     is; once we hold a real snapshot the torn copy is pure duplication
    #     (~2x the tier's bytes). When the snapshot did NOT succeed, the torn
    #     copy stays in — worse than a snapshot, far better than nothing — and
    #     the MANIFEST says which of the two happened.
    #   $BACKUP_EXCLUDE — operator-supplied extra patterns, space-separated and
    #     anchored at data/ (e.g. "/kafka /opensearch-snapshots"). A host whose
    #     free disk cannot hold a full bundle must be able to take a NARROWER
    #     one deliberately, and have the narrowing recorded, rather than have
    #     the nightly abort on ENOSPC and leave nothing at all. The patterns are
    #     echoed into the MANIFEST and into the run report so the Data
    #     Protection page can never present a narrowed bundle as a full one.
    declare -a DATA_EXCLUDES=(
        --exclude=/swtpm --exclude=/secrets-seal
        --exclude=/backups --exclude=/restore-staging
        --exclude=/victoria/snapshots
    )
    VM_COPY_NOTE="data/victoria INCLUDED as a live (torn) copy — no consistent snapshot was taken"
    if [[ "$(comp_status victoriametrics)" == "pass" ]]; then
        DATA_EXCLUDES+=(--exclude=/victoria)
        VM_COPY_NOTE="data/victoria excluded — superseded by the consistent snapshot in ./victoriametrics"
    fi
    # Word-splitting on $BACKUP_EXCLUDE is INTENTIONAL: it is a space-separated
    # pattern list, and each pattern becomes its own --exclude.
    # shellcheck disable=SC2086
    for pat in ${BACKUP_EXCLUDE:-}; do
        DATA_EXCLUDES+=("--exclude=$pat")
    done
    rsync_rc=0
    rsync -a --delete --info=stats1 \
        "${DATA_EXCLUDES[@]}" \
        "$DATA_DIR/" "$STAGE/data/" || rsync_rc=$?
    case "$rsync_rc" in
        0)  note "data/ snapshot (rsync; custody root + backups excluded; $VM_COPY_NOTE${BACKUP_EXCLUDE:+; operator excludes: $BACKUP_EXCLUDE})"
            comp data_dir pass ;;
        24) note "data/ snapshot (rsync rc=24: vanished files — expected on a live stack; $VM_COPY_NOTE${BACKUP_EXCLUDE:+; operator excludes: $BACKUP_EXCLUDE})"
            comp data_dir pass ;;
        *)  fail "data/ snapshot rsync failed (rc=$rsync_rc)"
            comp data_dir fail ;;
    esac
else
    echo "  (no data/ directory yet)"
    skip "no data/ directory yet"
    comp data_dir skip
fi

# ---- .env + configs --------------------------------------------------------

echo "→ Snapshotting .env and configs"
CURRENT_STEP=".env + config snapshot"
if [[ -f "$COMPOSE_DIR/.env" ]]; then
    # H4: BACKUP_SIGN_KEY must NOT ride inside the artifact it authenticates —
    # an archive carrying its own MAC key is tamper-evident to nobody. Strip
    # that one line; every other .env line ships (0600 preserved by tar).
    env_grep_rc=0
    grep -v '^BACKUP_SIGN_KEY=' "$COMPOSE_DIR/.env" > "$STAGE/env.backup" || env_grep_rc=$?
    # grep rc=1 = zero lines survived (a .env holding only the sign key) — an
    # empty env.backup is then the correct content. rc>=2 is a real read error.
    if [[ $env_grep_rc -ge 2 ]]; then
        fail ".env snapshot failed (grep rc=$env_grep_rc reading $COMPOSE_DIR/.env)"
    fi
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
# M26: the directory holding whole-stack backups is operator-only. install -d
# also tightens a pre-existing world-readable data/backups to 0700.
install -d -m 0700 -- "$(dirname -- "$OUT")"
# -f: the cron names its artifact correlix-YYYYMMDD.tar.zst, so a same-day
# re-run (manual retry after a failure) targets an EXISTING file — without -f
# zstd refuses the overwrite and the whole run aborted (found 2026-08-14).
# Overwriting the same-day artifact with a fresh complete one is the intent.
tar -C "$STAGE" -cf - . | zstd -T0 -19 -f -o "$OUT"
# umask 077 already makes a fresh artifact 0600; the chmod covers the same-day
# OVERWRITE path, where zstd keeps the existing file's (possibly wider) mode.
chmod 0600 -- "$OUT"

# ---- artifact signature (H4) -----------------------------------------------
#
# $OUT.sig: a sha256 line (integrity — bit rot, truncation) and, when
# BACKUP_SIGN_KEY is set, an hmac-sha256 line (authenticity — a tamperer
# without the key cannot re-sign). The key comes from the environment or from
# .env, NEVER from data/ (the archive contains data/), and env.backup above is
# stripped of it. restore.sh verifies this sidecar before extracting a byte.
CURRENT_STEP="artifact signing"
echo "→ Signing"
sig_ok=1
SIGN_SHA=$(sha256sum -- "$OUT" | cut -d' ' -f1) || sig_ok=0
if [[ $sig_ok -eq 1 && -n "$SIGN_SHA" ]]; then
    {
        printf 'sha256 %s\n' "$SIGN_SHA"
        if [[ -n "${BACKUP_SIGN_KEY:-}" ]]; then
            printf 'hmac-sha256 %s\n' "$(BACKUP_SIGN_KEY="$BACKUP_SIGN_KEY" hmac_file "$OUT")"
        fi
    } > "$OUT.sig" || sig_ok=0
    # A key that was set but produced no MAC line (python3 missing, OOM) must
    # fail the component — restore.sh would flag the MAC-less sidecar anyway.
    if [[ $sig_ok -eq 1 && -n "${BACKUP_SIGN_KEY:-}" ]] && ! grep -q '^hmac-sha256 [0-9a-f]' "$OUT.sig"; then
        sig_ok=0
    fi
else
    sig_ok=0
fi
if [[ $sig_ok -eq 1 ]]; then
    chmod 0600 -- "$OUT.sig"
    comp signature pass
    if [[ -n "${BACKUP_SIGN_KEY:-}" ]]; then
        note "artifact signature (sha256 + HMAC) → $(basename -- "$OUT").sig"
    else
        note "artifact signature (sha256 only — no BACKUP_SIGN_KEY)"
        echo "!! WARNING: BACKUP_SIGN_KEY unset — the artifact carries a sha256 only." >&2
        echo "!!          Corruption is detectable; TAMPERING is not. Set BACKUP_SIGN_KEY" >&2
        echo "!!          (deployment/docker/.env or the cron environment) to add the" >&2
        echo "!!          HMAC that restore.sh authenticates against." >&2
    fi
else
    fail "artifact signing FAILED — restore.sh will refuse $OUT (python3 present? disk full?)"
    comp signature fail
fi

# ---- SHA256SUMS sidecar (S4) -----------------------------------------------
#
# $OUT.sig proves the artifact against a key we hold; SHA256SUMS is the thing
# the REMOTE END can check with nothing but coreutils, which is what turns "the
# push command exited 0" into "the bytes that arrived are the bytes we sent".
# rsync's own checksums cover the transfer, not the file sitting there a week
# later, and a truncated remote copy is a restore that fails at the worst
# possible moment. Written in the artifact's directory with BARE basenames so
# `sha256sum -c SHA256SUMS` works from any directory the files land in.
CURRENT_STEP="checksum sidecar"
OUT_DIR="$(dirname -- "$OUT")"
OUT_BASE="$(basename -- "$OUT")"
SUMS_FILE="$OUT_DIR/SHA256SUMS"
declare -a SUM_TARGETS=("$OUT_BASE")
[[ -f "$OUT.sig" ]] && SUM_TARGETS+=("$OUT_BASE.sig")
if ( cd "$OUT_DIR" && sha256sum -- "${SUM_TARGETS[@]}" > "SHA256SUMS" ); then
    chmod 0600 -- "$SUMS_FILE"
    note "checksum sidecar → SHA256SUMS ($(wc -l < "$SUMS_FILE") entries)"
else
    fail "could not write $SUMS_FILE — the remote copy could not be verified after transfer"
fi

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
    # The destination, not the transport, is echoed: BACKUP_PUSH can legitimately
    # carry credentials (an `-e "sshpass -p …"` transport), and this line goes to
    # a cron mail spool and the operator's terminal (§8, §16.5).
    echo "→ Off-host copy → $BACKUP_REMOTE"
    # The .sig sidecar and SHA256SUMS ride along: a remote copy that cannot be
    # authenticated at restore time re-creates the unsigned-artifact problem
    # off-host, and one that cannot be checksummed cannot be proven intact.
    push_rc=0
    $PUSH_CMD "$OUT" "$BACKUP_REMOTE" 2>"$STAGE/push.err" || push_rc=$?
    if [[ $push_rc -eq 0 && -f "$OUT.sig" ]]; then
        $PUSH_CMD "$OUT.sig" "$BACKUP_REMOTE" 2>>"$STAGE/push.err" || push_rc=$?
    fi
    if [[ $push_rc -eq 0 && -f "$SUMS_FILE" ]]; then
        $PUSH_CMD "$SUMS_FILE" "$BACKUP_REMOTE" 2>>"$STAGE/push.err" || push_rc=$?
    fi
    if [[ $push_rc -eq 0 ]]; then
        REMOTE_PUSHED=1
        note "off-host copy (artifact + signature + SHA256SUMS) → $BACKUP_REMOTE"
        comp offhost pass
    else
        fail "off-host copy FAILED: $(tail -1 "$STAGE/push.err" 2>/dev/null) — the artifact is ON-HOST ONLY (no DR)"
        comp offhost fail
    fi

    # ---- prove the REMOTE bytes (S4) --------------------------------------
    #
    # "the push exited 0" is the same class of evidence as "docker compose up
    # exited 0": it says a command ran, not that a restorable copy exists at the
    # other end. BACKUP_REMOTE_VERIFY=1 goes and checks, over the operator's own
    # ssh transport, that `sha256sum -c SHA256SUMS` passes in the destination
    # directory. Only the rsync/ssh `[user@]host:path` destination shape can be
    # queried this way; anything else (s3://, a local mount) says so plainly and
    # leaves verified_at empty rather than claiming a proof it did not obtain.
    if [[ $push_rc -eq 0 && "${BACKUP_REMOTE_VERIFY:-0}" == "1" ]]; then
        CURRENT_STEP="off-host verification"
        SSH_CMD="${BACKUP_SSH:-ssh}"
        if [[ "$BACKUP_REMOTE" == *:* && "$BACKUP_REMOTE" != *://* ]]; then
            R_HOST="${BACKUP_REMOTE%%:*}"
            R_PATH="${BACKUP_REMOTE#*:}"
            [[ -z "$R_PATH" ]] && R_PATH="."
            echo "→ Verifying the REMOTE copy on $R_HOST"
            # Word-splitting on $SSH_CMD is INTENTIONAL: BACKUP_SSH is an
            # operator-supplied transport ("ssh -i /path/key -p 2222"), the same
            # shape BACKUP_PUSH already has.
            # shellcheck disable=SC2086
            if timeout 300 $SSH_CMD -o BatchMode=yes -o ConnectTimeout=15 "$R_HOST" \
                    "cd $(printf '%q' "$R_PATH") && sha256sum -c SHA256SUMS" >"$STAGE/verify.out" 2>&1; then
                REMOTE_VERIFIED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
                note "off-host copy VERIFIED at the destination (sha256sum -c SHA256SUMS) at $REMOTE_VERIFIED_AT"
            else
                fail "off-host VERIFICATION failed on $R_HOST: $(tail -1 "$STAGE/verify.out" 2>/dev/null) — the remote copy is present but UNPROVEN"
            fi
        else
            echo "!! WARNING: BACKUP_REMOTE_VERIFY=1 but $BACKUP_REMOTE is not an [user@]host:path" >&2
            echo "!!          destination — this script cannot run sha256sum at the far end of" >&2
            echo "!!          an object-store or local-mount transport. The copy is UNVERIFIED." >&2
            note "off-host verification NOT ATTEMPTED — the destination shape cannot be queried over ssh"
        fi
    fi
else
    echo "!! WARNING: BACKUP_REMOTE unset — this backup shares the primary data's" >&2
    echo "!!          failure domain (same disk/host). It is NOT disaster recovery." >&2
    echo "!!          See docs/audit/BACKUP-FAILURE-DOMAIN.md. Set BACKUP_REMOTE to fix." >&2
    comp offhost skip
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
