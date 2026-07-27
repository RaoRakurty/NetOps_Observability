#!/usr/bin/env bash
#
# backup-retention.sh — proves scripts/backup.sh's retention sweep (audit item 6).
#
# The finding: apply-backup-config.sh installs a DAILY cron writing
# data/backups/correlix-YYYYMMDD.tar.zst and NOTHING pruned them, while the
# runbook claimed retention was "already in place". This test is the evidence
# that it now IS, and it exercises the real code path — `backup.sh --prune`
# calls the same prune_backups() the nightly run calls.
#
# Runs entirely against a throwaway temp directory (mktemp -d). It NEVER touches
# data/backups, never starts a container, and never runs a backup (CLAUDE.md
# §16.3: dry-run before destructive action; never point a pruner at a live
# volume it was not given).
#
# Usage: tests/backup-retention.sh          → runs every case, exits non-zero on failure

set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP="$DIR/../scripts/backup.sh"
[[ -x "$BACKUP" || -f "$BACKUP" ]] || { echo "cannot find $BACKUP" >&2; exit 2; }

PASS=0
FAILN=0
ok()   { PASS=$((PASS + 1)); echo "  ok   — $*"; }
bad()  { FAILN=$((FAILN + 1)); echo "  FAIL — $*" >&2; }

# seed <dir> <n> — n managed artifacts, oldest first, with distinct mtimes so
# "newest" is unambiguous. Named the way the cron names them.
seed() {
    local dir="$1" n="$2" i
    mkdir -p "$dir"
    for ((i = 1; i <= n; i++)); do
        printf 'backup-%02d' "$i" > "$dir/correlix-202607$(printf '%02d' "$i").tar.zst"
        touch -d "2026-07-$(printf '%02d' "$i") 03:00:00" \
              "$dir/correlix-202607$(printf '%02d' "$i").tar.zst"
    done
}

count() { find "$1" -maxdepth 1 -type f -name 'correlix-*.tar.zst' | wc -l; }
newest() {
    find "$1" -maxdepth 1 -type f -name 'correlix-*.tar.zst' -printf '%T@\t%p\n' \
        | sort -rn | head -1 | cut -f2-
}

run_prune() { BACKUP_KEEP="$1" bash "$BACKUP" --prune "$2" ${3:+--dry-run}; }

echo "== backup retention =="

# ---- 1. keep-N: the N newest survive, everything older is pruned -----------
T="$(mktemp -d -t backup-retention-XXXXXX)"
trap 'rm -rf -- "$T"' EXIT
seed "$T/keepn" 10
WANT_NEWEST="$(newest "$T/keepn")"
run_prune 3 "$T/keepn" >/dev/null
if [[ "$(count "$T/keepn")" -eq 3 ]]; then
    ok "BACKUP_KEEP=3 left exactly 3 of 10 artifacts"
else
    bad "BACKUP_KEEP=3 left $(count "$T/keepn") artifacts, want 3"
fi
if [[ "$(newest "$T/keepn")" == "$WANT_NEWEST" ]]; then
    ok "the NEWEST artifact survived the sweep"
else
    bad "the newest artifact was deleted — this is the one thing a pruner may never do"
fi
# The survivors must be the newest N, not an arbitrary N.
if [[ -f "$T/keepn/correlix-20260710.tar.zst" && -f "$T/keepn/correlix-20260709.tar.zst" \
      && -f "$T/keepn/correlix-20260708.tar.zst" && ! -f "$T/keepn/correlix-20260707.tar.zst" ]]; then
    ok "the survivors are the 3 NEWEST by mtime"
else
    bad "the survivors are not the 3 newest"
fi

# ---- 2. idempotent: a second sweep changes nothing (§16.3) ------------------
run_prune 3 "$T/keepn" >/dev/null
if [[ "$(count "$T/keepn")" -eq 3 ]]; then
    ok "a second sweep is a no-op (idempotent)"
else
    bad "the sweep is not idempotent: $(count "$T/keepn") artifacts after a repeat run"
fi

# ---- 3. NEVER delete the last backup, whatever the setting ------------------
seed "$T/single" 1
LAST="$(newest "$T/single")"
run_prune 1 "$T/single" >/dev/null
if [[ -f "$LAST" ]]; then
    ok "KEEP=1 with one artifact leaves it in place"
else
    bad "the only backup was deleted at KEEP=1"
fi

# ---- 4. dry-run deletes NOTHING and says what it would do -------------------
seed "$T/dry" 6
OUTPUT="$(run_prune 2 "$T/dry" --dry-run)"
if [[ "$(count "$T/dry")" -eq 6 ]]; then
    ok "--dry-run deleted nothing"
else
    bad "--dry-run DELETED files ($(count "$T/dry") of 6 left)"
fi
if grep -q 'would delete' <<<"$OUTPUT"; then
    ok "--dry-run states what it would touch before touching it"
else
    bad "--dry-run printed no plan"
fi

# ---- 5. KEEP=0 disables retention LOUDLY, it does not delete everything -----
seed "$T/zero" 5
OUTPUT="$(BACKUP_KEEP=0 bash "$BACKUP" --prune "$T/zero" 2>&1)"
if [[ "$(count "$T/zero")" -eq 5 ]]; then
    ok "BACKUP_KEEP=0 is 'retention disabled', not 'delete everything'"
else
    bad "BACKUP_KEEP=0 deleted artifacts"
fi
if grep -qi 'WARNING' <<<"$OUTPUT"; then
    ok "BACKUP_KEEP=0 warns that backups will accumulate"
else
    bad "BACKUP_KEEP=0 is silent — a disabled safety must never be quiet (§16.1)"
fi

# ---- 6. only the MANAGED naming scheme is touched --------------------------
seed "$T/mixed" 5
echo "not ours" > "$T/mixed/some-other-archive.tar.zst"
echo "not ours" > "$T/mixed/correlix-notes.txt"
run_prune 1 "$T/mixed" >/dev/null
if [[ -f "$T/mixed/some-other-archive.tar.zst" && -f "$T/mixed/correlix-notes.txt" ]]; then
    ok "unmanaged files in the backup directory are left alone"
else
    bad "the sweep deleted a file it does not manage"
fi

# ---- 7. a missing directory is reported, not a crash ------------------------
if run_prune 3 "$T/does-not-exist" >/dev/null; then
    ok "a missing backup directory exits 0 with a message (nothing to prune)"
else
    bad "a missing backup directory made the sweep fail"
fi

# ---- 8. a non-integer BACKUP_KEEP is REFUSED, never coerced ----------------
if BACKUP_KEEP="all" bash "$BACKUP" --prune "$T/keepn" >/dev/null 2>&1; then
    bad "BACKUP_KEEP='all' was accepted — a malformed retention setting must fail closed"
else
    ok "a malformed BACKUP_KEEP is refused (fail closed)"
fi

echo
echo "== $PASS passed, $FAILN failed =="
[[ $FAILN -eq 0 ]]
