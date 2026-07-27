#!/usr/bin/env bash
#
# apply-backup-config.sh — enforce the Data Protection settings the UI stored.
#
# The backend runs in a container and cannot write the host crontab or the host
# .env where BACKUP_REMOTE lives (system_backup.go ARCHITECTURE NOTE). It stores
# the operator's INTENT to /data/system_backup.json; THIS script, run host-side
# by install/upgrade (or by hand), enforces it: it writes BACKUP_REMOTE/BACKUP_PUSH
# into deployment/docker/.env and installs or removes the backup cron.
#
# CLAUDE.md §16: no swallowed errors, explicit PATH, idempotent, and it REFUSES
# to schedule a full backup without an off-host remote (F-55 — a local-only
# nightly backup fills the disk it needs).
#
# Usage: scripts/apply-backup-config.sh [--dry-run]

set -uo pipefail
_HOME="${HOME:-/home/$(id -un 2>/dev/null || echo rao)}"
export PATH="/usr/local/bin:/usr/bin:/bin:${_HOME}/.local/bin:${PATH:-}"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
ENV_FILE="$ROOT/deployment/docker/.env"
# The config the backend writes. Its /data maps to data/api on the host.
CONFIG="${BACKUP_CONFIG_FILE:-$ROOT/data/api/system_backup.json}"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

die() { echo "apply-backup-config: ERROR: $*" >&2; exit 1; }
say() { echo "apply-backup-config: $*"; }

command -v python3 >/dev/null 2>&1 || die "python3 not on PATH ($PATH)"

if [ ! -f "$CONFIG" ]; then
  say "no config at $CONFIG yet — nothing to apply (set it in Settings → Data Protection)"
  exit 0
fi

# Parse the JSON without assuming jq is present.
read_json() { python3 -c "import json,sys; d=json.load(open('$CONFIG')); print(d.get('$1',''))" 2>/dev/null; }
REMOTE="$(read_json remote_url)"
PUSH="$(read_json push_command)"
SCHED="$(read_json schedule_enabled)"    # 'True' / 'False'
CRON="$(read_json schedule_cron)"
[ -z "$CRON" ] && CRON="30 2 * * *"

# Retention (2026-07-27). The nightly cron wrote a full backup a day and NOTHING
# pruned them; the only retention in the product was OPENSEARCH_SNAPSHOT_KEEP.
# BACKUP_KEEP mirrors that convention exactly (keep the N newest, 0 = disabled)
# and backup.sh reads it out of .env, so it works under cron's bare environment.
KEEP="$(read_json retain_count)"
[ -z "$KEEP" ] && KEEP="$(read_json keep_count)"
[ -z "$KEEP" ] && KEEP=7
case "$KEEP" in
  ''|*[!0-9]*) die "retain_count in $CONFIG is not a non-negative integer: '$KEEP'" ;;
esac

# F-55 guard, enforced here too (defence in depth with the API's own check).
if [ "$SCHED" = "True" ] && [ -z "$REMOTE" ]; then
  die "schedule is enabled but no off-host remote is set — refusing to schedule a local-only nightly backup that would fill the disk (F-55). Set a remote first."
fi

# --- 1. write BACKUP_REMOTE / BACKUP_PUSH into .env (idempotent) -------------
set_env() { # key value
  local key="$1" val="$2"
  [ -f "$ENV_FILE" ] || die "no .env at $ENV_FILE (run install.py first)"
  if grep -q "^${key}=" "$ENV_FILE"; then
    if [ "$DRY" = 1 ]; then say "[dry-run] would set ${key} in .env"; return; fi
    # Use a python rewrite so a value with slashes/spaces is safe (no sed escaping).
    python3 - "$ENV_FILE" "$key" "$val" <<'PY'
import sys
path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path).read().splitlines()
out = [f"{key}={val}" if l.startswith(key + "=") else l for l in lines]
open(path, "w").write("\n".join(out) + "\n")
PY
  else
    [ "$DRY" = 1 ] && { say "[dry-run] would append ${key} to .env"; return; }
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
  fi
}
set_env BACKUP_REMOTE "$REMOTE"
set_env BACKUP_PUSH "${PUSH:-rsync -a}"
set_env BACKUP_KEEP "$KEEP"
say "applied BACKUP_REMOTE=${REMOTE:-<empty>} BACKUP_KEEP=${KEEP} to .env"
if [ "$KEEP" = "0" ] && [ "$SCHED" = "True" ]; then
  say "WARNING: BACKUP_KEEP=0 with a nightly schedule — retention is DISABLED and"
  say "         backups will accumulate until they fill the disk the stack needs."
fi

# --- 2. install / remove the backup cron ------------------------------------
CRON_TAG="# correlix-backup (managed by apply-backup-config.sh)"
BACKUP_CMD="$DIR/backup.sh $ROOT/data/backups/correlix-\$(date +\\%Y\\%m\\%d).tar.zst >> $DIR/backup.log 2>&1"
CRON_LINE="$CRON $BACKUP_CMD $CRON_TAG"

current="$(crontab -l 2>/dev/null | grep -v "correlix-backup (managed" || true)"
if [ "$SCHED" = "True" ]; then
  new="$current"$'\n'"$CRON_LINE"
  say "scheduling full backup: $CRON"
else
  new="$current"
  say "full-backup schedule DISABLED (removing any managed cron)"
fi
if [ "$DRY" = 1 ]; then
  # `${SCHED:+…}` tested for a NON-EMPTY SCHED, so it printed the cron line even
  # when SCHED=False — a dry-run that showed a schedule about to be installed
  # when the real run would remove it. Test the actual value.
  say "[dry-run] resulting crontab backup line:"
  if [ "$SCHED" = "True" ]; then echo "$CRON_LINE"; else echo "(none — schedule disabled)"; fi
else
  mkdir -p "$ROOT/data/backups"
  printf '%s\n' "$new" | grep -v '^$' | crontab -
  say "crontab updated"
fi

say "done."
