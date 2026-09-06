#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# apply-backup-config.sh — enforce the Data Protection settings the UI stored.
#
# The backend runs in a container and cannot write the host crontab or the host
# .env where BACKUP_REMOTE lives (system_backup.go ARCHITECTURE NOTE). It stores
# the operator's INTENT to /data/system_backup.json; THIS script, run host-side,
# enforces it: it writes BACKUP_REMOTE/BACKUP_PUSH into deployment/docker/.env
# and installs or removes the backup cron.
#
# WHO RUNS IT (#150 loop closure, 2026-08-14): the stack watchdog cron invokes
# this every time the stored intent file is NEWER than its last-applied stamp
# (scripts/stack-watchdog.sh, apply_backup_intent) — so a GUI change is live on
# the host within a minute. It can also be run by hand.
#
# CLAUDE.md §16: no swallowed errors, explicit PATH, idempotent, and it REFUSES
# to schedule a full backup without an off-host remote (F-55 — a local-only
# nightly backup fills the disk it needs). Every mutation (.env write, crontab
# install) is CHECKED and verified; a failed apply exits non-zero and loud —
# it must never print "applied"/"updated" for a write that did not land.
#
# Usage: scripts/apply-backup-config.sh [--dry-run]

set -euo pipefail
_HOME="${HOME:-/home/$(id -un 2>/dev/null || echo rao)}"
export PATH="/usr/local/bin:/usr/bin:/bin:${_HOME}/.local/bin:${PATH:-}"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
ENV_FILE="$ROOT/deployment/docker/.env"
# The config the backend writes. Its /data maps to data/api on the host.
CONFIG="${BACKUP_CONFIG_FILE:-$ROOT/data/api/system_backup.json}"
DRY=0
if [ "${1:-}" = "--dry-run" ]; then DRY=1; fi

die() { echo "apply-backup-config: ERROR: $*" >&2; exit 1; }
say() { echo "apply-backup-config: $*"; }

command -v python3 >/dev/null 2>&1 || die "python3 not on PATH ($PATH)"

if [ ! -f "$CONFIG" ]; then
  say "no config at $CONFIG yet — nothing to apply (set it in Settings → Data Protection)"
  exit 0
fi

# Refuse unparsable intent OUTRIGHT: the previous read_json swallowed parse
# errors (2>/dev/null), so a corrupt config read as all-empty values and the
# script would happily apply BACKUP_REMOTE=<empty> + remove the cron.
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$CONFIG" 2>/dev/null \
  || die "config $CONFIG is not valid JSON — refusing to apply garbage (fix or re-save it in Settings → Data Protection)"

# Parse the JSON without assuming jq is present. Parse errors are impossible
# here (validated above); a missing key is legitimately empty.
read_json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2],''))" "$CONFIG" "$1"; }
REMOTE="$(read_json remote_url)"
PUSH="$(read_json push_command)"
SCHED="$(read_json schedule_enabled)"    # 'True' / 'False'
CRON="$(read_json schedule_cron)"
if [ -z "$CRON" ]; then CRON="30 2 * * *"; fi

# --- INDEPENDENT re-validation (defence in depth; this script is the security
# boundary, not the API). Every field below is written verbatim into the root
# crontab or .env, so a value that broke out of its line = host command
# execution. The API (system_backup.go) validates too; we do NOT trust that it
# ran — a hand-edited /data/system_backup.json reaches here directly. Refuse
# anything but the exact shapes we render. (review 2026-08-15, host-RCE class.)
has_ctrl() { case "$1" in *[[:cntrl:]]*) return 0 ;; *) return 1 ;; esac; }
for _f in "$REMOTE" "$PUSH" "$CRON"; do
  if has_ctrl "$_f"; then
    die "backup config field contains a control character (newline/tab/etc.) — refusing (host-injection guard)"
  fi
done
# push_command: an allowlisted transport binary + bare flag/value tokens only.
if [ -n "$PUSH" ]; then
  set -f; # shellcheck disable=SC2086
  set -- $PUSH; set +f
  case "$1" in
    rsync|rclone|scp|sftp|aws|gsutil|gcloud|b2|azcopy|cp|mc) : ;;
    *) die "push_command must start with an allowlisted transport (rsync/rclone/scp/aws/gsutil/b2/azcopy/cp/…), got '$1' — refusing" ;;
  esac
  for _tok in "$@"; do
    case "$_tok" in
      *[!A-Za-z0-9._/@=:+-]*) die "push_command token '$_tok' contains a shell metacharacter — refusing" ;;
    esac
  done
fi
# schedule_cron: exactly 5 fields, each digits and the cron operators only.
if [ "$SCHED" = "True" ]; then
  set -f; # shellcheck disable=SC2086
  set -- $CRON; set +f
  if [ "$#" -ne 5 ]; then die "schedule_cron must have exactly 5 fields, got $# ('$CRON') — refusing"; fi
  for _fld in "$@"; do
    case "$_fld" in
      *[!0-9*,/-]*) die "schedule_cron field '$_fld' has an illegal character (only digits and * , - / allowed) — refusing" ;;
    esac
  done
fi

# Retention (2026-07-27). The nightly cron wrote a full backup a day and NOTHING
# pruned them; the only retention in the product was OPENSEARCH_SNAPSHOT_KEEP.
# BACKUP_KEEP mirrors that convention exactly (keep the N newest, 0 = disabled)
# and backup.sh reads it out of .env, so it works under cron's bare environment.
KEEP="$(read_json retain_count)"
if [ -z "$KEEP" ]; then KEEP="$(read_json keep_count)"; fi
if [ -z "$KEEP" ]; then KEEP=7; fi
case "$KEEP" in
  ''|*[!0-9]*) die "retain_count in $CONFIG is not a non-negative integer: '$KEEP'" ;;
esac

# F-55 guard, enforced here too (defence in depth with the API's own check).
if [ "$SCHED" = "True" ] && [ -z "$REMOTE" ]; then
  die "schedule is enabled but no off-host remote is set — refusing to schedule a local-only nightly backup that would fill the disk (F-55). Set a remote first."
fi

# --- 1. write BACKUP_REMOTE / BACKUP_PUSH into .env (idempotent, VERIFIED) ---
set_env() { # key value — dies unless the key VERIFIABLY lands in .env
  local key="$1" val="$2"
  [ -f "$ENV_FILE" ] || die "no .env at $ENV_FILE (run install.py first)"
  if grep -q "^${key}=" "$ENV_FILE"; then
    if [ "$DRY" = 1 ]; then say "[dry-run] would set ${key} in .env"; return; fi
    # Use a python rewrite so a value with slashes/spaces is safe (no sed escaping).
    python3 - "$ENV_FILE" "$key" "$val" <<'PY' \
      || die "failed to rewrite ${key} in $ENV_FILE (permissions? disk full?)"
import sys
path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path).read().splitlines()
out = [f"{key}={val}" if l.startswith(key + "=") else l for l in lines]
open(path, "w").write("\n".join(out) + "\n")
PY
  else
    if [ "$DRY" = 1 ]; then say "[dry-run] would append ${key} to .env"; return; fi
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE" \
      || die "failed to append ${key} to $ENV_FILE (permissions? disk full?)"
  fi
  # Verify the key actually landed with the intended value before EVER claiming
  # success: the pre-fix version printed "applied …" after a silently failed
  # write, leaving cron to run backup.sh with no BACKUP_REMOTE (local-only
  # nightly backups filling the primary disk while reporting green — F-55).
  grep -qxF "${key}=${val}" "$ENV_FILE" \
    || die "verification failed: ${key}=${val} is not in $ENV_FILE after writing it"
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

# `crontab -l` legitimately fails when the user has no crontab yet — that is
# the empty-crontab case, not an error to surface.
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
  mkdir -p "$ROOT/data/backups" || die "could not create $ROOT/data/backups"
  # Stage the new crontab in a file so the `crontab` exit status is judged on
  # its own (a bare pipe conflates grep's "no lines" with a crontab failure),
  # then VERIFY the installed crontab matches the intent before claiming so.
  tmp_cron="$(mktemp)" || die "mktemp failed"
  # grep rc=1 here means the resulting crontab is empty — legitimate when the
  # schedule is disabled and no other entries exist.
  printf '%s\n' "$new" | grep -v '^$' > "$tmp_cron" || true
  crontab "$tmp_cron" || { rm -f "$tmp_cron"; die "crontab update failed — the schedule intent was NOT applied"; }
  rm -f "$tmp_cron"
  if [ "$SCHED" = "True" ]; then
    crontab -l 2>/dev/null | grep -qF "$CRON_TAG" \
      || die "verification failed: managed backup cron line missing after install"
  else
    if crontab -l 2>/dev/null | grep -qF "$CRON_TAG"; then
      die "verification failed: managed backup cron line still present after removal"
    fi
  fi
  say "crontab updated"
fi

say "done."
