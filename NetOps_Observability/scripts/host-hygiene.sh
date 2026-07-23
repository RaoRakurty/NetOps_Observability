#!/usr/bin/env bash
#
# Host hygiene — threshold-driven self-cleanup for the NetOps stack host.
#
# Born from the 2026-07-14 incident: the GO BUILD CACHE (not Docker) filled /
# to 100%; the stack-watchdog's docker-only valve couldn't help, 80 OpenSearch
# indices flipped read-only at the flood watermark and Kafka crash-looped.
# Freeing space did NOT heal OpenSearch — the read-only blocks stay until
# explicitly cleared. This script closes both gaps:
#
#   1. CLEAN  — when / crosses TRIGGER_PCT, reclaim every known dev-host cache
#               class, escalating at CRITICAL_PCT. Never touches product state
#               (data/ bind mounts, named volumes, tagged in-use images).
#   2. HEAL   — whenever disk is back under FLOOD_CLEAR_PCT, detect and clear
#               OpenSearch read_only_allow_delete index blocks (the exact
#               damage a full disk leaves behind), and alert that it happened.
#
# What it cleans (tier 1, disk >= TRIGGER_PCT, default 85):
#   * go build cache        (go clean -cache — 13 GB in the incident)
#   * npm + pip caches
#   * docker build cache    (keep 2 GB hot layers) + dangling images
#   * oversized container json-logs (truncate > LOG_MAX_MB, default 512)
# Escalation (tier 2, disk >= CRITICAL_PCT, default 92):
#   * docker build cache    (drop ALL of it)
#   * docker images unused by any container and older than 72h
#   * anonymous/unreferenced volumes (same rule as docker-hygiene.sh)
#
# Deliberately NOT here (need sudo, this host has no passwordless sudo —
# run by hand when needed):  journalctl --vacuum-size=500M · apt-get clean
#
# Division of labour:
#   stack-watchdog.sh   every 1m   — alerting + tiny 90% docker-cache valve
#   host-hygiene.sh     every 10m  — THIS: full cache sweep + OS block healing
#   docker-hygiene.sh   weekly     — scheduled wide docker pass
#
# Install (cron, every 10 minutes):
#   (crontab -l; echo '*/10 * * * * /home/rao/Projects/NetOps_Observability/NetOps_Observability/scripts/host-hygiene.sh >> /home/rao/Projects/NetOps_Observability/NetOps_Observability/scripts/host-hygiene.log 2>&1') | crontab -
#
# Usage: host-hygiene.sh [--status | --force | --test]
#   --status  report disk + cache sizes and OS block state, change nothing
#   --force   run the tier-1 (+tier-2 if critical) sweep regardless of disk %
#   --test    send one ntfy push to confirm alerting, then exit
#
# Config via scripts/stack-watchdog.env (shared with the watchdog):
#   NTFY_TOPIC / NTFY_SERVER    phone alerts (optional)
#   HYGIENE_TRIGGER_PCT=85  HYGIENE_CRITICAL_PCT=92  HYGIENE_FLOOD_CLEAR_PCT=90
#   HYGIENE_LOG_MAX_MB=512  KEEP_BUILD_CACHE=2GB

set -uo pipefail
# PATH under cron is only /usr/bin:/bin, and the tools this script's whole job
# depends on do NOT live there: go is at ~/.local/go/bin, and user npm/pip shims
# under ~/.local/bin. Before this line included the go dir, `go clean -cache`
# was command-not-found on every cron run — swallowed by `|| true` — so the
# single biggest reclaimable item (11 GB of go-build cache) was NEVER cleaned by
# the cron that exists to clean it. The disk climbed to 91% while the log said
# "91% -> 91%" every ten minutes. Resolve HOME's tool dirs explicitly.
_HOME="${HOME:-/home/$(id -un 2>/dev/null || echo rao)}"
export PATH="/usr/local/bin:/usr/bin:/bin:${_HOME}/.local/go/bin:${_HOME}/go/bin:${_HOME}/.local/bin:${PATH:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${WATCHDOG_ENV:-$SCRIPT_DIR/stack-watchdog.env}"
STATE_FILE="$SCRIPT_DIR/.host-hygiene.state"

# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

# Heartbeat for the stack-watchdog's staleness check: quiet runs write nothing
# to the log, so this marker is how "the cron is alive" stays observable.
touch "$SCRIPT_DIR/.host-hygiene.heartbeat" 2>/dev/null || true

TRIGGER_PCT="${HYGIENE_TRIGGER_PCT:-85}"
CRITICAL_PCT="${HYGIENE_CRITICAL_PCT:-92}"
FLOOD_CLEAR_PCT="${HYGIENE_FLOOD_CLEAR_PCT:-90}"
LOG_MAX_MB="${HYGIENE_LOG_MAX_MB:-512}"
NTFY_SERVER="${NTFY_SERVER:-https://ntfy.sh}"

push() {  # title, tags, priority, body
  [ -n "${NTFY_TOPIC:-}" ] || return 0
  curl -fsS -m 10 -H "Title: $1" -H "Tags: $2" -H "Priority: $3" \
    -d "$4" "$NTFY_SERVER/$NTFY_TOPIC" -o /dev/null \
    || echo "host-hygiene: ntfy push failed" >&2
}

disk_pct() { df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9'; }
disk_free() { df -h --output=avail / 2>/dev/null | tail -1 | tr -d ' '; }

# ── OpenSearch healing ────────────────────────────────────────────────────────
# A full disk flips indices read_only_allow_delete=true at the 95% flood stage
# and OpenSearch NEVER clears the block itself. Ingest silently dies until an
# operator remembers this (it cost a full outage once, 2026-06). Heal it the
# moment disk is safe again — and say so, because silent healing hides the
# lesson that disk hit flood stage at all.
os_ip() {
  docker inspect netops-opensearch-1 \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null
}

os_blocked_count() {
  local ip="$1"
  curl -fsS -m 10 "http://$ip:9200/_all/_settings/index.blocks.read_only_allow_delete" 2>/dev/null \
    | grep -o 'read_only_allow_delete' | wc -l
}

heal_opensearch() {
  local pct ip blocked
  pct=$(disk_pct)
  [ -n "$pct" ] && [ "$pct" -lt "$FLOOD_CLEAR_PCT" ] || return 0  # never unlock while disk is still hot
  ip=$(os_ip); [ -n "$ip" ] || return 0
  blocked=$(os_blocked_count "$ip")
  [ "${blocked:-0}" -gt 0 ] || return 0
  echo "-- healing: clearing read_only_allow_delete on $blocked indices (disk ${pct}%) --"
  if curl -fsS -m 30 -X PUT "http://$ip:9200/_all/_settings" \
       -H 'Content-Type: application/json' \
       -d '{"index.blocks.read_only_allow_delete": null}' -o /dev/null; then
    push "NetOps: OpenSearch indices healed" "adhesive_bandage" "high" \
      "Cleared read-only blocks on $blocked indices after a disk-pressure episode on $(hostname). Disk now ${pct}%. Log ingest resumes; investigate what filled the disk (host-hygiene.log has the sweep record)."
  else
    push "NetOps: OpenSearch heal FAILED" "rotating_light" "high" \
      "$blocked indices remain read-only on $(hostname) and the unblock call failed — log ingest is dead until cleared by hand."
  fi
}

# ── cache sweeps ──────────────────────────────────────────────────────────────
truncate_big_container_logs() {
  # json-file logs are outside Docker's prune surface and unbounded by default.
  # Truncation loses `docker logs` history only — never container state.
  local dir="/var/lib/docker/containers"
  [ -r "$dir" ] || { echo "   (container logs not readable without sudo — skipped)"; return 0; }
  find "$dir" -name '*-json.log' -size +"${LOG_MAX_MB}"M 2>/dev/null | while read -r f; do
    echo "   truncating $(du -h "$f" | cut -f1) $f"
    : > "$f" 2>/dev/null || echo "   (no permission to truncate $f)"
  done
}

# reclaim runs one cleanup command and REPORTS what happened. It is the opposite
# of `cmd >/dev/null 2>&1 || true`, which is how this script used to hide a
# command-not-found and report "91% -> 91%" every ten minutes while reclaiming
# nothing. Three failure modes are now distinct and none is silent:
#
#   - tool missing  → WARN naming the tool (the go-on-cron-PATH bug that let the
#                     disk reach 91% unnoticed)
#   - command fails → WARN with the tool's own stderr, and a non-zero tally so
#                     the caller can alert
#   - command works → the bytes it reclaimed, measured, not assumed
#
# $1 label, $2 path whose freed bytes to measure (or ""), $3.. the command.
RECLAIM_FAILURES=0
reclaim() {
  local label="$1" measure="$2"; shift 2
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "   WARN: $label skipped — '$tool' not on PATH ($PATH). Cache NOT reclaimed."
    RECLAIM_FAILURES=$((RECLAIM_FAILURES + 1))
    return 1
  fi
  local before=0 after=0 err rc
  [ -n "$measure" ] && before=$(du -sb "$measure" 2>/dev/null | cut -f1 || echo 0)
  # Capture stderr so a real failure is REPORTED with its cause, not discarded.
  err=$("$@" 2>&1 >/dev/null); rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "   WARN: $label failed (rc=$rc): ${err:0:200}"
    RECLAIM_FAILURES=$((RECLAIM_FAILURES + 1))
    return 1
  fi
  if [ -n "$measure" ]; then
    after=$(du -sb "$measure" 2>/dev/null | cut -f1 || echo 0)
    local freed=$(( before - after ))
    [ "$freed" -lt 0 ] && freed=0
    echo "   $label: reclaimed $(numfmt --to=iec "$freed" 2>/dev/null || echo "${freed}B") (was $(numfmt --to=iec "$before" 2>/dev/null || echo "${before}B"))"
  else
    echo "   $label: ok"
  fi
  return 0
}

tier1() {
  echo "-- tier 1: dev caches --"
  reclaim "go build cache" "$HOME/.cache/go-build"           go clean -cache
  reclaim "npm cache"      "$HOME/.npm"                       npm cache clean --force
  reclaim "pip cache"      "$HOME/.cache/pip"                 python3 -m pip cache purge
  reclaim "docker build cache" ""  docker builder prune -f --keep-storage "${KEEP_BUILD_CACHE:-2GB}"
  reclaim "docker dangling images" ""  docker image prune -f
  truncate_big_container_logs
  return 0
}

tier2() {
  echo "-- tier 2 (critical): full docker reclaim --"
  reclaim "docker build cache (full)" "" docker builder prune -af
  reclaim "docker unused images (>72h)" "" docker image prune -af --filter "until=72h"
  reclaim "docker anonymous volumes" "" docker volume prune -f
  return 0
}

status() {
  echo "== host-hygiene status $(date -Is) =="
  echo "disk: $(disk_pct)% used, $(disk_free) free (trigger ${TRIGGER_PCT}% / critical ${CRITICAL_PCT}%)"
  echo "go build cache:  $(du -sh ~/.cache/go-build 2>/dev/null | cut -f1 || echo '—')"
  echo "npm cache:       $(du -sh ~/.npm 2>/dev/null | cut -f1 || echo '—')"
  echo "pip cache:       $(du -sh ~/.cache/pip 2>/dev/null | cut -f1 || echo '—')"
  docker system df 2>/dev/null || true
  local ip; ip=$(os_ip)
  if [ -n "$ip" ]; then
    echo "opensearch read-only indices: $(os_blocked_count "$ip")"
  fi
}

# ── entry ─────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --test)
    push "NetOps host-hygiene test" "test_tube" "default" \
      "Test alert from $(hostname) at $(date -Is). Hygiene alerting works."
    echo "Sent test push to topic '${NTFY_TOPIC:-<unset>}'"
    exit 0 ;;
  --status)
    status
    exit 0 ;;
esac

pct=$(disk_pct)
force=0; [ "${1:-}" = "--force" ] && force=1

# Healing runs on EVERY invocation (cheap: one docker inspect + one GET) —
# blocks can appear from any disk episode, not only ones this script cleaned.
heal_opensearch

if [ "$force" -eq 0 ] && { [ -z "$pct" ] || [ "$pct" -lt "$TRIGGER_PCT" ]; }; then
  # Below threshold: quiet exit. Reset the episode marker so the NEXT crossing
  # alerts again (one push per episode, not one per 10-minute run).
  [ -f "$STATE_FILE" ] && rm -f "$STATE_FILE"
  exit 0
fi

echo "== host-hygiene sweep $(date -Is) — disk ${pct:-?}% =="
before_pct="$pct"; before_free=$(disk_free)

tier1
pct=$(disk_pct)
if [ "${pct:-0}" -ge "$CRITICAL_PCT" ]; then
  tier2
  pct=$(disk_pct)
fi

# space may have been what kept OS blocked — try healing again post-sweep.
heal_opensearch

echo "== done: ${before_pct}% -> ${pct}% ($(disk_free) free), reclaim_failures=${RECLAIM_FAILURES} =="

# A sweep that reclaimed NOTHING while still over threshold is the failure this
# script was blind to for weeks: it ran, swallowed a command-not-found, and
# reported "91% -> 91%" as if healthy. That is now an explicit, alerting
# condition — a hygiene job that cannot clean must be as loud as a full disk.
if [ "$RECLAIM_FAILURES" -gt 0 ] && [ "${pct:-0}" -ge "$TRIGGER_PCT" ]; then
  push "NetOps: host hygiene DEGRADED" "warning" "high" \
    "$RECLAIM_FAILURES cleanup step(s) failed on $(hostname) and disk is still ${pct}% — the sweeper is not reclaiming. Check host-hygiene.log for the WARN lines (likely a tool not on cron PATH)."
fi

# one push per episode: only when this run CROSSED the threshold (no state file).
if [ ! -f "$STATE_FILE" ] && [ "$force" -eq 0 ]; then
  date -Is > "$STATE_FILE"
  push "NetOps: host hygiene triggered" "broom" "high" \
    "Disk hit ${before_pct}% on $(hostname) (${before_free} free). Swept dev caches + docker debris: now ${pct}% ($(disk_free) free). If this recurs, something is filling the disk faster than caches explain — check host-hygiene.log."
fi

# Non-zero exit when the sweep could not do its job, so a supervisor/CI or a
# `set -e` caller treats a broken sweeper as the failure it is.
[ "$RECLAIM_FAILURES" -gt 0 ] && [ "${pct:-0}" -ge "$TRIGGER_PCT" ] && exit 1
exit 0
