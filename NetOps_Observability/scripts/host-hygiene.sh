#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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

# ---------------------------------------------------------------------------
# 2026-09-03 — THE HEALING HAS NEVER WORKED ON A TLS INSTALL.
#
# Every call below used to be a bare `http://$ip:9200/...`. This deployment runs
# OpenSearch with the security plugin and HTTPS on 9200, so each one hit the TLS
# listener with a plaintext HTTP request: OpenSearch logged NotSslRecordException
# (that spam is ~90% of a 1.1 GiB container log — the healer was the thing
# filling the disk it exists to protect), curl failed, and `-fsS ... 2>/dev/null
# | grep -o ... | wc -l` turned the failure into the number **0**. So
# heal_opensearch reported "no blocked indices" and returned — i.e. the
# flood-stage healing this whole script exists for has never once run on a
# secured install. Textbook §16.1: the probe failed and the script reported
# health.
#
# Two fixes, and the second is the one that matters:
#   1. Speak the right protocol. Try https with the internal CA and the ADMIN
#      client certificate (data/tls/admin — the superadmin DN; clearing an
#      index block is a cluster-admin write), fall back to plaintext only if
#      that is genuinely what the node speaks.
#   2. A failed probe is a NAMED WARN carrying curl's own error, never a 0.
#      "I could not ask" and "the answer is none" are different facts.
#
# --resolve, never -k: the issued SAN set is `DNS:opensearch` plus a SPIFFE URI
# and NO IP address, so https://<container-ip> cannot pass hostname
# verification. Pinning the NAME to the container's address keeps full
# verification; -k would convert a real MITM or a misissued cert into a silent
# pass, which is the same swallow in a different costume.
# ---------------------------------------------------------------------------
OS_TLS_DIR="${HYGIENE_TLS_DIR:-$SCRIPT_DIR/../data/tls}"
OS_URL=""
OS_CURL_ARGS=()
OS_PROBE_ERR=""
OS_BLOCKED=""
OS_BLOCKED_ERR=""
OS_PROBE_STATE="$SCRIPT_DIR/.host-hygiene.osprobe.state"

# os_probe_setup <container-ip> — decide the scheme ONCE per run from evidence.
# Sets OS_URL + OS_CURL_ARGS on success; sets OS_PROBE_ERR and returns 1 when
# neither scheme answers, so the caller can report WHY rather than assume.
os_probe_setup() {
  local ip="$1" out rc ca crt key tls_err http_err
  OS_URL=""; OS_CURL_ARGS=(); OS_PROBE_ERR=""
  ca="$OS_TLS_DIR/ca.pem"
  [ -r "$ca" ] || ca="$OS_TLS_DIR/admin/ca.pem"
  crt="$OS_TLS_DIR/admin/admin.crt"
  key="$OS_TLS_DIR/admin/admin.key"
  if [ -r "$ca" ] && [ -r "$crt" ] && [ -r "$key" ]; then
    # stderr KEPT (§16.1): curl's own message is the evidence.
    out=$(curl -sS -m 10 --cacert "$ca" --cert "$crt" --key "$key" \
            --resolve "opensearch:9200:$ip" \
            "https://opensearch:9200/_cluster/health" 2>&1)
    rc=$?   # OWN LINE — inside `if ! out=$(...)` this would be the if's status.
    if [ "$rc" -eq 0 ]; then
      OS_URL="https://opensearch:9200"
      OS_CURL_ARGS=(--cacert "$ca" --cert "$crt" --key "$key"
                    --resolve "opensearch:9200:$ip")
      return 0
    fi
    tls_err="https probe failed (curl rc=$rc): $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
  else
    tls_err="https not attempted — TLS material unreadable (need $ca, $crt, $key)"
  fi
  # Plaintext fallback: correct for a non-TLS install, and deliberately SECOND
  # so a secured node is never poked with a plaintext request (that is what
  # produced the NotSslRecordException flood).
  out=$(curl -sS -m 10 "http://$ip:9200/_cluster/health" 2>&1)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    OS_URL="http://$ip:9200"
    OS_CURL_ARGS=()
    return 0
  fi
  http_err="http probe failed (curl rc=$rc): $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
  OS_PROBE_ERR="$tls_err ;; $http_err"
  return 1
}

# os_blocked_count — sets OS_BLOCKED to the count and returns 0, or returns 1
# with the cause in OS_BLOCKED_ERR. It must never yield 0 for a question it
# could not ask.
#
# The result comes back in a GLOBAL, not on stdout, on purpose: `n=$(fn)` runs
# the function in a SUBSHELL, and a subshell cannot export OS_BLOCKED_ERR back
# to its caller — the error would vanish and the caller would fall through as
# though nothing had failed, which is precisely the swallow this whole change
# removes. (Caught by the unit test, not by review.)
os_blocked_count() {
  local out rc
  OS_BLOCKED_ERR=""; OS_BLOCKED=""
  if [ -z "$OS_URL" ]; then
    OS_BLOCKED_ERR="no OpenSearch endpoint resolved (os_probe_setup not run or failed)"
    return 1
  fi
  out=$(curl -sS -m 10 "${OS_CURL_ARGS[@]+"${OS_CURL_ARGS[@]}"}" \
          "$OS_URL/_all/_settings/index.blocks.read_only_allow_delete" 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    OS_BLOCKED_ERR="curl rc=$rc: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
    return 1
  fi
  # A 401/403/exception body is a 200-shaped failure: curl exits 0, `grep -o`
  # finds nothing, and the old code called that "0 blocked".
  case "$out" in
    *security_exception*|*NotSslRecordException*|*'"status":40'*|*'"status":50'*)
      OS_BLOCKED_ERR="OpenSearch refused the query: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
      return 1 ;;
  esac
  OS_BLOCKED=$(printf '%s' "$out" | grep -o 'read_only_allow_delete' | wc -l)
  return 0
}

# One push per TRANSITION into (and out of) a broken probe — a 10-minute cron
# that pushed every run would be muted within the hour, and a muted alert is
# how the original bug survived. The log line is emitted every run regardless.
os_probe_failure_transition() {  # $1 = current state: ok|failed
  local prev
  prev=$(cat "$OS_PROBE_STATE" 2>/dev/null || echo "ok")
  [ "$prev" = "$1" ] && return 1
  printf '%s\n' "$1" > "$OS_PROBE_STATE" 2>/dev/null ||
    echo "   WARN: could not persist $OS_PROBE_STATE — probe-state transitions will re-alert" >&2
  return 0
}

heal_opensearch() {
  local pct ip blocked
  pct=$(disk_pct)
  [ -n "$pct" ] && [ "$pct" -lt "$FLOOD_CLEAR_PCT" ] || return 0  # never unlock while disk is still hot
  # No OpenSearch container on this host is not a fault — nothing to heal.
  ip=$(os_ip); [ -n "$ip" ] || return 0
  if ! os_probe_setup "$ip"; then
    # NAMED, with curl's own error. Counted as a reclaim failure so the run
    # exits non-zero and the existing degraded push covers a sweep that could
    # not do its job (§16.1) — the healer being blind is exactly as serious as
    # the flood stage it heals.
    echo "   WARN: OPENSEARCH_PROBE_FAILED — flood-stage read-only healing did NOT run and the number of blocked indices is UNKNOWN (not zero). $OS_PROBE_ERR"
    RECLAIM_FAILURES=$((RECLAIM_FAILURES + 1))
    if os_probe_failure_transition failed; then
      push "NetOps: OpenSearch heal probe FAILED" "warning" "high" \
        "host-hygiene cannot reach OpenSearch on $(hostname), so flood-stage read-only healing is OFF and the blocked-index count is UNKNOWN. If ingest stops after a disk episode this is why. Detail: $OS_PROBE_ERR"
    fi
    return 1
  fi
  # Recovery: record "ok" so the NEXT failure alerts again. The non-zero return
  # here means "no transition" (we were already ok), which is the normal path —
  # it is a value, not an error, so there is nothing to report. This is NOT a
  # `|| true` swallow: os_probe_failure_transition reports its own write failure
  # on stderr and has no other failure mode.
  if os_probe_failure_transition ok; then :; fi
  if ! os_blocked_count; then
    echo "   WARN: OPENSEARCH_BLOCK_QUERY_FAILED — cannot tell whether any index is read-only (this is UNKNOWN, not zero). $OS_BLOCKED_ERR"
    RECLAIM_FAILURES=$((RECLAIM_FAILURES + 1))
    return 1
  fi
  blocked="$OS_BLOCKED"
  [ "$blocked" -gt 0 ] || return 0
  echo "-- healing: clearing read_only_allow_delete on $blocked indices (disk ${pct}%) --"
  if curl -fsS -m 30 "${OS_CURL_ARGS[@]+"${OS_CURL_ARGS[@]}"}" \
       -X PUT "$OS_URL/_all/_settings" \
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
  if [ -z "$ip" ]; then
    echo "opensearch: no netops-opensearch-1 container — nothing to heal"
  elif ! os_probe_setup "$ip"; then
    # --status must report UNKNOWN, not a comfortable 0. This line is what
    # would have shown, in one command, that the healer had been blind for
    # months on this TLS install.
    echo "opensearch read-only indices: UNKNOWN — probe failed: $OS_PROBE_ERR"
  else
    if os_blocked_count; then
      echo "opensearch read-only indices: $OS_BLOCKED (via $OS_URL)"
    else
      echo "opensearch read-only indices: UNKNOWN — query failed: $OS_BLOCKED_ERR"
    fi
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
