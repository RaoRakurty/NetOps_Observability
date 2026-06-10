#!/usr/bin/env bash
# =============================================================================
# pipeline-watchdog.sh — telemetry-FLOW watchdog + auto-heal for the ingest
# pipeline (companion to stack-watchdog.sh, which only checks container health).
#
# It catches the failure class that bit us on 2026-06-10: a Vector sink wedged
# after a transient docker-DNS blip (during a downstream restart). The Kafka
# CONSUMER kept advancing — so "container up" and "lag 0" both looked fine —
# while the sink silently stopped writing to OpenSearch for hours.
#
# The reliable signal for that is per-stream: INPUT is advancing (the Redpanda
# topic high-watermark grew) but OUTPUT is stale (no fresh docs in the store).
# That combination = a wedged consumer/sink, so we restart vector-router. A
# stream that is simply quiet (no input) is NOT flagged — input must be moving.
#
#   ./pipeline-watchdog.sh            # one check (for cron: * * * * *)
#   ./pipeline-watchdog.sh --loop 60  # self-paced loop, 60s interval
#   ./pipeline-watchdog.sh --dry-run  # detect + log, never restart
#
# Heal fires only after STALE_STRIKES consecutive bad checks (default 3) and
# then holds off for COOLDOWN_SECS so a restart gets time to drain the backlog.
# Config overrides live in pipeline-watchdog.env next to this script.
# =============================================================================
set -uo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${PIPELINE_WATCHDOG_ENV:-$SCRIPT_DIR/pipeline-watchdog.env}"
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

# ---- tunables (override in pipeline-watchdog.env) ---------------------------
STALE_SECS="${STALE_SECS:-600}"          # output considered stale after this
STALE_STRIKES="${STALE_STRIKES:-3}"      # consecutive bad checks before heal
COOLDOWN_SECS="${COOLDOWN_SECS:-600}"    # min seconds between heals
STATE_FILE="${STATE_FILE:-/tmp/pipeline-watchdog.state}"
COMPOSE_DIR="${COMPOSE_DIR:-$SCRIPT_DIR/../deployment/docker}"
OS_CONTAINER="${OS_CONTAINER:-netops-opensearch-1}"
RP_CONTAINER="${RP_CONTAINER:-netops-redpanda-1}"
HEAL_TARGET="${HEAL_TARGET:-vector-router}"
NTFY_TOPIC="${NTFY_TOPIC:-}"             # optional phone push on heal
DRY_RUN=0; LOOP=0

while [ $# -gt 0 ]; do case "$1" in
  --loop) LOOP="${2:?}"; shift 2;;
  --dry-run) DRY_RUN=1; shift;;
  -h|--help) sed -n '2,33p' "$0"; exit 0;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done

log(){ echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Streams to watch: "name redpanda_topic os_index_glob"
STREAMS=(
  "syslog   netops.syslog   netops-syslog-*"
  "flows    netops.flows    netops-flows-*"
  "applogs  netops.applogs  netops-applogs-*"
  "snmptrap netops.snmptrap netops-snmptrap-*"
)

# topic_hwm <topic> -> sum of partition high-watermarks (input progress marker)
topic_hwm(){
  docker exec "$RP_CONTAINER" rpk topic describe "$1" -p 2>/dev/null \
    | awk 'NR>1{s+=$NF} END{print s+0}'
}

# os_age_secs <index_glob> -> seconds since the newest doc (huge if none/error)
os_age_secs(){
  local body
  body=$(docker exec "$OS_CONTAINER" curl -s \
    "http://127.0.0.1:9200/$1/_search" -H 'Content-Type: application/json' \
    -d '{"size":1,"sort":[{"timestamp":"desc"}],"_source":["timestamp"]}' 2>/dev/null)
  printf '%s' "$body" | python3 -c '
import json,sys,calendar,time
try:
    d=json.load(sys.stdin); h=d.get("hits",{}).get("hits",[])
    if not h: print(10**9); sys.exit()
    ts=h[0]["_source"]["timestamp"].replace("Z","+0000")
    import datetime
    t=datetime.datetime.strptime(ts[:19],"%Y-%m-%dT%H:%M:%S")
    print(int(time.time()-calendar.timegm(t.timetuple())))
except Exception:
    print(10**9)
' 2>/dev/null || echo 1000000000
}

# state file: "stream last_hwm strikes" per line; plus "_lastheal <epoch>"
read_state(){ grep -E "^$1 " "$STATE_FILE" 2>/dev/null | tail -1; }
now(){ date +%s; }

heal(){
  local reason="$1"
  log "HEAL: restarting $HEAL_TARGET — $reason"
  if [ "$DRY_RUN" = 1 ]; then log "(dry-run, not restarting)"; return; fi
  ( cd "$COMPOSE_DIR" && docker compose restart "$HEAL_TARGET" ) >/dev/null 2>&1 \
    && log "HEAL: $HEAL_TARGET restarted" || log "HEAL: restart FAILED"
  [ -n "$NTFY_TOPIC" ] && curl -fsS -m 8 -d "pipeline-watchdog healed: $reason" \
    "https://ntfy.sh/${NTFY_TOPIC}" >/dev/null 2>&1 || true
}

check_once(){
  touch "$STATE_FILE"
  local last_heal; last_heal=$(read_state _lastheal | awk '{print $2}'); last_heal=${last_heal:-0}
  local wedged=""
  local newstate; newstate=$(grep -vE '^(_lastheal|[^ ]+ )' "$STATE_FILE" 2>/dev/null || true)
  # rebuild state fresh each run
  : > "$STATE_FILE.tmp"
  echo "_lastheal $last_heal" >> "$STATE_FILE.tmp"

  local line name topic glob hwm age prev prev_hwm strikes
  for line in "${STREAMS[@]}"; do
    read -r name topic glob <<<"$line"
    hwm=$(topic_hwm "$topic"); hwm=${hwm:-0}
    age=$(os_age_secs "$glob"); age=${age:-1000000000}
    prev=$(read_state "$name"); prev_hwm=$(awk '{print $2}' <<<"$prev"); strikes=$(awk '{print $3}' <<<"$prev")
    prev_hwm=${prev_hwm:-$hwm}; strikes=${strikes:-0}

    local advancing=0; [ "$hwm" -gt "$prev_hwm" ] && advancing=1
    local stale=0; [ "$age" -gt "$STALE_SECS" ] && stale=1

    if [ "$advancing" = 1 ] && [ "$stale" = 1 ]; then
      strikes=$((strikes+1))
      log "WARN $name: input advancing (hwm ${prev_hwm}->${hwm}) but output stale (${age}s) — strike ${strikes}/${STALE_STRIKES}"
      [ "$strikes" -ge "$STALE_STRIKES" ] && wedged="${wedged}${name}(${age}s) "
    else
      [ "$strikes" -ne 0 ] && log "OK   $name: recovered (advancing=$advancing stale=$stale age=${age}s)"
      strikes=0
    fi
    echo "$name $hwm $strikes" >> "$STATE_FILE.tmp"
  done
  mv "$STATE_FILE.tmp" "$STATE_FILE"

  if [ -n "$wedged" ]; then
    local since=$(( $(now) - last_heal ))
    if [ "$since" -lt "$COOLDOWN_SECS" ]; then
      log "WEDGED [$wedged] but in cooldown (${since}s < ${COOLDOWN_SECS}s) — not restarting yet"
    else
      heal "wedged streams: $wedged"
      # reset strikes + record heal time
      sed -i 's/\( [0-9]*\)$/ 0/' "$STATE_FILE" 2>/dev/null || true
      grep -v '^_lastheal' "$STATE_FILE" > "$STATE_FILE.tmp" 2>/dev/null || true
      echo "_lastheal $(now)" >> "$STATE_FILE.tmp"; mv "$STATE_FILE.tmp" "$STATE_FILE"
    fi
  fi
}

if [ "$LOOP" -gt 0 ] 2>/dev/null; then
  log "pipeline-watchdog loop every ${LOOP}s (stale>${STALE_SECS}s, ${STALE_STRIKES} strikes)"
  while :; do check_once; sleep "$LOOP"; done
else
  check_once
fi
