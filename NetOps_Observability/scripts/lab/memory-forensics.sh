#!/usr/bin/env bash
# External memory/pressure sampler for a correlation diagnostic run.
#
# WHY IT IS EXTERNAL. The in-process diagnostics cannot report during the very
# event they exist to explain: a 112-second event-loop stall stops the service
# emitting anything, so the stall looks like a GAP in the data rather than a
# stall. This sampler runs on the host, reads the kernel's own accounting, and
# keeps producing rows while the container is wedged. Anything derived from the
# correlation event loop is a second opinion here, never the only one.
#
# Emits one JSON object per container per interval on stdout (NDJSON).
#
# §16.1: a field whose source could not be read is emitted as "__unreadable__"
# or "__absent__", never as 0 — a sampler that reports a healthy-looking zero
# for a file it could not open is exactly the false-green class this programme
# keeps finding.
#
# Usage: memory-forensics.sh <container> [container...] [--interval SECONDS]
set -Eeuo pipefail

# §16.2: cron/minimal environments do not have a useful PATH.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

DOCKER_TIMEOUT="${MEMFOR_DOCKER_TIMEOUT:-10}"
INTERVAL="${MEMFOR_INTERVAL:-5}"
CONTAINERS=()

usage() { sed -n '2,19p' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --interval) INTERVAL="${2:?--interval needs a value}"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    -*)         echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)          CONTAINERS+=("$1"); shift ;;
  esac
done

if [ "${#CONTAINERS[@]}" -eq 0 ]; then
  echo "usage: $0 <container> [container...] [--interval S]" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "memory-forensics: docker not found on PATH ($PATH) — cannot sample" >&2
  exit 3
fi

# Read a cgroup/proc file, distinguishing "not there" from "could not read".
read_or_absent() {
  local f="$1"
  if [ ! -e "$f" ]; then printf '__absent__'; return 0; fi
  if [ ! -r "$f" ]; then printf '__unreadable__'; return 0; fi
  cat -- "$f" 2>/dev/null || printf '__unreadable__'
}

json_escape() { printf '%s' "$1" | tr -d '\000' | sed 's/\\/\\\\/g; s/"/\\"/g'; }

readable() { [ "$1" != "__absent__" ] && [ "$1" != "__unreadable__" ]; }

# flat-keyed cgroup file ("key value" per line) -> JSON object body
kv_to_json() {
  awk 'NF>=2 {printf "%s\"%s\":%s", (NR>1?",":""), $1, ($2 ~ /^-?[0-9]+$/ ? $2 : "\"" $2 "\"")}'
}

# PSI ("some avg10=0.00 avg60=0.00 avg300=0.00 total=0") -> JSON object body
psi_to_json() {
  awk '{ pre=$1
         for (i=2;i<=NF;i++) { split($i,kv,"=")
           printf "%s\"%s_%s\":%s", (out++?",":""), pre, kv[1], kv[2] } }'
}

dk() { timeout "$DOCKER_TIMEOUT" docker "$@"; }

while true; do
  TS="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  for NAME in "${CONTAINERS[@]}"; do
    if ! CID="$(dk inspect -f '{{.Id}}' "$NAME" 2>/dev/null)" || [ -z "$CID" ]; then
      printf '{"ts":"%s","container":"%s","state":"absent_or_unreachable"}\n' \
        "$TS" "$(json_escape "$NAME")"
      continue
    fi
    STATE="$(dk inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null || printf 'unknown')"
    RESTARTS="$(dk inspect -f '{{.RestartCount}}' "$NAME" 2>/dev/null || printf -- '-1')"
    PID="$(dk inspect -f '{{.State.Pid}}' "$NAME" 2>/dev/null || printf '0')"

    BASE="/sys/fs/cgroup/system.slice/docker-${CID}.scope"
    [ -d "$BASE" ] || BASE="/sys/fs/cgroup/docker/${CID}"

    CUR="$(read_or_absent "$BASE/memory.current")"
    MAX="$(read_or_absent "$BASE/memory.max")"
    HIGH="$(read_or_absent "$BASE/memory.high")"
    SWAPC="$(read_or_absent "$BASE/memory.swap.current")"
    EV="$(read_or_absent "$BASE/memory.events")"
    EVL="$(read_or_absent "$BASE/memory.events.local")"
    PSI="$(read_or_absent "$BASE/memory.pressure")"
    CPSI="$(read_or_absent "$BASE/cpu.pressure")"
    MSTAT="$(read_or_absent "$BASE/memory.stat")"

    EV_J=""; EVL_J=""; PSI_J=""; CPSI_J=""; STAT_J=""
    readable "$EV"   && EV_J="$(printf '%s\n' "$EV"   | kv_to_json)"
    readable "$EVL"  && EVL_J="$(printf '%s\n' "$EVL" | kv_to_json)"
    readable "$PSI"  && PSI_J="$(printf '%s\n' "$PSI" | psi_to_json)"
    readable "$CPSI" && CPSI_J="$(printf '%s\n' "$CPSI" | psi_to_json)"
    if readable "$MSTAT"; then
      # The whole file is noise; these keys carry the story (anon vs file
      # residency, reclaim activity, refaults).
      STAT_J="$(printf '%s\n' "$MSTAT" | grep -E '^(anon|file|slab|kernel_stack|sock|shmem|anon_thp|pgfault|pgmajfault|pgscan|pgsteal|workingset_refault_anon|workingset_refault_file) ' | kv_to_json || printf '')"
    fi

    # Process RSS. Host /proc/<pid> is only readable as root, so record WHICH
    # source answered: a 0 that silently means "could not read" is precisely the
    # false-green this sampler exists to avoid.
    RSS="__unreadable__"; RSS_SRC="none"; SMAPS_J=""
    # NOTE: /proc/<pid>/statm is world-READABLE but the kernel reports resident
    # as 0 for a process this uid does not own. A readable file with a hidden
    # value is worse than an unreadable one, so a zero resident is treated as
    # no answer and the cgroup fallback is used instead.
    HOST_RSS=""
    if [ "$PID" != "0" ] && [ -r "/proc/$PID/statm" ]; then
      HOST_RSS="$(awk -v p="$(getconf PAGESIZE)" '$2>0 {print $2*p}' "/proc/$PID/statm" 2>/dev/null || printf '')"
    fi
    if [ -n "$HOST_RSS" ]; then
      RSS="$HOST_RSS"
      RSS_SRC="host_proc"
      if [ -r "/proc/$PID/smaps_rollup" ]; then
        SMAPS_J="$(awk -F: '/^(Rss|Pss|Private_Clean|Private_Dirty|Shared_Clean|Shared_Dirty|Anonymous|Swap):/ {gsub(/[ \tkB]/,"",$2); printf "%s\"smaps_%s\":%d", (out++?",":""), tolower($1), $2*1024}' "/proc/$PID/smaps_rollup" 2>/dev/null || printf '')"
      fi
    else
      # Fallback: anon from memory.stat is the closest cgroup-side equivalent of
      # anonymous RSS, and it stays readable when host /proc is not.
      if readable "$MSTAT"; then
        ANON="$(printf '%s\n' "$MSTAT" | awk '$1=="anon"{print $2; exit}')"
        if [ -n "$ANON" ]; then RSS="$ANON"; RSS_SRC="cgroup_anon"; fi
      fi
    fi

    if [ "$RSS" = "__unreadable__" ]; then RSS_FIELD='"__unreadable__"'; else RSS_FIELD="$RSS"; fi
    printf '{"ts":"%s","container":"%s","state":"%s","restarts":%s,"pid":%s,"rss_bytes":%s,"rss_source":"%s"' \
      "$TS" "$(json_escape "$NAME")" "$STATE" "$RESTARTS" "$PID" "$RSS_FIELD" "$RSS_SRC"
    printf ',"memory_current":"%s","memory_max":"%s","memory_high":"%s","memory_swap_current":"%s"' \
      "$CUR" "$MAX" "$HIGH" "$SWAPC"
    [ -n "$EV_J" ]    && printf ',"memory_events":{%s}' "$EV_J"
    [ -n "$EVL_J" ]   && printf ',"memory_events_local":{%s}' "$EVL_J"
    [ -n "$PSI_J" ]   && printf ',"memory_pressure":{%s}' "$PSI_J"
    [ -n "$CPSI_J" ]  && printf ',"cpu_pressure":{%s}' "$CPSI_J"
    [ -n "$STAT_J" ]  && printf ',"memory_stat":{%s}' "$STAT_J"
    [ -n "$SMAPS_J" ] && printf ',%s' "$SMAPS_J"
    printf '}\n'
  done
  sleep "$INTERVAL"
done
