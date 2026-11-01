#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# cx-lane-watch.sh — self-heal for a Kafka lane that is JOINED but not CONSUMING.
#
# THE INCIDENT (lab, 2026-10-30 08:07Z → found 2026-10-31 14:30Z, ~30 h):
# during a disk-flood event the router process stalled long enough that the
# broker expired the heartbeat of EVERY netops-router-* member at once
# (08:07:38, "removing member ... on heartbeat expiration"). All ten lanes
# rejoined within 12 s. Seven resumed. Three — applogs, flows, snmptrap, the
# lanes that had unacknowledged events in flight towards a sink that was
# retrying (OpenSearch flood-stage 429s) — came back as a group member that
# owns its partitions and never hands another message to the pipeline:
#   * the broker sees one member, a stable generation, no further rebalances;
#   * the committed offset never moves again (lag reached 35 M on applogs);
#   * vector_component_received_events_total for the source stays flat;
#   * the applogs client issued ~200 requests per 10 min (heartbeats only,
#     its prefetch queue full and unread) while every other consumer in the
#     same process issued ~5,900; the flows client kept fetching
#     (librdkafka counted messages consumed) yet the source emitted nothing.
# That is Vector's kafka source (0.40, unchanged on upstream master) losing
# the per-partition consumer task across a revoke→assign that lands while it
# is still draining acknowledgements. Nothing recovers it in-process, the
# container stays `healthy` (/health is process-level), and the alerts that
# DID fire (KafkaConsumerStalled, RouterConsumerLagGrowing) have no actor.
#
# WHAT THIS DOES. Runs beside vector (started by cx-enrichment-reload.sh when
# CX_LANE_WATCH=1), reads vector's OWN Prometheus exporter once per poll, and
# for every kafka SOURCE compares two series vector already exports:
#   * vector_kafka_consumer_lag (needs `metrics.topic_lag_metric: true` on the
#     source) — summed over the source's partitions, negatives (= unknown)
#     ignored;
#   * vector_component_received_events_total — summed over partitions.
# A source is WEDGED when its lag is > 0 and its received counter has not moved
# for CX_LANE_WATCH_STRIKES consecutive polls, while NO sink buffer is at or
# above CX_LANE_WATCH_BACKPRESSURE_PCT of its capacity. The back-pressure
# exclusion is what separates the bug from a storage outage: a source blocked
# by a full sink buffer is doing its job (Kafka is the buffer, #209), and a
# restart would not help it. A healthy source with lag > 0 and no back-pressure
# ALWAYS receives events, so "lag > 0, nothing received, nothing full" has no
# benign reading.
#
# On a wedge it logs one loud line per wedged source, sends vector SIGTERM
# (graceful: acknowledged offsets are committed on the way down) and exits 75.
# The wrapper turns that into container exit 75 + an explicit log line, the
# restart policy brings a fresh consumer back, and the lane resumes from its
# last COMMITTED offset — with end-to-end acknowledgements on (router F-04),
# nothing that was not durably written is skipped. The restart is itself
# visible: the container RestartCount bump is pushed by stack-watchdog.sh with
# the last log line, which is this script's reason.
#
# Usage:
#   cx-lane-watch.sh --watch <vector-pid>   loop until vector exits (wrapper)
#   cx-lane-watch.sh --evaluate <state>     ONE evaluation: exporter text on
#                                           stdin, result lines on stdout
#                                           (the unit-test seam)
# --evaluate output lines:
#   STATE <src>:<received>:<strikes>,...    carry into the next evaluation
#   WEDGED <src> lag=<n> received=<n> strikes=<k>
#   BACKPRESSURE <sink> <events>/<max>       (wedge suppressed this poll)
#
# Runs under busybox ash in the timberio/vector alpine image (wget, awk, kill
# are busybox applets). §16: every external call is bounded (wget -T), no error
# is swallowed (fetch failures are logged on transition), config is validated.
set -eu

POLL="${CX_LANE_WATCH_POLL_SECONDS:-60}"
STRIKES="${CX_LANE_WATCH_STRIKES:-5}"
BP_PCT="${CX_LANE_WATCH_BACKPRESSURE_PCT:-90}"
URL="${CX_LANE_WATCH_METRICS_URL:-http://127.0.0.1:9598/metrics}"
FETCH_TIMEOUT="${CX_LANE_WATCH_FETCH_TIMEOUT_SECONDS:-10}"

# Exit status that tells the wrapper "I stopped vector on purpose".
HEAL_STATUS=75

say() { echo "cx-lane-watch: $*" >&2; }

is_posint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        0) return 1 ;;
        *) return 0 ;;
    esac
}

validate_config() {
    for pair in "CX_LANE_WATCH_POLL_SECONDS=$POLL" "CX_LANE_WATCH_STRIKES=$STRIKES" \
                "CX_LANE_WATCH_BACKPRESSURE_PCT=$BP_PCT" \
                "CX_LANE_WATCH_FETCH_TIMEOUT_SECONDS=$FETCH_TIMEOUT"; do
        if ! is_posint "${pair#*=}"; then
            say "INVALID CONFIG ${pair%%=*}='${pair#*=}' (want a positive integer) — lane watch NOT running; a wedged kafka lane will not self-heal"
            return 1
        fi
    done
    if [ "$BP_PCT" -gt 100 ]; then
        say "INVALID CONFIG CX_LANE_WATCH_BACKPRESSURE_PCT=$BP_PCT (> 100) — lane watch NOT running"
        return 1
    fi
    return 0
}

# evaluate <prev-state> — exporter text on stdin.
evaluate() {
    awk -v prev="$1" -v strikes_max="$STRIKES" -v bp_pct="$BP_PCT" '
    function label(s, key,    re, v) {
        re = key "=\"[^\"]*\""
        if (match(s, re) == 0) return ""
        v = substr(s, RSTART + length(key) + 2, RLENGTH - length(key) - 3)
        return v
    }
    BEGIN {
        n = split(prev, ent, ",")
        for (i = 1; i <= n; i++) {
            if (split(ent[i], f, ":") == 3 && f[1] != "") {
                had[f[1]] = 1; precv[f[1]] = f[2] + 0; pstr[f[1]] = f[3] + 0
            }
        }
    }
    /^#/ || NF < 2 { next }
    {
        # "name{labels} value [timestamp]" — labels never contain spaces in
        # vector exporter output for the series read here.
        name = $1; sub(/\{.*/, "", name)
        val = $2 + 0
        cid = label($1, "component_id")
        if (cid == "") next
        if (name == "vector_component_received_events_total" &&
            label($1, "component_kind") == "source" &&
            label($1, "component_type") == "kafka") {
            src[cid] = 1; recv[cid] += val
        } else if (name == "vector_kafka_consumer_lag" &&
                   label($1, "component_kind") == "source") {
            src[cid] = 1
            if (val > 0) lag[cid] += val
        } else if (name == "vector_buffer_events" &&
                   label($1, "component_kind") == "sink") {
            bev[cid "|" label($1, "stage")] = val
        } else if (name == "vector_buffer_max_event_size" &&
                   label($1, "component_kind") == "sink") {
            bmax[cid "|" label($1, "stage")] = val
        }
    }
    END {
        bp = 0
        for (k in bmax) {
            if (bmax[k] > 0 && (k in bev) && bev[k] * 100 >= bmax[k] * bp_pct) {
                split(k, kk, "|")
                printf "BACKPRESSURE %s %.0f/%.0f\n", kk[1], bev[k], bmax[k]
                bp = 1
            }
        }
        state = ""
        for (c in src) {
            r = (c in recv) ? recv[c] : 0
            l = (c in lag) ? lag[c] : 0
            s = 0
            if (l > 0 && (c in had) && r == precv[c] && !bp) s = pstr[c] + 1
            if (s >= strikes_max)
                printf "WEDGED %s lag=%.0f received=%.0f strikes=%d\n", c, l, r, s
            # NB: never write `state (...)` here — busybox awk parses an
            # identifier followed by "(" as a FUNCTION CALL (undefined).
            sep = ","
            if (state == "") sep = ""
            state = state sep c ":" sprintf("%.0f", r) ":" s
        }
        print "STATE " state
    }'
}

fetch_metrics() {
    # busybox wget: -T bounds the whole transfer; -q quiet; -O - to stdout.
    wget -q -T "$FETCH_TIMEOUT" -O - "$URL"
}

watch_loop() {
    vpid="$1"
    validate_config || exit 64
    say "watching kafka sources of vector pid ${vpid} (poll ${POLL}s, wedge after ${STRIKES} flat polls with lag>0, back-pressure gate ${BP_PCT}%)"
    state=""
    fetch_failing=0
    while kill -0 "$vpid" 2>/dev/null; do
        sleep "$POLL"
        kill -0 "$vpid" 2>/dev/null || break
        if ! body="$(fetch_metrics 2>&1)"; then
            # §16.1: report, do not swallow. Log on the transition only, so a
            # vector that is still starting does not spam once a minute.
            if [ "$fetch_failing" -eq 0 ]; then
                say "cannot read ${URL} (${body:-no output}) — lane checks paused until it answers"
                fetch_failing=1
            fi
            continue
        fi
        if [ "$fetch_failing" -eq 1 ]; then
            say "${URL} answering again — lane checks resumed"
            fetch_failing=0
        fi
        result="$(printf '%s\n' "$body" | evaluate "$state")"
        state="$(printf '%s\n' "$result" | awk '/^STATE /{print $2}')"
        wedged="$(printf '%s\n' "$result" | awk '/^WEDGED /')"
        if [ -n "$wedged" ]; then
            printf '%s\n' "$wedged" | while IFS= read -r line; do
                say "LANE WEDGED: ${line#WEDGED } — kafka source holds its partitions (lag > 0) but has delivered nothing for ${STRIKES} polls (~$((POLL * STRIKES))s) with no sink back-pressure. Restarting vector so the consumer rejoins and resumes from its last committed offset (acknowledgements on: nothing unwritten is skipped)."
            done
            if ! kill -TERM "$vpid" 2>/dev/null; then
                say "vector pid ${vpid} already gone before the heal signal"
            fi
            exit "$HEAL_STATUS"
        fi
    done
    exit 0
}

case "${1:-}" in
    --watch)
        [ -n "${2:-}" ] || { say "usage: $0 --watch <vector-pid>"; exit 64; }
        watch_loop "$2"
        ;;
    --evaluate)
        validate_config || exit 64
        evaluate "${2:-}"
        ;;
    *)
        say "usage: $0 --watch <vector-pid> | --evaluate <state>"
        exit 64
        ;;
esac
