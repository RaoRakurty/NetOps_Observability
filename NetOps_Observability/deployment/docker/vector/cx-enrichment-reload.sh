#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# cx-enrichment-reload.sh — Vector entrypoint wrapper: reload on enrichment
# change (F-10, tracker #151 step 3).
#
# Vector's --watch-config watches CONFIG files only; enrichment tables
# (device_tenant.csv) are read ONCE at (re)load. A device→tenant assignment
# therefore took effect only at the next container restart — until then that
# device's telemetry landed UNTAGGED (platform-only), and with Sealed Fields
# on, a tenant-guarded seal rule silently did not apply (the F-11 fail-open
# path rides exactly this staleness).
#
# This wrapper is PID 1: it starts vector with the args compose passes
# (compose `command:` arrives as "$@"), then polls the enrichment CSV's
# CONTENT — md5, not mtime, so the truth does not depend on the writer's
# rewrite discipline (the api additionally skips no-op rewrites since F-10) —
# and sends vector SIGHUP on change. Vector's reload is safe here: it
# validates first and keeps the old topology on error, and a reload re-reads
# enrichment tables (proven live on this stack, 2026-08-09 e2e round 2).
#
# Runs under busybox ash in the timberio/vector alpine image (md5sum, cut and
# kill are busybox builtins/applets).
set -eu

CSV="${CX_ENRICHMENT_CSV:-/etc/vector/enrichment/device_tenant.csv}"
POLL="${CX_ENRICHMENT_POLL_SECONDS:-15}"
# The binary is overridable ONLY so tests can run this wrapper against a stub;
# the images ship vector at exactly this path.
VECTOR_BIN="${CX_VECTOR_BIN:-/usr/local/bin/vector}"
HERE="$(dirname "$0")"

# Tracker 373: derive the Docker bridge gateway so the VRL can stamp a sender
# that docker-proxy re-sourced from it (source_masked). Only under
# CX_MASKED_SOURCE_DETECT=docker-bridge (compose sets it): on host networking
# or Kubernetes the default gateway is a real router. The routing table path is
# overridable ONLY for tests. Either outcome is said on stderr, never silent.
bridge_gateway() {
    # /proc/net/route prints the gateway as little-endian hex: 010012AC is
    # 172.18.0.1. The first default route (Destination 00000000) with a
    # non-zero gateway wins.
    hexgw="$(awk 'NR > 1 && $2 == "00000000" && $3 != "00000000" { print $3; exit }' "$1")" || return 1
    case "$hexgw" in
        [0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]) ;;
        *) return 1 ;;
    esac
    printf '%d.%d.%d.%d\n' \
        "0x$(printf '%s' "$hexgw" | cut -c7-8)" "0x$(printf '%s' "$hexgw" | cut -c5-6)" \
        "0x$(printf '%s' "$hexgw" | cut -c3-4)" "0x$(printf '%s' "$hexgw" | cut -c1-2)"
}
if [ "${CX_MASKED_SOURCE_DETECT:-}" = "docker-bridge" ]; then
    ROUTES="${CX_ROUTE_TABLE:-/proc/net/route}"
    if gw="$(bridge_gateway "$ROUTES")" && [ -n "$gw" ]; then
        CX_BRIDGE_GATEWAY="$gw"
        export CX_BRIDGE_GATEWAY
        echo "cx-enrichment-reload: masked-source detection on (bridge gateway ${gw})" >&2
    else
        echo "cx-enrichment-reload: masked-source detection OFF — no default gateway readable in ${ROUTES}" >&2
    fi
fi

"$VECTOR_BIN" "$@" &
VECTOR_PID=$!

# Kafka lane self-heal (2026-10-30 incident, see cx-lane-watch.sh): a kafka
# source can stay JOINED to its consumer group while delivering nothing, and
# nothing in-process recovers it. Opt-in per tier — the router sets
# CX_LANE_WATCH=1 (it owns every kafka source); the aggregator has none.
WATCH_PID=""
if [ "${CX_LANE_WATCH:-0}" = "1" ]; then
    /bin/sh "$HERE/cx-lane-watch.sh" --watch "$VECTOR_PID" &
    WATCH_PID=$!
fi

# We are PID 1 — forward lifecycle signals to vector. `|| true` is safe here
# ONLY because the failure mode is "vector already exited", which the `wait`
# below reports on its own; nothing is swallowed.
trap 'kill -TERM "$VECTOR_PID" 2>/dev/null || true' TERM INT
trap 'kill -HUP "$VECTOR_PID" 2>/dev/null || true' HUP

hash_of() {
    # Prints the content hash, or nothing if the file is momentarily unreadable
    # (the api writes via rename, so a partial read cannot happen; a missing
    # file means the export has not run yet).
    md5sum "$1" 2>/dev/null | cut -d' ' -f1
}

last="$(hash_of "$CSV" || true)"

# Tracker 387 (a): further files a config-load secret backend reads (the
# aggregator's community fingerprint set, served by cx-credfp-set.sh), so a
# change to them reloads vector too — a reload re-runs every secret backend.
# Space-separated absolute paths; unset on the router. Unlike the CSV, a file
# that is ABSENT has a state of its own ("absent"), so its first appearance —
# the api's first publish after the aggregator booted on an empty set — reloads.
EXTRA="${CX_ENRICHMENT_EXTRA:-}"
extra_state() {
    out=''
    for f in $EXTRA; do
        h="$(hash_of "$f" || true)"
        out="${out}${h:-absent};"
    done
    printf '%s' "$out"
}
last_extra="$(extra_state)"
if [ -n "$EXTRA" ]; then
    echo "cx-enrichment-reload: also reloading on changes to: ${EXTRA}" >&2
fi

(
    while kill -0 "$VECTOR_PID" 2>/dev/null; do
        sleep "$POLL"
        if [ -n "$EXTRA" ]; then
            now_extra="$(extra_state)"
            if [ "$now_extra" != "$last_extra" ]; then
                last_extra="$now_extra"
                echo "cx-enrichment-reload: ${EXTRA} changed — reloading vector (SIGHUP)" >&2
                if ! kill -HUP "$VECTOR_PID" 2>/dev/null; then
                    echo "cx-enrichment-reload: vector process not running; exiting watcher" >&2
                    break
                fi
            fi
        fi
        now="$(hash_of "$CSV" || true)"
        # Skip when unreadable/absent; also skip the very first appearance vs
        # an empty baseline only if identical — any content change reloads.
        [ -n "$now" ] || continue
        if [ "$now" != "$last" ]; then
            last="$now"
            echo "cx-enrichment-reload: ${CSV} changed — reloading vector (SIGHUP)" >&2
            if ! kill -HUP "$VECTOR_PID" 2>/dev/null; then
                # vector is gone; the main wait is about to exit the container.
                echo "cx-enrichment-reload: vector process not running; exiting watcher" >&2
                break
            fi
        fi
    done
) &

# The container lives and dies with vector; its exit code is the container's.
#
# 324 — SAY WHY IT DIED, on the way out. This shell is PID 1, vector is its
# CHILD, and that hid a memory problem for ten days. The kernel's cgroup OOM
# killer picks the fattest task in the cgroup — vector — not PID 1, so the
# container's init survives and Docker never stamps `State.OOMKilled`. An
# operator running `docker inspect` then reads `OOMKilled=false, ExitCode=0`
# (Docker also zeroes both on a container that has since RESTARTED) and
# concludes the restarts were clean. On .122 they were not: 114 cgroup OOM
# kills of vector-router between 2026-09-06 and 2026-09-15 all read that way.
# §10 — no silent failures: the exit status is data we already have, so report
# it rather than making the next operator reach for dmesg to learn it existed.
#
# §16.1: nothing is swallowed. `set +e` is scoped to the `wait` ONLY so the
# status can be captured instead of killing the shell before it can be
# reported, and the script still exits with exactly that status — the
# container's exit code is unchanged by this block.
set +e
wait "$VECTOR_PID"
vector_status=$?
# A trapped signal (docker stop → TERM, forwarded above) makes `wait` return
# 128+n IMMEDIATELY, while vector is still draining. Exiting then would end
# PID 1 and the kernel would kill vector mid-drain — so keep waiting until
# vector itself has exited, and report ITS status.
while kill -0 "$VECTOR_PID" 2>/dev/null; do
    wait "$VECTOR_PID"
    vector_status=$?
done
# Was this exit the lane watcher's doing? It exits 75 right after signalling
# vector, so by now it has normally finished; if it is still running (vector
# died for another reason) stop it — its status is then 143, not 75.
watch_status=""
if [ -n "$WATCH_PID" ]; then
    if kill -0 "$WATCH_PID" 2>/dev/null; then
        # Safe to ignore: the only failure is "already exited", which the
        # `wait` below reports through its status.
        kill -TERM "$WATCH_PID" 2>/dev/null || true
    fi
    wait "$WATCH_PID"
    watch_status=$?
fi
set -e

if [ "$watch_status" = "75" ]; then
    # §10: a self-heal restart must never look like a clean exit. 75
    # (EX_TEMPFAIL) is the container's exit code, the restart policy brings
    # it back, and this line is the reason the restart push carries.
    echo "cx-enrichment-reload: vector stopped by cx-lane-watch — a kafka" \
         "lane was joined but not consuming (see the LANE WEDGED line above);" \
         "exiting 75 so the container restarts and the consumer rejoins" \
         "(vector status was ${vector_status})" >&2
    exit 75
fi
if [ -n "$watch_status" ] && [ "$watch_status" != "143" ] && [ "$watch_status" != "0" ]; then
    echo "cx-enrichment-reload: cx-lane-watch had exited with status" \
         "${watch_status} (64 = invalid config) — lane self-heal was NOT" \
         "running" >&2
fi

case "$vector_status" in
    0)
        ;;
    137)
        echo "cx-enrichment-reload: vector was KILLED (SIGKILL, status 137)." \
             "Under a container memory cap this is almost always the cgroup" \
             "OOM killer reaping the child process; \`docker inspect\` will" \
             "still report OOMKilled=false because PID 1 (this shell)" \
             "survived. Confirm with:" \
             "dmesg -T | grep -i 'Memory cgroup out of memory'" >&2
        ;;
    *)
        echo "cx-enrichment-reload: vector exited with status ${vector_status}" >&2
        ;;
esac

exit "$vector_status"
