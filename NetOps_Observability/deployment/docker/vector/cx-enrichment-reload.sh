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

/usr/local/bin/vector "$@" &
VECTOR_PID=$!

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

(
    while kill -0 "$VECTOR_PID" 2>/dev/null; do
        sleep "$POLL"
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
set -e

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
