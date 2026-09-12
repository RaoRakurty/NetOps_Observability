#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# rotate-tls-services.sh — SEC-019.1 part 2: propagate re-minted SVIDs to
# every service that loads its certificate material once at start.
#
# WHY THIS EXISTS (incident 2026-08-05): the api's CA re-issues all SVIDs to
# disk at TTL/2, but clickhouse and postgres SERVED the copies they loaded at
# their last container start until those expired — a store outage with
# perfectly fresh disk material. This sweep closes the disk→wire gap using
# the cheapest mechanism each service actually supports (each one proven
# live on 2026-08-06 before being encoded here):
#
#   kafka       dynamic per-listener keystore re-set (kafka-configs --alter
#               with the SAME path forces a file re-read; no broker restart)
#   postgres    re-stage + pg_reload_conf() (ssl_* are reload-safe)
#   clickhouse  re-stage + SYSTEM RELOAD CONFIG (cert reloader re-reads)
#   nginx       nginx -s reload
#   redis       valkey CONFIG SET tls-cert-file+tls-key-file (hot re-read)
#   vmauth      nothing — VictoriaMetrics re-reads cert files automatically
#   the rest    docker compose restart, one at a time, health-gated
#               (opensearch stays restart-class until the security plugin's
#               hot-reload flag is adopted)
#
# VERIFICATION IS THE POINT: after acting, every mesh endpoint's SERVED
# certificate must match the current on-disk mint for that service —
# compared expiry-to-expiry, not assumed. A sweep that cannot prove the wire
# moved exits non-zero (§16.1: a maintenance job that cannot do its job is
# as loud as the condition it maintains against).
#
# Modes:   rotate-tls-services.sh            act + verify
#          rotate-tls-services.sh --check    verify only (no changes)
# Cron:    DAILY act sweep (installed 2026-08-23); also run on a
#          TLSServedCertExpiringSoon page. Daily is cheap by design: the
#          hot-reload legs are zero-downtime, and the restart class is
#          NEED-BASED — a service is restarted only when the cert its
#          process holds drops under RESTART_WHEN_LEFT_H (default 72h),
#          i.e. the Istio/step-ca "renew at ~2/3 elapsed" semantics applied
#          to the wire. A fixed weekly restart cadence is arithmetically
#          unsafe at TTL=7d (can catch a TTL/2 mint and return post-expiry).
# GUARD:   a live scale-miniladder.py run (qualification / soak) OWNS the
#          stack — act mode runs hot-reload legs but defers the restart
#          class rather than restarting services mid-evidence. Deferred /
#          not-due endpoints are verified against WIRE_MIN_LEFT_H (48h):
#          planned deferral is quiet, imminent expiry stays loud, and the
#          vmalert served-cert expiry rules page independently.
# NOTE: the kafka dynamic AlterConfigs currently rides the pre-enforce
# ANONYMOUS window; when SEC-007.2 flips default-deny, add an admin client
# config to the two kafka-configs calls (tracked with the enforce flip).
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$DIR/../deployment/docker}"
TLS_DIR="${TLS_DIR:-$DIR/../data/tls}"
HEARTBEAT="${HEARTBEAT:-$DIR/rotate-tls.heartbeat}"
# Refuse to sweep stale material: if the freshest disk cert has less than
# this many hours left, the api's reissue loop is broken and spreading its
# output would just spread the problem. Fix the loop first.
MIN_DISK_LEFT_H="${MIN_DISK_LEFT_H:-72}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

for tool in docker openssl date; do
    command -v "$tool" >/dev/null || { echo "rotate-tls: FATAL: $tool not on PATH ($PATH)" >&2; exit 78; }
done

# The compose dir must actually hold the deployment (guards a bad COMPOSE_DIR
# override and the moved-checkout case before any service is touched).
if [ ! -r "$COMPOSE_DIR/docker-compose.yml" ] || [ ! -r "$COMPOSE_DIR/.env" ]; then
    echo "rotate-tls: FATAL: $COMPOSE_DIR does not contain docker-compose.yml + .env — set COMPOSE_DIR" >&2
    exit 78
fi

# Qualification guard: a live miniladder run (nightly T-nominal, weekly S1,
# or a 72h soak) owns the stack. The HOT-RELOAD legs (kafka dynamic keystore,
# postgres pg_reload_conf, clickhouse RELOAD CONFIG, nginx graceful reload)
# are evidence-safe — each proven zero-downtime against a live soak on
# 2026-08-23 — so they still run. Only the RESTART class is deferred: a
# service restart mid-run invalidates the run's evidence. A deferred
# endpoint is then verified against WIRE_MIN_LEFT_H (time-to-expiry) instead
# of mint-match: planned deferral is quiet, imminent expiry stays loud.
MODE=$([ "$CHECK_ONLY" -eq 1 ] && echo check || echo act)
RESTARTS_OK=1
WIRE_MIN_LEFT_H="${WIRE_MIN_LEFT_H:-48}"

# Compose resolves its file set from COMPOSE_FILE/COMPOSE_PROFILES in the
# deployment .env, which it only reads from that directory — so run compose
# FROM the compose dir (subshell keeps the caller's CWD). `--project-directory`
# alone does NOT discover compose files from another CWD (2026-08-23 incident:
# a repo-root invocation found no services and flagged all 23 legs).
dc() { (cd "$COMPOSE_DIR" && docker compose "$@"); }
log() { echo "[rotate-tls] $*" >&2; }
FAILURES=0
flag() { log "FAIL: $*"; FAILURES=$((FAILURES + 1)); }

# A REAL harness run is "a python interpreter executing scale-miniladder.py" —
# not any command line that merely MENTIONS the file. The old bare
# `pgrep -f 'scale-miniladder\.py'` also matched an editor, a `tail -f` on a
# path carrying the name, a grep, or an agent shell whose own argv quoted it
# (the exact false-match class scale-ab-driver.py's HARNESS_PROC_RE documents;
# ultra #21, 2026-09-01) — any of which deferred the restart class
# INDEFINITELY. So: candidates from `pgrep -af` (pid + full cmdline), then
# narrow to lines where an interpreter is invoked ON the harness file, which
# is what every real invocation looks like after `setsid nohup` execs (cron's
# included). pgrep rc=1 means "no candidates"; rc>1 means pgrep itself failed
# — then the sweep cannot PROVE the host is idle, so it defers the restart
# class AND flags the run (16.1: refusing to guess must be loud; the deferred
# endpoints still get the WIRE_MIN_LEFT_H floor check in phase 3).
harness_live=0
if harness_out=$(pgrep -af 'scale-miniladder\.py' 2>&1); then
    harness_rc=0
else
    harness_rc=$?
fi
if [ "$harness_rc" -eq 0 ]; then
    if printf '%s\n' "$harness_out" | grep -Eq '(^|[/[:space:]])python[0-9.]*[[:space:]]+[^[:space:]]*scale-miniladder\.py([[:space:]]|$)'; then
        harness_live=1
    fi
elif [ "$harness_rc" -gt 1 ]; then
    flag "pgrep for scale-miniladder.py failed (rc=${harness_rc}): ${harness_out:-no output} — cannot prove the host is idle; deferring the restart class"
    harness_live=1
fi
if [ "$CHECK_ONLY" -eq 0 ] && [ "$harness_live" -eq 1 ]; then
    log "DEFER: live qualification/soak run owns the stack — hot-reload legs only, restart class deferred"
    RESTARTS_OK=0
    MODE=deferred
fi

# disk_end <svc>: epoch NotAfter of the service's on-disk SVID.
disk_end() {
    local crt="$TLS_DIR/services/$1/$1.crt"
    [ -r "$crt" ] || { echo 0; return; }
    local end
    end=$(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2-) || { echo 0; return; }
    date -d "$end" +%s 2>/dev/null || echo 0
}

# served_end <host:port> [starttls-proto]: epoch NotAfter of the certificate
# the endpoint SERVES, observed from inside the mesh (the correlation
# container ships openssl and is always present).
served_end() {
    local addr="$1" extra=""
    [ -n "${2:-}" ] && extra="-starttls $2"
    local end
    # shellcheck disable=SC2086  # $extra is deliberately word-split flags
    end=$(dc exec -T correlation sh -c \
        "echo | timeout 15 openssl s_client $extra -connect '$addr' 2>/dev/null | openssl x509 -noout -enddate" \
        2>/dev/null | cut -d= -f2-) || { echo 0; return; }
    [ -n "$end" ] || { echo 0; return; }
    date -d "$end" +%s 2>/dev/null || echo 0
}

# ── held-cert bookkeeping (need-based restarts) ─────────────────────────────
# For services with a probeable TLS endpoint the WIRE is ground truth. The
# rest load a client SVID at start and expose nothing — for those, record the
# disk mint's expiry AT THE RESTART THIS SWEEP PERFORMED (the loaded copy is
# exactly that mint) in a state file, and judge freshness from the record.
# An absent record forces one establishing restart; after that it is exact.
ROTATE_STATE="${ROTATE_STATE:-$DIR/.rotate-tls.loaded}"
RESTART_WHEN_LEFT_H="${RESTART_WHEN_LEFT_H:-72}"
RESTARTED=""   # services THIS run restarted — they get strict mint verification

record_loaded() { # <svc> <epoch>
    [ "${2:-0}" -gt 0 ] || return 0   # a 0 disk_end must not masquerade as data
    local tmp="$ROTATE_STATE.new"
    { [ -f "$ROTATE_STATE" ] && awk -v s="$1" '$1!=s' "$ROTATE_STATE"; \
      printf '%s %s\n' "$1" "$2"; } > "$tmp" && mv "$tmp" "$ROTATE_STATE"
}

holds_end() { # <svc> — epoch NotAfter of the cert the running process HOLDS
    case "$1" in
        correlation)      served_end correlation:8443 ;;
        opensearch)       served_end opensearch:9200 ;;
        vector-aggregator) served_end vector-aggregator:6601 ;;
        gotenberg)        served_end gotenberg:3000 ;;
        *) awk -v s="$1" '$1==s{print $2; found=1} END{if(!found) print 0}' \
               "$ROTATE_STATE" 2>/dev/null || echo 0 ;;
    esac
}

wait_state() { # <svc> — healthy (or running when no healthcheck), bounded
    local svc="$1" cid state i
    for i in $(seq 1 30); do
        cid=$(dc ps -q "$svc" 2>/dev/null | head -1)
        if [ -n "$cid" ]; then
            state=$(docker inspect "$cid" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null || echo unknown)
            [ "$state" = "healthy" ] && return 0
            [ "$state" = "running" ] && [ "$i" -ge 3 ] && return 0
        fi
        sleep 6
    done
    return 1
}

# ── phase 0: the disk material itself must be fresh ─────────────────────────
now=$(date +%s)
kafka_disk=$(disk_end kafka)
if [ "$kafka_disk" -eq 0 ]; then
    log "FATAL: cannot read $TLS_DIR/services/kafka/kafka.crt — wrong TLS_DIR, or the mesh is not enabled on this host"
    exit 78
fi
left_h=$(( (kafka_disk - now) / 3600 ))
if [ "$left_h" -lt "$MIN_DISK_LEFT_H" ]; then
    log "FATAL: on-disk SVIDs have only ${left_h}h left (< ${MIN_DISK_LEFT_H}h) — the api's reissue loop is not doing its job; fix THAT before sweeping"
    exit 1
fi
log "disk material OK (${left_h}h remaining); mode=$MODE"

# ── phase 1: native reloads (no restarts) ───────────────────────────────────
if [ "$CHECK_ONLY" -eq 0 ]; then
    log "kafka: re-stage PEM keystore + dynamic reload on both secure listeners"
    if dc exec -T kafka sh -c 'umask 077 && cat /certs-src/kafka.key /certs-src/kafka.crt > /tmp/kafka-tls/keystore.pem.new && mv /tmp/kafka-tls/keystore.pem.new /tmp/kafka-tls/keystore.pem && cp /certs-src/ca.pem /tmp/kafka-tls/truststore.pem && printf "security.protocol=SSL\nssl.keystore.type=PEM\nssl.keystore.location=/tmp/kafka-tls/keystore.pem\nssl.truststore.type=PEM\nssl.truststore.location=/tmp/kafka-tls/truststore.pem\n" > /tmp/kafka-tls/admin.properties'; then
        # Authenticated admin plane (2026-08-06): MTLS:9094 with the broker's
        # own SVID (super-user; admin.properties written by tls-entrypoint.sh).
        # 9092-as-ANONYMOUS goes blind at the SEC-007.2 flip and the listener
        # itself dies at SEC-006.3 — this leg must not depend on either.
        for listener in mtls flows controller; do
            if ! dc exec -T kafka timeout 90 /opt/kafka/bin/kafka-configs.sh \
                --bootstrap-server kafka:9094 --command-config /tmp/kafka-tls/admin.properties \
                --entity-type brokers --entity-name 1 \
                --alter --add-config "listener.name.$listener.ssl.keystore.location=/tmp/kafka-tls/keystore.pem" >/dev/null; then
                flag "kafka listener $listener dynamic keystore reload"
            fi
        done
    else
        flag "kafka keystore re-stage"
    fi

    log "postgres: re-stage + pg_reload_conf()"
    if dc exec -T -u root postgres sh -c 'cp /certs-src/postgres.crt /var/lib/postgresql/tls/server.crt.new && cp /certs-src/postgres.key /var/lib/postgresql/tls/server.key.new && chown postgres:postgres /var/lib/postgresql/tls/server.crt.new /var/lib/postgresql/tls/server.key.new && chmod 640 /var/lib/postgresql/tls/server.crt.new && chmod 600 /var/lib/postgresql/tls/server.key.new && mv /var/lib/postgresql/tls/server.crt.new /var/lib/postgresql/tls/server.crt && mv /var/lib/postgresql/tls/server.key.new /var/lib/postgresql/tls/server.key'; then
        dc exec -T -u postgres postgres psql -U "${DB_USER:-netops}" -t -c "SELECT pg_reload_conf();" >/dev/null || flag "postgres pg_reload_conf"
    else
        flag "postgres cert re-stage"
    fi

    log "clickhouse: re-stage + SYSTEM RELOAD CONFIG"
    if dc exec -T -u root clickhouse sh -c 'cp /certs-src/clickhouse.crt /etc/clickhouse-server/tls/server.crt.new && cp /certs-src/clickhouse.key /etc/clickhouse-server/tls/server.key.new && chown clickhouse:clickhouse /etc/clickhouse-server/tls/server.crt.new /etc/clickhouse-server/tls/server.key.new && chmod 640 /etc/clickhouse-server/tls/server.crt.new && chmod 600 /etc/clickhouse-server/tls/server.key.new && mv /etc/clickhouse-server/tls/server.crt.new /etc/clickhouse-server/tls/server.crt && mv /etc/clickhouse-server/tls/server.key.new /etc/clickhouse-server/tls/server.key'; then
        dc exec -T clickhouse timeout 30 clickhouse-client -q "SYSTEM RELOAD CONFIG" >/dev/null || flag "clickhouse SYSTEM RELOAD CONFIG"
    else
        flag "clickhouse cert re-stage"
    fi

    log "nginx: reload (re-reads server cert + proxy client SVID)"
    dc exec -T nginx nginx -s reload || flag "nginx reload"

    # redis (valkey): COVERAGE GAP found 2026-08-24 — this service was in NO
    # class, so its serving cert silently EXPIRED at the old mint's notAfter
    # (7h of api/prober cache TLS failures, healthcheck failing streak 2601).
    # Valkey re-reads both files on CONFIG SET (single command so cert+key
    # stay a matched pair). Password rides stdin -> REDISCLI_AUTH: never argv
    # (§8 — argv is visible to ps on host and container).
    # --insecure on the reload connection is deliberate: it is a LOOPBACK
    # exec inside the redis container (127.0.0.1), and the very failure this
    # leg must recover from — an EXPIRED serving cert — makes a verifying
    # client refuse to connect at all (2026-08-24: 7h expired, only a restart
    # could have fixed it otherwise). Verification of the wire happens right
    # after, in phase 3, from a verifying client.
    log "redis (valkey): hot cert reload via CONFIG SET"
    rpw=$(grep -E '^REDIS_PASSWORD=' "$COMPOSE_DIR/.env" | cut -d= -f2-) || rpw=""
    if [ -n "$rpw" ]; then
        # shellcheck disable=SC2016  # $(cat) must expand inside the container shell
        if ! printf '%s' "$rpw" | dc exec -T redis sh -c \
            'REDISCLI_AUTH=$(cat) valkey-cli --tls --insecure --cacert /tls/ca.pem -p 6380 CONFIG SET tls-cert-file /tls/svid/redis.crt tls-key-file /tls/svid/redis.key' \
            | grep -q OK; then
            flag "redis CONFIG SET cert reload"
        fi
    else
        flag "redis: REDIS_PASSWORD missing from $COMPOSE_DIR/.env — cannot hot-reload its certs"
    fi

    # ── phase 2: restart class — NEED-BASED, one at a time, health-gated ────
    # 2026-08-23 redesign (vendor benchmark): a fixed weekly restart cadence
    # with TTL=7d / reissue-at-TTL/2 can catch a mint with only TTL/2 left and
    # not come back until AFTER it expires — the 2026-08-05 outage class with
    # a cron on top. Industry semantics (Istio/step-ca/SPIRE: renew when ~2/3
    # elapsed) applied to the WIRE instead: this sweep runs DAILY, and each
    # restart-class service is restarted ONLY when the certificate its process
    # actually holds drops under RESTART_WHEN_LEFT_H — measured from the wire
    # for probeable endpoints, from the recorded loaded-mint expiry otherwise.
    # correlation FIRST: the served-cert verifier below execs openssl inside
    # it, so it must be settled before verification. opensearch is here until
    # the security plugin cert reload API is adopted (staged: SEC-019.1 part 4).
    # syslog-ng: its client SVID (F-1 hop) is loaded at start; skipping it here
    # leaves the old cert in the running process until the aggregator refuses it.
    if [ "$RESTARTS_OK" -eq 1 ]; then
        for svc in correlation opensearch vector-router vector-aggregator syslog-ng kafka-exporter grafana gnmic opensearch-dashboards; do
            cur=$(holds_end "$svc")
            if [ "$cur" -gt 0 ]; then
                cur_left_h=$(( (cur - $(date +%s)) / 3600 ))
                if [ "$cur_left_h" -ge "$RESTART_WHEN_LEFT_H" ]; then
                    log "fresh: $svc holds a cert with ${cur_left_h}h left (>= ${RESTART_WHEN_LEFT_H}h) — no restart needed"
                    continue
                fi
                log "restart: $svc (held cert has ${cur_left_h}h left < ${RESTART_WHEN_LEFT_H}h)"
            else
                log "restart: $svc (held-cert expiry unknown — first sweep or unreadable; restarting to establish)"
            fi
            if ! dc restart "$svc" >/dev/null 2>&1; then
                flag "$svc restart"
                continue
            fi
            if wait_state "$svc"; then
                record_loaded "$svc" "$(disk_end "$svc")"
                RESTARTED="$RESTARTED $svc"
            else
                flag "$svc did not reach healthy/running after restart"
            fi
        done
    else
        log "DEFER: restart class (correlation opensearch vector-router vector-aggregator syslog-ng kafka-exporter grafana gnmic opensearch-dashboards) — live run owns the stack"
    fi

    # ── gotenberg (OPTIONAL pdf profile): re-stage + restart ────────────────
    # Certs reach gotenberg only via the gotenberg-tls-init staging one-shot
    # (cross-uid: the image runs uid 1001, the mint is uid 65532), so a
    # rotation must re-run the one-shot BEFORE the restart or gotenberg
    # reloads the same stale staged copy. The profile is optional — skip
    # loudly-with-log when the service is not running (a deployment without
    # pdf has nothing to rotate; flagging it would page on a non-fault).
    if [ "$RESTARTS_OK" -eq 0 ]; then
        log "DEFER: gotenberg (restart class) — live run owns the stack"
    elif [ -n "$(dc ps -q --status running gotenberg 2>/dev/null)" ]; then
        g_end=$(holds_end gotenberg)
        g_left_h=$(( (g_end - $(date +%s)) / 3600 ))
        if [ "$g_end" -gt 0 ] && [ "$g_left_h" -ge "$RESTART_WHEN_LEFT_H" ]; then
            log "fresh: gotenberg serves a cert with ${g_left_h}h left (>= ${RESTART_WHEN_LEFT_H}h) — no restart needed"
        else
            log "gotenberg: re-stage via gotenberg-tls-init + restart (${g_left_h}h left)"
            # stdout only is muted — the one-shot's diagnostics (incl. its FATAL
            # refusal message) go to stderr and must reach the sweep log (§16.1).
            if dc run --rm gotenberg-tls-init >/dev/null; then
                if dc restart gotenberg >/dev/null 2>&1; then
                    if wait_state gotenberg; then RESTARTED="$RESTARTED gotenberg"; else
                        flag "gotenberg did not reach healthy/running after restart"; fi
                else
                    flag "gotenberg restart"
                fi
            else
                flag "gotenberg-tls-init re-stage"
            fi
        fi
    else
        log "skip: gotenberg (pdf profile not running on this deployment)"
    fi
fi

# ── phase 3: verify the WIRE, endpoint by endpoint ──────────────────────────
# Each endpoint must serve exactly the mint currently on disk for its service
# (expiry compared with a 90-minute tolerance for a reissue racing the sweep).
TOL=5400
verify() { # <endpoint host:port> <svc-dir> [starttls] — strict mint-match
    local ep="$1" svc="$2" proto="${3:-}"
    local want got
    want=$(disk_end "$svc")
    got=$(served_end "$ep" "$proto")
    if [ "$got" -eq 0 ]; then
        flag "$ep: could not read served certificate"
        return
    fi
    local diff=$((got - want)); [ "$diff" -lt 0 ] && diff=$((-diff))
    if [ "$diff" -gt "$TOL" ]; then
        flag "$ep: serves a cert expiring $(date -u -d "@$got" +%FT%TZ) but disk mint for $svc expires $(date -u -d "@$want" +%FT%TZ) — the reload did not take"
    else
        log "ok: $ep serves the current mint (expires $(date -u -d "@$got" +%FT%TZ))"
    fi
}

# verify_r: restart-class endpoints. Restarts are NEED-BASED, so a mint
# mismatch is the normal state for a service that was not due — strict
# mint-match applies only to a service THIS run restarted. Everything else
# (not due, check mode, deferred under a live run) is judged by the floor:
# under WIRE_MIN_LEFT_H hours of wire validity means at least one daily
# act pass failed or was deferred past its margin — that is the loud case.
verify_r() { # <endpoint host:port> <svc-dir> [starttls]
    local ep="$1" svc="$2" proto="${3:-}"
    case " ${RESTARTED} " in
        *" $svc "*) verify "$@"; return ;;
    esac
    local got left_h
    got=$(served_end "$ep" "$proto")
    if [ "$got" -eq 0 ]; then
        flag "$ep: could not read served certificate"
        return
    fi
    left_h=$(( (got - $(date +%s)) / 3600 ))
    if [ "$left_h" -lt "$WIRE_MIN_LEFT_H" ]; then
        flag "$ep: served cert has only ${left_h}h left (< ${WIRE_MIN_LEFT_H}h) and no restart landed — the need-based pass failed or was deferred too long"
    else
        log "ok: $ep wire cert has ${left_h}h left (not due; floor ${WIRE_MIN_LEFT_H}h)"
    fi
}

# Hot-reload class: strict mint-match always (the reload ran even under a
# deferral, so anything stale here is a real reload failure).
verify kafka:9093 kafka
verify kafka:9094 kafka
verify kafka:9095 kafka
verify postgres:5432 postgres postgres
verify clickhouse:8443 clickhouse
verify clickhouse:9440 clickhouse
verify redis:6380 redis
verify vmauth:8427 vmauth
# Restart class: expiry-floor check while deferred, strict otherwise.
verify_r opensearch:9200 opensearch
verify_r correlation:8443 correlation
verify_r vector-aggregator:6601 vector-aggregator
# gotenberg is profile-gated (pdf) — verify only when it is actually running,
# same guard as its rotation leg above (an absent optional service is not a
# degraded sweep).
if [ -n "$(dc ps -q --status running gotenberg 2>/dev/null)" ]; then
    verify_r gotenberg:3000 gotenberg
else
    log "skip: gotenberg:3000 (pdf profile not running on this deployment)"
fi

# Heartbeat so "the sweep stopped running" is itself detectable (§16.2).
# mode=act|check|deferred distinguishes "rotated" from "only verified": the
# staleness monitor must key on the last ACT sweep, not any run of the script.
printf '%s status=%s mode=%s failures=%d\n' "$(date -u +%FT%TZ)" \
    "$([ "$FAILURES" -eq 0 ] && echo ok || echo DEGRADED)" "$MODE" "$FAILURES" >"$HEARTBEAT"
# Separate act-only heartbeat: its AGE is the "no successful rotation sweep in
# N days" signal (a daily --check refreshing the main heartbeat must not mask
# a weekly act sweep that has stopped landing).
if [ "$MODE" = "act" ] && [ "$FAILURES" -eq 0 ]; then
    printf '%s status=ok failures=0\n' "$(date -u +%FT%TZ)" >"${HEARTBEAT%.heartbeat}.act.heartbeat"
fi

if [ "$FAILURES" -gt 0 ]; then
    log "DEGRADED: $FAILURES failure(s) — see lines above; the wire may still be serving stale certs"
    exit 1
fi
if [ "$MODE" = "deferred" ]; then
    log "sweep complete (deferred): hot-reload class on current mint; restart class deferred with >=${WIRE_MIN_LEFT_H}h wire margin — run the act sweep after the live run ends"
else
    log "sweep complete: every mesh endpoint serves the current mint"
fi
