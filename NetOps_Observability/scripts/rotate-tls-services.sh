#!/usr/bin/env bash
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
# Cron:    weekly, or on a TLSServedCertExpiringSoon page.
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

dc() { docker compose --project-directory "$COMPOSE_DIR" "$@"; }
log() { echo "[rotate-tls] $*" >&2; }
FAILURES=0
flag() { log "FAIL: $*"; FAILURES=$((FAILURES + 1)); }

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
log "disk material OK (${left_h}h remaining); mode=$([ $CHECK_ONLY -eq 1 ] && echo check || echo act)"

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

    # ── phase 2: restart class, one at a time, health-gated ─────────────────
    # correlation FIRST: the served-cert verifier below execs openssl inside
    # it, so it must be settled before verification. opensearch is here until
    # the security plugin's cert hot-reload flag is adopted.
    # syslog-ng: its client SVID (F-1 hop) is loaded at start; skipping it here
    # leaves the old cert in the running process until the aggregator refuses it.
    for svc in correlation opensearch vector-router vector-aggregator syslog-ng kafka-exporter grafana gnmic opensearch-dashboards; do
        log "restart: $svc"
        if ! dc restart "$svc" >/dev/null 2>&1; then
            flag "$svc restart"
            continue
        fi
        wait_state "$svc" || flag "$svc did not reach healthy/running after restart"
    done

    # ── gotenberg (OPTIONAL pdf profile): re-stage + restart ────────────────
    # Certs reach gotenberg only via the gotenberg-tls-init staging one-shot
    # (cross-uid: the image runs uid 1001, the mint is uid 65532), so a
    # rotation must re-run the one-shot BEFORE the restart or gotenberg
    # reloads the same stale staged copy. The profile is optional — skip
    # loudly-with-log when the service is not running (a deployment without
    # pdf has nothing to rotate; flagging it would page on a non-fault).
    if [ -n "$(dc ps -q --status running gotenberg 2>/dev/null)" ]; then
        log "gotenberg: re-stage via gotenberg-tls-init + restart"
        # stdout only is muted — the one-shot's diagnostics (incl. its FATAL
        # refusal message) go to stderr and must reach the sweep log (§16.1).
        if dc run --rm gotenberg-tls-init >/dev/null; then
            if dc restart gotenberg >/dev/null 2>&1; then
                wait_state gotenberg || flag "gotenberg did not reach healthy/running after restart"
            else
                flag "gotenberg restart"
            fi
        else
            flag "gotenberg-tls-init re-stage"
        fi
    else
        log "skip: gotenberg (pdf profile not running on this deployment)"
    fi
fi

# ── phase 3: verify the WIRE, endpoint by endpoint ──────────────────────────
# Each endpoint must serve exactly the mint currently on disk for its service
# (expiry compared with a 90-minute tolerance for a reissue racing the sweep).
TOL=5400
verify() { # <endpoint host:port> <svc-dir> [starttls]
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

verify kafka:9093 kafka
verify kafka:9094 kafka
verify kafka:9095 kafka
verify postgres:5432 postgres postgres
verify clickhouse:8443 clickhouse
verify clickhouse:9440 clickhouse
verify opensearch:9200 opensearch
verify correlation:8443 correlation
verify vmauth:8427 vmauth
verify vector-aggregator:6601 vector-aggregator
# gotenberg is profile-gated (pdf) — verify only when it is actually running,
# same guard as its rotation leg above (an absent optional service is not a
# degraded sweep).
if [ -n "$(dc ps -q --status running gotenberg 2>/dev/null)" ]; then
    verify gotenberg:3000 gotenberg
else
    log "skip: gotenberg:3000 (pdf profile not running on this deployment)"
fi

# Heartbeat so "the sweep stopped running" is itself detectable (§16.2).
printf '%s status=%s failures=%d\n' "$(date -u +%FT%TZ)" \
    "$([ "$FAILURES" -eq 0 ] && echo ok || echo DEGRADED)" "$FAILURES" >"$HEARTBEAT"

if [ "$FAILURES" -gt 0 ]; then
    log "DEGRADED: $FAILURES failure(s) — see lines above; the wire may still be serving stale certs"
    exit 1
fi
log "sweep complete: every mesh endpoint serves the current mint"
