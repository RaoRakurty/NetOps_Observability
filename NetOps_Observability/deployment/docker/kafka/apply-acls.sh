#!/bin/sh
# apply-acls.sh — SEC-007: the per-identity Kafka ACL matrix.
#
# Runs INSIDE the kafka container (the only place kafka-acls.sh lives),
# mounted at /acls/apply-acls.sh by compose.tls.yml:
#   docker compose exec kafka /acls/apply-acls.sh
# Idempotent: kafka-acls --add of an existing ACL is a no-op and --remove
# --force of an absent one is too, so re-running converges (safe after every
# broker rebuild, identity change, or data/kafka wipe).
#
# CONNECTION: on a TLS deployment the broker admin-plane client config
# (/tmp/kafka-tls/admin.properties, staged by tls-entrypoint.sh; the broker
# SVID is the KAFKA_SUPER_USERS principal) is auto-detected and the
# bootstrap defaults to the mTLS listener kafka:9094. Override with
# KAFKA_BOOTSTRAP / KAFKA_COMMAND_CONFIG for non-standard layouts; without
# admin.properties (pre-TLS lab broker) it falls back to localhost:9092.
#
# POSTURE: ENFORCED. SEC-007.2 (2026-08-09) flipped
# allow.everyone.if.no.acl.found to false in compose.tls.yml, so the KRaft
# ACL store IS the authorization state — and it lives in data/kafka. A
# fresh install or a data/kafka wipe therefore boots an EMPTY store: every
# non-super-user principal is denied while every healthcheck stays green
# (live incident 2026-08-16: vector-router + correlation auth-dead ~80 min,
# lag frozen, all containers "healthy"). install.py runs this script
# automatically after TLS phase B; this file stays the manual runbook path
# (docs/runbooks/tls-enforce-wave.md).
#
# PRINCIPALS are full DN strings (no ssl.principal.mapping.rules — see the
# compose override note: the rule value crosses three escaping layers and
# the RULE parser's delimiter is the / the SPIFFE URI is full of).
#
# THE MATRIX (HLD §7 authorization column + owner option-1 for goflow2):
#   vector-aggregator  produce  netops.* (prefixed) — it IS the bus bridge:
#                      the kafka_bus sink multiplexes every HTTP-ingested
#                      lane by __topic, so enumerating lanes here would just
#                      go stale; the HTTP side authenticates producers.
#   vector-router      consume  its 9 lanes (incl. netops.flows.raw — the
#                      scale-P0 re-key hop, and netops.security — the P3-L1
#                      findings lane); produce netops.deadletter AND
#                      netops.flows (the tenant-keyed flow feed);
#                      groups netops-router-* (prefixed)
#   correlation        consume  its 13 topics (incl. netops.syslog.control,
#                      the A4 pre-screened syslog lane — granted now so the
#                      engine can be switched onto it by env alone, with no
#                      second ACL-and-restart step in the change window);
#                      group netops-correlation
#   kafka-exporter     describe netops.* topics + netops-* groups (lag math
#                      is ListOffsets/OffsetFetch = Describe on both)
#   ANONYMOUS          produce  netops.flows.raw ONLY — goflow2 on the FLOWS
#                      listener (no client-cert capability; owner decision
#                      2026-08-05; scale P0 moved goflow2 from netops.flows
#                      to the raw topic the router re-keys). NOTE: until the
#                      PLAINTEXT listener dies (SEC-006.3), everything on
#                      :9092 is also ANONYMOUS — the flip to enforce narrows
#                      that blast radius to exactly this one topic.
set -eu

ADMIN_PROPS=/tmp/kafka-tls/admin.properties
BOOTSTRAP="${KAFKA_BOOTSTRAP:-}"
CONFIG="${KAFKA_COMMAND_CONFIG:-}"
if [ -z "$BOOTSTRAP" ]; then
    if [ -f "$ADMIN_PROPS" ]; then
        # TLS broker: authenticate on the mTLS listener as the super-user
        # broker SVID (the plaintext 9092 listener died at SEC-006.3).
        BOOTSTRAP="kafka:9094"
        CONFIG="${CONFIG:-$ADMIN_PROPS}"
    else
        BOOTSTRAP="localhost:9092"
    fi
fi
ACLS="/opt/kafka/bin/kafka-acls.sh --bootstrap-server $BOOTSTRAP"
if [ -n "$CONFIG" ]; then
    ACLS="$ACLS --command-config $CONFIG"
fi

SA="CN=spiffe://netops/ns/default/sa"
AGG="User:$SA/vector-aggregator"
ROUTER="User:$SA/vector-router"
CORR="User:$SA/correlation"
EXPORTER="User:$SA/kafka-exporter"

echo "acls: aggregator — produce on netops.* (prefixed, bus-bridge role)" >&2
$ACLS --add --allow-principal "$AGG" --producer \
    --topic netops. --resource-pattern-type prefixed >/dev/null

echo "acls: router — consume its lanes, produce deadletter+flows, own its groups" >&2
# P3-L1: netops.security joins the router's consume set — the security
# findings lane (kafka_security → opensearch_secfindings). The topic is
# already created by kafka-init in BOTH compose files and produced by the
# backend's secbus producer under the aggregator's prefixed netops. grant;
# only the router's READ was missing, so only the READ is added here.
for t in netops.applogs netops.syslog netops.flows netops.flows.raw \
         netops.snmptrap netops.security \
         netops.cloudlogs netops.cloudcosts netops.deadletter; do
    $ACLS --add --allow-principal "$ROUTER" \
        --operation Read --operation Describe --topic "$t" >/dev/null
done
$ACLS --add --allow-principal "$ROUTER" --producer \
    --topic netops.deadletter >/dev/null
# Scale P0: the router is the flows re-key hop — it consumes goflow2's raw
# feed (netops.flows.raw, Read above) and republishes it tenant-keyed onto
# netops.flows for the co-partitioned correlation consumers.
$ACLS --add --allow-principal "$ROUTER" --producer \
    --topic netops.flows >/dev/null
$ACLS --add --allow-principal "$ROUTER" --operation Read \
    --group netops-router- --resource-pattern-type prefixed >/dev/null

# A4 Phase 1: the aggregator's WRITE on netops.syslog.control needs no grant
# of its own — the bus-bridge `--producer --topic netops. --resource-pattern-type
# prefixed` ACL above already covers every netops.* topic, and adding a
# redundant literal ACL would imply the prefixed one does not apply.
#
# vector-router is deliberately NOT granted Read on netops.syslog.control: it
# indexes the FULL syslog lane from netops.syslog, and a second consumer would
# duplicate every admitted document into OpenSearch.
echo "acls: correlation — consume-only on its 13 topics + its one group" >&2
for t in netops.syslog netops.syslog.control \
         netops.flows netops.metrics netops.probes \
         netops.snmptrap netops.cloud netops.app.identities.v1 \
         netops.controller_events netops.app.edge netops.verification \
         netops.wireless_sessions netops.wireless_events; do
    $ACLS --add --allow-principal "$CORR" \
        --operation Read --operation Describe --topic "$t" >/dev/null
done
$ACLS --add --allow-principal "$CORR" --operation Read \
    --group netops-correlation >/dev/null

echo "acls: kafka-exporter — describe-only" >&2
$ACLS --add --allow-principal "$EXPORTER" --operation Describe \
    --topic netops. --resource-pattern-type prefixed >/dev/null
$ACLS --add --allow-principal "$EXPORTER" --operation Describe \
    --group netops- --resource-pattern-type prefixed >/dev/null

echo "acls: ANONYMOUS (goflow2/FLOWS) — produce netops.flows.raw ONLY" >&2
$ACLS --add --allow-principal "User:ANONYMOUS" \
    --operation Write --operation Describe --topic netops.flows.raw >/dev/null
# Scale P0 retirement: goflow2 moved to netops.flows.raw; the keyed
# netops.flows is now written ONLY by the router (and the aggregator's
# prefixed bus-bridge grant). --remove is idempotent (removing an absent ACL
# is a no-op), so this converges like the interim-grant retirements below.
$ACLS --remove --force --allow-principal "User:ANONYMOUS" \
    --operation Write --operation Describe --topic netops.flows >/dev/null

CLOUDINGEST="User:$SA/cloud-ingest"

echo "acls: cloud-ingest — produce its three cloud lanes (client 6/6)" >&2
for t in netops.cloud netops.cloudcosts netops.cloudlogs; do
    $ACLS --add --allow-principal "$CLOUDINGEST" --producer --topic "$t" >/dev/null
done

# RETIREMENT (2026-08-06, task #9): the interim ANONYMOUS grants that bridged
# the two clients the SEC-006.2 list missed are now REMOVED — cloud-ingest
# produces on the mTLS listener with its own SVID (above), and rca-canary
# injects through the aggregator's authenticated bus lane. --remove is
# idempotent (removing an absent ACL is a no-op), so this converges: after
# the grants are gone, re-running neither re-adds nor errors. The 2026-08-05
# lesson stands in the history: allow.everyone.if.no.acl.found is
# per-resource — a topic's first ACL is enforcement against everyone not
# named on it.
echo "acls: RETIRING interim ANONYMOUS grants (cloud lanes + canary topics)" >&2
for t in netops.cloud netops.cloudcosts netops.cloudlogs netops.probes netops.app.edge; do
    $ACLS --remove --force --allow-principal "User:ANONYMOUS" \
        --operation Write --operation Describe --topic "$t" >/dev/null
done

# ---- verification (§16.1: no blind success) --------------------------------
# Every --add above already fails the run via set -e, but read the state BACK:
# an installer that reports success over an empty/partial matrix is exactly
# the auth-dead-bus defect this script exists to prevent. Assert one
# load-bearing principal/topic pair (the router's deadletter grant) plus a
# count floor over the whole store.
VERIFY=$($ACLS --list --topic netops.deadletter) || {
    echo "acls: FATAL: could not list ACLs back after applying — matrix state unknown" >&2
    exit 1
}
case "$VERIFY" in
*"$ROUTER"*) : ;;
*)
    echo "acls: FATAL: router grant missing from netops.deadletter after apply —" >&2
    echo "acls: the matrix did not take; the bus would be auth-dead" >&2
    exit 1
    ;;
esac
# grep -c exits 1 on zero matches; a zero count is caught by the floor below,
# not swallowed (§16.1) — the || true only neutralizes that documented exit.
COUNT=$($ACLS --list | grep -c "principal=" || true)
FLOOR=40
if [ "$COUNT" -lt "$FLOOR" ]; then
    echo "acls: FATAL: only $COUNT ACL entries live (< $FLOOR) — partial matrix" >&2
    exit 1
fi
echo "acls: matrix applied and verified — $COUNT ACL entries live" >&2
echo "acls: (enforce posture: allow.everyone.if.no.acl.found=false since SEC-007.2)" >&2
