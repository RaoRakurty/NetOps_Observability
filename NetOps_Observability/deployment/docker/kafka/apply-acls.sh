#!/bin/sh
# apply-acls.sh — SEC-007.1: the per-identity Kafka ACL matrix.
#
# Runs INSIDE the kafka container (the only place kafka-acls.sh lives):
#   docker compose exec kafka /acls/apply-acls.sh
# Idempotent: kafka-acls --add of an existing ACL is a no-op, so re-running
# converges (safe after every broker rebuild or identity change).
#
# POSTURE: this script only WRITES the matrix. Enforcement is
# allow.everyone.if.no.acl.found, which stays TRUE (observe) until the
# SEC-007.2 flip — after a quiet observation window, per the runbook. In
# observe mode a principal missing from this matrix keeps working and the
# authorizer DEBUG log shows the fallback being used; after the flip it is
# denied outright.
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
#   vector-router      consume  its 7 lanes; produce netops.deadletter;
#                      groups netops-router-* (prefixed)
#   correlation        consume  its 12 topics; group netops-correlation
#   kafka-exporter     describe netops.* topics + netops-* groups (lag math
#                      is ListOffsets/OffsetFetch = Describe on both)
#   ANONYMOUS          produce  netops.flows ONLY — goflow2 on the FLOWS
#                      listener (no client-cert capability; owner decision
#                      2026-08-05). NOTE: until the PLAINTEXT listener dies
#                      (SEC-006.3), everything on :9092 is also ANONYMOUS —
#                      the flip to enforce narrows that blast radius to
#                      exactly this one topic.
set -eu

BOOTSTRAP="${KAFKA_BOOTSTRAP:-localhost:9092}"
ACLS="/opt/kafka/bin/kafka-acls.sh --bootstrap-server $BOOTSTRAP"

SA="CN=spiffe://netops/ns/default/sa"
AGG="User:$SA/vector-aggregator"
ROUTER="User:$SA/vector-router"
CORR="User:$SA/correlation"
EXPORTER="User:$SA/kafka-exporter"

echo "acls: aggregator — produce on netops.* (prefixed, bus-bridge role)" >&2
$ACLS --add --allow-principal "$AGG" --producer \
    --topic netops. --resource-pattern-type prefixed >/dev/null

echo "acls: router — consume its lanes, produce deadletter, own its groups" >&2
for t in netops.applogs netops.syslog netops.flows netops.snmptrap \
         netops.cloudlogs netops.cloudcosts netops.deadletter; do
    $ACLS --add --allow-principal "$ROUTER" \
        --operation Read --operation Describe --topic "$t" >/dev/null
done
$ACLS --add --allow-principal "$ROUTER" --producer \
    --topic netops.deadletter >/dev/null
$ACLS --add --allow-principal "$ROUTER" --operation Read \
    --group netops-router- --resource-pattern-type prefixed >/dev/null

echo "acls: correlation — consume-only on its 12 topics + its one group" >&2
for t in netops.syslog netops.flows netops.metrics netops.probes \
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

echo "acls: ANONYMOUS (goflow2/FLOWS) — produce netops.flows ONLY" >&2
$ACLS --add --allow-principal "User:ANONYMOUS" \
    --operation Write --operation Describe --topic netops.flows >/dev/null

# INTERIM (2026-08-05, expires with cloud-ingest's mTLS cutover): cloud-ingest
# is a DIRECT kafka producer on the plaintext listener that the SEC-006.2
# client list MISSED — the same service F-08 missed for the shared token; its
# own source says so ("cloud-ingest was the missed producer"). The moment the
# matrix landed, its lanes' ACLs disabled the per-RESOURCE allow-everyone
# fallback and every ANONYMOUS produce was DENIED (17k+ denials, cloudcosts
# lane dark ~25min). LESSON, recorded hard: allow.everyone.if.no.acl.found
# is per-resource — "observe posture" only observes resources with NO ACLs;
# writing an ACL for a topic IS enforcement against every principal not
# named on it. These grants restore the lanes until cloud-ingest presents a
# real identity (client 6/6); then DELETE them.
echo "acls: ANONYMOUS INTERIM — cloud-ingest lanes until its mTLS cutover" >&2
for t in netops.cloud netops.cloudcosts netops.cloudlogs; do
    $ACLS --add --allow-principal "User:ANONYMOUS" \
        --operation Write --operation Describe --topic "$t" >/dev/null
done

# INTERIM (same class, same expiry logic): scripts/rca-canary.sh injects its
# two known failure events via kafka-console-producer on :9092 — ANONYMOUS.
# The matrix broke it the same way it broke cloud-ingest (the canary paged
# "bus→normalizer→CH path broken" within 15 minutes — working exactly as
# designed). Until the canary produces through an authenticated path (the
# aggregator's HTTP ingest lanes, or an mTLS client config), its two topics
# carry ANONYMOUS Write; then DELETE these with the block above.
echo "acls: ANONYMOUS INTERIM — rca-canary injection topics" >&2
for t in netops.probes netops.app.edge; do
    $ACLS --add --allow-principal "User:ANONYMOUS" \
        --operation Write --operation Describe --topic "$t" >/dev/null
done

COUNT=$($ACLS --list 2>/dev/null | grep -c "principal=" || true)
echo "acls: matrix applied — $COUNT ACL entries live (observe posture; the" >&2
echo "acls: SEC-007.2 flip to allow.everyone=false is a separate, soaked step)" >&2
