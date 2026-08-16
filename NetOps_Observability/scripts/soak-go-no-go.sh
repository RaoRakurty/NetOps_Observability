#!/usr/bin/env bash
# soak-go-no-go.sh — the SEC-007.2 enforce-flip gate (tracker #151).
#
# Reviews the Kafka authorizer soak window and answers GO or NO-GO for the
# enforce wave (docs/runbooks/tls-enforce-wave.md). The soak signal is actual
# DENIED decisions in the authorizer log (INFO level — lesson (l): DEBUG's
# allowed-decision flood is not a signal, it is a disk-filler) plus any
# Kafka-class alert that fired.
#
# Exit codes are three-valued ON PURPOSE — a broken check must never read as
# a quiet soak:
#   0 = GO      (zero denials, zero kafka alerts firing)
#   1 = NO-GO   (denials or alerts found; printed for classification)
#   2 = CHECK FAILED (could not read the log or the alert feed)
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin

fail_check() { echo "[soak] CHECK FAILED: $*" >&2; exit 2; }

command -v docker >/dev/null || fail_check "docker not on PATH"
docker inspect netops-kafka-1 >/dev/null 2>&1 || fail_check "netops-kafka-1 not present"

# Authorizer denials over the whole retained log window (json-file 50m x 3 —
# the same cap that bounds this read). rc of the pipeline is inspected: grep
# exiting 1 (no match) is the GOOD outcome, not an error to hide.
log_out=$(docker logs netops-kafka-1 2>&1) || fail_check "docker logs netops-kafka-1 failed"
denials=$(printf '%s\n' "$log_out" | { grep -iE "denied" || true; } | { grep -viE "allowed" || true; })

# Kafka-class alerts currently firing, from vmalert's own API (no credentials
# needed inside the container).
alerts_json=$(docker exec netops-vmalert-1 wget -qO- http://127.0.0.1:8880/api/v1/alerts) \
    || fail_check "vmalert alert feed unreachable"
kafka_alerts=$(printf '%s\n' "$alerts_json" | { grep -oE '"name":"Kafka[A-Za-z]+"' || true; } | sort -u)

echo "[soak] window: the broker's retained log (json-file cap bounds it)"
if [ -n "$denials" ]; then
    echo "[soak] DENIALS FOUND:"
    printf '%s\n' "$denials" | tail -50
fi
if [ -n "$kafka_alerts" ]; then
    echo "[soak] KAFKA ALERTS FIRING:"
    printf '%s\n' "$kafka_alerts"
fi

if [ -z "$denials" ] && [ -z "$kafka_alerts" ]; then
    echo "[soak] GO — zero authorizer denials, zero kafka alerts. Proceed per docs/runbooks/tls-enforce-wave.md"
    exit 0
fi
echo "[soak] NO-GO — classify each denial (missing grant -> deployment/docker/kafka/apply-acls.sh; unexpected principal -> investigate) before the flip"
exit 1
