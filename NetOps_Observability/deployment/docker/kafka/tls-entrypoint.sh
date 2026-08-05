#!/bin/sh
# tls-entrypoint.sh — Kafka broker TLS bootstrap (SEC-006.1).
#
# Same wrapper family as postgres/clickhouse tls-entrypoint.sh, with a
# different job: Kafka's PEM keystore (ssl.keystore.type=PEM +
# ssl.keystore.location) requires the private key and certificate chain
# CONCATENATED IN ONE FILE, while the internal CA mints them split
# (kafka.key + kafka.crt under /data/tls/services/kafka). No cross-uid
# problem here — the apache/kafka image runs as appuser (uid 1000) and the
# registry mints service material world-readable (TLS_SERVICE_KEY_MODE) —
# so this stages into /tmp, the only dir this uid owns.
#
# FAIL-CLOSED: only TLS-enabled deployments mount this wrapper; missing cert
# material means refusing to start, never silently serving plaintext-only.
# First-enablement ordering (the postgres lesson): the api must have minted
# /data/tls/services/kafka BEFORE this wrapper is enabled.
set -eu

SRC="${KAFKA_TLS_SRC:-/certs-src}"
DST=/tmp/kafka-tls

if [ ! -f "$SRC/kafka.crt" ] || [ ! -f "$SRC/kafka.key" ] || [ ! -f "$SRC/ca.pem" ]; then
    echo "tls-entrypoint: FATAL: $SRC/kafka.{crt,key} or ca.pem not found — the api's" >&2
    echo "TLS_SERVICE_CERT_ROOT issuance has not minted the kafka SVID yet." >&2
    echo "Refusing to start WITHOUT TLS on a deployment that asked for it." >&2
    exit 78 # EX_CONFIG
fi

mkdir -p "$DST"
umask 077
cat "$SRC/kafka.key" "$SRC/kafka.crt" > "$DST/keystore.pem"
cp "$SRC/ca.pem" "$DST/truststore.pem"
echo "tls-entrypoint: kafka broker SVID staged from $SRC (PEM keystore; SSL:9094 mTLS + FLOWS:9095 server-TLS)" >&2

# "$@" is the image CMD (/etc/kafka/docker/run); the stock entrypoint chain
# is preserved underneath.
exec /__cacert_entrypoint.sh "$@"
