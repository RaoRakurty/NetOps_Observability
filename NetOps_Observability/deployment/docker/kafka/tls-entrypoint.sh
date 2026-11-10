#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# tls-entrypoint.sh — Kafka broker TLS bootstrap (SEC-006.1).
#
# Same wrapper family as postgres/clickhouse tls-entrypoint.sh, with a
# different job: Kafka's PEM keystore (ssl.keystore.type=PEM +
# ssl.keystore.location) requires the private key and certificate chain
# CONCATENATED IN ONE FILE, while the internal CA mints them split
# (kafka.key + kafka.crt under /data/tls/services/kafka). The apache/kafka image
# runs as appuser (uid 1000), and the key is 0640 under the api's uid and gid:
# compose.tls.yml gives this container that gid through group_add. A "Permission
# denied" here means that group_add is missing or CORRELIX_GID changed. This
# stages into /tmp, the only dir this uid owns.
#
# FAIL-CLOSED: only TLS-enabled deployments mount this wrapper; missing cert
# material means refusing to start, never silently serving plaintext-only.
# First-enablement ordering (the postgres lesson): the api must have minted
# /data/tls/services/kafka BEFORE this wrapper is enabled.
set -eu

SRC="${KAFKA_TLS_SRC:-/certs-src}"
DST=/tmp/kafka-tls

# A directory this uid cannot enter makes every file below look absent, which
# would send the operator after the mint instead of the missing group (seen in the
# 2026-11-09 wrong-order upgrade proof). Name it first.
if [ -d "$SRC" ] && [ ! -x "$SRC" ]; then
    echo "tls-entrypoint: FATAL: uid $(id -u) (groups: $(id -G)) cannot enter $SRC." >&2
    echo "The kafka key directory is 0750 under the api's uid and gid: this container" >&2
    echo "needs CORRELIX_GID through group_add (compose.tls.yml). Recreate it: docker compose up -d kafka" >&2
    exit 78 # EX_CONFIG
fi
if [ ! -r "$SRC/kafka.key" ] && [ -f "$SRC/kafka.key" ]; then
    echo "tls-entrypoint: FATAL: $SRC/kafka.key is not readable by uid $(id -u) (groups: $(id -G))." >&2
    echo "It is 0640 under the api's gid: this container needs CORRELIX_GID through group_add." >&2
    exit 78 # EX_CONFIG
fi
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

# Admin-plane client config (2026-08-06, pre-SEC-007.2): the broker's own SVID
# is the KAFKA_SUPER_USERS principal AND carries clientAuth, so every in-
# container admin exec (rotate-tls dynamic keystore re-set, consumer-group
# diagnostics, console tools) authenticates on MTLS:9094 with this file
# instead of riding 9092-as-ANONYMOUS — which goes blind at the default-deny
# flip and dies with the 9092 listener. Written here so the paths can never
# drift from the staging above.
cat > "$DST/admin.properties" <<EOF
security.protocol=SSL
ssl.keystore.type=PEM
ssl.keystore.location=$DST/keystore.pem
ssl.truststore.type=PEM
ssl.truststore.location=$DST/truststore.pem
EOF
echo "tls-entrypoint: admin-plane client config written to $DST/admin.properties (MTLS:9094, broker SVID = super-user)" >&2

# "$@" is the image CMD (/etc/kafka/docker/run); the stock entrypoint chain
# is preserved underneath.
exec /__cacert_entrypoint.sh "$@"
