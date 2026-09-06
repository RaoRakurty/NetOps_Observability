#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# tls-entrypoint.sh — ClickHouse server TLS bootstrap (SEC-009.1).
#
# Same cross-uid problem and solution as postgres/tls-entrypoint.sh: the
# internal CA mints the clickhouse server SVID as uid 65532 with a 0600 key;
# ClickHouse runs as uid 101 (clickhouse) and must read it. This wrapper runs
# as root before the official image drops privileges: stage the SVID with
# clickhouse ownership, then exec the stock entrypoint. The dual-listener
# migration keeps :8123 plaintext alive until every client is cut over
# (tls.xml adds :8443; plaintext removal is the epic's final hardening step).
#
# FAIL-CLOSED: only TLS-enabled deployments mount this wrapper; missing cert
# material means refusing to start, never silently serving plaintext-only.
# First-enablement ordering (the postgres lesson): the api must have minted
# /data/tls/services/clickhouse BEFORE this wrapper is enabled.
set -eu

SRC="${CH_TLS_SRC:-/certs-src}"
DST=/etc/clickhouse-server/tls

if [ ! -f "$SRC/clickhouse.crt" ] || [ ! -f "$SRC/clickhouse.key" ]; then
    echo "tls-entrypoint: FATAL: $SRC/clickhouse.{crt,key} not found — the api's" >&2
    echo "TLS_SERVICE_CERT_ROOT issuance has not minted the clickhouse SVID yet." >&2
    echo "Refusing to start WITHOUT TLS on a deployment that asked for it." >&2
    exit 78 # EX_CONFIG
fi

mkdir -p "$DST"
cp "$SRC/clickhouse.crt" "$DST/server.crt"
cp "$SRC/clickhouse.key" "$DST/server.key"
chown -R clickhouse:clickhouse "$DST"
chmod 640 "$DST/server.crt"
chmod 600 "$DST/server.key"
echo "tls-entrypoint: clickhouse server SVID staged from $SRC (https_port 8443 via tls.xml)" >&2

exec /entrypoint.sh "$@"
