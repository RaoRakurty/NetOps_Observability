#!/bin/sh
# tls-entrypoint.sh — Postgres server TLS bootstrap (SEC-011.1).
#
# The internal CA (api, SEC-003.3 registry) mints the postgres server SVID as
# uid 65532 with a 0600 key; Postgres refuses a key it does not own. This
# wrapper runs as root BEFORE the official image drops privileges: it copies
# the SVID to a postgres-owned location with the exact ownership/mode Postgres
# demands, then execs the stock entrypoint with ssl switched on.
#
# FAIL-CLOSED: this wrapper exists only on deployments that asked for TLS —
# if the cert material is missing, refusing to start is the correct outcome
# (a silent fall-back to plaintext would defeat the point). The base compose
# does not use this wrapper; fresh installs keep the documented plaintext
# baseline until the end-state installer question enables the mesh.
#
# Certs are re-issued by the api at ~TTL/2. Postgres reads the key ONCE at
# startup (and on SIGHUP for the cert): the deployment reloads postgres via
# `docker kill -s HUP` from the rotation hook, or relies on the 24h TTL being
# far longer than routine restart cadence. (SEC-019.1 formalizes rotation.)
set -eu

SRC="${PG_TLS_SRC:-/certs-src}"
DST=/var/lib/postgresql/tls

if [ ! -f "$SRC/postgres.crt" ] || [ ! -f "$SRC/postgres.key" ]; then
    echo "tls-entrypoint: FATAL: $SRC/postgres.{crt,key} not found — the api's" >&2
    echo "TLS_SERVICE_CERT_ROOT issuance has not minted the postgres SVID yet." >&2
    echo "Refusing to start WITHOUT TLS on a deployment that asked for it." >&2
    exit 78 # EX_CONFIG
fi

mkdir -p "$DST"
cp "$SRC/postgres.crt" "$DST/server.crt"
cp "$SRC/postgres.key" "$DST/server.key"
chown -R postgres:postgres "$DST"
chmod 640 "$DST/server.crt"
chmod 600 "$DST/server.key"
echo "tls-entrypoint: postgres server SVID staged from $SRC (ssl=on)" >&2

# F-4 (TLS assurance run 2026-08-09): `host` matches SSL AND non-SSL, so the
# initdb/image default `host all all all scram-sha-256` accepted plaintext TCP
# from the compose network — TLS was client-side convention only, and a
# credentialed client could put password + rows on the wire. On a TLS
# deployment the network row must be `hostssl`: a non-TLS connection is then
# refused BEFORE any auth exchange. The wrapper OWNS the hba file (passed via
# -c hba_file below) rather than sed-editing PGDATA's copy, so the policy does
# not depend on initdb having run first and survives re-inits. The local +
# loopback rows mirror the image's initdb defaults: in-container access
# (healthcheck, psql exec) is inside the container boundary.
HBA="$DST/pg_hba.conf"
cat > "$HBA" <<'EOF'
# WRITTEN BY tls-entrypoint.sh — do not edit (regenerated every start).
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
local   replication     all                                     trust
host    replication     all             127.0.0.1/32            trust
host    replication     all             ::1/128                 trust
# Network access requires TLS: hostssl, never host (F-4 / SEC-011).
hostssl all             all             all                     scram-sha-256
EOF
chown postgres:postgres "$HBA"
chmod 600 "$HBA"
echo "tls-entrypoint: pg_hba staged — network access is hostssl-only (F-4)" >&2

# Compose passes the service's `command:` as "$@", and ours begins with the
# binary name ("postgres -c shared_buffers=..."). Absorb that leading token so
# the resource-plan flags survive and the binary isn't named twice.
if [ "${1:-}" = "postgres" ]; then
    shift
fi
exec docker-entrypoint.sh postgres \
    -c ssl=on \
    -c ssl_cert_file="$DST/server.crt" \
    -c ssl_key_file="$DST/server.key" \
    -c hba_file="$HBA" \
    "$@"
