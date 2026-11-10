#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# apply-security.sh — SEC-008.1 security-config bootstrap.
#
# Runs INSIDE the opensearch container (the only place securityadmin.sh and
# the admin cert both exist). Generates internal_users.yml from the
# installer-provided per-service passwords (hashed with the plugin's own
# hash.sh — plaintext never lands in a file), then applies users + roles +
# mappings with securityadmin.sh.
#
# Idempotent: securityadmin overwrites the security index from these files,
# so re-running converges. Safe to re-run after every credential rotation.
#
# FAIL LOUD: any step failing exits non-zero with the reason. A half-applied
# security config is worse than none — it can lock every client out while
# leaving the operator believing bootstrap succeeded (§16.1).
set -eu

OS_HOME=${OS_HOME:-/usr/share/opensearch}
SEC_DIR=$OS_HOME/plugins/opensearch-security
CONF_SRC=${SEC_CONF_SRC:-/security-config}
WORK=/tmp/netops-security
export OPENSEARCH_JAVA_HOME="${OPENSEARCH_JAVA_HOME:-$OS_HOME/jdk}"
ADMIN_CA=${OS_ADMIN_CA:-$OS_HOME/config/tls/ca.pem}
ADMIN_CERT=${OS_ADMIN_CERT:-$OS_HOME/config/tls/admin.crt}
ADMIN_KEY=${OS_ADMIN_KEY:-$OS_HOME/config/tls/admin.key}
# Refuse a certificate this close to expiry: securityadmin takes seconds, and a
# handshake that fails halfway is a far worse message than this script's.
ADMIN_CERT_MARGIN_S=60

die() {
    echo "apply-security: FATAL: $*" >&2
    exit 78
}

# The image's home must be enterable by this uid. An image built before the 0750
# home (opensearch/Dockerfile) refuses every non-1000 uid, and without this check
# the failure surfaces as "config set missing", which names the wrong thing.
if [ ! -x "$OS_HOME" ]; then
    die "uid $(id -u) gid $(id -g) cannot enter $OS_HOME: this image predates the group-readable home. Rebuild it: docker compose build opensearch"
fi

# The admin material. The api mints it, so "missing" means the api has not run yet.
for f in "$ADMIN_CA" "$ADMIN_CERT" "$ADMIN_KEY"; do
    if [ ! -e "$f" ]; then
        die "$f is missing: the api mints the admin identity at boot and has not done so yet (or this uid cannot enter its directory). Start the api first: docker compose up -d api"
    fi
    if [ ! -r "$f" ]; then
        die "$f is not readable by uid $(id -u): the admin key is 0600 under CORRELIX_UID, so this job must run as CORRELIX_UID. Check CORRELIX_UID in .env against the owner of data/tls/admin"
    fi
done

# The api re-issues the admin certificate every TTL/2 while it runs. If the api
# has been down past the TTL this certificate has expired, and securityadmin
# would fail with a TLS error that names nothing. No openssl in this image, so
# the JDK's keytool reads the validity (public fields only; nothing is printed).
admin_cert_check() {
    keytool=$OPENSEARCH_JAVA_HOME/bin/keytool
    printed=$(LC_ALL=C "$keytool" -J-Duser.language=en -J-Duser.country=US \
            -printcert -file "$ADMIN_CERT" 2>&1) \
        || die "keytool could not read $ADMIN_CERT (exit $?), so its validity is unknown. The api re-mints it at boot: docker compose up -d api, then re-run this job"
    not_after=$(printf '%s\n' "$printed" | sed -n 's/^Valid from: .* until: //p' | head -n 1)
    if [ -z "$not_after" ]; then
        die "could not find the validity line in keytool's output for $ADMIN_CERT, so its validity is unknown (keytool format changed?)"
    fi
    if ! not_after_s=$(date -d "$not_after" +%s 2>/dev/null); then
        die "could not parse the admin certificate's expiry '$not_after'"
    fi
    now_s=$(date +%s)
    if [ "$not_after_s" -le "$((now_s + ADMIN_CERT_MARGIN_S))" ]; then
        die "admin certificate $ADMIN_CERT expired or expires within ${ADMIN_CERT_MARGIN_S}s (not after: $not_after). The api re-issues it only while running, so the api was down past its TTL. Start the api first, then re-run this job: docker compose up -d api && docker compose up opensearch-security-init"
    fi
}
admin_cert_check

for v in OS_API_PASSWORD OS_ROUTER_PASSWORD OS_CORRELATION_PASSWORD \
         OS_BOOTSTRAP_PASSWORD OS_DASHBOARDS_PASSWORD OS_AGGREGATOR_PASSWORD; do
    # Tracker 384: compose mounts one file per identity and names the directory.
    # The chart still supplies these through its Secret, so the environment form
    # stays. Exported for hash.sh -env, in this process tree only.
    if [ -n "${OS_SECRET_DIR:-}" ]; then
        if [ ! -r "$OS_SECRET_DIR/$v" ]; then
            echo "apply-security: FATAL: $OS_SECRET_DIR/$v is missing or unreadable — re-run scripts/install.py (it renders data/secrets)" >&2
            exit 78
        fi
        val=$(cat "$OS_SECRET_DIR/$v")
        eval "$v=\$val"
        # shellcheck disable=SC2163 # exporting the variable NAMED by $v
        export "$v"
    fi
    eval "val=\${$v:-}"
    if [ -z "$val" ]; then
        echo "apply-security: FATAL: $v is empty — refusing to bootstrap a role model with a blank credential" >&2
        exit 78
    fi
done

mkdir -p "$WORK"
# securityadmin -cd requires the COMPLETE config set (action_groups, tenants,
# nodes_dn, whitelist, config, audit ...), not just the files we customize.
# Seed from the plugin's shipped defaults, then overlay ours — so we own
# exactly three files and inherit the rest, which is also what keeps upgrades
# cheap (a new default file appears automatically).
DEFAULTS=$OS_HOME/config/opensearch-security
if [ ! -d "$DEFAULTS" ]; then
    echo "apply-security: FATAL: $DEFAULTS missing — cannot seed the config set" >&2
    exit 78
fi
cp "$DEFAULTS"/*.yml "$WORK/"
rm -f "$WORK/opensearch.yml.example"
cp "$CONF_SRC/roles.yml" "$CONF_SRC/roles_mapping.yml" "$WORK/"

hash_of() {
    # $1 names an exported variable: `-env` reads the value from the environment,
    # because `-p <password>` would put it on the java process's argv (tracker 384).
    # hash.sh prints the bcrypt hash on the last non-empty line.
    "$SEC_DIR/tools/hash.sh" -env "$1" 2>/dev/null | grep -v '^$' | tail -1
}

echo "apply-security: hashing service credentials ..." >&2
H_API=$(hash_of OS_API_PASSWORD)
H_ROUTER=$(hash_of OS_ROUTER_PASSWORD)
H_CORR=$(hash_of OS_CORRELATION_PASSWORD)
H_BOOT=$(hash_of OS_BOOTSTRAP_PASSWORD)
H_DASH=$(hash_of OS_DASHBOARDS_PASSWORD)
H_AGG=$(hash_of OS_AGGREGATOR_PASSWORD)
for h in "$H_API" "$H_ROUTER" "$H_CORR" "$H_BOOT" "$H_DASH" "$H_AGG"; do
    case "$h" in
        \$2*) : ;; # bcrypt
        *) echo "apply-security: FATAL: hash.sh did not return a bcrypt hash" >&2; exit 1 ;;
    esac
done

# internal_users.yml is GENERATED (never committed): hashes only, and the
# file lives in the container's tmpfs-scoped work dir, not a bind mount.
cat > "$WORK/internal_users.yml" <<EOF
---
_meta:
  type: "internalusers"
  config_version: 2

svc_api:
  hash: "$H_API"
  reserved: false
  description: "Correlix api (SEC-008)"

svc_router:
  hash: "$H_ROUTER"
  reserved: false
  description: "vector-router log ingest writer (SEC-008)"

svc_correlation:
  hash: "$H_CORR"
  reserved: false
  description: "correlation engine, read-only (SEC-008)"

svc_bootstrap:
  hash: "$H_BOOT"
  reserved: false
  description: "opensearch-init templates/ISM/snapshots (SEC-008)"

svc_dashboards:
  hash: "$H_DASH"
  reserved: false
  description: "OpenSearch Dashboards (SEC-008)"

svc_aggregator:
  hash: "$H_AGG"
  reserved: false
  description: "vector-aggregator F-17 stats scraper, cluster-monitor only (SEC-008)"
EOF

echo "apply-security: applying security configuration ..." >&2
"$SEC_DIR/tools/securityadmin.sh" \
    -cd "$WORK" \
    -icl -nhnv \
    -cacert "$ADMIN_CA" \
    -cert "$ADMIN_CERT" \
    -key "$ADMIN_KEY" \
    -h "${OS_HOST:-localhost}" -p "${OS_PORT:-9200}"

# Never leave plaintext-derived material behind.
rm -rf "$WORK"
echo "apply-security: security configuration applied (6 service identities)" >&2
