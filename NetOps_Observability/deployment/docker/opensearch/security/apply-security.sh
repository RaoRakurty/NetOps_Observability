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

SEC_DIR=/usr/share/opensearch/plugins/opensearch-security
CONF_SRC=${SEC_CONF_SRC:-/security-config}
WORK=/tmp/netops-security
export OPENSEARCH_JAVA_HOME="${OPENSEARCH_JAVA_HOME:-/usr/share/opensearch/jdk}"

for v in OS_API_PASSWORD OS_ROUTER_PASSWORD OS_CORRELATION_PASSWORD \
         OS_BOOTSTRAP_PASSWORD OS_DASHBOARDS_PASSWORD OS_AGGREGATOR_PASSWORD; do
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
DEFAULTS=/usr/share/opensearch/config/opensearch-security
if [ ! -d "$DEFAULTS" ]; then
    echo "apply-security: FATAL: $DEFAULTS missing — cannot seed the config set" >&2
    exit 78
fi
cp "$DEFAULTS"/*.yml "$WORK/"
rm -f "$WORK/opensearch.yml.example"
cp "$CONF_SRC/roles.yml" "$CONF_SRC/roles_mapping.yml" "$WORK/"

hash_of() {
    # hash.sh prints the bcrypt hash on the last non-empty line.
    "$SEC_DIR/tools/hash.sh" -p "$1" 2>/dev/null | grep -v '^$' | tail -1
}

echo "apply-security: hashing service credentials ..." >&2
H_API=$(hash_of "$OS_API_PASSWORD")
H_ROUTER=$(hash_of "$OS_ROUTER_PASSWORD")
H_CORR=$(hash_of "$OS_CORRELATION_PASSWORD")
H_BOOT=$(hash_of "$OS_BOOTSTRAP_PASSWORD")
H_DASH=$(hash_of "$OS_DASHBOARDS_PASSWORD")
H_AGG=$(hash_of "$OS_AGGREGATOR_PASSWORD")
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
    -cacert "${OS_ADMIN_CA:-/usr/share/opensearch/config/tls/ca.pem}" \
    -cert "${OS_ADMIN_CERT:-/usr/share/opensearch/config/tls/admin.crt}" \
    -key "${OS_ADMIN_KEY:-/usr/share/opensearch/config/tls/admin.key}" \
    -h "${OS_HOST:-localhost}" -p "${OS_PORT:-9200}"

# Never leave plaintext-derived material behind.
rm -rf "$WORK"
echo "apply-security: security configuration applied (6 service identities)" >&2
