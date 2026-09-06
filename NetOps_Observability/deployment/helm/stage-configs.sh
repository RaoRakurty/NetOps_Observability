#!/usr/bin/env bash
# stage-configs.sh — mirror the canonical stack configuration into the Helm
# chart's files/ directory.
#
# WHY THIS EXISTS
# ---------------
# Helm cannot read a file outside the chart root, so a chart that renders
# ConfigMaps for the pipeline configuration must carry its own copies. A chart
# that cannot render its own ConfigMaps is not a chart — it is a fragment that
# only works next to a checkout — so the copies are CHECKED IN and this script
# is the ONLY supported way to refresh them.
#
# Same shape as scripts/sync-docs-corpus.sh + ai/docs_corpus_drift_test.go:
# a checked-in mirror plus a drift gate. Here the gate is
# tests/test_helm_chart.py::test_staged_configs_match_canonical_sources, which
# fails whenever a canonical file changes and this script was not re-run.
#
# THE ONE DELIBERATE DIFFERENCE. deployment/docker/nginx/default.conf pins
# `resolver 127.0.0.11` — Docker's embedded DNS, which does not exist in a
# Kubernetes pod. The staged copy rewrites exactly that one directive to the
# cluster DNS service; every other byte is identical, and the drift test
# asserts that the single-line rewrite is the ONLY difference.
#
# Usage:  bash deployment/helm/stage-configs.sh   [--check]
#         --check  report drift and exit 1 without writing (what CI runs)
#
# Style contract: NetOps_Observability/scripts/CLAUDE.md §16.1 (never swallow an
# error), §16.2 (explicit PATH, nothing sourced), §16.3 (set -euo pipefail,
# quoted expansions, idempotent, dry-run before writing).
set -euo pipefail

# §16.2: assume the hostile minimal environment; name the PATH explicitly.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(cd "$HERE/../.." && pwd)"
DST="$HERE/correlix/files"

CHECK=0
case "${1:-}" in
    --check) CHECK=1 ;;
    "")      ;;
    *)       printf 'usage: %s [--check]\n' "$0" >&2; exit 2 ;;
esac

# The Docker embedded-DNS resolver the compose gateway uses, and the in-cluster
# replacement. kube-dns is the Service name of CoreDNS in every conformant
# cluster; `ipv6=off` is kept because the upstream file sets it.
DOCKER_RESOLVER='resolver 127.0.0.11 valid=10s ipv6=off;'
K8S_RESOLVER='resolver kube-dns.kube-system.svc.cluster.local valid=10s ipv6=off;'

# canonical-relative-path  ->  staged-relative-path
# Only files the chart actually mounts. A file listed here that does not exist
# is a hard error: a silently-skipped source is a ConfigMap that renders empty.
MAP=(
    "src/config/rules.yaml|config/rules.yaml"
    "src/config/rules-scale-slo.yaml|config/rules-scale-slo.yaml"
    "src/config/vmscrape.yml|config/vmscrape.yml"
    "src/config/vmauth.yml|config/vmauth.yml"
    "src/config/config.yaml|config/config.yaml"
    "src/config/devices.yaml|config/devices.yaml"
    "src/config/snmp_profiles.json|config/snmp_profiles.json"
    "src/config/gnmi_fidelity.yaml|config/gnmi_fidelity.yaml"
    "deployment/docker/vector/vector.yaml|vector/vector.yaml"
    "deployment/docker/vector/cx-enrichment-reload.sh|vector/cx-enrichment-reload.sh"
    "deployment/docker/vector/generated/syslog-admission.vrl|vector/syslog-admission.vrl"
    "deployment/docker/vector-router/vector.yaml|vector-router/vector.yaml"
    "deployment/docker/vector-router/processors-default.yaml|vector-router/processors-default.yaml"
    "deployment/docker/vector-router/cx-secret-backend.sh|vector-router/cx-secret-backend.sh"
    "deployment/docker/gnmic/gnmic.yaml|gnmic/gnmic.yaml"
    "deployment/docker/kafka/apply-acls.sh|kafka/apply-acls.sh"
    "deployment/docker/syslog-ng/syslog-ng.conf|syslog-ng/syslog-ng.conf"
    "deployment/docker/nginx/nginx.conf|nginx/nginx.conf"
    "deployment/docker/clickhouse/init.sql|clickhouse/init.sql"
    "deployment/docker/clickhouse/custom-settings.xml|clickhouse/custom-settings.xml"
    "deployment/docker/clickhouse/prometheus.xml|clickhouse/prometheus.xml"
    "deployment/docker/clickhouse/memory.xml|clickhouse/memory.xml"
    "deployment/docker/clickhouse/system-logs.xml|clickhouse/system-logs.xml"
    "deployment/docker/clickhouse/logger.xml|clickhouse/logger.xml"
    "deployment/docker/clickhouse/query-spill.xml|clickhouse/query-spill.xml"
    "deployment/docker/clickhouse/workload-profiles.xml|clickhouse/workload-profiles.xml"
    "deployment/docker/opensearch/apply-ism.sh|opensearch/apply-ism.sh"
    "deployment/docker/opensearch/index-templates.json|opensearch/index-templates.json"
)
# Rendered through the resolver rewrite rather than copied byte-for-byte.
REWRITTEN="deployment/docker/nginx/default.conf|nginx/default.conf"

drift=0
staged=0

# Emit the staged form of one canonical file on stdout.
render() {  # canonical-abs-path, canonical-rel-path
    if [ "$2" = "deployment/docker/nginx/default.conf" ]; then
        # §16.1: a rewrite that matched nothing would silently stage a config
        # whose resolver still points at Docker's DNS, so the caller CHECKS the
        # substitution happened rather than trusting sed's exit status (sed
        # exits 0 when a pattern does not match).
        sed "s|^\( *\)${DOCKER_RESOLVER}\$|\1${K8S_RESOLVER}|" "$1"
    else
        cat "$1"
    fi
}

process() {  # canonical-rel, staged-rel
    local src="$PROJ/$1" dst="$DST/$2" tmp
    if [ ! -f "$src" ]; then
        printf 'stage-configs: canonical source missing: %s\n' "$1" >&2
        return 1
    fi
    tmp="$(mktemp "${TMPDIR:-/tmp}/stage-configs.XXXXXX")"
    # shellcheck disable=SC2064  # expand $tmp now, on purpose
    trap "rm -f '$tmp'" RETURN
    render "$src" "$1" > "$tmp"

    if [ "$1" = "deployment/docker/nginx/default.conf" ]; then
        if ! grep -qF "$K8S_RESOLVER" "$tmp"; then
            printf 'stage-configs: the nginx resolver rewrite matched nothing in %s — the upstream directive changed; update DOCKER_RESOLVER in this script\n' "$1" >&2
            return 1
        fi
    fi

    if [ -f "$dst" ] && cmp -s "$tmp" "$dst"; then
        return 0
    fi
    drift=$((drift + 1))
    if [ "$CHECK" -eq 1 ]; then
        printf '  DRIFT  %s -> %s\n' "$1" "$2"
        return 0
    fi
    mkdir -p "$(dirname "$dst")"
    cat "$tmp" > "$dst"
    # Preserve the executable bit: two of these are entrypoint scripts, and a
    # ConfigMap mount cannot restore a mode the source did not have.
    if [ -x "$src" ]; then chmod +x "$dst"; fi
    staged=$((staged + 1))
    printf '  staged %s\n' "$2"
}

for pair in "${MAP[@]}" "$REWRITTEN"; do
    process "${pair%%|*}" "${pair##*|}"
done

if [ "$CHECK" -eq 1 ]; then
    if [ "$drift" -ne 0 ]; then
        printf 'stage-configs: %d staged file(s) differ from their canonical source. Run: bash deployment/helm/stage-configs.sh\n' "$drift" >&2
        exit 1
    fi
    printf 'stage-configs: %d staged file(s) match their canonical sources\n' "$(( ${#MAP[@]} + 1 ))"
    exit 0
fi

printf 'stage-configs: %d file(s) written, %d already current\n' "$staged" "$(( ${#MAP[@]} + 1 - staged ))"
