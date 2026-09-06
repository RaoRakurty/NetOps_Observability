// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package oslog is the OpenSearch log-search projection core (Phase-2 W3.6,
// extracted from package main's logs.go): index-pattern algebra (heavily
// commented as a CONTRACT with vector.yaml), the per-tenant index segment,
// the app-log pattern gate, the per-doc tenant filter DSL with
// restricted-tenant exclusion, and the flexible time parser. The scope
// resolver (claims/visibility), the env-configured OpenSearch client and the
// handlers stay in main.
package oslog

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func IndexBase(signal string) string {
	switch strings.ToLower(signal) {
	case "applogs", "app":
		return "netops-applogs"
	case "syslog":
		return "netops-syslog"
	case "snmptrap", "trap", "traps":
		return "netops-snmptrap"
	case "flows", "netflow", "flow":
		return "netops-flows"
	case "cloud", "cloudlogs", "cloudlog":
		// Tagged raw cloud logs (waf/lb/dns/flow/host/change/inventory), written
		// by the cloud poller + aggregator into netops-cloudlogs-{tenant}-{date}.
		return "netops-cloudlogs"
	case "secfindings", "security":
		// Security findings (P3-L1, SECURITY_FINDINGS_STORE_DECISION 2026-08-28):
		// the durable, append-only verdict store the router writes from the
		// netops.security topic into netops-secfindings-{tenant}-{date}. It is
		// deliberately NOT part of the "" / "all" log search (it is verdict data,
		// not log lines) and is reachable only through this explicit signal.
		return "netops-secfindings"
	default:
		return "netops"
	}
}

// tenantSegRe strips any character not allowed in an OpenSearch index segment.
// normTenantSeg mirrors main's tenant normalization (duplicated).
func normTenantSeg(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

var tenantSegRe = regexp.MustCompile(`[^a-z0-9_-]`)

// IndexTenantSeg sanitizes a tenant id into the per-tenant index segment. It MUST
// match the derivation in deployment/docker/vector-router/vector.yaml (#20 Phase
// 3) so reads name the same indices ingest writes. "" → "untagged".
func IndexTenantSeg(tenant string) string {
	seg := strings.ToLower(strings.TrimSpace(tenant))
	if seg == "" {
		return "untagged"
	}
	return tenantSegRe.ReplaceAllString(seg, "-")
}

// TenantIndexPattern returns the comma-separated OpenSearch index pattern a caller
// may read for a signal (#20 Phase 3 — at-rest separation). The platform owner
// (cross) reads every tenant's indices; a scoped tenant reads ONLY its own tagged
// indices plus the shared untagged indices (where the per-doc device matcher in
// TenantFilter still narrows results — the populate-time fallback, mirroring the
// ClickHouse row policy). Another tenant's indices are never named, so its docs
// are unreachable even if the query filter is ever dropped.
// appLogPatternAllowed is the defense-in-depth chokepoint for the platform↔tenant
// boundary: a non-platform-owner may NEVER read the platform's app-log indices,
// regardless of how the index pattern was built. Returns false (deny) when a
// non-owner's resolved pattern references any applogs index. Used by both the
// interactive search and the export path so the rule is enforced identically.
func AppLogPatternAllowed(index string, platformOwner bool) bool {
	return platformOwner || !strings.Contains(index, "applogs")
}

func TenantIndexPattern(signal, tenant string, cross bool) string {
	// Empty/"all" = LOG signals only (device syslog + SNMP traps). Flows are
	// deliberately EXCLUDED from "all": they're 5-tuple telemetry records (no
	// message/level), they outnumber real logs by ~1000:1, and a flat
	// timestamp-sorted top-N "all" view drowns out sparse-but-important log
	// sources (e.g. firewall/fw_logs records in syslog) behind a wall of flows.
	// Flows remain reachable via the explicit signal="flows" filter. App logs are
	// the platform's own internal container/API logs — they must NEVER appear in an
	// "all" search; they're reachable ONLY via signal="applogs", gated to the
	// platform owner in the handler.
	if s := strings.ToLower(strings.TrimSpace(signal)); s == "" || s == "all" {
		bases := []string{"netops-syslog", "netops-snmptrap"}
		parts := make([]string, 0, len(bases)*2)
		for _, b := range bases {
			if cross {
				parts = append(parts, b+"-*")
			} else {
				parts = append(parts, b+"-"+IndexTenantSeg(tenant)+"-*", b+"-untagged-*")
			}
		}
		return strings.Join(parts, ",")
	}
	base := IndexBase(signal)
	if cross {
		return base + "-*"
	}
	return base + "-" + IndexTenantSeg(tenant) + "-*," + base + "-untagged-*"
}

// TenantCatPattern is the _cat/indices pattern a caller may enumerate: all
// netops-* for the platform owner; only the caller's own + untagged indices
// (across signals) for a scoped tenant, so index names/counts don't leak.
func TenantCatPattern(tenant string, cross bool) string {
	if cross {
		return "netops-*"
	}
	seg := IndexTenantSeg(tenant)
	// App logs are platform-owner only (handled in the search path) — a scoped
	// tenant doesn't even enumerate their index names. Device telemetry signals
	// (syslog, snmp traps, flows) plus tagged cloud logs are tenant-visible
	// (own + untagged-from-own-devices).
	bases := []string{"netops-syslog", "netops-snmptrap", "netops-flows", "netops-cloudlogs"}
	parts := make([]string, 0, len(bases)*2)
	for _, b := range bases {
		parts = append(parts, b+"-"+seg+"-*", b+"-untagged-*")
	}
	return strings.Join(parts, ",")
}

// TenantFilter builds the OpenSearch query clause enforcing per-tenant isolation
// for a scoped caller (#20 Phase 3), mirroring chTenantScope's ClickHouse policy:
// a doc is visible iff its tenant_id == the caller's tenant, OR it is untagged
// (tenant_id "" / missing) AND was emitted by one of the caller's devices
// (host/hostname/source_ip). Returns nil for the platform owner (cross) — no
// restriction. It is defense in depth UNDER TenantIndexPattern (which already
// excludes other tenants' indices at the storage layer).
func TenantFilter(tenant string, cross bool, deviceKeys, deviceAddrs []string) map[string]any {
	if cross {
		return nil
	}
	var dev []any
	if len(deviceKeys) > 0 {
		dev = append(dev,
			map[string]any{"terms": map[string]any{"host": deviceKeys}},
			map[string]any{"terms": map[string]any{"hostname": deviceKeys}},
		)
	}
	if len(deviceAddrs) > 0 {
		dev = append(dev, map[string]any{"terms": map[string]any{"source_ip": deviceAddrs}})
	}
	if len(dev) == 0 {
		dev = append(dev, map[string]any{"match_none": map[string]any{}})
	}
	untagged := map[string]any{"bool": map[string]any{
		"should": []any{
			map[string]any{"term": map[string]any{"tenant_id": ""}},
			map[string]any{"bool": map[string]any{"must_not": []any{
				map[string]any{"exists": map[string]any{"field": "tenant_id"}},
			}}},
		},
		"minimum_should_match": 1,
	}}
	return map[string]any{"bool": map[string]any{
		"should": []any{
			map[string]any{"term": map[string]any{"tenant_id": normTenantSeg(tenant)}},
			map[string]any{"bool": map[string]any{"must": []any{
				untagged,
				map[string]any{"bool": map[string]any{"should": dev, "minimum_should_match": 1}},
			}}},
		},
		"minimum_should_match": 1,
	}}
}

func QueryOrAll(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return "*"
	}
	return q
}

// openSearch is a tiny HTTP client wrapper for the OpenSearch cluster.
// Auth would go here once DISABLE_SECURITY_PLUGIN is flipped off.
func ParseTimeFlexible(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 1_000_000_000_000_000 {
			return time.Unix(0, n).UTC(), nil
		}
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %q", s)
}
