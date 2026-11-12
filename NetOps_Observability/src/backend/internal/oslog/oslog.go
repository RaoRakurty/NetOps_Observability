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
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/owner"
)

// SecFindingsIndexBase is the security-findings index family. It is exported so
// the log-search chokepoint can refuse this family by the base a signal RESOLVES
// TO rather than by a list of signal spellings: a new alias added to IndexBase
// below is then refused automatically instead of opening a new door.
const SecFindingsIndexBase = "netops-secfindings"

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
		// not log lines): the log-search chokepoint REFUSES this family outright
		// (review 2026-09-08, H9 — the free-form `signal` parameter used to reach
		// it with no permission and no licence check). The base is returned here
		// so secapi, which owns the gated read, can name the pattern.
		return SecFindingsIndexBase
	default:
		return CatchAllIndexBase
	}
}

// CatchAllIndexBase is what IndexBase answers for a signal it does not
// recognise. It is NOT a readable family: `netops-*` glob-matches EVERY index
// this stack writes, the security-findings and quarantine families included,
// so TenantIndexPattern never turns it into a pattern (review 2026-09-08, H9 —
// the named-signal refusal closed `signal=security`, and `signal=anything-else`
// still resolved a wildcard that reached the same documents for a cross-tenant
// caller, with no licence check).
const CatchAllIndexBase = "netops"

// IsSecFindingsSignal reports whether a caller-supplied log-search `signal`
// names the security-findings family, whatever its spelling.
//
// It asks IndexBase rather than comparing against a list of names, so an alias
// added there is covered here without a second edit. It TRIMS first (IndexBase
// does not), so a padded spelling cannot dodge the refusal — the same
// normalization the applogs gate applies.
func IsSecFindingsSignal(signal string) bool {
	return IndexBase(strings.TrimSpace(signal)) == SecFindingsIndexBase
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
	base := IndexBase(signal)
	// "", "all" and every UNRECOGNISED signal resolve here. An unrecognised one
	// used to take the branch below with base "netops", which for a cross-tenant
	// caller renders the bare wildcard `netops-*` — a pattern that glob-matches
	// netops-secfindings-<tenant>-<date> and netops-quarantine-<date> as
	// happily as it matches a log index. Log search reads LOG indices, so a
	// signal that names no log family reads the log families, never everything.
	if base == CatchAllIndexBase {
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
	if cross {
		return base + "-*"
	}
	return base + "-" + IndexTenantSeg(tenant) + "-*," + base + "-untagged-*"
}

// scopedLogFamilies are the log index families a tenant-scoped caller reads:
// device telemetry (syslog, SNMP traps, flows) and tagged cloud logs. App and
// platform logs are platform-owner only and security findings have their own
// gated door (secapi). Every family here must satisfy the device-identity
// contract (see deviceIdentityFields); ScopedLogFamilies is what that contract
// test iterates, so adding a family here enrols it automatically.
var scopedLogFamilies = []string{"netops-syslog", "netops-snmptrap", "netops-flows", "netops-cloudlogs"}

// ScopedLogFamilies returns a copy of the tenant-readable log families.
func ScopedLogFamilies() []string { return append([]string(nil), scopedLogFamilies...) }

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
	parts := make([]string, 0, len(scopedLogFamilies)*2)
	for _, b := range scopedLogFamilies {
		parts = append(parts, b+"-"+seg+"-*", b+"-untagged-*")
	}
	return strings.Join(parts, ",")
}

// IdentityKind says what values a device-identity field holds, and therefore
// which of a caller's device identities may be sent to it.
type IdentityKind int

const (
	// IdentityKey holds a device key: the inventory id, the hostname or, for
	// producers that write the sender there, its address. Mapped `keyword`.
	IdentityKey IdentityKind = iota
	// IdentityAddr holds the sender's address as text. Mapped `keyword`.
	IdentityAddr
	// IdentityIP holds the sender's address mapped as an OpenSearch `ip`. A
	// terms query that carries a value which does not parse as an address makes
	// the WHOLE search fail, so only parseable addresses are ever sent to it.
	IdentityIP
)

// DeviceIdentityField is a document field that names the device which emitted
// the document. It is how an untagged document is tied to a tenant's device.
type DeviceIdentityField struct {
	Name string
	Kind IdentityKind
}

// deviceIdentityFields is the ONE registry of the fields TenantFilter matches an
// untagged document's emitting device on. Every log family a scoped caller can
// read must map at least one of them, with the type its Kind requires — the
// contract test over deployment/docker/opensearch/index-templates.json enforces
// that, so a new family (or a family whose producer names its sender in a new
// field) fails the build instead of going silently empty for every tenant scope.
// That is exactly what happened to flows: the family maps only
// `sampler_address`, none of the fields matched here, so a tenant-scoped flows
// search could never match a single untagged document (found 2026-11-01).
var deviceIdentityFields = []DeviceIdentityField{
	{Name: "host", Kind: IdentityKey},
	{Name: "hostname", Kind: IdentityKey},
	{Name: "source_ip", Kind: IdentityAddr},
	{Name: "sampler_address", Kind: IdentityIP}, // flows: the exporter (goflow2)
}

// DeviceIdentityFields returns a copy of the registry.
func DeviceIdentityFields() []DeviceIdentityField {
	return append([]DeviceIdentityField(nil), deviceIdentityFields...)
}

// IsProviderScope reports whether a NON-cross scope is the Provider — the
// platform's own realm. It is exactly the platform owner spelling "global"
// (internal/owner.Platform). The unbound scope "" is deliberately NOT the
// Provider: owner.Of folds "" into the platform for ROW owners, but a caller
// whose scope did not resolve is a missing tenant, and widening it would turn
// a missing tenant into access (the same direction owner.ScopeReads takes).
func IsProviderScope(tenant string) bool {
	return normTenantSeg(tenant) == owner.Platform
}

// TenantFilter builds the OpenSearch query clause enforcing per-tenant isolation
// for a non-cross caller (#20 Phase 3). It returns nil for the platform owner's
// cross-tenant view: no restriction. It is defense in depth UNDER
// TenantIndexPattern, which already keeps other tenants' indices out of the
// pattern at the storage layer.
//
// Ownership follows the ONE owner rule (internal/owner), the same rule devices,
// alerts and integrations apply:
//
//   - a document stamped tenant_id=T belongs to T;
//   - an UNTAGGED document (tenant_id "" or missing) belongs to the platform.
//     Ingest leaves a document untagged when its sender is a platform-owned
//     device (tenant_registry=hit, owner "") or no known device at all
//     (tenant_registry=miss); a tenant's device is stamped with its tenant.
//
// So the Provider scope reads its own stamped documents AND every untagged one
// (tracker 365 made Provider a real scope; until then it bypassed this filter
// entirely, and once it stopped bypassing it every flow and every
// unknown-sender trap vanished from the Provider's log search — 2026-11-01).
//
// A tenant scope reads its own stamped documents, plus untagged documents whose
// emitting device — named by one of the device-identity fields — is one of the
// tenant's devices. That branch covers a tenant device whose documents were
// written before ingest learned its owner.
//
// deviceKeys/deviceAddrs must be the caller's UNAMBIGUOUS identities — held by
// its devices and by no other owner's (the api root's untaggedClaimFor, tracker
// 370). A device name or address is not unique across owners, so passing the
// caller's whole device set would hand it every untagged document that names a
// device another owner also has.
func TenantFilter(tenant string, cross bool, deviceKeys, deviceAddrs []string) map[string]any {
	if cross {
		return nil
	}
	if normTenantSeg(tenant) == "" {
		// An unbound, non-cross caller reads nothing — the ClickHouse twin of
		// this rule is chScopeRule's "__none__". Without it the own-tenant
		// branch would be `term tenant_id: ""` and hand a caller whose tenant
		// did not resolve every untagged (platform) document.
		return map[string]any{"match_none": map[string]any{}}
	}
	own := map[string]any{"term": map[string]any{"tenant_id": normTenantSeg(tenant)}}
	if IsProviderScope(tenant) {
		return shouldOne(own, untaggedClause())
	}
	return shouldOne(own, map[string]any{"bool": map[string]any{"must": []any{
		untaggedClause(),
		shouldOne(deviceIdentityClauses(deviceKeys, deviceAddrs)...),
	}}})
}

// untaggedClause matches a document that carries no tenant: tenant_id "" or
// absent.
func untaggedClause() map[string]any {
	return shouldOne(
		map[string]any{"term": map[string]any{"tenant_id": ""}},
		map[string]any{"bool": map[string]any{"must_not": []any{
			map[string]any{"exists": map[string]any{"field": "tenant_id"}},
		}}},
	)
}

// deviceIdentityClauses is one terms clause per registry field that has values
// of its kind to match. With none it is match_none, so a tenant without devices
// claims no untagged document.
func deviceIdentityClauses(keys, addrs []string) []any {
	ips := parseableAddrs(addrs)
	var out []any
	for _, f := range deviceIdentityFields {
		var vals []string
		switch f.Kind {
		case IdentityKey:
			vals = keys
		case IdentityAddr:
			vals = addrs
		case IdentityIP:
			vals = ips
		}
		if len(vals) > 0 {
			out = append(out, map[string]any{"terms": map[string]any{f.Name: vals}})
		}
	}
	if len(out) == 0 {
		return []any{map[string]any{"match_none": map[string]any{}}}
	}
	return out
}

// parseableAddrs keeps the values an `ip` field accepts: a bare IPv4/IPv6
// address, canonicalized. A zone (fe80::1%eth0), a host name or a CIDR is
// dropped rather than sent, because one unparseable value fails the search.
func parseableAddrs(addrs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range addrs {
		ip, err := netip.ParseAddr(strings.TrimSpace(a))
		if err != nil || ip.Zone() != "" {
			continue
		}
		c := ip.Unmap().String()
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// shouldOne is a bool clause that matches when at least one branch does.
func shouldOne(branches ...any) map[string]any {
	return map[string]any{"bool": map[string]any{"should": branches, "minimum_should_match": 1}}
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
