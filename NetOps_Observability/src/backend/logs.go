package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// Structured logger — emits one JSON line per event to stdout. Vector's
// docker_logs source picks them up, parses the JSON, ships to Redpanda
// (topic netops.applogs), and vector-router then writes them into the
// `netops-applogs-YYYY.MM.DD` OpenSearch index.
// ----------------------------------------------------------------------------

type jsonLogger struct {
	mu sync.Mutex
	w  io.Writer
}

var appLog = &jsonLogger{w: os.Stdout}

func (l *jsonLogger) log(level, component, msg string, fields map[string]any) {
	event := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"component": component,
		"msg":       msg,
	}
	for k, v := range fields {
		event[k] = v
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = json.NewEncoder(l.w).Encode(event)
}

func logInfo(component, msg string, fields map[string]any) {
	appLog.log("info", component, msg, fields)
}
func logWarn(component, msg string, fields map[string]any) {
	appLog.log("warn", component, msg, fields)
}
func logError(component, msg string, fields map[string]any) {
	appLog.log("error", component, msg, fields)
}

// ----------------------------------------------------------------------------
// Log search — OpenSearch query proxy.
//
// The Logs tab posts a small JSON body with { query, from, to, size,
// signal }. We build a real OpenSearch _search request and return the
// response untouched so the frontend can render hits + aggregations.
//
// `signal` selects which index pattern to hit:
//   - "applogs" → netops-applogs-*    (container/API logs)
//   - "syslog"  → netops-syslog-*     (network device syslog)
//   - "flows"   → netops-flows-*      (NetFlow / IPFIX / sFlow records)
//   - ""        → netops-*            (everything)
// ----------------------------------------------------------------------------

type logSearchReq struct {
	Query  string `json:"query"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Size   int    `json:"size,omitempty"`
	Signal string `json:"signal,omitempty"`
}

func (s *server) handleLogsSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req logSearchReq
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		q := r.URL.Query()
		req.Query = q.Get("query")
		req.From = q.Get("from")
		req.To = q.Get("to")
		req.Signal = q.Get("signal")
		if n, err := strconv.Atoi(q.Get("size")); err == nil {
			req.Size = n
		}
	}
	if req.Size <= 0 || req.Size > 5000 {
		req.Size = 200
	}

	end := time.Now().UTC()
	start := end.Add(-15 * time.Minute)
	if req.From != "" {
		if t, err := parseTimeFlexible(req.From); err == nil {
			start = t
		}
	}
	if req.To != "" {
		if t, err := parseTimeFlexible(req.To); err == nil {
			end = t
		}
	}

	// Compose a query string DSL body. We use query_string so callers
	// can pass either bare text ("error") or full Lucene syntax
	// ("severity:err AND host:router-01").
	// All netops-* indices (applogs/syslog/flows) timestamp their docs with the
	// field `timestamp` (Vector's default), not the ECS `@timestamp`. Sort and
	// range-filter on that. unmapped_type keeps the sort from failing on any
	// index whose mapping happens to lack the field rather than erroring the
	// whole multi-index search.
	filters := []any{
		map[string]any{
			"range": map[string]any{
				"timestamp": map[string]string{
					"gte": start.Format(time.RFC3339),
					"lte": end.Format(time.RFC3339),
				},
			},
		},
	}

	// Tenant isolation (#20 Phase 3). The caller may only read its own tenant's
	// indices (tenantIndexPattern names nothing else) and, within them, only its
	// own tagged docs plus untagged docs from its own devices (osTenantFilter,
	// mirroring the ClickHouse row policy). The platform owner is unrestricted.
	claims, authed := userFrom(r.Context())
	tenant, cross := "", true
	if authed {
		tenant, cross = principalTenant(claims)
		keys, _ := s.visibleDeviceKeys(claims)
		addrs, _ := s.visibleDeviceAddrs(claims)
		if f := osTenantFilter(tenant, cross, keys, addrs); f != nil {
			filters = append(filters, f)
		}
	}

	// App logs are the platform's OWN container/API logs (netops-applogs-untagged-*),
	// not customer telemetry. They expose infra-stack internals, so only the
	// platform owner may read them — a scoped tenant is refused even if it names the
	// signal directly. Gate on identity (isPlatformOwner), not on the cross flag, so
	// the owner keeps infra access while narrowed to a tenant/Global via the switcher.
	// (UI also hides the option; this is the enforced boundary per the zero-trust rule.)
	if sig := strings.ToLower(strings.TrimSpace(req.Signal)); (sig == "applogs" || sig == "app") && !isPlatformOwner(claims) {
		writeError(w, http.StatusForbidden, fmt.Errorf("app logs are restricted to the platform owner"))
		return
	}

	index := tenantIndexPattern(req.Signal, tenant, cross)

	// Guardrail (defense-in-depth, zero-leak bar): app logs are the platform's own
	// internals. Even if a future change to signal/index logic let an applogs index
	// into a non-owner's resolved pattern, fail CLOSED here — the platform↔tenant
	// boundary can never be silently reopened by a refactor. (Layered UNDER the
	// explicit signal gate above and the per-doc osTenantFilter below.)
	if !appLogPatternAllowed(index, claims) {
		writeError(w, http.StatusForbidden, fmt.Errorf("app logs are restricted to the platform owner"))
		return
	}

	boolQuery := map[string]any{
		"must": []any{
			map[string]any{
				"query_string": map[string]any{
					"query":            queryOrAll(req.Query),
					"analyze_wildcard": true,
				},
			},
		},
		"filter": filters,
	}
	// Compliance: enforce per-tenant operator-visibility (Tenant.OperatorRestricted).
	// A restricted tenant's telemetry is excluded from the operator's Global view,
	// and the operator is denied if it scoped into one. No-op for a tenant's own
	// users and when nothing is restricted.
	if exclude, deny := s.operatorTelemetryRestriction(claims, tenant, cross); deny {
		boolQuery["filter"] = append(filters, map[string]any{"match_none": map[string]any{}})
	} else if len(exclude) > 0 {
		boolQuery["must_not"] = []any{map[string]any{"terms": map[string]any{"tenant_id": exclude}}}
	}

	body := map[string]any{
		"size":  req.Size,
		"sort":  []any{map[string]any{"timestamp": map[string]string{"order": "desc", "unmapped_type": "date"}}},
		"query": map[string]any{"bool": boolQuery},
	}

	resp, err := openSearch("POST", "/"+index+"/_search", body)
	if err != nil {
		logError("logs", "opensearch search failed", map[string]any{"err": err.Error()})
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("logs: copy response: %v", err)
	}
}

func (s *server) handleLogsIndices(w http.ResponseWriter, r *http.Request) {
	// Scope the index listing to the caller (#20 Phase 3) so a scoped tenant can't
	// enumerate other tenants' index names / doc counts.
	var claims jwtClaims
	tenant, cross := "", true
	if c, ok := userFrom(r.Context()); ok {
		claims = c
		tenant, cross = principalTenant(claims)
	}
	resp, err := openSearch("GET", "/_cat/indices/"+tenantCatPattern(tenant, cross)+"?format=json", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()

	// Compliance: drop restricted tenants' indices from the operator's listing so
	// it can't even enumerate their index names / doc counts (zero-knowledge). Only
	// applies to the operator's cross-tenant view and when something is restricted.
	if exclude, _ := s.operatorTelemetryRestriction(claims, tenant, cross); len(exclude) > 0 {
		s.writeFilteredIndices(w, resp, exclude)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// writeFilteredIndices re-emits a _cat/indices JSON array with any index belonging
// to a restricted tenant removed. An index is netops-{signal}-{tenantseg}-{date};
// we drop those whose tenant segment matches a restricted tenant. On any parse
// error it fails CLOSED (empty list) rather than leaking the unfiltered listing.
func (s *server) writeFilteredIndices(w http.ResponseWriter, resp *http.Response, excludeTenants []string) {
	w.Header().Set("Content-Type", "application/json")
	var rows []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		_, _ = w.Write([]byte("[]"))
		return
	}
	segs := make(map[string]bool, len(excludeTenants))
	for _, t := range excludeTenants {
		segs["-"+indexTenantSeg(t)+"-"] = true
	}
	kept := rows[:0]
	for _, row := range rows {
		name, _ := row["index"].(string)
		restricted := false
		for seg := range segs {
			if strings.Contains(name, seg) {
				restricted = true
				break
			}
		}
		if !restricted {
			kept = append(kept, row)
		}
	}
	_ = json.NewEncoder(w).Encode(kept)
}

// indexBase maps a signal to its OpenSearch index base name (no tenant/date).
func indexBase(signal string) string {
	switch strings.ToLower(signal) {
	case "applogs", "app":
		return "netops-applogs"
	case "syslog":
		return "netops-syslog"
	case "snmptrap", "trap", "traps":
		return "netops-snmptrap"
	case "flows", "netflow", "flow":
		return "netops-flows"
	default:
		return "netops"
	}
}

// tenantSegRe strips any character not allowed in an OpenSearch index segment.
var tenantSegRe = regexp.MustCompile(`[^a-z0-9_-]`)

// indexTenantSeg sanitizes a tenant id into the per-tenant index segment. It MUST
// match the derivation in deployment/docker/vector-router/vector.yaml (#20 Phase
// 3) so reads name the same indices ingest writes. "" → "untagged".
func indexTenantSeg(tenant string) string {
	seg := strings.ToLower(strings.TrimSpace(tenant))
	if seg == "" {
		return "untagged"
	}
	return tenantSegRe.ReplaceAllString(seg, "-")
}

// tenantIndexPattern returns the comma-separated OpenSearch index pattern a caller
// may read for a signal (#20 Phase 3 — at-rest separation). The platform owner
// (cross) reads every tenant's indices; a scoped tenant reads ONLY its own tagged
// indices plus the shared untagged indices (where the per-doc device matcher in
// osTenantFilter still narrows results — the populate-time fallback, mirroring the
// ClickHouse row policy). Another tenant's indices are never named, so its docs
// are unreachable even if the query filter is ever dropped.
// appLogPatternAllowed is the defense-in-depth chokepoint for the platform↔tenant
// boundary: a non-platform-owner may NEVER read the platform's app-log indices,
// regardless of how the index pattern was built. Returns false (deny) when a
// non-owner's resolved pattern references any applogs index. Used by both the
// interactive search and the export path so the rule is enforced identically.
func appLogPatternAllowed(index string, c jwtClaims) bool {
	return isPlatformOwner(c) || !strings.Contains(index, "applogs")
}

func tenantIndexPattern(signal, tenant string, cross bool) string {
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
				parts = append(parts, b+"-"+indexTenantSeg(tenant)+"-*", b+"-untagged-*")
			}
		}
		return strings.Join(parts, ",")
	}
	base := indexBase(signal)
	if cross {
		return base + "-*"
	}
	return base + "-" + indexTenantSeg(tenant) + "-*," + base + "-untagged-*"
}

// tenantCatPattern is the _cat/indices pattern a caller may enumerate: all
// netops-* for the platform owner; only the caller's own + untagged indices
// (across signals) for a scoped tenant, so index names/counts don't leak.
func tenantCatPattern(tenant string, cross bool) string {
	if cross {
		return "netops-*"
	}
	seg := indexTenantSeg(tenant)
	// App logs are platform-owner only (handled in the search path) — a scoped
	// tenant doesn't even enumerate their index names. Device telemetry signals
	// (syslog, snmp traps, flows) are tenant-visible (own + untagged-from-own-devices).
	bases := []string{"netops-syslog", "netops-snmptrap", "netops-flows"}
	parts := make([]string, 0, len(bases)*2)
	for _, b := range bases {
		parts = append(parts, b+"-"+seg+"-*", b+"-untagged-*")
	}
	return strings.Join(parts, ",")
}

// osTenantFilter builds the OpenSearch query clause enforcing per-tenant isolation
// for a scoped caller (#20 Phase 3), mirroring chTenantScope's ClickHouse policy:
// a doc is visible iff its tenant_id == the caller's tenant, OR it is untagged
// (tenant_id "" / missing) AND was emitted by one of the caller's devices
// (host/hostname/source_ip). Returns nil for the platform owner (cross) — no
// restriction. It is defense in depth UNDER tenantIndexPattern (which already
// excludes other tenants' indices at the storage layer).
func osTenantFilter(tenant string, cross bool, deviceKeys, deviceAddrs []string) map[string]any {
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
			map[string]any{"term": map[string]any{"tenant_id": normTenant(tenant)}},
			map[string]any{"bool": map[string]any{"must": []any{
				untagged,
				map[string]any{"bool": map[string]any{"should": dev, "minimum_should_match": 1}},
			}}},
		},
		"minimum_should_match": 1,
	}}
}

func queryOrAll(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return "*"
	}
	return q
}

// openSearch is a tiny HTTP client wrapper for the OpenSearch cluster.
// Auth would go here once DISABLE_SECURITY_PLUGIN is flipped off.
func openSearch(method, path string, body any) (*http.Response, error) {
	base := envOr("OPENSEARCH_URL", "http://opensearch:9200")
	u, err := url.Parse(strings.TrimRight(base, "/") + path)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := backendHTTPClient(30 * time.Second)
	return client.Do(req)
}

// parseTimeFlexible accepts RFC3339, Unix seconds, or Unix nanoseconds.
func parseTimeFlexible(s string) (time.Time, error) {
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
