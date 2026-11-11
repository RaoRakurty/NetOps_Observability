// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/internal/flownames"
	"netops/backend/internal/iana"

	"netops/backend/internal/logroutine"
	"netops/backend/internal/logsecrets"
	"netops/backend/internal/oslog"
	// DEBUG-ROUTES-BEGIN
	"netops/backend/internal/pipedebug"
	// DEBUG-ROUTES-END
)

// ----------------------------------------------------------------------------
// Structured logging — the logger itself lives in internal/applog; these
// wrappers keep the historical names for the root package's ~90 call sites.
// ----------------------------------------------------------------------------

func logInfo(component, msg string, fields map[string]any)  { applog.Info(component, msg, fields) }
func logWarn(component, msg string, fields map[string]any)  { applog.Warn(component, msg, fields) }
func logError(component, msg string, fields map[string]any) { applog.Error(component, msg, fields) }

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
//   - "cloud"   → netops-cloudlogs-*  (tagged raw cloud logs: waf/lb/dns/flow/host…)
//   - ""        → netops-*            (everything)
//
// Cloud logs carry the ingest-tagged fields cloud_family / cloud_provider /
// resource_id (stamped at the cloud poller + aggregator, see cloud_tag.py and
// vector), so a caller narrows a lane with a plain Lucene clause, e.g.
// `cloud_family:waf AND cloud_provider:aws`. They are their OWN plane — kept out
// of the "all" search like flows — reachable only via signal="cloud".
// ----------------------------------------------------------------------------

// logsReadModule is the RBAC module that gates every read of the log stores:
// search, retention, the index listing and every export door.
const logsReadModule = "explore"

type logSearchReq struct {
	Query  string `json:"query"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Size   int    `json:"size,omitempty"`
	Signal string `json:"signal,omitempty"`
	// Offset pages through the result set ("Load more"): OpenSearch `from`.
	// Bounded server-side to the engine's result window (see logsMaxWindow).
	Offset int `json:"offset,omitempty"`
	// IncludeRoutineMgmt shows routine management sessions (monitoring polls
	// and SD-WAN controller sessions, internal/logroutine). Absent or false:
	// they are left out and the answer says how many (owner 2026-11-11).
	IncludeRoutineMgmt bool `json:"include_routine_mgmt,omitempty"`
}

// routineSources are the addresses whose sessions are routine for this
// principal: Correlix's own (configuration) and the principal's own SD-WAN
// controller nodes (its integrations' inventory, tenant-scoped). A controller
// read that fails is logged and leaves those sessions visible: the page then
// hides fewer records, never more.
func (s *server) routineSources(r *http.Request, claims jwtClaims) logroutine.Sources {
	tenant, cross := principalTenant(claims)
	ctl, err := s.routineCtl.Addrs(r.Context(), tenant, cross)
	if err != nil {
		logWarn("logs", "controller addresses could not be read; the controller's own sessions stay visible on the Logs page", map[string]any{"err": err.Error()})
	}
	return logroutine.Sources{Platform: platformAddrsFromEnv().IPs(), Controllers: ctl}
}

// routineApplies reports whether a store can hold routine management records.
// The flows store cannot (it has its own toggle for Correlix's polling
// traffic, flownames/platform.go), so no clause or count is sent to it.
func routineApplies(signal string) bool {
	return !isFlowsSignal(signal)
}

// logsMaxWindow is OpenSearch's default max_result_window: from+size may not
// exceed it. The offset is clamped so a deep "Load more" degrades to the last
// reachable page instead of a 500 from the engine.
const logsMaxWindow = 10000

// flowsOSSampleRate is the 1-in-N flow sample the router writes to
// netops-flows-* (vector-router/vector.yaml: flows_os_sample rate + the
// flows_os_stamped `.sample_rate` stamp). ClickHouse holds the canonical,
// UNSAMPLED flow store; OpenSearch — what this search serves for signal=flows
// — holds the 1:N sample, so hit counts and totals are estimates (multiply by
// N). Sample honesty (finder 2026-08-14, owner directive DON'T HIDE): every
// flows response carries this disclosure so no consumer can present the
// sample as exact. tests/test_ingest_contract.py pins this constant, the
// router config and the UI to the same N.
const flowsOSSampleRate = 50

// isFlowsSignal reports whether a Logs request targets the sampled flows store.
func isFlowsSignal(signal string) bool {
	return strings.ToLower(strings.TrimSpace(signal)) == "flows"
}

// flowsSamplingMeta is the disclosure attached to flows search/retention/export
// responses (ASCII only — the same text rides an HTTP header on sync exports).
func flowsSamplingMeta() map[string]any {
	return map[string]any{
		"rate": flowsOSSampleRate,
		"note": fmt.Sprintf("1:%d sample - counts and totals are estimates (multiply by %d); ClickHouse holds the canonical unsampled flow store", flowsOSSampleRate, flowsOSSampleRate),
	}
}

// logsScope resolves the caller's tenant-scoped OpenSearch read surface for one
// signal — the SINGLE scoping path shared by the interactive search and the
// retention-floor read, so isolation (#20 Phase 3 + the applogs platform
// boundary + operator restrictions) is enforced identically on both:
//
//	index    — the caller's index pattern (never names another tenant's indices)
//	filters  — per-doc tenant filter (osTenantFilter; defense in depth)
//	mustNot  — restricted-tenant exclusions for the operator's Global view
//	denyAll  — the caller is scoped into a restricted tenant: match nothing
//	forbidden— platform-only signal (applogs) requested by a non-owner
func (s *server) logsScope(r *http.Request, signal string) (index string, filters, mustNot []any, denyAll, forbidden bool) {
	// Default-closed (§3a rule 1): a request that reached here with no principal
	// resolves no index at all. This used to fall through as tenant "", cross
	// true, the WIDEST read there is; withAuth was the only thing in front of it.
	claims, authed := userFrom(r.Context())
	if !authed {
		return "", nil, nil, false, true
	}
	tenant, cross := principalTenant(claims)
	keys, _ := s.visibleDeviceKeys(claims)
	addrs, _ := s.visibleDeviceAddrs(claims)
	if f := oslog.TenantFilter(tenant, cross, keys, addrs); f != nil {
		filters = append(filters, f)
	}
	// App logs are the platform's OWN container/API logs — platform owner only
	// (identity gate, not the cross flag; see handleLogsSearch's original note).
	if sig := strings.ToLower(strings.TrimSpace(signal)); (sig == "applogs" || sig == "app") && !isPlatformOwner(claims) {
		return "", nil, nil, false, true
	}
	// Security findings are NOT log lines and are not served here (review
	// 2026-09-08, H9). oslog.IndexBase maps the signals `security` and
	// `secfindings` onto the netops-secfindings-* family, and this handler calls
	// requirePerm zero times — so the free-form parameter reached a tenant's CTEM
	// verdicts with no permission check and no licence check, for any principal
	// that merely authenticated (a zero-permission ingest key included).
	//
	// GATE CHOICE (§3a rule 3). Findings are per-tenant OPERATOR data, so the
	// right gate is requirePerm(infrastructure:read) plus the licence feature —
	// and that gate already exists on /api/security/findings, along with the
	// tenant filter and the per-doc isolation clause. Adding a second permission
	// gate here would build a SECOND door onto the same data carrying its own
	// copy of the isolation rules, which is what §3a rule 4 forbids, and it would
	// still miss the licence check. So the family is refused OUTRIGHT, here at
	// the chokepoint the interactive search, the retention read and the
	// pipeline-debug replay all resolve through, and the caller is sent to the
	// door that has both gates.
	if oslog.IsSecFindingsSignal(signal) {
		return "", nil, nil, false, true
	}
	index = oslog.TenantIndexPattern(signal, tenant, cross)
	// Defense-in-depth chokepoint: fail CLOSED if a non-owner's resolved pattern
	// ever references an applogs index.
	if !oslog.AppLogPatternAllowed(index, isPlatformOwner(claims)) {
		return "", nil, nil, false, true
	}
	// Compliance: per-tenant operator-visibility (Tenant.OperatorRestricted).
	if exclude, deny := s.operatorTelemetryRestriction(claims, tenant, cross); deny {
		denyAll = true
	} else if len(exclude) > 0 {
		mustNot = append(mustNot, map[string]any{"terms": map[string]any{"tenant_id": exclude}})
	}
	// DEBUG-ROUTES-BEGIN
	// Synthetic pipeline-debug probes never appear in a customer-facing view
	// (docs/design/PIPELINE_DEBUGGER_2026-09-04.md §4). correlix-debug injects a
	// real record through the real ingress so the real path is exercised — which
	// means the record IS in the tenant's index, and the only thing standing
	// between it and an operator's log search is this clause.
	//
	// It sits in logsScope, the ONE chokepoint both the interactive search and
	// the retention read resolve through, so a future log surface inherits the
	// exclusion instead of having to remember it. match_phrase on the analysed
	// `message` field: the standard analyser splits `cx_synthetic=true` into two
	// adjacent tokens, so the phrase form matches exactly that pair (a term
	// query on an analysed field would never match at all).
	mustNot = append(mustNot, syntheticDebugExclusion())
	// DEBUG-ROUTES-END
	return index, filters, mustNot, denyAll, false
}

// DEBUG-ROUTES-BEGIN
// syntheticDebugExclusion is the must_not clause that keeps correlix-debug's
// marked probes out of every customer-facing log query. `cx_synthetic=true` is
// a RESERVED token: a genuine device log containing it is hidden too, which is
// the safe direction for a debug tag.
func syntheticDebugExclusion() map[string]any {
	return map[string]any{"match_phrase": map[string]any{"message": pipedebug.SyntheticTag}}
}

// DEBUG-ROUTES-END

// logsForbiddenErr names WHY a log read was refused. logsScope returns one
// boolean for two different boundaries, and an operator who asked for security
// findings must not be told that app logs are restricted (§10: no silent or
// misleading failures) — they need to know which door to use instead.
func logsForbiddenErr(signal string) error {
	if oslog.IsSecFindingsSignal(signal) {
		return errors.New("security findings are not part of log search — read them at /api/security/findings, which checks infrastructure:read and the license feature")
	}
	return errors.New("app logs are restricted to the platform owner")
}

// logValueMasker is the by-value credential mask every log read path hands to
// internal/logsecrets (the configured SNMP communities, internal/credscrub). A
// server without one (a test, or a build that never wired the store) masks no
// value: an untyped nil, never a typed-nil interface.
func (s *server) logValueMasker() logsecrets.ValueMasker {
	if s == nil || s.credScrub == nil {
		return nil
	}
	return s.credScrub
}

// credScrubRefresh re-reads the configured communities after a credential
// write, so a new community is masked from the next read on rather than after
// the next periodic refresh. A failure keeps the previous set and is logged.
func (s *server) credScrubRefresh(ctx context.Context) {
	if s == nil || s.credScrub == nil {
		return
	}
	if err := s.credScrub.Refresh(ctx); err != nil {
		logError("credscrub", "configured SNMP communities could not be re-read after a credential change; the previous set stays in force", errf(err))
	}
}

// logsSearchResponseCap bounds how much of one search answer is held in memory
// for the credential strip (§9). A page is at most 5000 documents.
const logsSearchResponseCap = 256 << 20

func (s *server) handleLogsSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Device syslog carries usernames, retained for security attribution (owner
	// decision D7, 2026-11-09), so reading it is a permission and not merely
	// being signed in. explore:read is the module the Logs page lives under and
	// the one Iris's search_logs already answers to (aiPrincipal "logs:read").
	claims, ok := s.requirePerm(w, r, logsReadModule, LevelRead)
	if !ok {
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
		if n, err := strconv.Atoi(q.Get("offset")); err == nil {
			req.Offset = n
		}
		inc, err := logroutine.ParseParam(q.Get(logroutine.Param))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		req.IncludeRoutineMgmt = inc
	}
	if req.Size <= 0 || req.Size > 5000 {
		req.Size = 200
	}
	// Bound the paging offset to the engine's result window (never trust input).
	if req.Offset < 0 {
		req.Offset = 0
	}
	if req.Offset+req.Size > logsMaxWindow {
		req.Offset = logsMaxWindow - req.Size
	}

	end := time.Now().UTC()
	start := end.Add(-15 * time.Minute)
	if req.From != "" {
		if t, err := oslog.ParseTimeFlexible(req.From); err == nil {
			start = t
		}
	}
	if req.To != "" {
		if t, err := oslog.ParseTimeFlexible(req.To); err == nil {
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
	// Tenant isolation (#20 Phase 3): index pattern + per-doc filter + platform
	// applogs boundary + operator restrictions all resolve through the shared
	// logsScope path (identical for search and retention reads).
	index, scopeFilters, mustNot, denyAll, forbidden := s.logsScope(r, req.Signal)
	if forbidden {
		writeError(w, http.StatusForbidden, logsForbiddenErr(req.Signal))
		return
	}

	filters := append([]any{
		map[string]any{
			"range": map[string]any{
				"timestamp": map[string]string{
					"gte": start.Format(time.RFC3339),
					"lte": end.Format(time.RFC3339),
				},
			},
		},
	}, scopeFilters...)

	boolQuery := map[string]any{
		"must": []any{
			map[string]any{
				"query_string": map[string]any{
					"query":            oslog.QueryOrAll(req.Query),
					"analyze_wildcard": true,
				},
			},
		},
		"filter": filters,
	}
	if denyAll {
		boolQuery["filter"] = append(filters, map[string]any{"match_none": map[string]any{}})
	} else if len(mustNot) > 0 {
		boolQuery["must_not"] = mustNot
	}

	body := map[string]any{
		"size": req.Size,
		// Exact totals, always (owner directive: DON'T HIDE). Without this,
		// OpenSearch caps hits.total at 10k and the UI would understate how many
		// logs actually matched.
		"track_total_hits": true,
		"sort":             []any{map[string]any{"timestamp": map[string]string{"order": "desc", "unmapped_type": "date"}}},
		"query":            map[string]any{"bool": boolQuery},
		// Stored documents may still hold a device credential: see logsecrets.
		"_source": map[string]any{"excludes": logsecrets.SourceExcludes()},
	}
	if req.Offset > 0 {
		body["from"] = req.Offset
	}
	// Routine management sessions (owner 2026-11-11, internal/logroutine). The
	// class is counted by an aggregation, which runs over the whole query, and
	// left out of the rows by a post_filter, which hits.total honours: the
	// answer says how many matched and how many of those were left out, in one
	// round trip. The tenant scope above is untouched: the post_filter can only
	// remove documents the scoped query already matched. Shown, the class is an
	// optional named clause, so each routine row names its rule in
	// matched_queries and the event panel can say why.
	routine := routineApplies(req.Signal) && !denyAll
	if routine {
		src := s.routineSources(r, claims)
		body["aggs"] = map[string]any{logroutine.AggName: logroutine.Agg(src)}
		if req.IncludeRoutineMgmt {
			boolQuery["should"] = []any{logroutine.Clause(src)}
		} else {
			body["post_filter"] = logroutine.Exclusion(src)
		}
	}

	resp, err := openSearch("POST", "/"+index+"/_search", body)
	if err != nil {
		logError("logs", "opensearch search failed", map[string]any{"err": err.Error()})
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	// An error answer carries no documents, so it is relayed as it was.
	if resp.StatusCode >= 300 {
		w.WriteHeader(resp.StatusCode)
		counts, err := relayLogSearch(w, resp.Body)
		if err != nil {
			log.Printf("logs: copy response: %v", err)
		}
		s.auditLogSearch(r, claims, req, resp.StatusCode, counts)
		return
	}
	// Default-closed: a success body is served only after the credential strip
	// has run over all of it. One too large to read whole, or one that may hold
	// the field but cannot be parsed, is refused rather than relayed.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, logsSearchResponseCap+1))
	if err != nil {
		logError("logs", "read search response", map[string]any{"err": err.Error()})
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if len(raw) > logsSearchResponseCap {
		logError("logs", "search response over the read cap", map[string]any{"cap_bytes": logsSearchResponseCap})
		writeError(w, http.StatusBadGateway, errors.New("log search response is too large: narrow the query, time range or page size"))
		return
	}
	raw, err = logsecrets.StripSearchResponse(raw, s.logValueMasker())
	if err != nil {
		logError("logs", "search response refused by the credential strip", map[string]any{"err": err.Error()})
		writeError(w, http.StatusBadGateway, errors.New("log search returned a response that could not be checked"))
		return
	}
	if routine {
		if raw, err = logroutine.Inject(raw, req.IncludeRoutineMgmt); err != nil {
			logError("logs", "search response could not carry the routine-session count", map[string]any{"err": err.Error()})
			writeError(w, http.StatusBadGateway, errors.New("log search returned a response that could not be read"))
			return
		}
	}
	// Recorded here, once, because this is the point the delivered rows are known.
	s.auditLogSearch(r, claims, req, resp.StatusCode, countLogHits(raw))
	// Sample honesty: signal=flows serves the router's 1:50 OpenSearch sample
	// (ClickHouse keeps the canonical store). Inject the sampling disclosure
	// into the successful response object so "showing X of Y matched" can never
	// read as exact — the payload itself passes through untouched. Any body
	// that fails to parse as a JSON object is served verbatim instead.
	if isFlowsSignal(req.Signal) {
		var out map[string]any
		if json.Unmarshal(raw, &out) == nil {
			out["sampling"] = flowsSamplingMeta()
			// Tracker 387 PR 13b: interface, protocol and service names beside
			// each stored document, by the document's own tenant.
			flownames.AnnotateHits(out, s.ifaceNames, iana.Default(), platformAddrsFromEnv())
			w.WriteHeader(resp.StatusCode)
			_ = json.NewEncoder(w).Encode(out) // best-effort: a failed encode/write means the client is gone
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	// The only request-derived bytes are the routine summary's boolean, which
	// logroutine.Inject marshals itself; the rest is the store's JSON answer.
	if _, err := w.Write(raw); err != nil { // #nosec G705 -- a JSON document with a JSON content type, not HTML
		log.Printf("logs: write response: %v", err)
	}
}

// handleLogsRetention serves GET /api/logs/retention?signal=… — the retention
// floor for the caller's visible log store (owner directive: "I should know how
// long back I can go"). One cheap size:0 aggregation: exact doc count
// (track_total_hits) + min(timestamp) over the SAME tenant-scoped surface the
// search reads (logsScope), so a tenant's floor never reflects another
// tenant's older docs. Response: { signal, total, oldest, days }.
func (s *server) handleLogsRetention(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Same gate as the search it describes: the totals and the oldest timestamp
	// are facts about a store this caller may have no access to.
	if _, ok := s.requirePerm(w, r, logsReadModule, LevelRead); !ok {
		return
	}
	signal := r.URL.Query().Get("signal")
	index, filters, mustNot, denyAll, forbidden := s.logsScope(r, signal)
	if forbidden {
		writeError(w, http.StatusForbidden, logsForbiddenErr(signal))
		return
	}
	if denyAll {
		writeJSON(w, http.StatusOK, map[string]any{"signal": signal, "total": 0, "oldest": nil, "days": 0})
		return
	}
	boolQuery := map[string]any{
		"must":   []any{map[string]any{"match_all": map[string]any{}}},
		"filter": filters,
	}
	if len(mustNot) > 0 {
		boolQuery["must_not"] = mustNot
	}
	body := map[string]any{
		"size":             0,
		"track_total_hits": true, // exact count — never the 10k estimate cap
		"query":            map[string]any{"bool": boolQuery},
		"aggs": map[string]any{
			"oldest_ts": map[string]any{"min": map[string]any{"field": "timestamp"}},
		},
	}
	resp, err := openSearch("POST", "/"+index+"/_search?ignore_unavailable=true", body)
	if err != nil {
		logError("logs", "opensearch retention query failed", map[string]any{"err": err.Error()})
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if resp.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, fmt.Errorf("opensearch: %s", strings.TrimSpace(string(raw))))
		return
	}
	var parsed struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			OldestTs struct {
				Value *float64 `json:"value"` // epoch millis; null when no docs
			} `json:"oldest_ts"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	var oldest any
	days := 0
	if v := parsed.Aggregations.OldestTs.Value; v != nil {
		t := time.UnixMilli(int64(*v)).UTC()
		oldest = t.Format(time.RFC3339)
		days = int(time.Since(t).Hours() / 24)
	}
	out := map[string]any{
		"signal": signal,
		"total":  parsed.Hits.Total.Value,
		"oldest": oldest,
		"days":   days,
	}
	// Sample honesty: "This store holds N logs" would otherwise present the
	// 1:50 flows sample count as the flow count.
	if isFlowsSignal(signal) {
		out["sampling"] = flowsSamplingMeta()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleLogsIndices(w http.ResponseWriter, r *http.Request) {
	// Scope the index listing to the caller (#20 Phase 3) so a scoped tenant can't
	// enumerate other tenants' index names / doc counts.
	claims, ok := s.requirePerm(w, r, logsReadModule, LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	resp, err := openSearch("GET", "/_cat/indices/"+oslog.TenantCatPattern(tenant, cross)+"?format=json", nil)
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
	_, _ = io.Copy(w, resp.Body) // best-effort: proxy stream; a failed copy means the client is gone
}

// writeFilteredIndices re-emits a _cat/indices JSON array with any index belonging
// to a restricted tenant removed. An index is netops-{signal}-{tenantseg}-{date};
// we drop those whose tenant segment matches a restricted tenant. On any parse
// error it fails CLOSED (empty list) rather than leaking the unfiltered listing.
func (s *server) writeFilteredIndices(w http.ResponseWriter, resp *http.Response, excludeTenants []string) {
	w.Header().Set("Content-Type", "application/json")
	var rows []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		_, _ = w.Write([]byte("[]")) // best-effort: status committed; a failed write means the client is gone
		return
	}
	segs := make(map[string]bool, len(excludeTenants))
	for _, t := range excludeTenants {
		segs["-"+oslog.IndexTenantSeg(t)+"-"] = true
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
	_ = json.NewEncoder(w).Encode(kept) // best-effort: a failed encode/write means the client is gone
}

// indexBase maps a signal to its OpenSearch index base name (no tenant/date).
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

// ----------------------------------------------------------------------------
// Severity counts — GET /api/logs/severity-counts (tracker 387, the Logs page's
// summary tiles). The tiles must say how many records of each severity MATCH the
// current search, not how many happen to be loaded on screen, so the store
// counts: one size:0 aggregation (internal/oslog SeverityCountsBody) over
// EXACTLY the surface the search reads: the same logsScope (tenant index
// pattern, osTenantFilter, the applogs owner gate, the secfindings refusal,
// operator restrictions), the same time range and the same query text. Nothing
// here can count a record the search would not return to the same caller.
// ----------------------------------------------------------------------------

func (s *server) handleLogsSeverityCounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The same gate as the search it summarises.
	claims, ok := s.requirePerm(w, r, logsReadModule, LevelRead)
	if !ok {
		return
	}
	q := r.URL.Query()
	signal := q.Get("signal")
	query := q.Get("query")
	if len(query) > oslog.SeverityCountsQueryMax {
		writeError(w, http.StatusBadRequest, fmt.Errorf("query is longer than %d bytes", oslog.SeverityCountsQueryMax))
		return
	}
	end := time.Now().UTC()
	start := end.Add(-15 * time.Minute)
	if v := q.Get("from"); v != "" {
		t, err := oslog.ParseTimeFlexible(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("from is not a time"))
			return
		}
		start = t
	}
	if v := q.Get("to"); v != "" {
		t, err := oslog.ParseTimeFlexible(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("to is not a time"))
			return
		}
		end = t
	}
	if end.Before(start) {
		writeError(w, http.StatusBadRequest, errors.New("to is before from"))
		return
	}
	includeRoutine, err := logroutine.ParseParam(q.Get(logroutine.Param))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	index, scopeFilters, mustNot, denyAll, forbidden := s.logsScope(r, signal)
	if forbidden {
		writeError(w, http.StatusForbidden, logsForbiddenErr(signal))
		return
	}
	out := oslog.SeverityCountsResp{Signal: signal, Counts: []oslog.SeverityCount{}}
	if isFlowsSignal(signal) {
		out.Sampling = flowsSamplingMeta()
	}
	// The tiles count what the rows show: routine management sessions are left
	// out unless the search shows them (the same default and the same class).
	if routineApplies(signal) {
		out.RoutineMgmtIncluded = &includeRoutine
		if !includeRoutine && !denyAll {
			mustNot = append(append([]any(nil), mustNot...), logroutine.Clause(s.routineSources(r, claims)))
		}
	}
	if denyAll {
		s.auditSeverityCounts(r, claims, signal, query, start, end, http.StatusOK, 0)
		writeJSON(w, http.StatusOK, out)
		return
	}
	body := oslog.SeverityCountsBody(query, start, end, scopeFilters, mustNot)
	resp, err := openSearch("POST", "/"+index+"/_search?ignore_unavailable=true", body)
	if err != nil {
		logError("logs", "opensearch severity counts failed", map[string]any{"err": err.Error()})
		s.auditSeverityCounts(r, claims, signal, query, start, end, http.StatusBadGateway, 0)
		writeError(w, http.StatusBadGateway, errors.New("the log store could not be counted"))
		return
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if resp.StatusCode >= 300 {
		logError("logs", "opensearch severity counts refused", map[string]any{"status": resp.StatusCode})
		s.auditSeverityCounts(r, claims, signal, query, start, end, http.StatusBadGateway, 0)
		writeError(w, http.StatusBadGateway, errors.New("the log store refused the count; check the query syntax"))
		return
	}
	if err := oslog.ParseSeverityCounts(raw, &out); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.auditSeverityCounts(r, claims, signal, query, start, end, http.StatusOK, out.Total)
	writeJSON(w, http.StatusOK, out)
}

// auditSeverityCounts records the read the way the search records its own: who,
// which store, what query and window, and how many records were counted. No row
// is read, so none can reach the trail.
func (s *server) auditSeverityCounts(r *http.Request, claims jwtClaims, signal, query string, start, end time.Time, status int, matched int64) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross, SessionID: claims.Sid,
		Method: auditMethodLogRead, Path: "/api/logs/severity-counts", Status: status, Decision: auditDecision(status),
		Remote: auditClientIP(r),
		Detail: map[string]any{
			"action": "logs.severity_counts", "signal": strings.ToLower(strings.TrimSpace(signal)),
			"query": auditQueryText(query), "from": start.Format(time.RFC3339), "to": end.Format(time.RFC3339),
			"matched": matched, "rows": 0,
		},
	})
}
