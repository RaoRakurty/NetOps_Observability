// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/oslog"
)

// ----------------------------------------------------------------------------
// Severity counts — GET /api/logs/severity-counts (tracker 387, the Logs page's
// summary tiles).
//
// The tiles over the Logs list must say how many records of each severity MATCH
// the current search, not how many happen to be loaded on screen. That needs the
// store to count, so this is one size:0 aggregation over EXACTLY the surface the
// search reads: the same logsScope (tenant index pattern, osTenantFilter, the
// applogs owner gate, the secfindings refusal, operator restrictions), the same
// time range and the same query text. Nothing here can count a record the search
// would not return to the same caller.
//
// The answer is the stored severity words as they are ("crit", "err", "2",
// "warning"); turning them into tiles is the UI's one severity map. A record
// carrying both `severity` and `level` (cloud logs) is counted once, by
// `severity`; one carrying neither is counted as unrated, so the parts always
// add up to the total.
//
// Response: { signal, total, counts: [{field, value, count}], unrated, other }.
// ----------------------------------------------------------------------------

// severityCountsTermLimit bounds the distinct severity words returned per field.
// Stores hold a handful (syslog's eight, a few alarm words); anything beyond the
// limit is reported in `other` rather than dropped.
const severityCountsTermLimit = 64

// severityCountsQueryMax bounds the query text accepted (§3: validate input).
const severityCountsQueryMax = 8 << 10

type severityCount struct {
	Field string `json:"field"`
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type severityCountsResp struct {
	Signal   string          `json:"signal"`
	Total    int64           `json:"total"`
	Counts   []severityCount `json:"counts"`
	Unrated  int64           `json:"unrated"`
	Other    int64           `json:"other"`
	Sampling map[string]any  `json:"sampling,omitempty"`
}

type osTermsAgg struct {
	SumOther int64 `json:"sum_other_doc_count"`
	Buckets  []struct {
		Key      any   `json:"key"`
		DocCount int64 `json:"doc_count"`
	} `json:"buckets"`
}

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
	if len(query) > severityCountsQueryMax {
		writeError(w, http.StatusBadRequest, fmt.Errorf("query is longer than %d bytes", severityCountsQueryMax))
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

	index, scopeFilters, mustNot, denyAll, forbidden := s.logsScope(r, signal)
	if forbidden {
		writeError(w, http.StatusForbidden, logsForbiddenErr(signal))
		return
	}
	out := severityCountsResp{Signal: signal, Counts: []severityCount{}}
	if isFlowsSignal(signal) {
		out.Sampling = flowsSamplingMeta()
	}
	if denyAll {
		s.auditSeverityCounts(r, claims, signal, query, start, end, http.StatusOK, 0)
		writeJSON(w, http.StatusOK, out)
		return
	}

	filters := append([]any{
		map[string]any{"range": map[string]any{"timestamp": map[string]string{
			"gte": start.Format(time.RFC3339), "lte": end.Format(time.RFC3339),
		}}},
	}, scopeFilters...)
	boolQuery := map[string]any{
		"must":   []any{map[string]any{"query_string": map[string]any{"query": oslog.QueryOrAll(query), "analyze_wildcard": true}}},
		"filter": filters,
	}
	if len(mustNot) > 0 {
		boolQuery["must_not"] = mustNot
	}
	hasSeverity := map[string]any{"exists": map[string]any{"field": "severity"}}
	hasLevel := map[string]any{"exists": map[string]any{"field": "level"}}
	body := map[string]any{
		"size":             0,
		"track_total_hits": true,
		"query":            map[string]any{"bool": boolQuery},
		"aggs": map[string]any{
			"sev": map[string]any{"terms": map[string]any{"field": "severity", "size": severityCountsTermLimit}},
			"lvl_only": map[string]any{
				"filter": map[string]any{"bool": map[string]any{"must_not": []any{hasSeverity}}},
				"aggs":   map[string]any{"lvl": map[string]any{"terms": map[string]any{"field": "level", "size": severityCountsTermLimit}}},
			},
			"none": map[string]any{"filter": map[string]any{"bool": map[string]any{"must_not": []any{hasSeverity, hasLevel}}}},
		},
	}
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
	var parsed struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			Sev     osTermsAgg `json:"sev"`
			LvlOnly struct {
				Lvl osTermsAgg `json:"lvl"`
			} `json:"lvl_only"`
			None struct {
				DocCount int64 `json:"doc_count"`
			} `json:"none"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		writeError(w, http.StatusBadGateway, errors.New("the log store answered something that is not a count"))
		return
	}
	out.Total = parsed.Hits.Total.Value
	add := func(field string, agg osTermsAgg) {
		for _, b := range agg.Buckets {
			v := strings.TrimSpace(fmt.Sprint(b.Key))
			if v == "" || b.DocCount <= 0 {
				continue
			}
			out.Counts = append(out.Counts, severityCount{Field: field, Value: v, Count: b.DocCount})
		}
		out.Other += agg.SumOther
	}
	add("severity", parsed.Aggregations.Sev)
	add("level", parsed.Aggregations.LvlOnly.Lvl)
	out.Unrated = parsed.Aggregations.None.DocCount
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
