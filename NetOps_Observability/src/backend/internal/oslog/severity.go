// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package oslog

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Severity counts for GET /api/logs/severity-counts (tracker 387, the Logs
// page's summary tiles): the pure half. The caller (the api's handler) owns the
// gate, the tenant scope (index pattern, osTenantFilter, owner gates), the audit
// row and the I/O; this file only builds the one size:0 aggregation over the
// scope it is GIVEN and reads the store's answer. Nothing here can widen the
// scope: every filter the caller passes is ANDed in unchanged.
//
// The answer is the stored severity words as they are ("crit", "err", "2",
// "warning"); turning them into tiles is the UI's one severity map. A record
// carrying both `severity` and `level` (cloud logs) is counted once, by
// `severity`; one carrying neither is counted as unrated, so the parts always
// add up to the total.

// SeverityCountsTermLimit bounds the distinct severity words returned per
// field. Stores hold a handful; anything beyond the limit is reported in
// `Other` rather than dropped.
const SeverityCountsTermLimit = 64

// SeverityCountsQueryMax bounds the query text accepted (§3: validate input).
const SeverityCountsQueryMax = 8 << 10

// SeverityCount is one stored severity word and how many records carry it.
type SeverityCount struct {
	Field string `json:"field"`
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// SeverityCountsResp is the endpoint's answer.
type SeverityCountsResp struct {
	Signal   string          `json:"signal"`
	Total    int64           `json:"total"`
	Counts   []SeverityCount `json:"counts"`
	Unrated  int64           `json:"unrated"`
	Other    int64           `json:"other"`
	Sampling map[string]any  `json:"sampling,omitempty"`
	// RoutineMgmtIncluded says whether routine management sessions are in the
	// counts (the api's internal/logroutine class); nil for a store that holds
	// none (flows).
	RoutineMgmtIncluded *bool `json:"routine_mgmt_included,omitempty"`
}

type termsAgg struct {
	SumOther int64 `json:"sum_other_doc_count"`
	Buckets  []struct {
		Key      any   `json:"key"`
		DocCount int64 `json:"doc_count"`
	} `json:"buckets"`
}

// SeverityCountsBody builds the aggregation over exactly the search's surface:
// the caller's scope filters and must-not clauses, the time window on
// `timestamp`, and the same query text the search runs.
func SeverityCountsBody(query string, start, end time.Time, scopeFilters, mustNot []any) map[string]any {
	filters := append([]any{
		map[string]any{"range": map[string]any{"timestamp": map[string]string{
			"gte": start.Format(time.RFC3339), "lte": end.Format(time.RFC3339),
		}}},
	}, scopeFilters...)
	boolQuery := map[string]any{
		"must":   []any{map[string]any{"query_string": map[string]any{"query": QueryOrAll(query), "analyze_wildcard": true}}},
		"filter": filters,
	}
	if len(mustNot) > 0 {
		boolQuery["must_not"] = mustNot
	}
	hasSeverity := map[string]any{"exists": map[string]any{"field": "severity"}}
	hasLevel := map[string]any{"exists": map[string]any{"field": "level"}}
	return map[string]any{
		"size":             0,
		"track_total_hits": true,
		"query":            map[string]any{"bool": boolQuery},
		"aggs": map[string]any{
			"sev": map[string]any{"terms": map[string]any{"field": "severity", "size": SeverityCountsTermLimit}},
			"lvl_only": map[string]any{
				"filter": map[string]any{"bool": map[string]any{"must_not": []any{hasSeverity}}},
				"aggs":   map[string]any{"lvl": map[string]any{"terms": map[string]any{"field": "level", "size": SeverityCountsTermLimit}}},
			},
			"none": map[string]any{"filter": map[string]any{"bool": map[string]any{"must_not": []any{hasSeverity, hasLevel}}}},
		},
	}
}

// ErrNotACount is returned when the store's answer is not an aggregation reply.
var ErrNotACount = errors.New("the log store answered something that is not a count")

// ParseSeverityCounts reads the store's answer into resp (Signal and Sampling
// are the caller's). Empty words and non-positive buckets are skipped; buckets
// past the term limit land in Other.
func ParseSeverityCounts(raw []byte, resp *SeverityCountsResp) error {
	var parsed struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			Sev     termsAgg `json:"sev"`
			LvlOnly struct {
				Lvl termsAgg `json:"lvl"`
			} `json:"lvl_only"`
			None struct {
				DocCount int64 `json:"doc_count"`
			} `json:"none"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ErrNotACount
	}
	if resp.Counts == nil {
		resp.Counts = []SeverityCount{}
	}
	resp.Total = parsed.Hits.Total.Value
	add := func(field string, agg termsAgg) {
		for _, b := range agg.Buckets {
			v := strings.TrimSpace(fmt.Sprint(b.Key))
			if v == "" || b.DocCount <= 0 {
				continue
			}
			resp.Counts = append(resp.Counts, SeverityCount{Field: field, Value: v, Count: b.DocCount})
		}
		resp.Other += agg.SumOther
	}
	add("severity", parsed.Aggregations.Sev)
	add("level", parsed.Aggregations.LvlOnly.Lvl)
	resp.Unrated = parsed.Aggregations.None.DocCount
	return nil
}
