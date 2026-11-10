// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package oslog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// The aggregation ANDs every scope filter the caller passes in, unchanged, so
// the count can never cover a record the search would not return.
func TestSeverityCountsBodyKeepsTheCallersScope(t *testing.T) {
	scope := []any{map[string]any{"term": map[string]any{"tenant_id": "acme"}}}
	mustNot := []any{map[string]any{"term": map[string]any{"owner": "x"}}}
	start := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	b := SeverityCountsBody("severity:err", start, start.Add(time.Hour), scope, mustNot)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"tenant_id":"acme"`, `"owner":"x"`, `"size":0`, `"track_total_hits":true`,
		`"query":"severity:err"`, `"gte":"2026-11-10T00:00:00Z"`, `"lte":"2026-11-10T01:00:00Z"`} {
		if !strings.Contains(s, want) {
			t.Errorf("body lacks %s: %s", want, s)
		}
	}
	if b2 := SeverityCountsBody("", start, start, nil, nil); b2["query"].(map[string]any)["bool"].(map[string]any)["must_not"] != nil {
		t.Errorf("no must_not clause should be emitted when none is given")
	}
}

func TestParseSeverityCountsAddsUp(t *testing.T) {
	raw := []byte(`{"hits":{"total":{"value":40}},"aggregations":{
	 "sev":{"sum_other_doc_count":2,"buckets":[{"key":"crit","doc_count":3},{"key":"warning","doc_count":20},{"key":" ","doc_count":9},{"key":"x","doc_count":0}]},
	 "lvl_only":{"lvl":{"sum_other_doc_count":0,"buckets":[{"key":"error","doc_count":10}]}},
	 "none":{"doc_count":5}}}`)
	var r SeverityCountsResp
	if err := ParseSeverityCounts(raw, &r); err != nil {
		t.Fatal(err)
	}
	if r.Total != 40 || r.Unrated != 5 || r.Other != 2 || len(r.Counts) != 3 {
		t.Fatalf("parsed: %+v", r)
	}
	if r.Counts[0] != (SeverityCount{"severity", "crit", 3}) || r.Counts[2] != (SeverityCount{"level", "error", 10}) {
		t.Fatalf("counts: %+v", r.Counts)
	}
	if err := ParseSeverityCounts([]byte("<html>"), &r); !errors.Is(err, ErrNotACount) {
		t.Fatalf("a non-JSON answer must be ErrNotACount, got %v", err)
	}
}
