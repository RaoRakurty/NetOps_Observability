// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// security_findings_agg_filter_test.go — the AGGREGATION half of tracker 283.
//
// security_findings_filter_test.go closed the list half: each clause was shown
// to exclude the rows it does not name, because the double now reads the emitted
// body. It said, in its own header, what it could not reach:
//
//	"WHAT IS STILL NOT PROVEN HERE, because the double does not honour it: any
//	 AGGREGATION. Facets, the CTEM funnel, coverage, the trend histogram and the
//	 compliance fold all read canned `aggregations` regardless of the query."
//
// That was still a live hole, and it was not theoretical. Measured before this
// file existed: making FacetsBody build its query from EMPTY filters — so every
// facet count on the page answers a question the operator did not ask, showing
// the whole estate's severity mix beside a filtered list — left `go test ./...`
// entirely GREEN across both this package and secapi. The same break in
// CurrentFoldBody, TrendBody and CoverageBody is the same class: a number on the
// CTEM page that no longer belongs to the filter beside it.
//
// The pinned-body tests in secapi could not catch it: they assert the body the
// builder emits for ONE filter set, and a builder that ignores its argument
// still emits a correct-looking body for the empty set. What was missing is the
// other end — the COUNT that comes back has to change when the filter changes.
//
// So this file runs the aggregation-backed endpoints over the same three-document
// corpus with the double in aggAware mode, where the aggregations are COMPUTED
// from the documents that actually matched the query.
//
// WHAT IS STILL NOT PROVEN, so nobody over-reads a green here: the compliance
// scorecard (HandleCompliance) is not exercised in aggAware mode. Its fold
// fixtures are hand-written on purpose — one of them is a bucket carrying a
// superseded verdict, a shape a computed answer cannot produce — and the shape
// of the body it emits is byte-pinned in secapi/frameworks_test.go, sort
// direction included. The narrowing of the frameworks fold therefore rests on
// that pin plus CurrentFoldBody's coverage here, not on an end-to-end count.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// secStartFilterAggOS is secStartFilterOS with the aggregations COMPUTED rather
// than canned: same corpus, same window honouring, but a facet count now comes
// from the documents the query matched.
func secStartFilterAggOS(t *testing.T, docs []secFilterDoc) *secFakeOS {
	t.Helper()
	rows := make([]string, 0, len(docs))
	for _, d := range docs {
		rows = append(rows, d.render())
	}
	fake := &secFakeOS{
		windowAware: true,
		aggAware:    true,
		docs:        map[string]string{secPatternFor("acme"): "[" + strings.Join(rows, ",") + "]"},
	}
	secStartFakeOS(t, fake)
	return fake
}

// secFacets runs one facets request and returns the five maps.
func secFacets(t *testing.T, s *server, query string) map[string]map[string]int64 {
	t.Helper()
	w := httptest.NewRecorder()
	s.secAPI.HandleFacets(w, req(http.MethodGet, "/api/security/findings/facets?"+query, "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("facets ?%s = %d (%s)", query, w.Code, w.Body.String())
	}
	var got struct {
		Severity      map[string]int64 `json:"severity"`
		Status        map[string]int64 `json:"status"`
		Seam          map[string]int64 `json:"seam"`
		Framework     map[string]int64 `json:"framework"`
		EvidenceClass map[string]int64 `json:"evidence_class"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode facets ?%s: %v (%s)", query, err, w.Body.String())
	}
	return map[string]map[string]int64{
		"severity": got.Severity, "status": got.Status, "seam": got.Seam,
		"framework": got.Framework, "evidence_class": got.EvidenceClass,
	}
}

// nonZero strips the always-present zero keys (an absent facet and a zero facet
// mean different things to an operator, so the handler emits both) and leaves
// the counts that actually came back.
func nonZero(m map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for k, v := range m {
		if v != 0 {
			out[k] = v
		}
	}
	return out
}

func sameCounts(got, want map[string]int64) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// TestSecurityFacetsNarrowWithTheFilters is the hole named above, closed: a
// facet count answers the SAME question as the list beside it.
func TestSecurityFacetsNarrowWithTheFilters(t *testing.T) {
	now := time.Now().UTC()
	secStartFilterAggOS(t, secFilterCorpus(now))
	s := secTestServer(t)

	cases := []struct {
		name  string
		query string
		want  map[string]map[string]int64
	}{
		{
			name:  "no filter counts the whole corpus",
			query: "",
			want: map[string]map[string]int64{
				"severity":       {"critical": 1, "high": 1, "low": 1},
				"status":         {"fail": 2, "pass": 1},
				"seam":           {"ISP": 2, "internet": 1},
				"framework":      {"CIS:1.2": 2, "NIST:AC-17": 1, "PCI:2.2": 1},
				"evidence_class": {"posture": 3},
			},
		},
		{
			// The one that was free to be wrong: with the facet query ignoring
			// its filters this row reported the whole estate's mix.
			name:  "severity narrows every facet, not just its own",
			query: "severity=critical",
			want: map[string]map[string]int64{
				"severity":       {"critical": 1},
				"status":         {"fail": 1},
				"seam":           {"ISP": 1},
				"framework":      {"CIS:1.2": 1, "NIST:AC-17": 1},
				"evidence_class": {"posture": 1},
			},
		},
		{
			name:  "status narrows",
			query: "status=fail",
			want: map[string]map[string]int64{
				"severity":       {"critical": 1, "low": 1},
				"status":         {"fail": 2},
				"seam":           {"ISP": 2},
				"framework":      {"CIS:1.2": 2, "NIST:AC-17": 1},
				"evidence_class": {"posture": 2},
			},
		},
		{
			name:  "device narrows by co-location token",
			query: "device=host:edge1",
			want: map[string]map[string]int64{
				"severity":       {"high": 1},
				"status":         {"pass": 1},
				"seam":           {"internet": 1},
				"framework":      {"PCI:2.2": 1},
				"evidence_class": {"posture": 1},
			},
		},
		{
			name:  "free text narrows",
			query: "q=telnet",
			want: map[string]map[string]int64{
				"severity":       {"critical": 1, "low": 1},
				"status":         {"fail": 2},
				"seam":           {"ISP": 2},
				"framework":      {"CIS:1.2": 2, "NIST:AC-17": 1},
				"evidence_class": {"posture": 2},
			},
		},
		{
			// A filter that matches nothing must produce EMPTY facets, never
			// the canned full set — H2's failure mode in aggregation form.
			name:  "a filter matching nothing empties every facet",
			query: "severity=info",
			want: map[string]map[string]int64{
				"severity": {}, "status": {}, "seam": {}, "framework": {}, "evidence_class": {},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := secFacets(t, s, tc.query)
			for facet, want := range tc.want {
				if !sameCounts(nonZero(got[facet]), want) {
					t.Errorf("?%s facet %q = %v, want %v — the facet did not answer the filtered question",
						tc.query, facet, nonZero(got[facet]), want)
				}
			}
		})
	}
}

// TestSecurityTrendNarrowsWithTheFilters — the histogram is a count per bucket,
// and a count is exactly what a canned aggregation cannot get wrong.
func TestSecurityTrendNarrowsWithTheFilters(t *testing.T) {
	now := time.Now().UTC()
	secStartFilterAggOS(t, secFilterCorpus(now))
	s := secTestServer(t)

	// A six-hour window at an hourly bucket: the whole corpus falls inside it,
	// and the handler refuses the 30-day default at this bucket (721 points over
	// a 400 cap) rather than silently coarsening the interval.
	window := "since=" + now.Add(-6*time.Hour).Format(time.RFC3339) +
		"&until=" + now.Format(time.RFC3339)

	totals := func(query string) (fail, pass, warn int64) {
		t.Helper()
		w := httptest.NewRecorder()
		s.secAPI.HandleTrend(w, req(http.MethodGet, "/api/security/findings/trend?bucket=1h&"+window+"&"+query, "", acme()))
		if w.Code != http.StatusOK {
			t.Fatalf("trend ?%s = %d (%s)", query, w.Code, w.Body.String())
		}
		var body struct {
			Buckets []struct {
				Fail int64 `json:"fail"`
				Warn int64 `json:"warn"`
				Pass int64 `json:"pass"`
			} `json:"buckets"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode trend ?%s: %v (%s)", query, err, w.Body.String())
		}
		if len(body.Buckets) == 0 {
			t.Fatalf("trend ?%s returned no buckets at all — this test would prove nothing", query)
		}
		for _, b := range body.Buckets {
			fail += b.Fail
			pass += b.Pass
			warn += b.Warn
		}
		return fail, pass, warn
	}

	if f, p, wn := totals(""); f != 2 || p != 1 || wn != 0 {
		t.Errorf("unfiltered trend = fail %d / pass %d / warn %d, want 2 / 1 / 0", f, p, wn)
	}
	if f, p, _ := totals("severity=critical"); f != 1 || p != 0 {
		t.Errorf("?severity=critical trend = fail %d / pass %d, want 1 / 0 — the histogram ignored the filter", f, p)
	}
	if f, p, _ := totals("status=pass"); f != 0 || p != 1 {
		t.Errorf("?status=pass trend = fail %d / pass %d, want 0 / 1", f, p)
	}
	if f, p, _ := totals("severity=info"); f != 0 || p != 0 {
		t.Errorf("a filter matching nothing must draw an EMPTY trend, got fail %d / pass %d", f, p)
	}
}

// postureNumbers is the CTEM funnel and coverage, as the page reads them.
type postureNumbers struct {
	Funnel struct {
		Scope      int `json:"scope"`
		Discover   int `json:"discover"`
		Prioritize int `json:"prioritize"`
		Mobilize   int `json:"mobilize"`
	} `json:"funnel"`
	Coverage struct {
		Assessed   int `json:"assessed_assets"`
		Total      int `json:"total_assets"`
		Unassessed int `json:"unassessed"`
	} `json:"coverage"`
	LastScan struct {
		ScanID string `json:"scan_id"`
	} `json:"last_scan"`
}

// TestSecurityPostureNarrowsWithTheFilters covers the other two bodies that were
// free to ignore their filters: CurrentFoldBody (the funnel) and CoverageBody
// (assessed assets + last scan).
//
// The funnel is a CURRENT-state fold, so the corpus's two scans of n-1 count
// once, as the newest verdict — which is also what makes this a real test of the
// fold rather than of a document count.
func TestSecurityPostureNarrowsWithTheFilters(t *testing.T) {
	now := time.Now().UTC()
	secStartFilterAggOS(t, secFilterCorpus(now))
	s := secTestServer(t)

	posture := func(query string) postureNumbers {
		t.Helper()
		w := httptest.NewRecorder()
		s.secAPI.HandlePosture(w, req(http.MethodGet, "/api/security/posture?"+query, "", acme()))
		if w.Code != http.StatusOK {
			t.Fatalf("posture ?%s = %d (%s)", query, w.Code, w.Body.String())
		}
		var p postureNumbers
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatalf("decode posture ?%s: %v (%s)", query, err, w.Body.String())
		}
		return p
	}

	// Unfiltered: two finding IDENTITIES (n-1 newest = critical/Fail on
	// acme-core, n-2 = high/Pass on acme-edge), both severities are priority
	// severities, both carry a seam, and two distinct devices were assessed.
	all := posture("")
	if all.Funnel.Discover != 2 {
		t.Errorf("discover = %d, want 2 — the fold counts identities, not the three documents", all.Funnel.Discover)
	}
	if all.Funnel.Prioritize != 2 || all.Funnel.Mobilize != 2 {
		t.Errorf("prioritize/mobilize = %d/%d, want 2/2", all.Funnel.Prioritize, all.Funnel.Mobilize)
	}
	if all.Coverage.Assessed != 2 {
		t.Errorf("assessed_assets = %d, want 2 distinct devices", all.Coverage.Assessed)
	}
	if all.LastScan.ScanID != "scan-2" {
		t.Errorf("last_scan = %q, want the NEWEST scan scan-2", all.LastScan.ScanID)
	}

	// One severity: one identity survives, and coverage drops with it.
	crit := posture("severity=critical")
	if crit.Funnel.Discover != 1 || crit.Funnel.Prioritize != 1 || crit.Funnel.Mobilize != 1 {
		t.Errorf("?severity=critical funnel = discover %d / prioritize %d / mobilize %d, want 1/1/1 — the fold ignored the filter",
			crit.Funnel.Discover, crit.Funnel.Prioritize, crit.Funnel.Mobilize)
	}
	if crit.Coverage.Assessed != 1 {
		t.Errorf("?severity=critical assessed_assets = %d, want 1 — coverage ignored the filter", crit.Coverage.Assessed)
	}

	// `low` names only the OLDER verdict of n-1: the current-state fold is
	// applied AFTER the filter, so the identity is still discovered once.
	low := posture("severity=low")
	if low.Funnel.Discover != 1 {
		t.Errorf("?severity=low discover = %d, want 1", low.Funnel.Discover)
	}
	if low.Funnel.Prioritize != 0 {
		t.Errorf("?severity=low prioritize = %d, want 0 — `low` is not a priority severity", low.Funnel.Prioritize)
	}
	if low.LastScan.ScanID != "scan-1" {
		t.Errorf("?severity=low last_scan = %q, want scan-1 — the newest doc the FILTER left", low.LastScan.ScanID)
	}

	// A filter matching nothing must empty the funnel. `scope` is the device
	// REGISTRY size and is deliberately not a function of the filter, so it
	// stays — an unassessed fleet must read as unassessed, never as zero.
	none := posture("severity=info")
	if none.Funnel.Discover != 0 || none.Funnel.Prioritize != 0 || none.Funnel.Mobilize != 0 {
		t.Errorf("a filter matching nothing must empty the funnel, got discover %d / prioritize %d / mobilize %d",
			none.Funnel.Discover, none.Funnel.Prioritize, none.Funnel.Mobilize)
	}
	if none.Coverage.Assessed != 0 {
		t.Errorf("a filter matching nothing must assess nothing, got %d", none.Coverage.Assessed)
	}
	if none.Coverage.Total != all.Coverage.Total || none.Coverage.Total == 0 {
		t.Errorf("scope must stay the registry size (%d), got %d", all.Coverage.Total, none.Coverage.Total)
	}
}
