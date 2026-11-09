// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func row(rows []VendorScore, vendor string) *VendorScore {
	for i := range rows {
		if rows[i].Vendor == vendor {
			return &rows[i]
		}
	}
	return nil
}

func TestTheEmbeddedScorecardLoads(t *testing.T) {
	rows, err := embeddedVendorCoverage()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("an empty scorecard would read as no vendor is supported")
	}
	std := 0
	for _, r := range rows {
		if r.Standard {
			std++
		}
		for _, lane := range []string{laneSyslog, laneTrap} {
			if _, ok := r.Lanes[lane]; !ok {
				t.Errorf("vendor %q has no %s row", r.Vendor, lane)
			}
		}
	}
	if std != 1 {
		t.Fatalf("want exactly one row for what holds for every sender, got %d", std)
	}
}

func TestEachCallIsAFreshCopy(t *testing.T) {
	a, err := embeddedVendorCoverage()
	if err != nil {
		t.Fatal(err)
	}
	vendorScores(a, map[string]map[string]LiveParse{a[0].Vendor: {laneSyslog: {Total: 9, Read: 9}}}, true)
	b, err := embeddedVendorCoverage()
	if err != nil {
		t.Fatal(err)
	}
	if b[0].Lanes[laneSyslog].Live != nil {
		t.Fatal("a request's reading leaked into the shared scorecard")
	}
}

func TestReadLiveAsksPerLaneAndRefusesHalfAReading(t *testing.T) {
	var asked []string
	got, ok := readLive(context.Background(), func(_ context.Context, q string) map[string]float64 {
		asked = append(asked, q)
		switch {
		case strings.Contains(q, `parser_status="parsed"`):
			return map[string]float64{"cisco": 90}
		case strings.Contains(q, `parser_status=~"decoded|partially_decoded"`):
			return map[string]float64{"cisco": 3}
		case strings.Contains(q, `lane="syslog"`):
			return map[string]float64{"cisco": 100, "arista": 7}
		default:
			return map[string]float64{"cisco": 4}
		}
	})
	if !ok {
		t.Fatal("a full answer must read as a reading")
	}
	if len(asked) != 4 {
		t.Fatalf("asked %v", asked)
	}
	if got["cisco"][laneSyslog] != (LiveParse{Total: 100, Read: 90}) || got["cisco"][laneTrap] != (LiveParse{Total: 4, Read: 3}) {
		t.Fatalf("cisco: %+v", got["cisco"])
	}
	if got["arista"][laneSyslog] != (LiveParse{Total: 7, Read: 0}) {
		t.Fatalf("arista with nothing parsed must read 7 and 0: %+v", got["arista"])
	}
	// One failed query in four: no reading at all, never a lane that looks empty.
	n := 0
	if _, ok := readLive(context.Background(), func(context.Context, string) map[string]float64 {
		n++
		if n == 3 {
			return nil
		}
		return map[string]float64{}
	}); ok {
		t.Fatal("half a reading must not be reported")
	}
	if _, ok := readLive(context.Background(), nil); ok {
		t.Fatal("no query seam means no reading")
	}
}

func TestVendorScoresKeepNoReadingApartFromNoLines(t *testing.T) {
	base := func() []VendorScore {
		rows, err := embeddedVendorCoverage()
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	// No reading: nil on every lane, so nothing can render as a number.
	for _, r := range vendorScores(base(), nil, false) {
		for lane, s := range r.Lanes {
			if s.Live != nil {
				t.Fatalf("%s/%s has a reading when none was available: %+v", r.Vendor, lane, s.Live)
			}
		}
	}
	// A reading with no lines for a vendor: {0,0}, which the page words as no lines.
	rows := vendorScores(base(), map[string]map[string]LiveParse{}, true)
	if r := row(rows, "cisco"); r == nil || r.Lanes[laneSyslog].Live == nil || *r.Lanes[laneSyslog].Live != (LiveParse{}) {
		t.Fatalf("cisco with no lines: %+v", r)
	}
	// The standards row is rules, not senders: no reading is ever attributed to it.
	for _, r := range rows {
		if r.Standard && r.Lanes[laneSyslog].Live != nil {
			t.Fatal("the standards row must carry no reading")
		}
	}
	if row(rows, "unidentified") != nil {
		t.Fatal("no stranger, no extra row")
	}
}

func TestVendorScoresShowWhatNoVendorClaimed(t *testing.T) {
	rows, err := embeddedVendorCoverage()
	if err != nil {
		t.Fatal(err)
	}
	got := vendorScores(rows, map[string]map[string]LiveParse{
		"unknown": {laneSyslog: {Total: 119000}},
		"other":   {laneSyslog: {Total: 1000, Read: 10}, laneTrap: {Total: 5, Read: 5}},
		"cisco":   {laneSyslog: {Total: 3, Read: 3}},
	}, true)
	u := row(got, "unidentified")
	if u == nil || !u.Unidentified {
		t.Fatalf("records with no known vendor must be shown: %+v", got)
	}
	if *u.Lanes[laneSyslog].Live != (LiveParse{Total: 120000, Read: 10}) || *u.Lanes[laneTrap].Live != (LiveParse{Total: 5, Read: 5}) {
		t.Fatalf("unidentified: %+v", u.Lanes)
	}
	if *row(got, "cisco").Lanes[laneSyslog].Live != (LiveParse{Total: 3, Read: 3}) {
		t.Fatal("a known vendor's reading must stay on its own row")
	}
}

func TestStatsRouteServesTheScorecard(t *testing.T) {
	h := newHarness(t, platform())
	h.replicas["https://c1:8443/healthz"] = `{"ingest":{"syslog_prefilter_passed":5,"syslog_prefilter_rejected":2,"syslog_high_severity_no_signal":7}}`
	h.replicas["https://c1:8443/metrics"] = ""
	h.replicas["https://c2:8443/healthz"] = `{"ingest":{"syslog_high_severity_no_signal":1}}`
	h.replicas["https://c2:8443/metrics"] = ""
	h.api.d.QueryByVendor = func(context.Context, string) map[string]float64 { return map[string]float64{} }

	w := httptest.NewRecorder()
	h.api.HandleStats(w, httptest.NewRequest(http.MethodGet, "/api/admin/parser/stats", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var st Stats
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Prefilter.HighSeveritySkipped != 8 {
		t.Fatalf("high-severity skipped = %d, want both replicas summed", st.Prefilter.HighSeveritySkipped)
	}
	if len(st.Vendors) == 0 || row(st.Vendors, "cisco") == nil {
		t.Fatalf("vendors: %+v", st.Vendors)
	}
}

// The metric store being down degrades the scorecard, never the route.
func TestStatsRouteSurvivesAnUnreachableMetricStore(t *testing.T) {
	h := newHarness(t, platform())
	h.replicas["https://c1:8443/healthz"] = `{"ingest":{"syslog_prefilter_passed":5}}`
	h.replicas["https://c1:8443/metrics"] = ""
	h.api.d.QueryByVendor = func(context.Context, string) map[string]float64 { return nil }

	w := httptest.NewRecorder()
	h.api.HandleStats(w, httptest.NewRequest(http.MethodGet, "/api/admin/parser/stats", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"live":null`) || strings.Contains(w.Body.String(), `"live":{`) {
		t.Fatalf("no reading must serialize as null: %s", w.Body.String()[:400])
	}
}
