// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The flows views leave platform monitoring out by default, the toggle brings
// it back, and an unconfigured install hides nothing.
func TestFlowsExcludePlatformMonitoringByDefault(t *testing.T) {
	t.Setenv("CX_PLATFORM_ADDRESSES", "10.70.245.122")
	t.Setenv("PATH_GRAPH_VANTAGE_ADDRESSES", "")
	for _, c := range []struct {
		path    string
		exclude bool
	}{
		{"/api/flows/top", true},
		{"/api/flows/topn?by=dst_port", true},
		{"/api/flows/topn?by=in_if", true},
		{"/api/flows/top?traffic=all", false},
		{"/api/flows/topn?by=dst_port&traffic=ALL", false},
	} {
		calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
		s := flowsTestServer(t)
		w := httptest.NewRecorder()
		r := req(http.MethodGet, c.path, "", superA())
		if strings.HasPrefix(c.path, "/api/flows/topn") {
			s.handleFlowsTopN(w, r)
		} else {
			s.handleFlowsTopTalkers(w, r)
		}
		if w.Code != http.StatusOK || len(*calls) != 1 {
			t.Fatalf("%s: status %d, %d queries", c.path, w.Code, len(*calls))
		}
		got := strings.Contains((*calls)[0].sql, "AND NOT (src_addr IN ('10.70.245.122') OR dst_addr IN ('10.70.245.122'))")
		if got != c.exclude {
			t.Errorf("%s: exclusion present=%v, want %v:\n%s", c.path, got, c.exclude, (*calls)[0].sql)
		}
	}
	t.Setenv("CX_PLATFORM_ADDRESSES", "")
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	s := flowsTestServer(t)
	s.handleFlowsTopTalkers(httptest.NewRecorder(), req(http.MethodGet, "/api/flows/top", "", superA()))
	if strings.Contains((*calls)[0].sql, "AND NOT") {
		t.Errorf("unconfigured install must hide nothing:\n%s", (*calls)[0].sql)
	}
}

// Coverage counts what the views hide, so the hiding is never silent.
func TestFlowsCoverageCountsPlatformMonitoring(t *testing.T) {
	t.Setenv("CX_PLATFORM_ADDRESSES", "10.70.245.122")
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	s := flowsTestServer(t)
	s.handleFlowsCoverage(httptest.NewRecorder(), req(http.MethodGet, "/api/flows/coverage", "", superA()))
	sql := (*calls)[0].sql
	if !strings.Contains(sql, "countIf((src_addr IN ('10.70.245.122') OR dst_addr IN ('10.70.245.122')))") ||
		!strings.Contains(sql, "1                    AS platform_addresses_configured") {
		t.Errorf("coverage does not count platform monitoring:\n%s", sql)
	}
	if strings.Contains(sql, "AND NOT (") {
		t.Errorf("coverage must count every selected row, not exclude:\n%s", sql)
	}
}
