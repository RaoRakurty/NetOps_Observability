// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/iana"
)

// The platform's addresses come from configuration, and only parsed values
// reach SQL: a malformed or hostile entry is dropped, never interpolated.
func TestParsePlatformAddrs(t *testing.T) {
	p := parsePlatformAddrs(" 10.70.245.122 , 10.99.0.0/16, bogus, 1.2.3.4') OR 1=1 --",
		"prober=10.70.245.123,lan-vantage-1:172.40.40.200,v6=2001:db8::1")
	if strings.Join(p.ips, ",") != "10.70.245.122,10.70.245.123,172.40.40.200,2001:db8::1" {
		t.Errorf("ips = %v", p.ips)
	}
	if len(p.nets) != 1 || p.nets[0].String() != "10.99.0.0/16" {
		t.Errorf("nets = %v", p.nets)
	}
	cond := p.sqlCond()
	if strings.Contains(cond, "bogus") || strings.Contains(cond, "1=1") {
		t.Fatalf("configuration text reached SQL: %s", cond)
	}
	for _, want := range []string{"src_addr IN ('10.70.245.122'", "dst_addr IN (", "isIPAddressInRange(src_addr, '10.99.0.0/16')"} {
		if !strings.Contains(cond, want) {
			t.Errorf("cond missing %q: %s", want, cond)
		}
	}
	if !p.contains("10.99.4.5") || !p.contains("10.70.245.122") || p.contains("10.70.245.124") {
		t.Error("contains() disagrees with the configured set")
	}
	if !parsePlatformAddrs("", "").empty() || parsePlatformAddrs("", "").sqlCond() != "" {
		t.Error("unconfigured must classify nothing")
	}
}

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

// The Logs page labels a platform-monitoring flow and deletes nothing.
func TestLogsFlowDocsLabelPlatformMonitoring(t *testing.T) {
	resp := map[string]any{}
	if err := json.Unmarshal([]byte(`{"hits":{"hits":[
	  {"_source":{"src_addr":"10.70.245.122","dst_addr":"10.70.245.104","proto":17,"src_port":50000,"dst_port":161}},
	  {"_source":{"src_addr":"192.0.2.1","dst_addr":"192.0.2.2","proto":6,"src_port":50000,"dst_port":443}}
	]}}`), &resp); err != nil {
		t.Fatal(err)
	}
	annotateFlowHits(resp, nil, iana.Default(), parsePlatformAddrs("10.70.245.122", ""))
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("a document was dropped: %d", len(hits))
	}
	r0 := hits[0].(map[string]any)["_resolved"].(map[string]any)
	r1 := hits[1].(map[string]any)["_resolved"].(map[string]any)
	if r0["traffic_class"] != trafficClassPlatform {
		t.Errorf("our own poll not labelled: %v", r0)
	}
	if _, ok := r1["traffic_class"]; ok {
		t.Errorf("customer traffic labelled platform: %v", r1)
	}
}
