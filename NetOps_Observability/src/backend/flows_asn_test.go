// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// AS numbers (tracker 387 PR 13d): the exporter's own AS wins, the iptoasn
// dataset fills the rest only when its dictionary loads, and every row says
// which (as_basis). A dataset that does not load reads absent, never an error.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCHDict is a ClickHouse stand-in whose dictionary probe succeeds or fails.
func fakeCHDict(t *testing.T, dictLoads bool) *[]string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b)
		mu.Lock()
		got = append(got, sql)
		mu.Unlock()
		if strings.Contains(sql, "IPv6StringToNumOrDefault('192.0.2.1')") && !dictLoads {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Code: 107. DB::Exception: FILE_DOESNT_EXIST"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return &got
}

func lastSQL(q *[]string) string { return (*q)[len(*q)-1] }

func TestFlowsTopNASUsesTheDatasetOnlyWhenItLoads(t *testing.T) {
	for _, side := range []string{"src", "dst"} {
		q := fakeCHDict(t, true)
		s := flowsTestServer(t)
		w := httptest.NewRecorder()
		s.handleFlowsTopN(w, req(http.MethodGet, "/api/flows/topn?by="+side+"_as", "", superA()))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", side, w.Code)
		}
		sql := lastSQL(q)
		for _, want := range []string{
			"if(" + side + "_as > 0, " + side + "_as, dictGetOrDefault('netops.ip_asn', 'asn', tuple(IPv6StringToNumOrDefault(" + side + "_addr)), toUInt32(0)))",
			"if(max(" + side + "_as) > 0, 'exporter', 'dataset') AS as_basis",
		} {
			if !strings.Contains(sql, want) {
				t.Errorf("%s: SQL lacks %q:\n%s", side, want, sql)
			}
		}

		q = fakeCHDict(t, false)
		w = httptest.NewRecorder()
		s.handleFlowsTopN(w, req(http.MethodGet, "/api/flows/topn?by="+side+"_as", "", superA()))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: a dataset that does not load must not fail the panel: %d", side, w.Code)
		}
		sql = lastSQL(q)
		if strings.Contains(sql, "netops.ip_asn") || !strings.Contains(sql, "AND "+side+"_as > 0") {
			t.Errorf("%s: unloaded dataset must leave the exporter's AS alone:\n%s", side, sql)
		}
	}
}

func TestFlowsCoverageCountsDatasetAS(t *testing.T) {
	q := fakeCHDict(t, true)
	flowsTestServer(t).handleFlowsCoverage(httptest.NewRecorder(), req(http.MethodGet, "/api/flows/coverage", "", superA()))
	sql := lastSQL(q)
	if !strings.Contains(sql, "AS flows_with_dataset_as") || !strings.Contains(sql, "countIf(src_as = 0 AND dst_as = 0 AND (") ||
		!strings.Contains(sql, "1                          AS asn_dataset_loaded") {
		t.Errorf("coverage does not count dataset AS numbers:\n%s", sql)
	}
	q = fakeCHDict(t, false)
	flowsTestServer(t).handleFlowsCoverage(httptest.NewRecorder(), req(http.MethodGet, "/api/flows/coverage", "", superA()))
	sql = lastSQL(q)
	if strings.Contains(sql, "netops.ip_asn") || !strings.Contains(sql, "0                          AS asn_dataset_loaded") {
		t.Errorf("an unloaded dataset must read absent in coverage:\n%s", sql)
	}
}
