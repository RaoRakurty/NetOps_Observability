// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Tests for the Logs "don't hide" surface (owner directive): the retention
// floor and the search read must (a) stay tenant-scoped through the shared
// logsScope path, (b) report EXACT totals (track_total_hits), and (c) bound
// the paging offset server-side.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/discovery"
	"strings"
	"testing"

	"netops/backend/models"
)

// fakeOS stands in for OpenSearch, capturing each request's path + body and
// answering with a canned aggregation response.
func fakeOS(t *testing.T, reply string) (paths *[]string, bodies *[]string) {
	t.Helper()
	var gotPaths, gotBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPaths = append(gotPaths, r.URL.Path)
		gotBodies = append(gotBodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
	return &gotPaths, &gotBodies
}

func logsTestServer(t *testing.T) *server {
	t.Helper()
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex"})
	return &server{discovery: d}
}

const osAggReply = `{"hits":{"total":{"value":123456,"relation":"eq"},"hits":[]},` +
	`"aggregations":{"oldest_ts":{"value":1718460000000,"value_as_string":"2024-06-15T14:00:00.000Z"}}}`

func TestLogsRetentionTenantScoped(t *testing.T) {
	paths, bodies := fakeOS(t, osAggReply)
	s := logsTestServer(t)

	w := httptest.NewRecorder()
	s.handleLogsRetention(w, req(http.MethodGet, "/api/logs/retention?signal=syslog", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if len(*paths) != 1 {
		t.Fatalf("want 1 OS request, got %d", len(*paths))
	}
	// Storage-layer isolation: only acme's own + untagged indices are ever named.
	p := (*paths)[0]
	if !strings.Contains(p, "netops-syslog-acme-*") || !strings.Contains(p, "netops-syslog-untagged-*") {
		t.Errorf("index pattern not tenant-scoped: %q", p)
	}
	if strings.Contains(p, "globex") {
		t.Errorf("TENANT LEAK: acme retention read names a foreign index: %q", p)
	}
	body := (*bodies)[0]
	// Per-doc isolation (defense in depth) + exact-count + min-timestamp agg.
	for _, must := range []string{
		`"tenant_id":"acme"`, `"track_total_hits":true`, `"oldest_ts"`, `"min"`, `"field":"timestamp"`,
	} {
		if !strings.Contains(body, must) {
			t.Errorf("retention query missing %q:\n%s", must, body)
		}
	}
	var out struct {
		Total  int64   `json:"total"`
		Oldest *string `json:"oldest"`
		Days   int     `json:"days"`
	}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Total != 123456 {
		t.Errorf("total = %d, want the exact hit count 123456", out.Total)
	}
	if out.Oldest == nil || !strings.HasPrefix(*out.Oldest, "2024-06-15T14:00:00") {
		t.Errorf("oldest = %v, want the min-timestamp bucket", out.Oldest)
	}
	if out.Days <= 0 {
		t.Errorf("days = %d, want a positive retention depth", out.Days)
	}
}

func TestLogsRetentionAppLogsForbiddenForTenant(t *testing.T) {
	paths, _ := fakeOS(t, osAggReply)
	s := logsTestServer(t)

	w := httptest.NewRecorder()
	s.handleLogsRetention(w, req(http.MethodGet, "/api/logs/retention?signal=applogs", "", acme()))
	if w.Code != http.StatusForbidden {
		t.Fatalf("applogs retention for a tenant should 403, got %d", w.Code)
	}
	if len(*paths) != 0 {
		t.Fatalf("forbidden request must never reach OpenSearch, got %d", len(*paths))
	}
}

func TestLogsRetentionEmptyStore(t *testing.T) {
	fakeOS(t, `{"hits":{"total":{"value":0}},"aggregations":{"oldest_ts":{"value":null}}}`)
	s := logsTestServer(t)

	w := httptest.NewRecorder()
	s.handleLogsRetention(w, req(http.MethodGet, "/api/logs/retention?signal=syslog", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var out map[string]any
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["oldest"] != nil || out["total"] != float64(0) {
		t.Errorf("empty store should report oldest=null total=0, got %v", out)
	}
}

// The interactive search must report EXACT totals and honor a bounded offset —
// the "Load more" contract.
func TestLogsSearchExactTotalsAndBoundedOffset(t *testing.T) {
	_, bodies := fakeOS(t, `{"hits":{"total":{"value":0},"hits":[]}}`)
	s := logsTestServer(t)

	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search",
		`{"query":"*","signal":"syslog","size":200,"offset":400}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	body := (*bodies)[0]
	if !strings.Contains(body, `"track_total_hits":true`) {
		t.Errorf("search must request exact totals:\n%s", body)
	}
	if !strings.Contains(body, `"from":400`) {
		t.Errorf("search must pass the paging offset:\n%s", body)
	}

	// An offset past the engine window is clamped, never proxied raw.
	w = httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search",
		`{"query":"*","signal":"syslog","size":1000,"offset":999999}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body = (*bodies)[1]
	if !strings.Contains(body, `"from":9000`) {
		t.Errorf("offset must clamp to max_result_window-size (9000):\n%s", body)
	}
}

// Sample honesty (finder 2026-08-14): netops-flows-* holds the router's 1:50
// OpenSearch sample (ClickHouse is the canonical flow store), so every flows
// search/retention response must carry the sampling disclosure — and no other
// signal may, because their stores ARE exact.
func TestLogsSearchFlowsSamplingDisclosed(t *testing.T) {
	fakeOS(t, `{"took":3,"hits":{"total":{"value":10,"relation":"eq"},"hits":[]}}`)
	s := logsTestServer(t)

	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search",
		`{"query":"*","signal":"flows"}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var out struct {
		Took int64 `json:"took"`
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Sampling *struct {
			Rate int    `json:"rate"`
			Note string `json:"note"`
		} `json:"sampling"`
	}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Sampling == nil {
		t.Fatalf("flows search response carries no sampling disclosure — the 1:50 sample reads as exact")
	}
	// 50 is asserted literally (not just == flowsOSSampleRate) so a drifted
	// constant cannot make this test agree with itself; the python contract
	// test pins the same literal to the router's sampler rate.
	if out.Sampling.Rate != 50 || flowsOSSampleRate != 50 {
		t.Errorf("sampling.rate = %d (const %d), want 50 (the router's flows_os_sample rate)", out.Sampling.Rate, flowsOSSampleRate)
	}
	if !strings.Contains(out.Sampling.Note, "1:50 sample") || !strings.Contains(out.Sampling.Note, "estimates") {
		t.Errorf("sampling.note must state the 1:50 sample and that totals are estimates, got %q", out.Sampling.Note)
	}
	// The engine payload passes through untouched around the injected key.
	if out.Hits.Total.Value != 10 || out.Took != 3 {
		t.Errorf("flows payload was altered beyond the sampling key: %+v", out)
	}

	// Retention: "This store holds N logs" must carry the same disclosure.
	w = httptest.NewRecorder()
	s.handleLogsRetention(w, req(http.MethodGet, "/api/logs/retention?signal=flows", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("retention status = %d, want 200", w.Code)
	}
	var ret map[string]any
	if err := json.NewDecoder(w.Body).Decode(&ret); err != nil {
		t.Fatalf("decode retention: %v", err)
	}
	if _, ok := ret["sampling"]; !ok {
		t.Errorf("flows retention response carries no sampling disclosure: %v", ret)
	}

	// Exact stores stay undisclosed: a sampling key on syslog would be a lie
	// in the opposite direction.
	w = httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search",
		`{"query":"*","signal":"syslog"}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("syslog status = %d, want 200", w.Code)
	}
	var m map[string]any
	if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
		t.Fatalf("decode syslog: %v", err)
	}
	if _, ok := m["sampling"]; ok {
		t.Errorf("syslog search response must NOT carry a sampling key — that store is exact")
	}
}
