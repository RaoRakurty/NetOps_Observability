// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Tests for GET /api/logs/severity-counts (tracker 387, the Logs summary tiles).
// The counts must come from exactly the surface the search reads (§3a): the
// caller's own tenant index pattern and per-document tenant clause, the same
// query and time window, the same refusals. The cross-org leg (own tenant only,
// as_tenant ignored, a foreign index never named) runs through the real router in
// logs_identity_protection_test.go TestLogReadsCrossOrgIsolation; the 403 for a
// role without log access runs there too (idpDoors).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const osSeverityReply = `{"hits":{"total":{"value":40,"relation":"eq"},"hits":[]},"aggregations":{` +
	`"sev":{"sum_other_doc_count":2,"buckets":[{"key":"crit","doc_count":3},{"key":"warning","doc_count":20},{"key":"","doc_count":9}]},` +
	`"lvl_only":{"doc_count":10,"lvl":{"sum_other_doc_count":0,"buckets":[{"key":"error","doc_count":10}]}},` +
	`"none":{"doc_count":5}}}`

func decodeSeverity(t *testing.T, w *httptest.ResponseRecorder) severityCountsResp {
	t.Helper()
	var out severityCountsResp
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestSeverityCountsAreTenantScopedLikeTheSearch(t *testing.T) {
	paths, bodies := fakeOS(t, osSeverityReply)
	s := logsTestServer(t)

	w := httptest.NewRecorder()
	// as_tenant is a narrowing selector the auth middleware applies to the claims;
	// the handler must never read it itself.
	s.handleLogsSeverityCounts(w, req(http.MethodGet,
		"/api/logs/severity-counts?signal=syslog&query=hostname%3A%22edge-1%22&from=2026-11-10T00:00:00Z&to=2026-11-10T06:00:00Z&as_tenant=globex",
		"", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if len(*paths) != 1 {
		t.Fatalf("want 1 store request, got %d", len(*paths))
	}
	p := (*paths)[0]
	if !strings.Contains(p, "netops-syslog-acme-*") {
		t.Errorf("index pattern not the caller's own: %q", p)
	}
	if strings.Contains(p, "globex") {
		t.Errorf("TENANT LEAK: acme's count names a foreign index: %q", p)
	}
	body := (*bodies)[0]
	for _, must := range []string{
		`"tenant_id":"acme"`, `"track_total_hits":true`, `"size":0`,
		`"query":"hostname:\"edge-1\""`, `"gte":"2026-11-10T00:00:00Z"`, `"lte":"2026-11-10T06:00:00Z"`,
		`"field":"severity"`, `"field":"level"`,
	} {
		if !strings.Contains(body, must) {
			t.Errorf("count query missing %q:\n%s", must, body)
		}
	}
	if strings.Contains(body, "globex") {
		t.Errorf("TENANT LEAK: the as_tenant value reached the query:\n%s", body)
	}
}

func TestSeverityCountsAddUpAndKeepTheStoredWords(t *testing.T) {
	fakeOS(t, osSeverityReply)
	s := logsTestServer(t)
	w := httptest.NewRecorder()
	s.handleLogsSeverityCounts(w, req(http.MethodGet, "/api/logs/severity-counts?signal=", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", w.Code, w.Body.String())
	}
	out := decodeSeverity(t, w)
	if out.Total != 40 || out.Unrated != 5 || out.Other != 2 {
		t.Errorf("total/unrated/other = %d/%d/%d, want 40/5/2", out.Total, out.Unrated, out.Other)
	}
	want := []severityCount{{"severity", "crit", 3}, {"severity", "warning", 20}, {"level", "error", 10}}
	if len(out.Counts) != len(want) {
		t.Fatalf("counts = %+v, want %+v (an empty key is not a severity)", out.Counts, want)
	}
	for i := range want {
		if out.Counts[i] != want[i] {
			t.Errorf("counts[%d] = %+v, want %+v", i, out.Counts[i], want[i])
		}
	}
	if out.Sampling != nil {
		t.Errorf("syslog/all counts are exact; no sampling key: %+v", out.Sampling)
	}
}

func TestSeverityCountsRefuseWhatTheSearchRefuses(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"app logs for a tenant", "/api/logs/severity-counts?signal=applogs"},
		{"security findings", "/api/logs/severity-counts?signal=security"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, _ := fakeOS(t, osSeverityReply)
			s := logsTestServer(t)
			w := httptest.NewRecorder()
			s.handleLogsSeverityCounts(w, req(http.MethodGet, tc.path, "", acme()))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", w.Code)
			}
			if len(*paths) != 0 {
				t.Fatalf("a refused count reached the store %d times", len(*paths))
			}
		})
	}
}

func TestSeverityCountsValidateInputBeforeTheStore(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"bad from", "/api/logs/severity-counts?from=yesterday-ish"},
		{"bad to", "/api/logs/severity-counts?to=%3Cscript%3E"},
		{"window backwards", "/api/logs/severity-counts?from=2026-11-10T06:00:00Z&to=2026-11-10T00:00:00Z"},
		{"query too long", "/api/logs/severity-counts?query=" + strings.Repeat("a", severityCountsQueryMax+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, _ := fakeOS(t, osSeverityReply)
			s := logsTestServer(t)
			w := httptest.NewRecorder()
			s.handleLogsSeverityCounts(w, req(http.MethodGet, tc.path, "", acme()))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
			if len(*paths) != 0 {
				t.Fatalf("invalid input reached the store")
			}
		})
	}
	s := logsTestServer(t)
	w := httptest.NewRecorder()
	s.handleLogsSeverityCounts(w, req(http.MethodPost, "/api/logs/severity-counts", "{}", acme()))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", w.Code)
	}
}

func TestSeverityCountsOnFlowsSayTheyAreASample(t *testing.T) {
	fakeOS(t, `{"hits":{"total":{"value":7}},"aggregations":{"sev":{"buckets":[]},"lvl_only":{"lvl":{"buckets":[]}},"none":{"doc_count":7}}}`)
	s := logsTestServer(t)
	w := httptest.NewRecorder()
	s.handleLogsSeverityCounts(w, req(http.MethodGet, "/api/logs/severity-counts?signal=flows", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	out := decodeSeverity(t, w)
	if out.Sampling == nil || out.Sampling["rate"] != float64(50) {
		t.Errorf("flows counts must carry the 1:50 sampling disclosure: %+v", out.Sampling)
	}
	if out.Unrated != 7 {
		t.Errorf("flows carry no severity: all 7 are unrated, got %d", out.Unrated)
	}
}

func TestSeverityCountsAStoreErrorIsNotRelayed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"root_cause":[{"reason":"internal index name netops-syslog-globex-2026"}]}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
	s := idpServer(t)
	w := httptest.NewRecorder()
	s.handleLogsSeverityCounts(w, req(http.MethodGet, "/api/logs/severity-counts?signal=syslog&query=(", "", acme()))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Errorf("the store's error text reached the caller: %s", w.Body.String())
	}
	if got := idpEvents(t, s, auditMethodLogRead); len(got) != 1 || got[0].Status != http.StatusBadGateway {
		t.Errorf("a failed count is still recorded once: %+v", got)
	}
}

func TestSeverityCountsAreAuditedOnceWithoutRows(t *testing.T) {
	fakeOS(t, osSeverityReply)
	s := idpServer(t)
	w := httptest.NewRecorder()
	s.handleLogsSeverityCounts(w, req(http.MethodGet, "/api/logs/severity-counts?signal=syslog&query=session+AND+password%3Dhunter2", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", w.Code, w.Body.String())
	}
	got := idpEvents(t, s, auditMethodLogRead)
	if len(got) != 1 {
		t.Fatalf("want exactly one read record, got %+v", got)
	}
	e := got[0]
	if e.Actor != acme().Sub || e.Tenant != "acme" || e.Cross || e.Path != "/api/logs/severity-counts" {
		t.Errorf("who/where: %+v", e)
	}
	if e.Detail["action"] != "logs.severity_counts" {
		t.Errorf("action: %+v", e.Detail)
	}
	if q, _ := e.Detail["query"].(string); strings.Contains(q, "hunter2") || !strings.Contains(q, "session") {
		t.Errorf("query recorded without the secret: %q", q)
	}
	if e.Detail["matched"] != float64(40) && e.Detail["matched"] != int64(40) {
		t.Errorf("matched: %+v", e.Detail)
	}
}
