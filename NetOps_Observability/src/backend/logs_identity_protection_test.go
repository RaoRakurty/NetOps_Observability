// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// logs_identity_protection_test.go — owner decision D7 (2026-11-09): device
// syslog carries usernames, they stay for security attribution, and reading them
// is role-gated, tenant-isolated, audited, export-controlled and retention-bound.
//
// Pinned here:
//   - every door onto the log stores needs explore:read, and refuses before one
//     byte reaches OpenSearch (a zero-permission ingest key, a custom role);
//   - §3a through the REAL router: own-only reads, as_tenant into another org
//     ignored, cross-tenant export status 404;
//   - each read and export leaves a record with who, the query and the row count,
//     and never a row;
//   - an export the trail cannot record does not happen;
//   - a stored export file has a retention limit that holds on every read path,
//     and the sweep removes it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/logexport"
	"netops/backend/internal/oslog"
	"netops/backend/internal/ratelimit"
	"netops/backend/internal/token"
	"netops/backend/reports"
)

// The identities in the fake log lines. A test that finds one of these in an
// audit record has found row contents in the audit trail.
const (
	idpFixtureUser = "fixture-person-7"
	idpFixtureLine = "audit user: " + idpFixtureUser + "/42 created new session"
)

// idpFakeOS answers like OpenSearch from one document per tenant segment named in
// the requested index pattern, so what a caller gets back depends on the index it
// was allowed to name, the same way it does against the real store.
type idpFakeOS struct {
	mu    sync.Mutex
	paths []string
	body  []string
}

func (f *idpFakeOS) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func (f *idpFakeOS) bodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.body...)
}

func idpStartFakeOS(t *testing.T) *idpFakeOS {
	t.Helper()
	f := &idpFakeOS{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf strings.Builder
		if r.Body != nil {
			b := make([]byte, 1<<16)
			for {
				n, err := r.Body.Read(b)
				buf.Write(b[:n])
				if err != nil {
					break
				}
			}
		}
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.body = append(f.body, buf.String())
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/_count"):
			_, _ = w.Write([]byte(`{"count":1}`))
		case strings.HasPrefix(path, "/_cat/"):
			_, _ = w.Write([]byte(`[]`))
		default:
			var hits []map[string]any
			index := strings.TrimPrefix(strings.TrimSuffix(path, "/_search"), "/")
			for i, name := range strings.Split(index, ",") {
				if strings.Contains(name, "untagged") {
					continue
				}
				hits = append(hits, map[string]any{
					"_index": name, "_id": fmt.Sprintf("d%d", i), "sort": []any{1, "x"},
					"_source": map[string]any{"message": idpFixtureLine + " index=" + name, "timestamp": "2026-11-09T00:00:00Z"},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{
				"total": map[string]any{"value": len(hits), "relation": "eq"}, "hits": hits,
			}})
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
	return f
}

// idpServer is the handler-level fixture: real role store, real audit store.
func idpServer(t *testing.T) *server {
	t.Helper()
	s := logsTestServer(t)
	au, err := newAuditStore(filepath.Join(t.TempDir(), "audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.audit = au
	s.exportLimiter = ratelimit.New()
	// A role that can see the network and has no business reading log lines.
	if _, err := s.roles.Upsert(Role{ID: "infra-only", Name: "Infra only", Permissions: map[string]int{"infrastructure": LevelRead, "reports": LevelRead}}); err != nil {
		t.Fatal(err)
	}
	return s
}

func infraOnly() jwtClaims { return jwtClaims{Sub: "i@acme", Role: "infra-only", Tenant: "acme"} }

// idpEvents is the trail, as the platform owner reads it.
func idpEvents(t *testing.T, s *server, method string) []AuditEvent {
	t.Helper()
	all, err := s.audit.List("", true, auditQuery{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	var out []AuditEvent
	for _, e := range all {
		if e.Method == method {
			out = append(out, e)
		}
	}
	return out
}

// idpNoRowContents fails if anything in the trail carries the log line or the
// person in it.
func idpNoRowContents(t *testing.T, s *server) {
	t.Helper()
	all, err := s.audit.List("", true, auditQuery{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), idpFixtureUser) {
		t.Fatalf("row contents reached the audit trail: %s", raw)
	}
}

// idpDoors is every door onto the log stores a person can call with a session.
func idpDoors() []struct{ name, method, path, body string } {
	return []struct{ name, method, path, body string }{
		{"search POST", http.MethodPost, "/api/logs/search", `{"signal":"syslog","query":"*"}`},
		{"search GET", http.MethodGet, "/api/logs/search?signal=syslog", ""},
		{"retention", http.MethodGet, "/api/logs/retention?signal=syslog", ""},
		{"indices", http.MethodGet, "/api/logs/indices", ""},
		{"export", http.MethodGet, "/api/logs/export?signal=syslog&format=csv", ""},
		{"export rows", http.MethodPost, "/api/logs/export/rows", `{"format":"csv","rows":[["a"]]}`},
		{"export status", http.MethodGet, "/api/exports/ex1", ""},
	}
}

func idpCall(s *server, w http.ResponseWriter, method, path, body string, claims jwtClaims) {
	r := req(method, path, body, claims)
	switch {
	case strings.HasPrefix(path, "/api/logs/search"):
		s.handleLogsSearch(w, r)
	case strings.HasPrefix(path, "/api/logs/retention"):
		s.handleLogsRetention(w, r)
	case strings.HasPrefix(path, "/api/logs/indices"):
		s.handleLogsIndices(w, r)
	case strings.HasPrefix(path, "/api/logs/export/rows"):
		s.handleLogsExportRows(w, r)
	case strings.HasPrefix(path, "/api/logs/export"):
		s.handleLogsExport(w, r)
	default:
		s.handleExportStatus(w, r)
	}
}

func TestEveryLogDoorRefusesARoleWithoutLogAccess(t *testing.T) {
	callers := map[string]jwtClaims{
		"zero-permission ingest key":   ingestKey(),
		"custom role without explore":  infraOnly(),
		"role name nobody ever issued": {Sub: "x@acme", Role: "no-such-role", Tenant: "acme"},
	}
	for who, claims := range callers {
		for _, door := range idpDoors() {
			t.Run(who+"/"+door.name, func(t *testing.T) {
				fake := idpStartFakeOS(t)
				s := idpServer(t)
				w := httptest.NewRecorder()
				idpCall(s, w, door.method, door.path, door.body, claims)
				if w.Code != http.StatusForbidden {
					t.Fatalf("status %d, want 403: %s", w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), "explore") {
					t.Errorf("the refusal must name the permission: %s", w.Body.String())
				}
				if n := len(fake.calls()); n != 0 {
					t.Errorf("%d OpenSearch calls on a refused request: %v", n, fake.calls())
				}
			})
		}
	}
}

func TestEveryLogDoorAdmitsTheRolesThatHoldExplore(t *testing.T) {
	for _, role := range []string{RoleOperator, RoleReadOnly, RoleAuditor, RoleAPIClient, RoleOrgAdmin} {
		for _, door := range idpDoors() {
			t.Run(role+"/"+door.name, func(t *testing.T) {
				idpStartFakeOS(t)
				s := idpServer(t)
				w := httptest.NewRecorder()
				idpCall(s, w, door.method, door.path, door.body, jwtClaims{Sub: "r@acme", Role: role, Tenant: "acme"})
				if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
					t.Fatalf("status %d: %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestLogsScopeIsClosedWithoutAPrincipal(t *testing.T) {
	s := idpServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/logs/search", nil)
	index, _, _, _, forbidden := s.logsScope(r, "syslog")
	if !forbidden || index != "" {
		t.Fatalf("no principal resolved index %q (forbidden=%v); it must resolve nothing", index, forbidden)
	}
}

func TestParserCoverageLinesNeedLogAccess(t *testing.T) {
	pcStartFakeOS(t)
	s := pcTestServer(t)
	if _, err := s.roles.Upsert(Role{ID: "infra-only", Name: "Infra only", Permissions: map[string]int{"infrastructure": LevelRead, "alerts": LevelWrite}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.parserCov.HandleUnrecognized(w, req(http.MethodGet, "/api/telemetry/unrecognized", "", infraOnly()))
	if w.Code != http.StatusForbidden {
		t.Errorf("read: status %d, want 403: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.parserCov.HandlePropose(w, req(http.MethodPost, "/api/telemetry/unrecognized/t-0123456789/propose", "", infraOnly()))
	if w.Code != http.StatusForbidden {
		t.Errorf("propose: status %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestParserCoverageReadIsAudited(t *testing.T) {
	pcStartFakeOS(t)
	s := pcTestServer(t)
	au, err := newAuditStore(filepath.Join(t.TempDir(), "audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.audit = au
	w := httptest.NewRecorder()
	s.parserCov.HandleUnrecognized(w, req(http.MethodGet, "/api/telemetry/unrecognized?days=3", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	got := idpEvents(t, s, http.MethodGet)
	if len(got) != 1 || got[0].Actor != acme().Sub || got[0].Detail["action"] != "parsercov.read" {
		t.Fatalf("want one parsercov.read record by the caller, got %+v", got)
	}
	if _, ok := got[0].Detail["scanned"]; !ok {
		t.Errorf("the record must say how many lines were read: %+v", got[0].Detail)
	}
	for k := range got[0].Detail {
		if k == "sample" || k == "template" || k == "items" {
			t.Errorf("row contents key %q in the audit record", k)
		}
	}
}

// ---- audit: who, query, row count, never a row ------------------------------

func TestLogSearchAuditHoldsWhoQueryAndCountsAndNoRow(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"POST", http.MethodPost, "/api/logs/search", `{"signal":"syslog","query":"session AND password=hunter2"}`},
		{"GET", http.MethodGet, "/api/logs/search?signal=syslog&query=session+AND+password%3Dhunter2", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idpStartFakeOS(t)
			s := idpServer(t)
			w := httptest.NewRecorder()
			s.handleLogsSearch(w, req(tc.method, tc.path, tc.body, acme()))
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), idpFixtureUser) {
				t.Fatalf("D7 retains usernames: the search must still return the line: %s", w.Body.String())
			}
			got := idpEvents(t, s, auditMethodLogRead)
			if len(got) != 1 {
				t.Fatalf("want exactly one read record, got %+v", got)
			}
			e := got[0]
			if e.Actor != acme().Sub || e.Tenant != "acme" || e.Cross {
				t.Errorf("who: %+v", e)
			}
			q, _ := e.Detail["query"].(string)
			if !strings.Contains(q, "session") {
				t.Errorf("the query must be recorded: %+v", e.Detail)
			}
			if strings.Contains(q, "hunter2") {
				t.Errorf("a secret pasted into the search box reached the trail: %q", q)
			}
			if e.Detail["rows"] != float64(1) && e.Detail["rows"] != 1 {
				t.Errorf("rows: %+v", e.Detail)
			}
			if e.Detail["matched"] != float64(1) && e.Detail["matched"] != int64(1) {
				t.Errorf("matched: %+v", e.Detail)
			}
			idpNoRowContents(t, s)
		})
	}
}

func TestAuditQueryTextIsBounded(t *testing.T) {
	long := strings.Repeat("é", exportAuditQueryMax)
	got := auditQueryText(long)
	if len(got) > exportAuditQueryMax+len(" …") {
		t.Errorf("length %d", len(got))
	}
	if strings.ToValidUTF8(got, "") != got {
		t.Error("the bound cut a character in half")
	}
}

func TestRelayLogSearchIsByteForByteAndCounts(t *testing.T) {
	for _, tc := range []struct {
		name, body    string
		matched, rows int
	}{
		{"search answer", `{"took":1,"hits":{"total":{"value":9},"hits":[{"_id":"a"},{"_id":"b"}]},"x":[1]}`, 9, 2},
		{"not json", `<html>proxy error</html>`, -1, -1},
		{"truncated", `{"hits":{"total":{"value":9},"hits":[{"_id":`, -1, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			got, err := relayLogSearch(&out, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.body {
				t.Errorf("the response changed: %q", out.String())
			}
			if got.Matched != int64(tc.matched) || got.Rows != tc.rows {
				t.Errorf("counts %+v, want %d/%d", got, tc.matched, tc.rows)
			}
		})
	}
}

// A log search is a read: the middleware must not add a second, path-only row
// for it, and it must not reach the correlation spine as a change.
func TestLogSearchLeavesOneRecordThroughTheMiddleware(t *testing.T) {
	idpStartFakeOS(t)
	s := idpServer(t)
	h := s.withAudit(http.HandlerFunc(s.handleLogsSearch))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodPost, "/api/logs/search", `{"signal":"syslog","query":"x"}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if got := idpEvents(t, s, http.MethodPost); len(got) != 0 {
		t.Errorf("a second path-only row was written: %+v", got)
	}
	if got := idpEvents(t, s, auditMethodLogRead); len(got) != 1 {
		t.Errorf("want one read record, got %+v", got)
	}
	// A refusal still lands in the trail, by way of the middleware.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodPost, "/api/logs/search", `{"signal":"syslog"}`, infraOnly()))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
	denied := idpEvents(t, s, http.MethodPost)
	if len(denied) != 1 || denied[0].Decision != "deny" || denied[0].Actor != infraOnly().Sub {
		t.Errorf("the denial must be recorded: %+v", denied)
	}
}

func TestLogReadsAreNotCorrelationSignals(t *testing.T) {
	for _, m := range []string{auditMethodLogRead, auditMethodConsole} {
		if auditSignalWorthy(AuditEvent{Decision: "allow", Method: m}) {
			t.Errorf("%s is a read and must stay off the correlation spine", m)
		}
	}
}

func TestRawConsoleIsAuditedOncePerMinutePerPerson(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret-for-the-console-gate-0123456789")
	s := idpServer(t)
	tenants, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.tenants = tenants
	tok, err := token.Sign(jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal, Exp: time.Now().Add(time.Hour).Unix()}, jwtSecret())
	if err != nil {
		t.Fatal(err)
	}
	gate := func(path string) int {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: osdCookieName, Value: tok})
		w := httptest.NewRecorder()
		s.handleOSDGate(w, r)
		return w.Code
	}
	for i := 0; i < 5; i++ { // every asset the console loads comes through here
		if code := gate("/api/auth/osd-gate?c=search"); code != http.StatusOK {
			t.Fatalf("gate: %d", code)
		}
	}
	got := idpEvents(t, s, auditMethodConsole)
	if len(got) != 1 || got[0].Actor != "root" || got[0].Detail["action"] != "logs.raw_console" {
		t.Fatalf("want one console record by the owner, got %+v", got)
	}
	// /netbox shares this gate and is not the log console.
	s2 := idpServer(t)
	s2.tenants = tenants
	r := httptest.NewRequest(http.MethodGet, "/api/auth/osd-gate", nil)
	r.AddCookie(&http.Cookie{Name: osdCookieName, Value: tok})
	s2.handleOSDGate(httptest.NewRecorder(), r)
	if got := idpEvents(t, s2, auditMethodConsole); len(got) != 0 {
		t.Errorf("a NetBox request was recorded as the raw console: %+v", got)
	}
}

func TestIrisLogSearchIsAuditedAndMasksEveryUsernameForm(t *testing.T) {
	lines := []string{
		"audit user: " + idpFixtureUser + "/42 created new session",
		"Accepted publickey for " + idpFixtureUser + " from 10.0.0.9 port 22 ssh2",
		"User '" + idpFixtureUser + "' authenticated successfully",
	}
	var hits []map[string]any
	for i, l := range lines {
		hits = append(hits, map[string]any{"_id": fmt.Sprint(i), "_source": map[string]any{"message": l, "timestamp": "2026-11-09T00:00:00Z", "host": "r1"}})
	}
	reply, err := json.Marshal(map[string]any{"hits": map[string]any{"total": map[string]any{"value": 40}, "hits": hits}})
	if err != nil {
		t.Fatal(err)
	}
	fakeOS(t, string(reply))
	s := idpServer(t)
	claims := acme()
	d := aiDataSource{srv: s, ctx: context.Background(), claims: claims}
	tr, err := d.moduleSearchLogs(s.aiPrincipal(claims), ai.ToolArgs{"query": "session password=hunter2", "window": "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Items) != len(lines) {
		t.Fatalf("items: %+v", tr.Items)
	}
	for _, it := range tr.Items {
		if strings.Contains(it.Text, idpFixtureUser) {
			t.Errorf("a username reached the model's context (LLM06): %q", it.Text)
		}
	}
	got := idpEvents(t, s, auditMethodLogRead)
	if len(got) != 1 || got[0].Actor != claims.Sub || got[0].Detail["action"] != "ai.search_logs" {
		t.Fatalf("want one record by the caller, got %+v", got)
	}
	if got[0].Detail["rows"] != 3 && got[0].Detail["rows"] != float64(3) {
		t.Errorf("rows: %+v", got[0].Detail)
	}
	if q, _ := got[0].Detail["query"].(string); strings.Contains(q, "hunter2") || !strings.Contains(q, "session") {
		t.Errorf("query in the record: %q", q)
	}
	idpNoRowContents(t, s)
}

// ---- export control ---------------------------------------------------------

func TestSyncExportAuditHoldsWhoQueryAndRowsAndNoRow(t *testing.T) {
	idpStartFakeOS(t)
	s := idpServer(t)
	w := httptest.NewRecorder()
	s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?signal=syslog&format=csv&query=session+AND+password%3Dhunter2", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), idpFixtureUser) {
		t.Fatalf("D7 retains usernames: the export must hold the line: %s", w.Body.String())
	}
	if w.Header().Get("X-Data-Notice") == "" {
		t.Error("the export must say it may hold usernames")
	}
	got := idpEvents(t, s, "EXPORT")
	if len(got) != 1 {
		t.Fatalf("want one EXPORT record, got %+v", got)
	}
	e := got[0]
	if e.Actor != acme().Sub || e.Tenant != "acme" {
		t.Errorf("who: %+v", e)
	}
	if e.Detail["matched"] != 1 && e.Detail["matched"] != float64(1) {
		t.Errorf("row count: %+v", e.Detail)
	}
	if q, _ := e.Detail["query"].(string); strings.Contains(q, "hunter2") || !strings.Contains(q, "session") {
		t.Errorf("query: %q", q)
	}
	idpNoRowContents(t, s)
}

func TestSelectedRowsExportAuditHoldsNoRow(t *testing.T) {
	s := idpServer(t)
	w := httptest.NewRecorder()
	body := `{"format":"csv","rows":[["t","r1","info","` + idpFixtureLine + `"],["t","r2","info","x"]]}`
	s.handleLogsExportRows(w, req(http.MethodPost, "/api/logs/export/rows", body, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	got := idpEvents(t, s, "EXPORT")
	if len(got) != 1 || (got[0].Detail["matched"] != 2 && got[0].Detail["matched"] != float64(2)) || got[0].Detail["mode"] != "rows" {
		t.Fatalf("record: %+v", got)
	}
	idpNoRowContents(t, s)
}

// An export the trail cannot hold does not happen, on any door.
func TestAnExportTheTrailRefusesIsNotDelivered(t *testing.T) {
	refuse := func(s *server) {
		s.audit = &failingAuditRepo{inner: s.audit, failRecordStrict: true}
	}
	t.Run("sync", func(t *testing.T) {
		idpStartFakeOS(t)
		s := idpServer(t)
		refuse(s)
		w := httptest.NewRecorder()
		s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?signal=syslog&format=csv", "", acme()))
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), idpFixtureUser) {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
	})
	t.Run("rows", func(t *testing.T) {
		s := idpServer(t)
		refuse(s)
		w := httptest.NewRecorder()
		s.handleLogsExportRows(w, req(http.MethodPost, "/api/logs/export/rows", `{"format":"csv","rows":[["`+idpFixtureUser+`"]]}`, acme()))
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), idpFixtureUser) {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
	})
	t.Run("queued", func(t *testing.T) {
		idpStartFakeOS(t)
		s := idpServer(t)
		refuse(s)
		queue := &idpQueue{}
		s.reportPipeline = &reportPipeline{srv: s, queue: queue, execs: newIDPExecs(), artifacts: newIDPArtifacts()}
		w := httptest.NewRecorder()
		s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?signal=syslog&format=csv&mode=async", "", acme()))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		if len(queue.jobs) != 0 {
			t.Errorf("the job was queued anyway: %+v", queue.jobs)
		}
	})
	t.Run("download", func(t *testing.T) {
		s, rec := idpExportServer(t, time.Now().UTC().Add(-time.Minute))
		refuse(s)
		w := httptest.NewRecorder()
		s.handleExportView(w, httptest.NewRequest(http.MethodGet, "/api/exports/view/"+signExportLink(rec.ID, rec.TenantID), nil))
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), idpFixtureUser) {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
	})
}

// The queued path: request record names the execution, the worker's record holds
// who asked and the rows in the file, the download record the same execution.
func TestQueuedExportAuditTrail(t *testing.T) {
	idpStartFakeOS(t)
	s := idpServer(t)
	queue := &idpQueue{}
	execs := newIDPExecs()
	arts := newIDPArtifacts()
	p := &reportPipeline{srv: s, queue: queue, execs: execs, artifacts: arts}
	s.reportPipeline = p

	w := httptest.NewRecorder()
	s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?signal=syslog&format=csv&mode=async&query=session", "", acme()))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var receipt struct {
		ID     string `json:"execution_id"`
		Notice string `json:"notice"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ID == "" || receipt.Notice == "" {
		t.Fatalf("receipt: %s", w.Body.String())
	}
	asked := idpEvents(t, s, "EXPORT")
	if len(asked) != 1 || asked[0].Detail["execution_id"] != receipt.ID || asked[0].Actor != acme().Sub {
		t.Fatalf("request record: %+v", asked)
	}
	if len(queue.jobs) != 1 || queue.jobs[0].ExecutionID != receipt.ID {
		t.Fatalf("the record and the job must name one execution: %+v", queue.jobs)
	}

	ctx := context.Background()
	p.processExport(ctx, ctx, "w1", queue.jobs[0], "acme", map[string]any{})
	done := idpEvents(t, s, "EXPORT_DONE")
	if len(done) != 1 {
		t.Fatalf("want one EXPORT_DONE record, got %+v", done)
	}
	e := done[0]
	if e.Actor != acme().Sub || e.Tenant != "acme" || e.Detail["execution_id"] != receipt.ID {
		t.Errorf("who/what: %+v", e)
	}
	if e.Detail["rows"] != 1 && e.Detail["rows"] != float64(1) {
		t.Errorf("rows: %+v", e.Detail)
	}

	w = httptest.NewRecorder()
	s.handleExportView(w, httptest.NewRequest(http.MethodGet, "/api/exports/view/"+signExportLink(receipt.ID, "acme"), nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), idpFixtureUser) {
		t.Fatalf("download: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Data-Notice") == "" {
		t.Error("the download must say it may hold usernames")
	}
	dl := idpEvents(t, s, "EXPORT_DOWNLOAD")
	if len(dl) != 1 || dl[0].Detail["execution_id"] != receipt.ID {
		t.Fatalf("download record: %+v", dl)
	}
	idpNoRowContents(t, s)
}

// reports:read must not be a side door onto the export file.
func TestReportHistoryRefusesAnExportByID(t *testing.T) {
	s, rec := idpExportServer(t, time.Now().UTC().Add(-time.Minute))
	for _, sub := range []string{"", "/artifact"} {
		w := httptest.NewRecorder()
		s.handleReportExecutionByID(w, req(http.MethodGet, "/api/reports/executions/"+rec.ID+sub, "", infraOnly()))
		if w.Code != http.StatusNotFound {
			t.Errorf("sub %q: status %d, want 404: %s", sub, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), idpFixtureUser) {
			t.Errorf("sub %q served the file: %s", sub, w.Body.String())
		}
	}
}

// ---- retention --------------------------------------------------------------

func TestExportFileRetentionHoldsOnEveryReadPath(t *testing.T) {
	old := time.Now().UTC().Add(-25 * time.Hour)
	s, rec := idpExportServer(t, old)

	w := httptest.NewRecorder()
	s.handleExportStatus(w, req(http.MethodGet, "/api/exports/"+rec.ID, "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "download_url") || !strings.Contains(w.Body.String(), `"expired":true`) {
		t.Errorf("an expired export must offer no link and say why: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	s.handleExportView(w, httptest.NewRequest(http.MethodGet, "/api/exports/view/"+signExportLink(rec.ID, rec.TenantID), nil))
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), idpFixtureUser) {
		t.Errorf("a valid link past retention: %d %s", w.Code, w.Body.String())
	}

	// Inside the window both still work.
	s, rec = idpExportServer(t, time.Now().UTC().Add(-time.Hour))
	w = httptest.NewRecorder()
	s.handleExportStatus(w, req(http.MethodGet, "/api/exports/"+rec.ID, "", acme()))
	if !strings.Contains(w.Body.String(), "download_url") {
		t.Errorf("inside retention: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleExportView(w, httptest.NewRequest(http.MethodGet, "/api/exports/view/"+signExportLink(rec.ID, rec.TenantID), nil))
	if w.Code != http.StatusOK {
		t.Errorf("inside retention: %d %s", w.Code, w.Body.String())
	}
}

func TestExportRetentionIsConfigurableAndABadValueKeepsTheLimit(t *testing.T) {
	rec := reports.ExecutionRecord{CompletedAt: time.Now().UTC().Add(-2 * time.Hour)}
	t.Setenv("EXPORT_ARTIFACT_RETENTION", "1h")
	if !exportExpired(rec, time.Now().UTC()) {
		t.Error("1h: a 2 h old file must be expired")
	}
	for _, bad := range []string{"0", "-1h", "forever", ""} {
		t.Setenv("EXPORT_ARTIFACT_RETENTION", bad)
		if exportArtifactRetention() != 24*time.Hour {
			t.Errorf("%q turned the limit into %s", bad, exportArtifactRetention())
		}
	}
}

func TestSweepRemovesOnlyFilesPastRetentionAndIsIdempotent(t *testing.T) {
	now := time.Now().UTC()
	execs := newIDPExecs()
	arts := newIDPArtifacts()
	p := &reportPipeline{execs: execs, artifacts: arts}
	add := func(id, kind string, at time.Time) reports.ArtifactRef {
		ref := reports.ArtifactRef{Format: "csv", Key: id}
		arts.files[id] = []byte(idpFixtureLine)
		execs.put(reports.ExecutionRecord{ID: id, Kind: kind, TenantID: "acme", FireTime: at, CompletedAt: at, Status: reports.StatusCompleted, Artifacts: []reports.ArtifactRef{ref}})
		return ref
	}
	add("old", jobTypeExport, now.Add(-48*time.Hour))
	add("fresh", jobTypeExport, now.Add(-time.Hour))
	add("old-report", "report", now.Add(-48*time.Hour))

	removed, err := p.sweepExportArtifacts(context.Background(), now)
	if err != nil || removed != 1 {
		t.Fatalf("removed %d, err %v", removed, err)
	}
	if len(arts.files["old"]) != 0 {
		t.Error("the expired export file is still there")
	}
	if len(arts.files["fresh"]) == 0 {
		t.Error("a file inside retention was removed")
	}
	if len(arts.files["old-report"]) == 0 {
		t.Error("a report's artifact was removed: this sweep is exports only")
	}
	if rec, _, found, _ := execs.Get(context.Background(), reports.PlatformExecScope(), "old"); !found || rec.ID != "old" {
		t.Error("the execution row is the record that the export happened and must stay")
	}
	if removed, err := p.sweepExportArtifacts(context.Background(), now); err != nil || removed != 0 {
		t.Errorf("second pass: removed %d, err %v", removed, err)
	}
}

func TestSweepReportsAFailureAndCarriesOn(t *testing.T) {
	now := time.Now().UTC()
	execs := newIDPExecs()
	arts := newIDPArtifacts()
	arts.failLoad = map[string]bool{"bad": true}
	p := &reportPipeline{execs: execs, artifacts: arts}
	for i, id := range []string{"bad", "good"} {
		arts.files[id] = []byte("x")
		at := now.Add(-48*time.Hour - time.Duration(i)*time.Minute)
		execs.put(reports.ExecutionRecord{ID: id, Kind: jobTypeExport, TenantID: "acme", FireTime: at, CompletedAt: at, Artifacts: []reports.ArtifactRef{{Key: id}}})
	}
	removed, err := p.sweepExportArtifacts(context.Background(), now)
	if err == nil {
		t.Error("an unreadable file must not read as a clean pass")
	}
	if removed != 1 || len(arts.files["good"]) != 0 {
		t.Errorf("one bad file stopped the rest: removed %d", removed)
	}
	execs.failList = true
	if _, err := p.sweepExportArtifacts(context.Background(), now); err == nil {
		t.Error("an unreadable history must not read as a clean pass")
	}
}

// ---- §3a: cross-org isolation through the real router ------------------------

func TestLogReadsCrossOrgIsolation(t *testing.T) {
	fake := idpStartFakeOS(t)
	srv, s := newTestServerState(t)
	s.exportLimiter = ratelimit.New()
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org: %d %s", st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		tenantID := idOf(t, b)
		user := "user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID})
		if st != 201 {
			t.Fatalf("create user: %d %s", st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]
	segA, segB := oslog.IndexTenantSeg(a.tenantID), oslog.IndexTenantSeg(b.tenantID)

	// One export of B's, in the shared history.
	execs := newIDPExecs()
	arts := newIDPArtifacts()
	arts.files["ex-b"] = []byte(idpFixtureLine)
	execs.put(reports.ExecutionRecord{
		ID: "ex-b", Kind: jobTypeExport, TenantID: b.tenantID, Status: reports.StatusCompleted,
		FireTime: time.Now().UTC(), CompletedAt: time.Now().UTC(),
		Artifacts: []reports.ArtifactRef{{Format: "csv", Key: "ex-b"}},
	})
	s.reportPipeline = &reportPipeline{srv: s, queue: &idpQueue{}, execs: execs, artifacts: arts}

	reads := []struct {
		name, method, path string
		body               any
	}{
		{"search", "POST", "/api/logs/search", map[string]any{"signal": "syslog", "query": "*"}},
		{"search as_tenant", "POST", "/api/logs/search?as_tenant=" + b.tenantID, map[string]any{"signal": "syslog", "query": "*"}},
		{"search GET as_tenant", "GET", "/api/logs/search?signal=syslog&as_tenant=" + b.tenantID, nil},
		{"retention", "GET", "/api/logs/retention?signal=syslog", nil},
		{"retention as_tenant", "GET", "/api/logs/retention?signal=syslog&as_tenant=" + b.tenantID, nil},
		{"indices", "GET", "/api/logs/indices", nil},
		{"indices as_tenant", "GET", "/api/logs/indices?as_tenant=" + b.tenantID, nil},
		{"export", "GET", "/api/logs/export?signal=syslog&format=json&mode=sync", nil},
		{"export as_tenant", "GET", "/api/logs/export?signal=syslog&format=json&mode=sync&as_tenant=" + b.tenantID, nil},
	}
	for _, rd := range reads {
		t.Run("own only/"+rd.name, func(t *testing.T) {
			before := len(fake.calls())
			st, body := do(t, srv, rd.method, rd.path, a.token, rd.body)
			if st != http.StatusOK {
				t.Fatalf("status %d: %s", st, body)
			}
			if strings.Contains(string(body), segB) {
				t.Errorf("A's response names B: %s", body)
			}
			calls := fake.calls()[before:]
			bodies := fake.bodies()[before:]
			if len(calls) == 0 {
				t.Fatal("no store query: the check would be vacuous")
			}
			for i, c := range calls {
				if strings.Contains(c, segB) {
					t.Errorf("A's request named B's index: %s", c)
				}
				if !strings.Contains(c, segA) && !strings.HasPrefix(c, "/_cat/") {
					t.Errorf("A's request does not name A's index: %s", c)
				}
				if strings.HasPrefix(c, "/_cat/") {
					continue
				}
				if !strings.Contains(bodies[i], `"tenant_id":"`+segA+`"`) {
					t.Errorf("no per-document tenant clause for A: %s", bodies[i])
				}
				if strings.Contains(bodies[i], b.tenantID) {
					t.Errorf("A's query names B: %s", bodies[i])
				}
			}
		})
	}

	// A's search gets A's row back, and the fake holds one per tenant.
	st, body := do(t, srv, "POST", "/api/logs/search", a.token, map[string]any{"signal": "syslog", "query": "*"})
	if st != http.StatusOK || !strings.Contains(string(body), "netops-syslog-"+segA) {
		t.Errorf("own row missing: %d %s", st, body)
	}

	// Cross-tenant get by id answers exactly what an unknown id answers.
	stB, bodyB := do(t, srv, "GET", "/api/exports/ex-b", a.token, nil)
	if stB != http.StatusNotFound {
		t.Errorf("A read B's export: %d %s", stB, bodyB)
	}
	stNone, bodyNone := do(t, srv, "GET", "/api/exports/no-such-id", a.token, nil)
	if stNone != stB || string(bodyNone) != string(bodyB) {
		t.Errorf("a cross-tenant id must be indistinguishable from an unknown one: %d %s vs %d %s", stB, bodyB, stNone, bodyNone)
	}
	if st, body := do(t, srv, "GET", "/api/exports/ex-b?as_tenant="+b.tenantID, a.token, nil); st != http.StatusNotFound {
		t.Errorf("as_tenant into B opened B's export: %d %s", st, body)
	}
	// B reads its own.
	if st, body := do(t, srv, "GET", "/api/exports/ex-b", b.token, nil); st != http.StatusOK {
		t.Errorf("B lost its own export: %d %s", st, body)
	}
	// A link for B's export, bound to A, is refused against B's row.
	if st, body := do(t, srv, "GET", "/api/exports/view/"+signExportLink("ex-b", a.tenantID), "", nil); st != http.StatusForbidden {
		t.Errorf("a link bound to A served B's file: %d %s", st, body)
	}

	// The platform owner's Global view reads across tenants.
	before := len(fake.calls())
	if st, body := do(t, srv, "POST", "/api/logs/search", admin, map[string]any{"signal": "syslog", "query": "*"}); st != http.StatusOK {
		t.Fatalf("owner: %d %s", st, body)
	}
	if calls := fake.calls()[before:]; len(calls) != 1 || !strings.Contains(calls[0], "netops-syslog-*") {
		t.Errorf("owner: %v", calls)
	}

	// And the trail keeps each tenant's reads to itself.
	as, err := s.audit.List(a.tenantID, false, auditQuery{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	reads2 := 0
	for _, e := range as {
		if e.Tenant != a.tenantID {
			t.Errorf("A's trail holds a row of tenant %q", e.Tenant)
		}
		if e.Method == auditMethodLogRead {
			reads2++
		}
	}
	if reads2 == 0 {
		t.Error("A's reads are not in A's trail")
	}
}

// ---- fakes ------------------------------------------------------------------

type idpQueue struct {
	reports.JobQueue
	jobs []reports.Job
}

func (q *idpQueue) Enqueue(_ context.Context, j reports.Job, _ time.Time) (reports.Job, bool, error) {
	q.jobs = append(q.jobs, j)
	return j, true, nil
}

func (q *idpQueue) Complete(context.Context, string, string) error { return nil }

// idpExecs answers through ExecScope.Sees, the rule the Postgres store applies.
type idpExecs struct {
	reports.ExecutionStore
	mu       sync.Mutex
	rows     map[string]reports.ExecutionRecord
	failList bool
}

func newIDPExecs() *idpExecs { return &idpExecs{rows: map[string]reports.ExecutionRecord{}} }

func (e *idpExecs) put(r reports.ExecutionRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rows[r.ID] = r
}

func (e *idpExecs) Append(_ context.Context, r reports.ExecutionRecord) error {
	e.put(r)
	return nil
}

func (e *idpExecs) RecordEvent(context.Context, string, string, reports.Phase, time.Time, string) error {
	return nil
}

func (e *idpExecs) Complete(_ context.Context, id string, at time.Time, refs []reports.ArtifactRef, _ []reports.DeliveryStatus, _ string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.rows[id]
	r.CompletedAt, r.Artifacts, r.Status = at, refs, reports.StatusCompleted
	e.rows[id] = r
	return nil
}

func (e *idpExecs) Get(_ context.Context, sc reports.ExecScope, id string) (reports.ExecutionRecord, []reports.ExecEvent, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.rows[id]
	if !ok || !sc.Sees(r) {
		return reports.ExecutionRecord{}, nil, false, nil
	}
	return r, nil, true, nil
}

func (e *idpExecs) List(_ context.Context, sc reports.ExecScope, q reports.ExecQuery) ([]reports.ExecutionRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failList {
		return nil, errors.New("history unavailable")
	}
	var out []reports.ExecutionRecord
	for _, r := range e.rows {
		if sc.Sees(r) && (q.Kind == "" || r.Kind == q.Kind) && (q.Before.IsZero() || r.FireTime.Before(q.Before)) {
			out = append(out, r)
		}
	}
	return out, nil
}

type idpArtifacts struct {
	reports.ArtifactStore
	mu       sync.Mutex
	files    map[string][]byte
	failLoad map[string]bool
}

func newIDPArtifacts() *idpArtifacts { return &idpArtifacts{files: map[string][]byte{}} }

func (a *idpArtifacts) Save(_ context.Context, key string, art reports.Artifact) (reports.ArtifactRef, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.files[key] = art.Bytes
	return reports.ArtifactRef{Format: art.Format, ContentType: art.ContentType, Key: key, Summary: art.Summary, SizeBytes: len(art.Bytes)}, nil
}

func (a *idpArtifacts) Load(_ context.Context, ref reports.ArtifactRef) (reports.Artifact, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failLoad[ref.Key] {
		return reports.Artifact{}, errors.New("unreadable")
	}
	return reports.Artifact{Format: ref.Format, ContentType: "text/csv", Bytes: a.files[ref.Key]}, nil
}

func (a *idpArtifacts) Delete(_ context.Context, ref reports.ArtifactRef) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.files[ref.Key] = nil
	return nil
}

// idpExportServer holds one completed export of acme's, finished at `at`.
func idpExportServer(t *testing.T, at time.Time) (*server, reports.ExecutionRecord) {
	t.Helper()
	s := idpServer(t)
	execs := newIDPExecs()
	arts := newIDPArtifacts()
	rec := reports.ExecutionRecord{
		ID: "ex-1", Kind: jobTypeExport, TenantID: "acme", Status: reports.StatusCompleted,
		FireTime: at, CompletedAt: at,
		Artifacts: []reports.ArtifactRef{{Format: "csv", ContentType: "text/csv", Key: "ex-1", Summary: logexport.Summary(1)}},
	}
	arts.files["ex-1"] = []byte(idpFixtureLine)
	execs.put(rec)
	s.reportPipeline = &reportPipeline{srv: s, queue: &idpQueue{}, execs: execs, artifacts: arts}
	return s, rec
}
