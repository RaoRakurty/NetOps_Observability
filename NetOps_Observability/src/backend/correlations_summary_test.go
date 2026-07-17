package main

// Tests for the Correlations "don't hide" surface (owner directive):
//   - /api/correlations/summary serves REAL tenant-scoped counts (never the
//     capped list length), and every ClickHouse read it issues carries the
//     caller's tenant_scope so the corr_current row policy enforces isolation.
//   - /api/correlations accepts the house keyset cursor and only advertises a
//     next_cursor on a full page.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// corrTestServer builds the minimal server the correlations handlers need
// (requirePerm resolves through the built-in role store).
func corrTestServer(t *testing.T) *server {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	return &server{roles: roles}
}

// corrFakeCH stands in for ClickHouse, capturing each request's SQL body AND
// its tenant_scope URL parameter (the row-policy enforcement key).
func corrFakeCH(t *testing.T) (sqls *[]string, scopes *[]string) {
	t.Helper()
	var gotSQL, gotScope []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSQL = append(gotSQL, string(b))
		gotScope = append(gotScope, r.URL.Query().Get("tenant_scope"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return &gotSQL, &gotScope
}

func TestCorrelationsSummaryCarriesTenantScope(t *testing.T) {
	sqls, scopes := corrFakeCH(t)
	s := corrTestServer(t)

	w := httptest.NewRecorder()
	s.handleCorrelationsSummary(w, req(http.MethodGet, "/api/correlations/summary?since=86400s", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if len(*scopes) != 1 {
		t.Fatalf("want exactly 1 CH query, got %d", len(*scopes))
	}
	if (*scopes)[0] != "acme" {
		t.Fatalf("TENANT LEAK: summary query ran at tenant_scope=%q, want %q", (*scopes)[0], "acme")
	}
	sql := (*sqls)[0]
	for _, must := range []string{
		"count()", "countIf(verdict_tier = 'confirmed')", "countIf(verdict_tier = 'suspected')",
		"countIf(verdict_tier = 'undetermined')", "countIf(state = 'open')",
		"FROM netops.corr_current FINAL",
		"created_at >= now() - INTERVAL 86400 SECOND", // bounded window
	} {
		if !strings.Contains(sql, must) {
			t.Errorf("summary SQL missing %q:\n%s", must, sql)
		}
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"total", "confirmed", "suspected", "undetermined", "open", "closed", "window_seconds"} {
		if _, ok := body[k]; !ok {
			t.Errorf("summary response missing %q: %v", k, body)
		}
	}
}

func TestCorrelationsSummaryCrossTenantScope(t *testing.T) {
	_, scopes := corrFakeCH(t)
	s := corrTestServer(t)

	w := httptest.NewRecorder()
	s.handleCorrelationsSummary(w, req(http.MethodGet, "/api/correlations/summary", "", superA()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if len(*scopes) != 1 || (*scopes)[0] != "__all__" {
		t.Fatalf("platform owner should query at __all__, got %v", *scopes)
	}
}

func TestCorrelationsSummaryRejectsBadState(t *testing.T) {
	sqls, _ := corrFakeCH(t)
	s := corrTestServer(t)

	w := httptest.NewRecorder()
	s.handleCorrelationsSummary(w, req(http.MethodGet, "/api/correlations/summary?state=x%27+OR+1", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("injection-shaped state should 400, got %d", w.Code)
	}
	if len(*sqls) != 0 {
		t.Fatalf("rejected input must never reach ClickHouse, got %d queries", len(*sqls))
	}
}

func TestCorrelationsSummarySQLStateFilter(t *testing.T) {
	sql := correlationsSummarySQL("created_at >= now() - INTERVAL 3600 SECOND", []string{"state = 'open'"})
	if !strings.Contains(sql, "AND state = 'open'") {
		t.Errorf("state filter lost:\n%s", sql)
	}
}

// The list endpoint's keyset cursor: a valid cursor becomes the strict
// (created_at, correlation_id) keyset clause; garbage is ignored (page 1);
// tenant_scope always rides the read.
func TestCorrelationsListCursorKeyset(t *testing.T) {
	sqls, scopes := corrFakeCH(t)
	s := corrTestServer(t)

	sid := "0192f1a2-3b4c-7d5e-8f60-112233445566"
	cur := encodeFeedCursor(1718460000123, sid)
	w := httptest.NewRecorder()
	s.handleCorrelations(w, req(http.MethodGet, "/api/correlations?limit=50&cursor="+cur, "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if len(*sqls) != 1 {
		t.Fatalf("want 1 CH query, got %d", len(*sqls))
	}
	if (*scopes)[0] != "acme" {
		t.Fatalf("list query lost tenant_scope: %q", (*scopes)[0])
	}
	sql := (*sqls)[0]
	ets := time.UnixMilli(1718460000123).UTC().Format("2006-01-02 15:04:05.000")
	if !strings.Contains(sql, "(created_at < '"+ets+"' OR (created_at = '"+ets+"' AND toString(correlation_id) < '"+sid+"'))") {
		t.Errorf("cursor keyset clause missing:\n%s", sql)
	}
	if !strings.Contains(sql, "ORDER BY created_at DESC, correlation_id DESC") {
		t.Errorf("picked CTE must order by the keyset total order:\n%s", sql)
	}
	// Empty result set → short page → no next_cursor.
	var body struct {
		NextCursor string `json:"next_cursor"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.NextCursor != "" {
		t.Errorf("short page must not advertise a next_cursor, got %q", body.NextCursor)
	}
}

func TestCorrelationsListGarbageCursorIgnored(t *testing.T) {
	sqls, _ := corrFakeCH(t)
	s := corrTestServer(t)

	w := httptest.NewRecorder()
	s.handleCorrelations(w, req(http.MethodGet, "/api/correlations?cursor=%21%21not-base64", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if strings.Contains((*sqls)[0], "correlation_id <") {
		t.Errorf("garbage cursor must fall back to page 1:\n%s", (*sqls)[0])
	}
}
