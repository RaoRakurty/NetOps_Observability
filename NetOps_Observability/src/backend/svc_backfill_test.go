package backend

// svc_backfill_test.go — window validation, routing/authz guards and the
// latest-version-wins read contract for the #69 §3.3 selector backfill.

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/servicecat"
)

func TestSvcBackfillWindowValidation(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	ok := func(from, to string) error {
		_, _, err := svcBackfillWindow(from, to, now, 30)
		return err
	}
	if err := ok("2026-07-01T00:00:00Z", "2026-07-02T00:00:00Z"); err != nil {
		t.Errorf("valid 1-day window rejected: %v", err)
	}
	cases := map[string][2]string{
		"missing":     {"", ""},
		"bad from":    {"yesterday", "2026-07-02T00:00:00Z"},
		"bad to":      {"2026-07-01T00:00:00Z", "tomorrow"},
		"inverted":    {"2026-07-02T00:00:00Z", "2026-07-01T00:00:00Z"},
		"future to":   {"2026-07-19T00:00:00Z", "2026-07-21T00:00:00Z"},
		"over 30d":    {"2026-06-01T00:00:00Z", "2026-07-10T00:00:00Z"},
		"zero window": {"2026-07-01T00:00:00Z", "2026-07-01T00:00:30Z"}, // truncates to equal minutes
	}
	for name, c := range cases {
		if err := ok(c[0], c[1]); err == nil {
			t.Errorf("%s window must be rejected", name)
		}
	}
}

// Routing + gates that run BEFORE the store: method, authz, 501 without the
// Postgres catalog, malformed version. (Cross-tenant → 404 rides GetService
// under RLS; covered by the DATABASE_URL_TEST-gated store isolation test.)
func TestSvcBackfillHandlerGates(t *testing.T) {
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{roles: roles}
	svcID := "11111111-1111-4111-8111-111111111111"
	path := "/api/services/" + svcID + "/selectors/2/backfill?from=2026-07-01T00:00:00Z&to=2026-07-02T00:00:00Z"

	// The prefix router 501s every /api/services/{id} route without the
	// Postgres catalog — backfill included (never a nil-pointer panic).
	w := httptest.NewRecorder()
	s.handleServiceByID(w, req("POST", path, "", superA()))
	if w.Code != 501 {
		t.Errorf("routed backfill without store = %d, want 501", w.Code)
	}
	// Direct sub-handler gates, in order: method → authz → store.
	w = httptest.NewRecorder()
	s.serveSelectorBackfill(w, req("GET", path, "", superA()), svcID, "2")
	if w.Code != 405 {
		t.Errorf("GET backfill = %d, want 405", w.Code)
	}
	// An operator lacks infrastructure:admin.
	w = httptest.NewRecorder()
	s.serveSelectorBackfill(w, req("POST", path, "", acme()), svcID, "2")
	if w.Code != 403 {
		t.Errorf("operator backfill = %d, want 403", w.Code)
	}
	// Admin, valid window, no Postgres catalog → honest 501.
	w = httptest.NewRecorder()
	s.serveSelectorBackfill(w, req("POST", path, "", superA()), svcID, "2")
	if w.Code != 501 {
		t.Errorf("no-store backfill = %d, want 501", w.Code)
	}
	// Malformed version segment → 400 (after authz, before any store IO).
	w = httptest.NewRecorder()
	s.serveSelectorBackfill(w, req("POST", path, "", superA()), svcID, "zero")
	if w.Code != 400 {
		t.Errorf("bad version = %d, want 400", w.Code)
	}
}

// The sanctioned rollup read resolves selector overlap latest-version-wins and
// stays pinned to ONE (tenant, service).
func TestSvcRollupLatestVersionSQLShape(t *testing.T) {
	sql := svcRollupLatestVersionSQL("acme", "11111111-1111-4111-8111-111111111111", time.Unix(1750000000, 0))
	for _, want := range []string{
		"argMax(b, selector_version)",
		"tenant_id = 'acme'",
		"service_id = toUUID('11111111-1111-4111-8111-111111111111')",
		"GROUP BY minute, selector_version",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("latest-version read missing %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "DELETE") || strings.Contains(sql, "ALTER") {
		t.Error("the read contract must never mutate history")
	}
}

// sqlStringLiteral must neutralize quotes (store-sourced values, but SR-011).
func TestSqlStringLiteralEscapes(t *testing.T) {
	if got := servicecat.SQLStringLiteral("a'b"); got != "'a''b'" {
		t.Errorf("sqlStringLiteral = %q", got)
	}
}
