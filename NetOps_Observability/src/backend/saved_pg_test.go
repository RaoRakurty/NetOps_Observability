package main

import (
	"context"
	"encoding/json"
	"netops/backend/internal/saved"
	"os"
	"strings"
	"testing"
)

// TestPgSavedStore exercises the Postgres saved-object repository: per-row
// create/get/update/delete, RLS-scoped List (strict tenancy — a scoped tenant
// sees only its own rows, NOT global/untagged; the platform owner sees all), and
// the type filter. Gated on DATABASE_URL_TEST.
func TestPgSavedStore(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres saved-store test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	s := saved.NewPGStore(rlsPG{db: ps.db}, logError)
	body := json.RawMessage(`{"k":"v"}`)

	acme1, _ := s.Create("report", "Acme Report", "u1", "acme", body)
	_, _ = s.Create("dashboard", "Acme Dash", "u1", "acme", body)
	glob, _ := s.Create("report", "Global Report", "admin", "", body)
	_, _ = s.Create("report", "Globex Report", "u2", "globex", body)

	// Platform owner sees all reports (3).
	if all := s.List("report", "", true); len(all) != 3 {
		t.Fatalf("platform report list = %d, want 3", len(all))
	}

	// acme scope sees ONLY its own report — strict tenancy: global/untagged is
	// platform-owned (not shared), and globex's is another tenant's.
	acmeReports := s.List("report", "acme", false)
	if len(acmeReports) != 1 || acmeReports[0].ID != acme1.ID {
		t.Fatalf("acme report list = %d, want 1 (acme only); got %v", len(acmeReports), acmeReports)
	}
	for _, o := range acmeReports {
		if normTenant(o.TenantID) != "acme" {
			t.Errorf("SAVED LEAK: acme scope saw tenant %q (global/untagged must be platform-only)", o.TenantID)
		}
	}

	// Type filter + scope together: acme sees only its dashboard (+ no global dash).
	if d := s.List("dashboard", "acme", false); len(d) != 1 {
		t.Fatalf("acme dashboard list = %d, want 1", len(d))
	}

	// Get + Update + Delete round-trip on a single row (per-row, not blob rewrite).
	got, ok := s.Get(acme1.ID)
	if !ok || got.Name != "Acme Report" {
		t.Fatalf("get acme1: ok=%v name=%q", ok, got.Name)
	}
	upd, err := s.Update(acme1.ID, "Acme Report v2", json.RawMessage(`{"k":"v2"}`))
	if err != nil || upd.Name != "Acme Report v2" {
		t.Fatalf("update: %v name=%q", err, upd.Name)
	}
	// Postgres JSONB normalizes whitespace, so compare the decoded value.
	if g2, _ := s.Get(acme1.ID); !strings.Contains(string(g2.Body), `"v2"`) {
		t.Fatalf("update body not persisted: %s", g2.Body)
	}
	if err := s.Delete(glob.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := s.Get(glob.ID); ok {
		t.Fatalf("deleted object still present")
	}
	if err := s.Delete("nope"); err == nil {
		t.Fatalf("delete missing should error")
	}
}
