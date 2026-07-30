package backend

import (
	"context"
	"netops/backend/internal/audit"
	"netops/backend/internal/platformdb"
	"os"
	"testing"
	"time"
)

// TestPgAuditStore exercises the Postgres audit repository end to end: per-row
// append, RLS-scoped reads (scoped tenant vs platform owner), tenant-id
// normalization, newest-first ordering, limit, keyset pagination (before), and
// the since window. Gated on DATABASE_URL_TEST (a superuser that provisions a
// non-superuser app role, so RLS actually enforces).
func TestPgAuditStore(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres audit test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	a := audit.NewPGStore(ps.DB(), logError)

	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	a.Record(AuditEvent{ID: "e1", Time: base, Tenant: "acme", Method: "POST", Decision: "allow"})
	a.Record(AuditEvent{ID: "e2", Time: base.Add(1 * time.Minute), Tenant: "globex", Method: "DELETE", Decision: "deny"})
	a.Record(AuditEvent{ID: "e3", Time: base.Add(2 * time.Minute), Tenant: "acme", Method: "PUT", Decision: "allow"})
	a.Record(AuditEvent{ID: "e4", Time: base.Add(3 * time.Minute), Tenant: "Acme", Method: "PATCH", Decision: "allow"}) // mixed case

	ids := func(es []AuditEvent) []string {
		out := make([]string, len(es))
		for i, e := range es {
			out[i] = e.ID
		}
		return out
	}

	// Platform owner sees all four, newest-first.
	all, allErr := a.List("", true, auditQuery{})
	if allErr != nil {
		t.Fatalf("list: %v", allErr)
	}
	if got := ids(all); len(got) != 4 || got[0] != "e4" || got[3] != "e1" {
		t.Fatalf("platform List = %v, want [e4 e3 e2 e1]", got)
	}

	// A scoped tenant sees ONLY its own rows — and "Acme" (e4) normalizes to
	// "acme", so RLS includes it. globex's e2 must be invisible.
	acme, acmeErr := a.List("acme", false, auditQuery{})
	if acmeErr != nil {
		t.Fatalf("list: %v", acmeErr)
	}
	if got := ids(acme); len(got) != 3 {
		t.Fatalf("acme List = %v, want 3 (e4 e3 e1, incl normalized Acme)", got)
	}
	for _, e := range acme {
		if normTenant(e.Tenant) != "acme" {
			t.Errorf("AUDIT LEAK: acme scope saw tenant %q", e.Tenant)
		}
	}

	// Limit caps and preserves newest-first.
	if got := ids(listOK(t, a, "", true, auditQuery{Limit: 2})); len(got) != 2 || got[0] != "e4" || got[1] != "e3" {
		t.Errorf("limit=2 List = %v, want [e4 e3]", got)
	}

	// Keyset pagination: before e3's timestamp → strictly older (e2, e1).
	if got := ids(listOK(t, a, "", true, auditQuery{Before: base.Add(2 * time.Minute)})); len(got) != 2 || got[0] != "e2" || got[1] != "e1" {
		t.Errorf("before-cursor List = %v, want [e2 e1]", got)
	}

	// Since window (inclusive lower bound): e3, e4.
	if got := ids(listOK(t, a, "", true, auditQuery{Since: base.Add(2 * time.Minute)})); len(got) != 2 || got[0] != "e4" || got[1] != "e3" {
		t.Errorf("since-window List = %v, want [e4 e3]", got)
	}
}

// mustList unwraps List's (events, error) pair — F-73 gave the audit seam an
// error channel precisely so a failure cannot masquerade as an empty trail.
func listOK(t *testing.T, a auditRepo, tenant string, cross bool, q auditQuery) []AuditEvent {
	t.Helper()
	events, err := a.List(tenant, cross, q)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	return events
}
