package backend

// security_control_plane_pg_test.go — storage-layer RLS proof for the
// security_rule_state and security_saved_views tables (migration 0037),
// mirroring rca_feedback_pg_isolation_test.go: the FORCE-RLS tenant_iso policy
// is the backstop even if every handler check were bypassed (§3a rule 4).
// Gated on DATABASE_URL_TEST like every pg-integration test in this package.

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"netops/backend/internal/platformdb"
	"netops/backend/secapi"
)

func TestSecurityControlPlaneRLSIsolationPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()
	st := secapi.NewPGStore(ps.DB())

	cat := secapi.Catalog()
	if len(cat) < 2 {
		t.Fatalf("catalog too small (%d)", len(cat))
	}
	ruleA, ruleB := cat[0].RuleID, cat[1].RuleID

	// ── rule state ──────────────────────────────────────────────────────────
	if err := st.SetRuleStates(ctx, "acme", false, "acme",
		[]secapi.RuleState{{RuleID: ruleA, Enabled: false, UpdatedBy: "a@acme"}}); err != nil {
		t.Fatalf("acme write: %v", err)
	}
	if err := st.SetRuleStates(ctx, "globex", false, "globex",
		[]secapi.RuleState{{RuleID: ruleB, Enabled: false, UpdatedBy: "g@globex"}}); err != nil {
		t.Fatalf("globex write: %v", err)
	}

	mine, err := st.RuleStates(ctx, "acme", false)
	if err != nil {
		t.Fatalf("acme read: %v", err)
	}
	if len(mine) != 1 {
		t.Fatalf("acme saw %d overrides %v — the RLS policy must scope the read", len(mine), mine)
	}
	if _, leaked := mine[ruleB]; leaked {
		t.Fatal("TENANT LEAK: the RLS policy let acme read globex's rule override")
	}
	all, err := st.RuleStates(ctx, "global", true)
	if err != nil {
		t.Fatalf("cross read: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("cross-tenant read = %d overrides, want 2", len(all))
	}

	// A write is stamped with the OWNER the handler derived, never the caller's
	// scope: writing globex's row while scoped to acme must be refused by the
	// policy's WITH CHECK clause rather than landing under the wrong tenant.
	if err := st.SetRuleStates(ctx, "acme", false, "globex",
		[]secapi.RuleState{{RuleID: ruleA, Enabled: false}}); err == nil {
		t.Fatal("CROSS-TENANT WRITE: the RLS WITH CHECK clause let acme write a globex-owned row")
	}

	// ── saved views ─────────────────────────────────────────────────────────
	theirs, err := st.AddView(ctx, "globex", false, secapi.SavedView{
		TenantID: "globex", Name: "their view",
		Filters: json.RawMessage(`{"severity":"high"}`), CreatedBy: "g@globex",
	})
	if err != nil {
		t.Fatalf("globex add view: %v", err)
	}
	views, err := st.Views(ctx, "acme", false)
	if err != nil {
		t.Fatalf("acme views: %v", err)
	}
	for _, v := range views {
		if v.ID == theirs.ID {
			t.Fatal("TENANT LEAK: acme read globex's saved view through the RLS policy")
		}
	}
	found, err := st.DeleteView(ctx, "acme", false, theirs.ID)
	if err != nil {
		t.Fatalf("acme delete: %v", err)
	}
	if found {
		t.Fatal("CROSS-TENANT DELETE: acme removed globex's saved view")
	}
	// Its owner can, which proves the row was really there and the 404 above
	// was isolation rather than a missing row.
	found, err = st.DeleteView(ctx, "globex", false, theirs.ID)
	if err != nil || !found {
		t.Fatalf("owner delete = (%v, %v), want (true, nil)", found, err)
	}
}
