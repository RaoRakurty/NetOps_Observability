package backend

// processors_pg_isolation_test.go — storage-layer RLS proof for the
// pipeline_processors table (migration 0032), mirroring
// maintenance_pg_isolation_test.go. Gated on DATABASE_URL_TEST.

import (
	"context"
	"os"
	"testing"

	"netops/backend/internal/platformdb"
	"netops/backend/processors"
)

func TestProcessorRulesRLSIsolation(t *testing.T) {
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
	st := processors.NewPGStore(ps.DB())

	// EVERY registered action must round-trip through Postgres. The original
	// test only exercised drop_field, so a CHECK constraint that rejected mask
	// and drop_event shipped: green in dev (file backend), 500 in production.
	for _, a := range processors.ActionCatalog() {
		r := processors.Processor{TenantID: "acme", Lane: "syslog", Type: a.Type, Enabled: true, Field: "probe_field"}
		if !a.TargetsField {
			r.Field = ""
			r.Match = &processors.Match{Field: "level", Op: processors.MatchEquals, Value: "debug"}
		}
		// Pattern-bearing actions need a detector. Both redact_pattern and tag
		// report UsesPattern()==true (registry.go); the first H8 fixture pass
		// covered only redact_pattern, so the tag action failed Validate. These
		// are the only two pattern-bearing actions — keep in sync with the
		// registry's UsesPattern verdicts.
		if a.Type == processors.TypeRedactPattern || a.Type == processors.TypeTag {
			r.PatternKind, r.Pattern = processors.PatternBuiltin, "email"
		}
		// Key-scoped actions need a key list, and seal needs a configured
		// engine + data type (mirroring generate_test.go's catalog loop) —
		// without these the fixtures fail Validate before ever reaching
		// Postgres (found when the DATABASE_URL_TEST corpus was wired into CI,
		// H8: this test had never actually run).
		if a.Type == processors.TypeRedactKeys {
			r.Keys = []string{"password"}
		}
		if a.Type == processors.TypeSeal {
			processors.SetSealEngine(regenStubEngine{})
			t.Cleanup(func() { processors.SetSealEngine(nil) })
			r.DataType = "card"
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("action %s: fixture must validate: %v", a.Type, err)
		}
		saved, err := st.Create(ctx, "acme", false, r)
		if err != nil {
			t.Fatalf("action %s must persist on the Postgres backend: %v", a.Type, err)
		}
		if _, found, err := st.Get(ctx, "acme", false, saved.ID); err != nil || !found {
			t.Fatalf("action %s must read back: %v found=%v", a.Type, err, found)
		}
		if _, err := st.Delete(ctx, "acme", false, saved.ID); err != nil {
			t.Fatalf("action %s cleanup: %v", a.Type, err)
		}
	}

	mk := func(tenant string) processors.Rule {
		r := processors.Rule{TenantID: tenant, Lane: "syslog", Type: processors.TypeDropField, Field: "secret", Enabled: true}
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
		out, err := st.Create(ctx, tenant, false, r)
		if err != nil {
			t.Fatalf("create %s: %v", tenant, err)
		}
		return out
	}
	ra := mk("acme")
	rb := mk("globex")

	la, err := st.List(ctx, "acme", false)
	if err != nil || len(la) != 1 || la[0].ID != ra.ID {
		t.Fatalf("acme must list exactly its own rule: %v %+v", err, la)
	}
	if _, found, _ := st.Get(ctx, "acme", false, rb.ID); found {
		t.Fatal("RLS LEAK: acme read globex's rule")
	}
	if _, found, _ := st.Update(ctx, "acme", false, rb.ID, rb); found {
		t.Fatal("RLS LEAK: acme updated globex's rule")
	}
	if found, _ := st.Delete(ctx, "acme", false, rb.ID); found {
		t.Fatal("RLS LEAK: acme deleted globex's rule")
	}

	// A forged body tenant is NEUTRALIZED at the app layer (§3a.2: the owner is
	// stamped from the caller, never the body — store.go Create), so a non-cross
	// Create with TenantID "globex" is written as the caller's "acme" rather than
	// reaching the database as a cross-tenant row. Assert the neutralization is
	// real: the rule is stamped acme, acme can read it, and globex cannot. (The
	// database WITH CHECK policy is the defence-in-depth backstop for a bug that
	// bypasses this stamping; it is exercised by the raw-SQL RLS tests, not
	// through the store which never emits a forged tenant.)
	forged := processors.Rule{TenantID: "globex", Lane: "syslog", Type: processors.TypeDropField, Field: "x", Enabled: true}
	if err := forged.Validate(); err != nil {
		t.Fatal(err)
	}
	created, err := st.Create(ctx, "acme", false, forged)
	if err != nil {
		t.Fatalf("non-cross Create must succeed with the body tenant stamped away, got %v", err)
	}
	if created.TenantID != "acme" {
		t.Fatalf("forged body tenant must be stamped to the caller: got %q, want acme", created.TenantID)
	}
	if _, found, _ := st.Get(ctx, "globex", false, created.ID); found {
		t.Fatal("RLS LEAK: globex read a rule the forge tried to plant in it")
	}
	if _, found, _ := st.Get(ctx, "acme", false, created.ID); !found {
		t.Fatal("the stamped rule must be readable by its real owner acme")
	}

	// The config writer's cross-tenant read sees both.
	if all, _ := st.AllEnabled(ctx); len(all) != 2 {
		t.Fatalf("AllEnabled must see every tenant's enabled rules: %+v", all)
	}

	// History + rollback must work on the RLS backend too, and stay scoped.
	hist, found, err := st.ListVersions(ctx, "acme", false, ra.ID)
	if err != nil || !found || len(hist) == 0 {
		t.Fatalf("pg history must record the create: %v found=%v %+v", err, found, hist)
	}
	if _, found, _ := st.ListVersions(ctx, "acme", false, rb.ID); found {
		t.Fatal("RLS LEAK: acme read globex's processor history")
	}
}
