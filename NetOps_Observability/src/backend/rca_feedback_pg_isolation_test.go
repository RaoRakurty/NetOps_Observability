package backend

// rca_feedback_pg_isolation_test.go — storage-layer RLS proof for the
// rca_feedback table (migration 0036), mirroring
// maintenance_pg_isolation_test.go: the FORCE-RLS tenant_iso policy is the
// backstop even if every handler check were bypassed (§3a rule 4). Gated on
// DATABASE_URL_TEST like every pg-integration test in this package.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
	"netops/backend/rcafeedback"
)

func TestRcaFeedbackRLSIsolationPG(t *testing.T) {
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
	st := rcafeedback.NewPGStore(ps.DB())

	const (
		caseA = "11111111-2222-4333-8444-555555555555"
		caseB = "66666666-7777-4888-8999-aaaaaaaaaaaa"
	)
	now := time.Now().UTC()
	version := 4
	add := func(tenant, corrID, verdict, wrongPart, template string) rcafeedback.Feedback {
		t.Helper()
		f, addErr := st.Add(ctx, tenant, false, rcafeedback.Feedback{
			TenantID: tenant, CorrelationID: corrID, Verdict: verdict,
			WrongPart: wrongPart, Reason: "recorded by the pg isolation test",
			CorrelationVersion: &version, TopHypothesis: template,
			VerdictTier: "suspected", CreatedBy: "op@" + tenant, CreatedAt: now,
		})
		if addErr != nil {
			t.Fatalf("add %s/%s: %v", tenant, verdict, addErr)
		}
		return f
	}
	fa := add("acme", caseA, "wrong", "cause", "link_down")
	add("acme", caseB, "correct", "", "bgp_flap")
	fb := add("globex", caseA, "correct", "", "link_down") // SAME case id, other tenant

	// Own-only list: acme's list of the shared case id carries only its row.
	la, err := st.List(ctx, "acme", false, caseA)
	if err != nil {
		t.Fatal(err)
	}
	if len(la) != 1 || la[0].ID != fa.ID || la[0].TenantID != "acme" {
		t.Fatalf("RLS LEAK: acme's list of a shared case id = %+v", la)
	}
	if la[0].CorrelationVersion == nil || *la[0].CorrelationVersion != version {
		t.Fatalf("correlation_version did not round-trip: %+v", la[0].CorrelationVersion)
	}
	if la[0].WrongPart != "cause" || la[0].TopHypothesis != "link_down" || la[0].VerdictTier != "suspected" {
		t.Fatalf("row did not round-trip: %+v", la[0])
	}

	lb, err := st.List(ctx, "globex", false, caseA)
	if err != nil {
		t.Fatal(err)
	}
	if len(lb) != 1 || lb[0].ID != fb.ID {
		t.Fatalf("RLS LEAK: globex's list = %+v", lb)
	}

	// WITH CHECK forge: inserting a row claiming another tenant under a scoped
	// transaction must be refused by policy (SQLSTATE 42501), NOT silently
	// rewritten — a forged owner is the whole attack this policy exists for.
	_, err = st.Add(ctx, "acme", false, rcafeedback.Feedback{
		TenantID: "globex", CorrelationID: caseA, Verdict: "wrong", CreatedAt: now,
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", err)
	}

	// The aggregate obeys RLS too: acme counts only acme's two rows.
	ba, err := st.Buckets(ctx, "acme", false, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	sa := rcafeedback.Summarize(ba)
	if sa.N != 2 || sa.Wrong != 1 || sa.Correct != 1 {
		t.Fatalf("RLS LEAK in the aggregate: %+v", sa.Counts)
	}
	if sa.FalsePositiveRate == nil || *sa.FalsePositiveRate != 0.5 {
		t.Fatalf("false_positive_rate = %v, want 0.5", sa.FalsePositiveRate)
	}

	// The window is applied in SQL: a `since` in the future yields nothing.
	future, err := st.Buckets(ctx, "acme", false, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if s := rcafeedback.Summarize(future); s.N != 0 || s.FalsePositiveRate != nil {
		t.Fatalf("the window was not applied: %+v", s.Counts)
	}

	// A tenant that owns nothing sees nothing (default-closed).
	if l, listErr := st.List(ctx, "initech", false, caseA); listErr != nil || len(l) != 0 {
		t.Fatalf("RLS LEAK: initech saw %+v (%v)", l, listErr)
	}

	// Platform principal (cross) spans both tenants.
	all, err := st.List(ctx, "", true, caseA)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("platform principal must see both rows: %+v", all)
	}
	crossBuckets, err := st.Buckets(ctx, "", true, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if s := rcafeedback.Summarize(crossBuckets); s.N != 3 {
		t.Fatalf("cross-tenant aggregate must span tenants: %+v", s.Counts)
	}

	// CHECK constraints back the API vocabulary at the storage layer.
	_, err = st.Add(ctx, "acme", false, rcafeedback.Feedback{
		TenantID: "acme", CorrelationID: caseA, Verdict: "maybe", CreatedAt: now,
	})
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("the verdict CHECK constraint must refuse an unknown verdict, got %v", err)
	}
}
