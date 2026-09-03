package backend

// iris_memory_pg_isolation_test.go — storage-layer RLS proof for the
// iris_investigations table (migration 0040), mirroring
// rca_feedback_pg_isolation_test.go: the FORCE-RLS tenant_iso policy is the
// backstop even if every handler and store check were bypassed (§3a rule 4).
// Gated on DATABASE_URL_TEST like every pg-integration test in this package.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/ai"
	"netops/backend/internal/platformdb"
)

func TestIrisInvestigationsRLSIsolationPG(t *testing.T) {
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
	st := ai.NewPGInvestigationStore(ps.DB())

	now := time.Now().UTC()
	record := func(tenant, device, peer, verdict string, outcome ai.InvestigationOutcome, at time.Time) {
		t.Helper()
		if err := st.Record(ctx, ai.InvestigationRow{
			TenantID: tenant, DeviceID: "dev-" + tenant, DeviceName: device, Peer: peer,
			Skills: []string{"bgp-session-down", "interface-down"}, Verdict: verdict,
			Citations: []string{"diagsig:sig-1"}, Outcome: outcome,
			CreatedAt: at, ResolvedAt: at,
		}); err != nil {
			t.Fatalf("record %s/%s: %v", tenant, device, err)
		}
	}
	// The SAME device name and the SAME peer in two tenants: the shape a leak
	// would expose.
	record("acme", "edge-1", "10.0.0.1", "acme: the uplink optic was failing", ai.OutcomeConfirmed, now)
	record("acme", "edge-2", "10.0.0.2", "acme: admin shutdown", ai.OutcomeWrong, now.Add(-time.Hour))
	record("globex", "edge-1", "10.0.0.1", "globex: the ISP dropped the session", ai.OutcomeConfirmed, now)

	// Own-only recall on a shared device name.
	rows, err := st.Recall(ctx, "acme", false, ai.InvestigationQuery{Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TenantID != "acme" {
		t.Fatalf("RLS LEAK: acme's recall of a shared device name = %+v", rows)
	}
	if rows[0].Verdict != "acme: the uplink optic was failing" || rows[0].Outcome != ai.OutcomeConfirmed {
		t.Fatalf("row did not round-trip: %+v", rows[0])
	}
	if len(rows[0].Skills) != 2 || len(rows[0].Citations) != 1 {
		t.Fatalf("array columns did not round-trip: %+v", rows[0])
	}

	// Own-only recall on a shared PEER address.
	rows, err = st.Recall(ctx, "globex", false, ai.InvestigationQuery{Peer: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TenantID != "globex" {
		t.Fatalf("RLS LEAK: globex's peer recall = %+v", rows)
	}

	// A tenant that owns nothing sees nothing (default-closed).
	if rows, err = st.Recall(ctx, "initech", false, ai.InvestigationQuery{Device: "edge-1"}); err != nil || len(rows) != 0 {
		t.Fatalf("RLS LEAK: initech saw %+v (%v)", rows, err)
	}

	// No unscoped list — not even for the platform principal.
	if rows, err = st.Recall(ctx, "", true, ai.InvestigationQuery{}); err != nil || len(rows) != 0 {
		t.Fatalf("an unkeyed recall returned %+v (%v)", rows, err)
	}
	// …but a KEYED cross-tenant recall spans both.
	rows, err = st.Recall(ctx, "", true, ai.InvestigationQuery{Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("platform principal must see both rows: %+v", rows)
	}

	// The window is applied in SQL.
	rows, err = st.Recall(ctx, "acme", false, ai.InvestigationQuery{Device: "edge-2", Since: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("a conclusion older than the window was recalled: %+v", rows)
	}

	// WITH CHECK forge: a row claiming another tenant is refused by policy
	// (SQLSTATE 42501), never silently rewritten. The store always scopes the
	// transaction to the row's own owner, so this is exercised by writing under
	// the RLS session of the forged tenant directly.
	forgeErr := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO iris_investigations
		        (tenant_id, id, device_name, verdict, outcome)
		    VALUES ('globex', gen_random_uuid(), 'edge-9', 'forged', 'confirmed')`)
		return execErr
	})
	var pgErr *pgconn.PgError
	if !errors.As(forgeErr, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", forgeErr)
	}

	// The CHECK constraint backs the closed outcome vocabulary at the storage
	// layer, so a bypass of the Go normalization cannot store a fourth value.
	checkErr := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO iris_investigations
		        (tenant_id, id, device_name, verdict, outcome)
		    VALUES ('acme', gen_random_uuid(), 'edge-9', 'v', 'definitely')`)
		return execErr
	})
	if !errors.As(checkErr, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("the outcome CHECK constraint must refuse an unknown outcome, got %v", checkErr)
	}
}

func TestIrisInvestigationsRetentionCapPG(t *testing.T) {
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
	st := ai.NewPGInvestigationStore(ps.DB())

	base := time.Now().UTC().Add(-24 * time.Hour)
	total := ai.MaxInvestigationsPerTenant + 5
	for i := 0; i < total; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		if err := st.Record(ctx, ai.InvestigationRow{
			TenantID: "acme", DeviceName: "edge-1", Verdict: "conclusion", ResolvedAt: at, CreatedAt: at,
		}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	// One row for another tenant: the cap is PER TENANT and must not touch it.
	if err := st.Record(ctx, ai.InvestigationRow{
		TenantID: "globex", DeviceName: "edge-1", Verdict: "globex", ResolvedAt: base,
	}); err != nil {
		t.Fatal(err)
	}

	var held, other int
	if err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM iris_investigations WHERE tenant_id='acme'`).Scan(&held); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM iris_investigations WHERE tenant_id='globex'`).Scan(&other)
	}); err != nil {
		t.Fatal(err)
	}
	if held != ai.MaxInvestigationsPerTenant {
		t.Fatalf("acme holds %d rows, want the cap of %d", held, ai.MaxInvestigationsPerTenant)
	}
	if other != 1 {
		t.Fatalf("globex holds %d rows — one tenant's eviction must never touch another's", other)
	}
	// Eviction is oldest-first: the newest conclusion is still recallable.
	rows, err := st.Recall(ctx, "acme", false, ai.InvestigationQuery{Device: "edge-1", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !rows[0].ResolvedAt.Equal(base.Add(time.Duration(total-1)*time.Minute)) {
		t.Fatalf("newest conclusion = %+v", rows)
	}
}
