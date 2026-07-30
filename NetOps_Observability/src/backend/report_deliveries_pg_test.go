package backend

import (
	"context"
	"netops/backend/internal/platformdb"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/reports"
)

// TestPgDeliveryStore exercises the per-recipient delivery ledger: record,
// sticky-ok (a retry cannot downgrade a success), failure→success on retry, the
// Delivered skip-set, and RLS scoping. Gated on DATABASE_URL_TEST.
func TestPgDeliveryStore(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres delivery-ledger test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	s := reports.NewPGDeliveryStore(ps.DB())
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Attempt 1: a ok, b failed.
	must(t, s.Record(ctx, "acme", "ex1", []reports.DeliveryStatus{
		{Channel: "email", Recipient: "a@x", OK: true, Attempt: 1, At: at},
		{Channel: "email", Recipient: "b@x", OK: false, Attempt: 1, Error: "smtp 550", At: at},
	}))
	del, err := s.Delivered(ctx, "ex1")
	if err != nil || !del["a@x"] || del["b@x"] {
		t.Fatalf("after attempt1 delivered=%v err=%v, want {a:true}", del, err)
	}

	// Attempt 2: b now succeeds; a stays ok (sticky — even if we tried to fail it).
	must(t, s.Record(ctx, "acme", "ex1", []reports.DeliveryStatus{
		{Channel: "email", Recipient: "a@x", OK: false, Attempt: 2, Error: "should be ignored", At: at.Add(time.Minute)},
		{Channel: "email", Recipient: "b@x", OK: true, Attempt: 2, At: at.Add(time.Minute)},
	}))
	del, _ = s.Delivered(ctx, "ex1")
	if !del["a@x"] || !del["b@x"] {
		t.Fatalf("after attempt2 both should be ok (a sticky), got %v", del)
	}

	// RLS: another tenant's deliveries are invisible to acme.
	must(t, s.Record(ctx, "globex", "ex9", []reports.DeliveryStatus{{Channel: "email", Recipient: "z@g", OK: true, Attempt: 1, At: at}}))
	// Delivered runs platform-scoped (infra) so it sees ex9; the RLS guarantee is
	// on tenant-scoped reads of the table — assert via a scoped query.
	var leaked int
	if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM report_execution_deliveries WHERE tenant_id='globex'`).Scan(&leaked)
	}); err != nil {
		t.Fatalf("scoped count: %v", err)
	}
	if leaked != 0 {
		t.Fatalf("DELIVERY LEAK: acme scope saw %d globex rows", leaked)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
