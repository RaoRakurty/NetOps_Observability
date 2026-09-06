package audit

// retention_test.go — guards for the retention half of audit F-57.
//
// `nms_store.go` held the ONLY time-based DELETE in the entire non-test Go
// tree. The file audit backend self-bounds to a 5,000-event ring; the Postgres
// backend had no counterpart at all — 29,002 rows / 13 MB and +597/day at audit
// time, with a read path capped at 1,000, so the table grew without bound while
// the UI stopped reflecting it.
//
// The retention sweeper is deliberately OPT-IN and OFF by default: an audit
// trail is evidence, and deleting it on a default nobody chose would be a worse
// defect than the growth. These tests pin that default hard.

import (
	"context"
	"testing"
)

func TestRetentionIsOffUnlessExplicitlyConfigured(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
	}{
		{"unset", ""},
		{"zero", "0"},
		{"negative", "-30"},
		{"typo", "30d"},
		{"empty-ish", "  "},
		{"not a number", "forever"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseRetentionDays(tc.raw); got != 0 {
				t.Fatalf("AUDIT_RETENTION_DAYS=%q → %d days. Retention must stay OFF for anything "+
					"that is not an explicit positive integer: an operator typo must never be "+
					"read as permission to delete evidence.", tc.raw, got)
			}
		})
	}
	if got := ParseRetentionDays("365"); got != 365 {
		t.Fatalf("an explicit 365 → %d", got)
	}
}

func TestSweepRetentionIsANoOpWithoutConfiguration(t *testing.T) {
	// nil db / days<=0 must not attempt a DELETE. Guards against a future
	// refactor that would let an unconfigured deployment start deleting.
	for _, days := range []int{0, -1} {
		n, err := SweepRetention(context.Background(), nil, days, DefaultTrailDays)
		if err != nil || n != 0 {
			t.Fatalf("sweep(days=%d) = (%d, %v), want (0, nil)", days, n, err)
		}
	}
	if n, err := SweepRetention(context.Background(), nil, 30, DefaultTrailDays); err != nil || n != 0 {
		t.Fatalf("sweep with a nil db = (%d, %v), want (0, nil)", n, err)
	}
}

// TestStartRetentionIsANoOpWithoutADB: the sweeper is a Postgres-only concern
// (the file backend self-bounds), and starting it anywhere else must be silent
// and harmless. Main gates on platformdb.ActivePG and passes nil never — this
// pins the package-side guard all the same.
func TestStartRetentionIsANoOpWithoutADB(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartRetention(ctx, nil, 30, DefaultTrailDays) // must not panic, must not start anything
	StartRetention(ctx, nil, 0, DefaultTrailDays)
}
