package main

// audit_retention_test.go — guards for the retention half of audit F-57.
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

func TestAuditRetentionIsOffUnlessExplicitlyConfigured(t *testing.T) {
	for _, tc := range []struct {
		name, env string
	}{
		{"unset", ""},
		{"zero", "0"},
		{"negative", "-30"},
		{"typo", "30d"},
		{"empty-ish", "  "},
		{"not a number", "forever"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(auditRetentionEnv, tc.env)
			if got := auditRetentionDays(); got != 0 {
				t.Fatalf("%s=%q → %d days. Retention must stay OFF for anything that is not "+
					"an explicit positive integer: an operator typo must never be read as "+
					"permission to delete evidence.", auditRetentionEnv, tc.env, got)
			}
		})
	}
	t.Setenv(auditRetentionEnv, "365")
	if got := auditRetentionDays(); got != 365 {
		t.Fatalf("an explicit 365 → %d", got)
	}
}

func TestSweepAuditRetentionIsANoOpWithoutConfiguration(t *testing.T) {
	// nil db / days<=0 must not attempt a DELETE. Guards against a future
	// refactor that would let an unconfigured deployment start deleting.
	for _, days := range []int{0, -1} {
		n, err := sweepAuditRetention(context.Background(), nil, days)
		if err != nil || n != 0 {
			t.Fatalf("sweep(days=%d) = (%d, %v), want (0, nil)", days, n, err)
		}
	}
	if n, err := sweepAuditRetention(context.Background(), nil, 30); err != nil || n != 0 {
		t.Fatalf("sweep with a nil db = (%d, %v), want (0, nil)", n, err)
	}
}

// TestStartAuditRetentionIsANoOpOnTheFileBackend: the sweeper is a Postgres-only
// concern (the file backend self-bounds), and starting it anywhere else must be
// silent and harmless.
func TestStartAuditRetentionIsANoOpOnTheFileBackend(t *testing.T) {
	t.Setenv(auditRetentionEnv, "30")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startAuditRetention(ctx) // must not panic, must not start anything
}
