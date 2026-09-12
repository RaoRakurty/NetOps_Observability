// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"netops/backend/internal/incident"
	"netops/backend/internal/platformdb"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// incidents_transition_race_pg_test.go — M13 (2026-08-15 review).
//
// FAILING-FIRST: Transition was read-check-update with no row lock and no
// status predicate on the UPDATE — two concurrent transitions could both
// validate against the same SELECTed status and the loser would then apply an
// edge the state machine forbids (resolved→acknowledged un-resolving a closed
// incident). The UPDATE now carries `AND status=$cur`; zero rows means the
// race was lost and the transition is re-validated against the ACTUAL status.
//
// The interleave is forced deterministically: transaction A takes the row lock
// and resolves the incident but does not commit until B's Transition has read
// the stale 'open' status and is blocked on the UPDATE. Gated on
// DATABASE_URL_TEST like every live-Postgres test.
func TestIncidentTransitionM13ConcurrentRace(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres transition-race test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	store := incident.NewPGStore(ps.DB())

	inc, _, err := store.Ingest(ctx, IncidentInput{
		TenantID: "acme", Title: "Link flap on edge-7", Severity: "high",
		SourceType: "alert", DedupKey: "m13:edge-7", Actor: "engine",
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// Transaction A: lock the row by resolving it, then hold the transaction
	// open until told to commit.
	locked := make(chan struct{})
	release := make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		aDone <- ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx,
				`UPDATE incidents SET status='resolved', resolved_at=now(), updated_at=now() WHERE id=$1`,
				inc.ID); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil // commit
		})
	}()
	<-locked

	// Transaction B: a real Transition to 'acknowledged'. Its SELECT reads the
	// still-committed 'open' (A is uncommitted), validates open→acknowledged,
	// and its UPDATE blocks on A's row lock — the exact race window.
	bDone := make(chan error, 1)
	go func() {
		_, err := store.Transition(ctx, "acme", false, inc.ID, "acknowledged", "operator", "race")
		bDone <- err
	}()

	// Give B time to pass its validation read and park on the row lock, then
	// let A commit 'resolved'.
	time.Sleep(300 * time.Millisecond)
	close(release)
	if err := <-aDone; err != nil {
		t.Fatalf("tx A: %v", err)
	}
	berr := <-bDone
	if berr == nil {
		t.Fatal("concurrent acknowledged over resolved was APPLIED — invalid transition raced past validation")
	}
	if !errors.Is(berr, incident.ErrBadTransition) {
		t.Fatalf("lost race error = %v, want ErrBadTransition", berr)
	}

	// The incident must still be resolved — the forbidden edge never landed.
	got, _, found, err := store.Get(ctx, "acme", false, inc.ID)
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if got.Status != incident.StatusResolved {
		t.Fatalf("status = %q, want resolved (the race un-resolved the incident)", got.Status)
	}

	// And a concurrent writer applying the SAME transition stays idempotent:
	// a second resolve reports success, not a bogus bad-transition.
	if _, err := store.Transition(ctx, "acme", false, inc.ID, "resolved", "operator", "again"); err != nil {
		t.Fatalf("idempotent same-status transition: %v", err)
	}
}
