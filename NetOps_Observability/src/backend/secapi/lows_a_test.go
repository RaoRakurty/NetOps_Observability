// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secapi

// lows_a_test.go — review findings 3.3-08 and 3.3-09.

import (
	"context"
	"testing"
)

// 3.3-08 — THE PLATFORM VIEW OF A RULE IS DETERMINISTIC.
//
// The cross-tenant fold ASSIGNED over an unordered map, so with two tenants
// disagreeing about one rule the platform answer was whichever owner the range
// happened to visit last — it flipped between refreshes of the same page. The
// framework register beside it already folds with an explicit union and says
// so. Run enough times that Go's map ordering cannot hide the defect.
func TestRuleStatesCrossTenantFoldIsAStableUnion(t *testing.T) {
	cat := Catalog()
	if len(cat) < 1 {
		t.Fatal("empty catalog")
	}
	rule := cat[0].RuleID
	ctx := context.Background()

	for attempt := 0; attempt < 64; attempt++ {
		s := NewFileStore("")
		// acme turns it OFF, globex leaves it ON: the two disagree.
		if err := s.SetRuleStates(ctx, "acme", false, "acme", []RuleState{{RuleID: rule, Enabled: false}}); err != nil {
			t.Fatalf("acme write: %v", err)
		}
		if err := s.SetRuleStates(ctx, "globex", false, "globex", []RuleState{{RuleID: rule, Enabled: true}}); err != nil {
			t.Fatalf("globex write: %v", err)
		}
		states, err := s.RuleStates(ctx, Principal{Cross: true})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !states[rule] {
			t.Fatalf("attempt %d: the platform view of %q read as disabled — the fold is last-writer-wins over an unordered map, so it flips between refreshes",
				attempt, rule)
		}
	}

	// A scoped caller is unaffected: only one owner is visible to it.
	s := NewFileStore("")
	if err := s.SetRuleStates(ctx, "acme", false, "acme", []RuleState{{RuleID: rule, Enabled: false}}); err != nil {
		t.Fatalf("acme write: %v", err)
	}
	states, err := s.RuleStates(ctx, Principal{Tenant: "acme"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if states[rule] {
		t.Fatal("the union changed what a tenant sees of its OWN override")
	}
}

// 3.3-09 — THE TWO BACKENDS ANSWER A MALFORMED VIEW ID THE SAME WAY.
//
// DeleteView cast a caller-supplied id with `$1::uuid` while the handler
// validated only isSafeToken, so an id like `not-a-uuid` — perfectly legal to
// that check — reached Postgres, raised SQLSTATE 22P02 and was rendered as a
// 502 carrying the database's own error text, while the file backend answered
// "not found". A shape check at the boundary makes both say the same thing and
// keeps Postgres's internals out of the response.
func TestDeleteViewRefusesAMalformedIDBeforeTheDatabase(t *testing.T) {
	file := NewFileStore("")
	ctx := context.Background()
	for _, id := range []string{"not-a-uuid", "1234", "....", "11111111-2222-4333-8444-55555555555"} {
		if !isSafeToken(id) {
			continue // the handler already refuses these with a 400
		}
		found, err := file.DeleteView(ctx, "acme", false, id)
		if err != nil || found {
			t.Fatalf("file backend, %q: found=%v err=%v", id, found, err)
		}
		if looksLikeUUID(id) {
			t.Fatalf("%q was taken for a uuid", id)
		}
	}
	// And the shape check admits the ids the store actually mints.
	real, err := newUUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	if !looksLikeUUID(real) {
		t.Fatalf("a minted view id %q does not pass the shape check — every delete would answer 404", real)
	}
}

// pgStore.DeleteView must not reach the database at all for a malformed id: a
// nil seam would panic the moment it were used, so returning cleanly is the
// proof that the shape check runs BEFORE the statement.
func TestPGDeleteViewShapeCheckRunsBeforeTheSeam(t *testing.T) {
	p := &pgStore{db: nil}
	found, err := p.DeleteView(context.Background(), "acme", false, "not-a-uuid")
	if found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
}
