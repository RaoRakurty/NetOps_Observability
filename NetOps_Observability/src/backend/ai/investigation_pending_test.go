package ai

// investigation_pending_test.go — the concluded-but-unjudged buffer. It is the
// one place where a conclusion sits between "the assistant answered" and "an
// operator judged it", so the properties that matter are isolation and bounds:
//
//   - a conclusion can only be taken by the SAME (tenant, subject) that produced
//     it — another tenant, or another operator, can never attach an outcome to
//     it (and therefore can never write it into their own memory);
//   - an entry expires, and an expired one is never handed back;
//   - the buffer is bounded per principal and overall (§9).

import (
	"testing"
	"time"
)

func pendingFixture(inv ConcludedInvestigation) ConcludedInvestigation {
	if inv.Verdict == "" {
		inv.Verdict = "the uplink optic was failing"
	}
	if !inv.HasKey() {
		inv.DeviceName = "edge-1"
	}
	return inv
}

func TestPendingInvestigationsIsolatesPrincipals(t *testing.T) {
	p := NewPendingInvestigations()
	p.Stash("acme", "op-1", pendingFixture(ConcludedInvestigation{AnswerID: "a-1"}))

	// Another tenant with the SAME subject id cannot take it.
	if _, ok := p.Take("globex", "op-1", "a-1"); ok {
		t.Fatal("LEAK: another tenant took acme's concluded investigation")
	}
	// The same tenant with another subject cannot take it either.
	if _, ok := p.Take("acme", "op-2", "a-1"); ok {
		t.Fatal("LEAK: another operator took this operator's concluded investigation")
	}
	// The owner can, exactly once.
	got, ok := p.Take("acme", "op-1", "a-1")
	if !ok || got.AnswerID != "a-1" {
		t.Fatalf("owner take = %+v, ok=%v", got, ok)
	}
	if _, ok := p.Take("acme", "op-1", "a-1"); ok {
		t.Fatal("a conclusion must be judged only once")
	}
}

func TestPendingInvestigationsTakeByAnswerIDAndFallback(t *testing.T) {
	p := NewPendingInvestigations()
	p.Stash("acme", "op-1", pendingFixture(ConcludedInvestigation{AnswerID: "a-1", DeviceName: "edge-1"}))
	p.Stash("acme", "op-1", pendingFixture(ConcludedInvestigation{AnswerID: "a-2", DeviceName: "edge-2"}))

	// An explicit id takes exactly that conclusion, even when it is not the newest.
	got, ok := p.Take("acme", "op-1", "a-1")
	if !ok || got.DeviceName != "edge-1" {
		t.Fatalf("explicit take = %+v, ok=%v", got, ok)
	}
	// No id → the principal's most recent remaining conclusion.
	got, ok = p.Take("acme", "op-1", "")
	if !ok || got.AnswerID != "a-2" {
		t.Fatalf("fallback take = %+v, ok=%v", got, ok)
	}
	// An unknown id takes NOTHING rather than falling back — a rating that names
	// an answer we no longer hold must not be attached to a different one.
	p.Stash("acme", "op-1", pendingFixture(ConcludedInvestigation{AnswerID: "a-3"}))
	if _, ok := p.Take("acme", "op-1", "a-9"); ok {
		t.Fatal("an unknown answer id must not fall back to another conclusion")
	}
}

func TestPendingInvestigationsExpire(t *testing.T) {
	now := time.Now().UTC()
	p := NewPendingInvestigations()
	p.now = func() time.Time { return now }
	p.Stash("acme", "op-1", pendingFixture(ConcludedInvestigation{AnswerID: "a-1"}))

	p.now = func() time.Time { return now.Add(PendingInvestigationTTL + time.Minute) }
	if _, ok := p.Take("acme", "op-1", "a-1"); ok {
		t.Fatal("an expired conclusion must not be judged — the rating is no longer plausibly about it")
	}
	if p.Len() != 0 {
		t.Fatalf("expired entries must be dropped, buffer holds %d", p.Len())
	}
}

func TestPendingInvestigationsIsBounded(t *testing.T) {
	p := NewPendingInvestigations()
	for i := 0; i < maxPendingPerPrincipal*3; i++ {
		p.Stash("acme", "op-1", pendingFixture(ConcludedInvestigation{AnswerID: "a-" + itoa(i)}))
	}
	if p.Len() != maxPendingPerPrincipal {
		t.Fatalf("one principal holds %d conclusions, want the bound of %d", p.Len(), maxPendingPerPrincipal)
	}
	// The newest survive; the oldest were dropped.
	if _, ok := p.Take("acme", "op-1", "a-0"); ok {
		t.Error("the oldest conclusion should have been evicted")
	}
	if _, ok := p.Take("acme", "op-1", "a-"+itoa(maxPendingPerPrincipal*3-1)); !ok {
		t.Error("the newest conclusion must survive")
	}

	// Whole-buffer bound: many principals, oldest-touched evicted.
	wide := NewPendingInvestigations()
	for i := 0; i < maxPendingPrincipals+50; i++ {
		wide.Stash("acme", "op-"+itoa(i), pendingFixture(ConcludedInvestigation{AnswerID: "a"}))
	}
	if wide.Len() > maxPendingPrincipals {
		t.Fatalf("buffer holds %d entries, want at most %d", wide.Len(), maxPendingPrincipals)
	}
}

func TestPendingInvestigationsDropsUnrecallableConclusions(t *testing.T) {
	p := NewPendingInvestigations()
	p.Stash("acme", "op-1", ConcludedInvestigation{AnswerID: "a-1", Verdict: "no entity key here"})
	p.Stash("acme", "op-1", ConcludedInvestigation{AnswerID: "a-2", DeviceName: "edge-1"}) // no verdict
	if p.Len() != 0 {
		t.Fatalf("a conclusion that could never be recalled must not be buffered, holds %d", p.Len())
	}
	// A nil buffer is a no-op, not a panic (memory not wired on this deployment).
	var nilBuf *PendingInvestigations
	nilBuf.Stash("acme", "op-1", pendingFixture(ConcludedInvestigation{AnswerID: "a-1"}))
	if _, ok := nilBuf.Take("acme", "op-1", ""); ok {
		t.Fatal("a nil buffer must never hand back a conclusion")
	}
}

func TestInvestigationRowFromStampsOwnerAndOutcome(t *testing.T) {
	concluded := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	resolved := concluded.Add(2 * time.Hour)
	inv := ConcludedInvestigation{
		AnswerID: "a-1", DeviceID: "dev-a", DeviceName: "edge-1", Peer: "10.0.0.1",
		Skills: []string{"bgp-session-down"}, Verdict: "hold timer expired",
		Citations: []string{"diagsig:sig-1"}, ConcludedAt: concluded,
	}
	row := InvestigationRowFrom("acme", inv, OutcomeWrong, resolved)
	if row.TenantID != "acme" {
		t.Errorf("owner must come from the caller's token: %q", row.TenantID)
	}
	if row.Outcome != OutcomeWrong || !row.ResolvedAt.Equal(resolved) || !row.CreatedAt.Equal(concluded) {
		t.Errorf("row = %+v", row)
	}
	// An unrecognized outcome fails closed rather than reading as a confirmation.
	if got := InvestigationRowFrom("acme", inv, InvestigationOutcome("yes!"), resolved); got.Outcome != OutcomeUnknown {
		t.Errorf("outcome = %q, want unknown", got.Outcome)
	}
}
