// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/orgcontext"
)

func TestTheFullLifecycle(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	if v, ok := r.Open(); !ok || v.State != orgcontext.StateDraft || v.Version != 1 {
		t.Fatalf("a new runbook must start as a draft: %+v", r.Versions)
	}
	if h.count() != 0 {
		t.Fatal("a draft is not proven: the harness runs at submit")
	}
	r = activate(t, s, tA, r.ID, alice, bob)
	a, ok := r.Active()
	if !ok || a.Approver != bob || a.Author != alice || !r.Harness[1].Passed || r.Harness[1].Fingerprint != "fp-1" || r.Harness[1].At == nil {
		t.Fatalf("approved: %+v %+v", a, r.Harness)
	}
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: carol, Body: edited("Second text.")})
	if a, _ := r.Active(); a.Version != 1 {
		t.Fatal("an open draft must not displace the active version")
	}
	r = activate(t, s, tA, r.ID, carol, alice)
	if a, _ := r.Active(); a.Version != 2 || r.Versions[0].State != orgcontext.StateSuperseded {
		t.Fatalf("v2 should be active: %+v", r.Versions)
	}
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpRollback, Actor: carol, ToVersion: 1, Reason: "v2 was wrong"})
	a, _ = r.Active()
	if a.Version != 3 || a.Author != alice || a.Approver != bob || a.ActivatedBy != carol || a.RestoredFrom != 1 || !r.Harness[3].Passed {
		t.Fatalf("rollback: %+v %+v", a, r.Harness)
	}
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpRetire, Actor: bob, Reason: "decommissioned"})
	if _, ok := r.Active(); ok || len(r.Versions) != 3 {
		t.Fatalf("retire: %+v", r.Versions)
	}
}

func TestBodyIsTheCanonicalTextAndTheHashBindsBothFiles(t *testing.T) {
	r := create(t, newMem(newFake()), tA, alice, good())
	want, err := CanonicalBody(Source{goodMD, goodCases})
	if err != nil {
		t.Fatal(err)
	}
	if want != goodMD+"\n--- CASES ---\n"+goodCases {
		t.Fatalf("the canonical form is pinned: %q", want)
	}
	v, _ := r.Open()
	if v.Body != want || v.BodySHA256 != orgcontext.BodySHA256(want) {
		t.Fatalf("version: %q %s", v.Body, v.BodySHA256)
	}
	src, err := SplitBody(v.Body)
	if err != nil || src.SkillMD != goodMD || src.CasesYAML != goodCases {
		t.Fatalf("split: %+v %v", src, err)
	}
	// One hash may not stand for two pairs of texts.
	for _, md := range []string{"a\n--- CASES ---\nb", "a\n--- CASES ---"} {
		if _, err := CanonicalBody(Source{SkillMD: md, CasesYAML: "c"}); err == nil {
			t.Errorf("%q must be refused: the join would be ambiguous", md)
		}
	}
	// A separator in the cases cannot move the split: the first one is the join.
	src, err = SplitBody("a" + bodySeparator + "b" + bodySeparator + "c")
	if err != nil || src.SkillMD != "a" || src.CasesYAML != "b"+bodySeparator+"c" {
		t.Fatalf("split on the first separator: %+v %v", src, err)
	}
	if _, err := SplitBody("no separator"); err == nil {
		t.Fatal("a text with no separator is not a version's body")
	}
}

func TestSubmitRunsTheHarnessAndAFailureStaysADraft(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	h.set(func(f *fakeHarness) { f.fail = true })
	_, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	var he *HarnessError
	if !errors.As(err, &he) || len(he.Problems) != 1 || he.Problems[0].Case != "the case" {
		t.Fatalf("a failing case must block the submit: %v", err)
	}
	got, _ := s.Get(context.Background(), tA, r.ID)
	if v, _ := got.Open(); v.State != orgcontext.StateDraft || len(got.Harness) != 0 {
		t.Fatalf("the state must stay draft: %+v %+v", got.Versions, got.Harness)
	}
	// Someone else's submit is refused before anyone waits for a run.
	h.set(func(f *fakeHarness) { f.fail, f.calls = false, 0 })
	if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: bob}); !errors.Is(err, orgcontext.ErrNotAuthor) {
		t.Fatalf("submit by another person: %v", err)
	}
	if h.count() != 0 {
		t.Fatal("a refused submit must not run the harness")
	}
}

func TestApprovalNeedsAPassUnderTheCurrentFingerprint(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	v, _ := r.Open()
	approve := orgcontext.Op{Kind: orgcontext.OpApprove, Actor: bob, Version: v.Version, BodySHA256: v.BodySHA256}

	h.set(func(f *fakeHarness) { f.fp = "fp-2" })
	if _, err := s.Do(context.Background(), tA, r.ID, approve); !errors.Is(err, ErrHarnessStale) {
		t.Fatalf("a stale fingerprint must block the approval: %v", err)
	}
	if got, _ := s.Get(context.Background(), tA, r.ID); func() bool { _, ok := got.Active(); return ok }() {
		t.Fatal("a stale approval activated the version")
	}
	// The author withdraws and submits again: the new result is under fp-2.
	do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpWithdraw, Actor: alice})
	got, _ := s.Get(context.Background(), tA, r.ID)
	if len(got.Harness) != 0 {
		t.Fatalf("a withdrawal must clear the proof: %+v", got.Harness)
	}
	do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	do(t, s, tA, r.ID, approve)

	// A rejection decides against the text, so it needs no proof.
	other := create(t, s, tA, alice, named("other-one"))
	do(t, s, tA, other.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	h.set(func(f *fakeHarness) { f.fp = "fp-3" })
	do(t, s, tA, other.ID, orgcontext.Op{Kind: orgcontext.OpReject, Actor: bob, Version: 1, Reason: "no"})
}

// The pass itself, not only the fingerprint: a stored result that failed under the
// current fingerprint does not approve. No path through the store writes one, so
// this goes in underneath it.
func TestApprovalRefusesAResultThatDidNotPass(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	v, _ := r.Open()
	for name, st := range map[string]*Stamp{
		"failed under the current fingerprint": {Passed: false, Fingerprint: "fp-1"},
		"no result at all":                     nil,
		"passed with no fingerprint":           {Passed: true},
		"a MOP's marker on an investigative":   {Passed: true, Fingerprint: FingerprintNotApplicable},
	} {
		t.Run(name, func(t *testing.T) {
			s.mu.Lock()
			cur := s.rows[tA][r.ID]
			if st == nil {
				delete(cur.Harness, v.Version)
			} else {
				cur.Harness[v.Version] = *st
			}
			s.mu.Unlock()
			_, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: bob, Version: v.Version, BodySHA256: v.BodySHA256})
			if !errors.Is(err, ErrHarnessStale) {
				t.Fatalf("approve: %v, want ErrHarnessStale", err)
			}
		})
	}
}

// Self-approval and a wrong hash answer for what they are, whatever the proof says.
func TestApprovalBindsToTheReviewedText(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	v, _ := r.Open()
	if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: alice, Version: v.Version, BodySHA256: v.BodySHA256}); !errors.Is(err, orgcontext.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: bob, Version: v.Version, BodySHA256: orgcontext.BodySHA256("other")}); !errors.Is(err, orgcontext.ErrStale) {
		t.Fatalf("wrong hash: %v", err)
	}
	// Withdrawn and edited after review: the old hash no longer approves it.
	do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpWithdraw, Actor: alice})
	do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: alice, Body: edited("Changed after review.")})
	do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: bob, Version: v.Version, BodySHA256: v.BodySHA256}); !errors.Is(err, orgcontext.ErrStale) {
		t.Fatalf("old hash on a changed text: %v", err)
	}
}

// A draft edited while the harness was running is not what was proven.
func TestSubmitRefusesATextThatMovedDuringTheRun(t *testing.T) {
	s := newMem(nil)
	h := &editingHarness{fakeHarness: newFake(), store: s}
	s.cfg.Harness = h
	r := create(t, s, tA, alice, good())
	h.id = r.ID
	if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice}); !errors.Is(err, orgcontext.ErrStale) {
		t.Fatalf("a text that moved during the run: %v, want ErrStale", err)
	}
	got, _ := s.Get(context.Background(), tA, r.ID)
	if v, _ := got.Open(); v.State != orgcontext.StateDraft {
		t.Fatalf("it must stay a draft: %+v", got.Versions)
	}
}

// editingHarness edits the draft the moment it is asked to prove it.
type editingHarness struct {
	*fakeHarness
	store *MemStore
	id    string
}

func (e *editingHarness) Run(ctx context.Context, req HarnessRequest) (HarnessResult, error) {
	if _, err := e.store.Do(ctx, tA, e.id, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: alice, Body: edited("Edited mid-run.")}); err != nil {
		return HarnessResult{}, err
	}
	return e.fakeHarness.Run(ctx, req)
}

func TestRollbackRunsTheHarnessAgainUnderTheCurrentFingerprint(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	activate(t, s, tA, r.ID, alice, bob)
	do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: carol, Body: edited("Second text.")})
	activate(t, s, tA, r.ID, carol, alice)

	h.set(func(f *fakeHarness) { f.fp, f.fail, f.calls = "fp-2", true, 0 })
	_, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpRollback, Actor: carol, ToVersion: 1, Reason: "v2 was wrong"})
	var he *HarnessError
	if !errors.As(err, &he) {
		t.Fatalf("a rollback to a text that no longer passes: %v", err)
	}
	if h.count() != 1 {
		t.Fatalf("the rollback must have re-run the harness: %d runs", h.count())
	}
	got, _ := s.Get(context.Background(), tA, r.ID)
	if a, _ := got.Active(); a.Version != 2 || len(got.Versions) != 2 {
		t.Fatalf("a refused rollback changed the runbook: %+v", got.Versions)
	}
	// Restored text is what was proven, under the new fingerprint.
	h.set(func(f *fakeHarness) { f.fail = false })
	got = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpRollback, Actor: carol, ToVersion: 1, Reason: "v2 was wrong"})
	v1, _ := got.version(1)
	src, _ := SplitBody(v1.Body)
	if h.last.Source != src {
		t.Fatalf("the harness proved %+v, not the restored text", h.last.Source)
	}
	if st := got.Harness[3]; !st.Passed || st.Fingerprint != "fp-2" || st.At == nil {
		t.Fatalf("the restored version's stamp: %+v", st)
	}
	if st := got.Harness[1]; st.Fingerprint != "fp-1" {
		t.Fatalf("version 1's own history must not change: %+v", st)
	}
	// A busy gate decides nothing.
	h.set(func(f *fakeHarness) { f.err = ErrHarnessBusy })
	if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpRollback, Actor: carol, ToVersion: 2, Reason: "x"}); !errors.Is(err, ErrHarnessBusy) {
		t.Fatalf("busy: %v", err)
	}
}

func TestAMOPIsStoredAsNotApplicableAndNeverGoesStale(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, mop())
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	if st := r.Harness[1]; !st.Passed || st.Fingerprint != FingerprintNotApplicable {
		t.Fatalf("a MOP stores n/a: %+v", st)
	}
	v, _ := r.Open()
	h.set(func(f *fakeHarness) { f.fp = "fp-2" })
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: bob, Version: v.Version, BodySHA256: v.BodySHA256})
	if _, ok := r.Active(); !ok {
		t.Fatal("a MOP approves whatever the fingerprint is")
	}
	if h.last.Siblings != nil {
		t.Fatal("a MOP runs nothing, so it needs no siblings")
	}
	// The kind cannot change under the review: the text must say what the row says.
	bad, _ := CanonicalBody(Source{SkillMD: goodMD, CasesYAML: goodCases})
	badName := strings.Replace(bad, "name: "+goodName, "name: "+mopName, 1)
	if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: alice, Body: badName}); err == nil {
		t.Fatal("a MOP's new draft may not turn it into an investigative runbook")
	}
}

func TestTheKindAndNameMustAgreeWithTheText(t *testing.T) {
	s := newMem(newFake())
	in := good()
	in.Kind = KindMOP
	if _, err := s.Create(context.Background(), tA, alice, in); err == nil {
		t.Fatal("kind mop over an investigative text must be refused")
	}
	in = good()
	in.Name = "other-name"
	if _, err := s.Create(context.Background(), tA, alice, in); err == nil {
		t.Fatal("a name that is not the text's must be refused")
	}
	in = good()
	in.Kind = "persona"
	if _, err := s.Create(context.Background(), tA, alice, in); err == nil {
		t.Fatal("an unknown kind must be refused")
	}
	// A compiled method's name is the parser's refusal.
	if _, err := s.Create(context.Background(), tA, alice, NewRunbook{Name: "interface-down", Kind: KindInvestigative, Source: Source{SkillMD: strings.Replace(goodMD, goodName, "interface-down", 1)}}); err == nil {
		t.Fatal("a compiled method's name must be refused")
	}
}

func TestBounds(t *testing.T) {
	t.Run("30 runbooks per tenant, under concurrency", func(t *testing.T) {
		s := newMem(newFake())
		var wg sync.WaitGroup
		var mu sync.Mutex
		var wins int
		var full int
		for i := 0; i < MaxRunbooksPerTenant+15; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := s.Create(context.Background(), tA, alice, named(fmt.Sprintf("rb-%d", i)))
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					wins++
				case errors.Is(err, orgcontext.ErrFull):
					full++
				default:
					t.Errorf("create %d: %v", i, err)
				}
			}(i)
		}
		wg.Wait()
		if wins != MaxRunbooksPerTenant || full != 15 {
			t.Fatalf("%d created, %d refused; the cap is %d", wins, full, MaxRunbooksPerTenant)
		}
		// The cap is per tenant.
		create(t, s, tB, alice, good())
	})
	t.Run("50 versions per runbook", func(t *testing.T) {
		s := newMem(newFake())
		r := create(t, s, tA, alice, good())
		for i := 1; i < MaxVersionsPerRunbook; i++ {
			do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
			do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpReject, Actor: bob, Version: i, Reason: "no"})
			do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: alice, Body: edited(fmt.Sprintf("Try %d.", i))})
		}
		// Editing the open draft adds no version.
		do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: alice, Body: edited("The last try.")})
		r = activate(t, s, tA, r.ID, alice, bob)
		if len(r.Versions) != MaxVersionsPerRunbook {
			t.Fatalf("%d versions", len(r.Versions))
		}
		if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: alice, Body: edited("One more.")}); !errors.Is(err, orgcontext.ErrFull) {
			t.Fatalf("version %d: %v", MaxVersionsPerRunbook+1, err)
		}
	})
	t.Run("a rollback counts as a version", func(t *testing.T) {
		s := newMem(newFake())
		r := create(t, s, tA, alice, good())
		activate(t, s, tA, r.ID, alice, bob)
		s.mu.Lock()
		cur := s.rows[tA][r.ID]
		for i := 2; i <= MaxVersionsPerRunbook; i++ {
			cur.Versions = append(cur.Versions, orgcontext.Version{Version: i, Body: cur.Versions[0].Body, BodySHA256: cur.Versions[0].BodySHA256, State: orgcontext.StateRejected, Author: alice})
		}
		s.rows[tA][r.ID] = cur
		s.mu.Unlock()
		if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpRetire, Actor: bob, Reason: "x"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpRollback, Actor: bob, ToVersion: 1}); !errors.Is(err, orgcontext.ErrFull) {
			t.Fatalf("rollback past the cap: %v", err)
		}
	})
	t.Run("40 cases per runbook", func(t *testing.T) {
		// The fixture's two real cases, then copies of its first under new names.
		first, _, _ := strings.Cut(goodCases, "---\n")
		cases := func(n int) string {
			out := goodCases
			for i := 2; i < n; i++ {
				out += "---\n" + strings.Replace(first, "case: logs naming", fmt.Sprintf("case: copy %d logs naming", i), 1)
			}
			return out
		}
		s := newMem(newFake())
		in := NewRunbook{Name: goodName, Kind: KindInvestigative, Source: Source{goodMD, cases(MaxCasesPerRunbook + 1)}}
		_, err := s.Create(context.Background(), tA, alice, in)
		var p orgcontext.Problem
		if !errors.As(err, &p) || !strings.Contains(p.Say, fmt.Sprintf("at most %d", MaxCasesPerRunbook)) {
			t.Fatalf("%d cases must be refused for their number: %v", MaxCasesPerRunbook+1, err)
		}
		in.Source.CasesYAML = cases(MaxCasesPerRunbook)
		if _, err := s.Create(context.Background(), tA, alice, in); err != nil {
			t.Fatalf("%d cases are allowed: %v", MaxCasesPerRunbook, err)
		}
	})
	t.Run("20 links per runbook", func(t *testing.T) {
		s := newMem(newFake())
		r := create(t, s, tA, alice, good())
		for i := 0; i < MaxLinksPerRunbook; i++ {
			if _, err := s.PutLink(context.Background(), tA, r.ID, alice, LinkAlert, fmt.Sprintf("alert-%d", i)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.PutLink(context.Background(), tA, r.ID, alice, LinkAlert, "one-more"); !errors.Is(err, orgcontext.ErrFull) {
			t.Fatalf("link %d: %v", MaxLinksPerRunbook+1, err)
		}
		// Adding one that exists is not a new link.
		if _, err := s.PutLink(context.Background(), tA, r.ID, alice, LinkAlert, "alert-0"); err != nil {
			t.Fatalf("an existing link at the cap: %v", err)
		}
	})
}

func TestSearchAndLinksAreTheTenantsOwn(t *testing.T) {
	s := newMem(newFake())
	ctx := context.Background()
	a := create(t, s, tA, alice, good())
	b := create(t, s, tB, alice, good())
	for _, p := range []struct {
		tenant, id string
	}{{tA, a.ID}, {tB, b.ID}} {
		if _, err := s.PutLink(ctx, p.tenant, p.id, alice, LinkSignature, "bgp-flap"); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []string{tA, tB} {
		want := a.ID
		if tenant == tB {
			want = b.ID
		}
		found, err := s.Search(ctx, tenant, "carrier fault", 10)
		if err != nil || len(found) != 1 || found[0].ID != want || found[0].Tenant != tenant {
			t.Fatalf("search as %s: %+v %v", tenant, found, err)
		}
		linked, err := s.ListByLink(ctx, tenant, LinkSignature, "bgp-flap")
		if err != nil || len(linked) != 1 || linked[0].ID != want || linked[0].Tenant != tenant {
			t.Fatalf("list by link as %s: %+v %v", tenant, linked, err)
		}
	}
	if found, _ := s.Search(ctx, "t-c", "carrier", 10); len(found) != 0 {
		t.Fatalf("a third tenant found %+v", found)
	}
	if linked, _ := s.ListByLink(ctx, "t-c", LinkSignature, "bgp-flap"); len(linked) != 0 {
		t.Fatalf("a third tenant found %+v", linked)
	}
	for _, f := range []func() error{
		func() error { _, err := s.Links(ctx, tB, a.ID); return err },
		func() error { _, err := s.PutLink(ctx, tB, a.ID, bob, LinkAlert, "x"); return err },
		func() error { _, err := s.DeleteLink(ctx, tB, a.ID, LinkSignature, "bgp-flap"); return err },
		func() error { _, err := s.Check(ctx, tB, a.ID); return err },
		func() error { _, err := s.Get(ctx, tB, a.ID); return err },
	} {
		if err := f(); !errors.Is(err, orgcontext.ErrNotFound) {
			t.Errorf("cross-tenant: %v", err)
		}
	}
	for _, k := range []orgcontext.OpKind{orgcontext.OpDraft, orgcontext.OpDiscard, orgcontext.OpSubmit, orgcontext.OpWithdraw, orgcontext.OpApprove, orgcontext.OpReject, orgcontext.OpRollback, orgcontext.OpRetire} {
		if _, err := s.Do(ctx, tB, a.ID, orgcontext.Op{Kind: k, Actor: carol, Body: edited("x"), Version: 1, ToVersion: 1, Reason: "r"}); !errors.Is(err, orgcontext.ErrNotFound) {
			t.Errorf("cross-tenant %s: %v", k, err)
		}
	}
}

func TestRetrievalCarriesAuthorityAndFindsOnlyApprovedText(t *testing.T) {
	s := newMem(newFake())
	ctx := context.Background()
	draft := create(t, s, tA, alice, named("drafted-one"))
	active := create(t, s, tA, alice, named("approved-one"))
	active = activate(t, s, tA, active.ID, alice, bob)

	found, err := s.Search(ctx, tA, "brownout", 10)
	if err != nil || len(found) != 2 {
		t.Fatalf("search: %+v %v", found, err)
	}
	if found[0].ID != active.ID || found[0].Authority != AuthorityApproved || found[0].ApprovedAt == nil {
		t.Fatalf("active first, carrying its approval: %+v", found[0])
	}
	if found[1].ID != draft.ID || found[1].Authority != AuthorityUnapproved || found[1].ApprovedAt != nil {
		t.Fatalf("the draft is unapproved: %+v", found[1])
	}
	d := found[0]
	if d.Type != "runbook" || d.Source != "customer" || d.Scope != orgcontext.ScopeTenant || d.Snippet == "" || d.CreatedAt.IsZero() {
		t.Fatalf("retrieval fields: %+v", d)
	}
	if strings.Contains(d.Snippet, "carrier portal") {
		t.Fatal("the method's body is not searchable text")
	}
	if got, _ := s.Search(ctx, tA, "portal", 10); len(got) != 0 {
		t.Fatalf("the method's body must not be searched: %+v", got)
	}
	if got, _ := s.Search(ctx, tA, "   ", 10); len(got) != 0 {
		t.Fatalf("an empty query finds nothing: %+v", got)
	}
	if got, _ := s.Search(ctx, tA, "brownout", 1); len(got) != 1 {
		t.Fatalf("limit: %+v", got)
	}

	// An unapproved edit must not change what an approved runbook is found by.
	md := strings.Replace(strings.Replace(goodMD, goodName, "approved-one", 1), "acme wan brownout", "unreviewed phrase", 1)
	body, err := CanonicalBody(Source{SkillMD: md, CasesYAML: strings.ReplaceAll(goodCases, goodName, "approved-one")})
	if err != nil {
		t.Fatal(err)
	}
	do(t, s, tA, active.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: carol, Body: body})
	if got, _ := s.Search(ctx, tA, "unreviewed", 10); len(got) != 0 {
		t.Fatalf("an unapproved phrase is searchable on an approved runbook: %+v", got)
	}
	activate(t, s, tA, active.ID, carol, alice)
	if got, _ := s.Search(ctx, tA, "unreviewed", 10); len(got) != 1 {
		t.Fatalf("once approved it is searchable: %+v", got)
	}
}

func TestDiscardingTheOnlyDraftRemovesTheRunbookAndItsLinks(t *testing.T) {
	s := newMem(newFake())
	ctx := context.Background()
	r := create(t, s, tA, alice, good())
	if _, err := s.PutLink(ctx, tA, r.ID, alice, LinkEntity, "edge-1"); err != nil {
		t.Fatal(err)
	}
	do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpDiscard, Actor: alice})
	if _, err := s.Get(ctx, tA, r.ID); !errors.Is(err, orgcontext.ErrNotFound) {
		t.Fatalf("a runbook with no versions left should be gone: %v", err)
	}
	if got, _ := s.ListByLink(ctx, tA, LinkEntity, "edge-1"); len(got) != 0 {
		t.Fatalf("its links should be gone: %+v", got)
	}
	create(t, s, tA, alice, good()) // and the name is free
}

func TestConcurrentApprovalsActivateOnce(t *testing.T) {
	s := newMem(newFake())
	r := create(t, s, tA, alice, good())
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	v, _ := r.Open()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for _, who := range []string{bob, carol, "u-dan", "u-eve"} {
		wg.Add(1)
		go func(who string) {
			defer wg.Done()
			if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: who, Version: v.Version, BodySHA256: v.BodySHA256}); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(who)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d approvals succeeded, want exactly 1", wins)
	}
}

// recordingDB proves every Postgres store call asks for the principal's tenant and
// never the cross-tenant scope, without needing a database: fn is not run.
type recordingDB struct {
	tenants []string
	cross   []bool
}

var errRecorded = errors.New("recorded")

func (r *recordingDB) WithTenant(_ context.Context, tenant string, cross bool, _ func(pgx.Tx) error) error {
	r.tenants = append(r.tenants, tenant)
	r.cross = append(r.cross, cross)
	return errRecorded
}

func TestEveryPostgresCallRunsInThePrincipalsTenant(t *testing.T) {
	id, err := orgcontext.NewID()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for name, call := range map[string]func(*PGStore) error{
		"List":   func(p *PGStore) error { _, err := p.List(ctx, tA); return err },
		"Get":    func(p *PGStore) error { _, err := p.Get(ctx, tA, id); return err },
		"Create": func(p *PGStore) error { _, err := p.Create(ctx, tA, alice, good()); return err },
		"Do": func(p *PGStore) error {
			_, err := p.Do(ctx, tA, id, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
			return err
		},
		"Check": func(p *PGStore) error { _, err := p.Check(ctx, tA, id); return err },
		"Links": func(p *PGStore) error { _, err := p.Links(ctx, tA, id); return err },
		"PutLink": func(p *PGStore) error {
			_, err := p.PutLink(ctx, tA, id, alice, LinkAlert, "x")
			return err
		},
		"DeleteLink": func(p *PGStore) error {
			_, err := p.DeleteLink(ctx, tA, id, LinkAlert, "x")
			return err
		},
		"ListByLink": func(p *PGStore) error { _, err := p.ListByLink(ctx, tA, LinkAlert, "x"); return err },
		"Search":     func(p *PGStore) error { _, err := p.Search(ctx, tA, "carrier", 5); return err },
	} {
		t.Run(name, func(t *testing.T) {
			db := &recordingDB{}
			err := call(NewPGStore(db, Config{Harness: newFake()}))
			if !errors.Is(err, errRecorded) {
				t.Fatalf("the call must reach the database seam: %v", err)
			}
			if len(db.tenants) == 0 {
				t.Fatal("no WithTenant call")
			}
			for i := range db.tenants {
				if db.tenants[i] != tA || db.cross[i] {
					t.Fatalf("WithTenant(%q, cross=%v), want (%q, false)", db.tenants[i], db.cross[i], tA)
				}
			}
		})
	}
}

func TestMetricsAreCountedAndNilSafe(t *testing.T) {
	var none *Metrics
	none.harness(HarnessResult{}, nil)
	none.staleApproval()
	none.op("x", nil)
	if err := none.Write(&strings.Builder{}); err != nil {
		t.Fatal(err)
	}

	m := &Metrics{}
	h := newFake()
	s := NewMemStore(Config{Harness: h, Metrics: m})
	r := create(t, s, tA, alice, good())
	r = do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	v, _ := r.Open()
	h.set(func(f *fakeHarness) { f.fp = "fp-2" })
	if _, err := s.Do(context.Background(), tA, r.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: bob, Version: v.Version, BodySHA256: v.BodySHA256}); !errors.Is(err, ErrHarnessStale) {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := m.Write(&b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`netops_iris_runbook_harness_total{outcome="passed"} 1`,
		`netops_iris_runbook_stale_approvals_total 1`,
		`netops_iris_runbook_ops_total{op="create",outcome="ok"} 1`,
		`netops_iris_runbook_ops_total{op="approve",outcome="refused"} 1`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
}
