// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package orgcontext

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

const (
	tA     = "t-a"
	tB     = "t-b"
	alice  = "u-alice"
	bob    = "u-bob"
	carol  = "u-carol"
	drBody = "core-02 is the DR site; treat its alerts as lower urgency until 06:00."
)

func newDoc(t *testing.T, s Store, tenant, actor, key, body string) Doc {
	t.Helper()
	d, err := s.Create(context.Background(), tenant, actor, NewDoc{Scope: ScopeTenant, Kind: KindTopologyNote, Key: key, Body: body})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return d
}

func do(t *testing.T, s Store, tenant, id string, op Op) Doc {
	t.Helper()
	d, err := s.Do(context.Background(), tenant, id, op)
	if err != nil {
		t.Fatalf("%s by %s: %v", op.Kind, op.Actor, err)
	}
	return d
}

// activate takes a document's open draft through submit + approve.
func activate(t *testing.T, s Store, tenant, id, author, approver string) Doc {
	t.Helper()
	d := do(t, s, tenant, id, Op{Kind: OpSubmit, Actor: author})
	v, _ := d.Open()
	return do(t, s, tenant, id, Op{Kind: OpApprove, Actor: approver, Version: v.Version, BodySHA256: v.BodySHA256})
}

func TestTheFullLifecycle(t *testing.T) {
	s := NewMemStore()
	d := newDoc(t, s, tA, alice, "dr", drBody)
	if v, ok := d.Open(); !ok || v.State != StateDraft || v.Version != 1 {
		t.Fatalf("a new fact must start as a draft: %+v", d.Versions)
	}
	facts, _ := s.ActiveFacts(context.Background(), tA)
	if len(facts) != 0 {
		t.Fatal("a draft must never be active")
	}
	d = activate(t, s, tA, d.ID, alice, bob)
	a, ok := d.Active()
	if !ok || a.Approver != bob || a.Author != alice || a.ActivatedBy != bob || a.DecidedAt == nil {
		t.Fatalf("approved: %+v", a)
	}
	// Edit → v2 draft; v1 stays active until v2 is approved.
	d = do(t, s, tA, d.ID, Op{Kind: OpDraft, Actor: carol, Body: drBody + " Updated."})
	if a, _ := d.Active(); a.Version != 1 {
		t.Fatal("an open draft must not displace the active version")
	}
	d = activate(t, s, tA, d.ID, carol, alice)
	if a, _ := d.Active(); a.Version != 2 || d.Versions[0].State != StateSuperseded {
		t.Fatalf("v2 should be active and v1 superseded: %+v", d.Versions)
	}
	// Rollback to v1 by ONE admin: a new version that keeps v1's two people.
	d = do(t, s, tA, d.ID, Op{Kind: OpRollback, Actor: carol, ToVersion: 1, Reason: "v2 was wrong"})
	a, _ = d.Active()
	if a.Version != 3 || a.Body != drBody || a.Author != alice || a.Approver != bob || a.ActivatedBy != carol || a.RestoredFrom != 1 {
		t.Fatalf("rollback: %+v", a)
	}
	// Retire: nothing active; history kept.
	d = do(t, s, tA, d.ID, Op{Kind: OpRetire, Actor: bob, Reason: "site decommissioned"})
	if _, ok := d.Active(); ok || len(d.Versions) != 3 {
		t.Fatalf("retire: %+v", d.Versions)
	}
	if facts, _ := s.ActiveFacts(context.Background(), tA); len(facts) != 0 {
		t.Fatal("a retired fact must leave the prompt")
	}
}

func TestNobodyApprovesTheirOwnText(t *testing.T) {
	s := NewMemStore()
	d := newDoc(t, s, tA, alice, "dr", drBody)
	d = do(t, s, tA, d.ID, Op{Kind: OpSubmit, Actor: alice})
	v, _ := d.Open()
	for _, k := range []OpKind{OpApprove, OpReject} {
		_, err := s.Do(context.Background(), tA, d.ID, Op{Kind: k, Actor: alice, Version: v.Version, BodySHA256: v.BodySHA256, Reason: "x"})
		if !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("%s by the author: %v, want ErrSelfApproval", k, err)
		}
	}
	// Rollback cannot launder new text past review: only an APPROVED version
	// can come back, and a pending one never was.
	if _, err := s.Do(context.Background(), tA, d.ID, Op{Kind: OpRollback, Actor: alice, ToVersion: v.Version}); !errors.Is(err, ErrWrongState) {
		t.Fatalf("rollback to an unapproved version: %v", err)
	}
}

func TestApprovalBindsToTheReviewedText(t *testing.T) {
	s := NewMemStore()
	d := newDoc(t, s, tA, alice, "dr", drBody)
	d = do(t, s, tA, d.ID, Op{Kind: OpSubmit, Actor: alice})
	v, _ := d.Open()
	if _, err := s.Do(context.Background(), tA, d.ID, Op{Kind: OpApprove, Actor: bob, Version: v.Version, BodySHA256: BodySHA256("other")}); !errors.Is(err, ErrStale) {
		t.Fatalf("approve with the wrong hash: %v", err)
	}
	if _, err := s.Do(context.Background(), tA, d.ID, Op{Kind: OpApprove, Actor: bob, Version: v.Version + 1, BodySHA256: v.BodySHA256}); !errors.Is(err, ErrWrongState) {
		t.Fatalf("approve the wrong version: %v", err)
	}
	// Withdrawn and edited after review: the old hash no longer approves it.
	do(t, s, tA, d.ID, Op{Kind: OpWithdraw, Actor: alice})
	do(t, s, tA, d.ID, Op{Kind: OpDraft, Actor: alice, Body: drBody + " (changed)"})
	do(t, s, tA, d.ID, Op{Kind: OpSubmit, Actor: alice})
	if _, err := s.Do(context.Background(), tA, d.ID, Op{Kind: OpApprove, Actor: bob, Version: v.Version, BodySHA256: v.BodySHA256}); !errors.Is(err, ErrStale) {
		t.Fatalf("approve a changed text with the old hash: %v", err)
	}
}

func TestOnlyTheAuthorChangesADraft(t *testing.T) {
	s := NewMemStore()
	d := newDoc(t, s, tA, alice, "dr", drBody)
	for _, op := range []Op{{Kind: OpDraft, Body: "x"}, {Kind: OpDiscard}, {Kind: OpSubmit}} {
		op.Actor = bob
		if _, err := s.Do(context.Background(), tA, d.ID, op); !errors.Is(err, ErrNotAuthor) {
			t.Errorf("%s by another person: %v", op.Kind, err)
		}
	}
	// Discarding the only version removes the fact.
	do(t, s, tA, d.ID, Op{Kind: OpDiscard, Actor: alice})
	if _, err := s.Get(context.Background(), tA, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a fact with no versions left should be gone: %v", err)
	}
}

func TestRejectAndRetireNeedAReason(t *testing.T) {
	s := NewMemStore()
	d := newDoc(t, s, tA, alice, "dr", drBody)
	d = do(t, s, tA, d.ID, Op{Kind: OpSubmit, Actor: alice})
	if _, err := s.Do(context.Background(), tA, d.ID, Op{Kind: OpReject, Actor: bob, Version: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reject without a reason: %v", err)
	}
	d = do(t, s, tA, d.ID, Op{Kind: OpReject, Actor: bob, Version: 1, Reason: "too vague"})
	if d.Versions[0].State != StateRejected || d.Versions[0].DecidedBy != bob || d.Versions[0].Approver != "" {
		t.Fatalf("reject: %+v", d.Versions[0])
	}
	// A rejected version is closed; a new draft is version 2.
	d = do(t, s, tA, d.ID, Op{Kind: OpDraft, Actor: alice, Body: drBody})
	if v, _ := d.Open(); v.Version != 2 {
		t.Fatalf("new draft after a rejection: %+v", d.Versions)
	}
	d = activate(t, s, tA, d.ID, alice, bob)
	if _, err := s.Do(context.Background(), tA, d.ID, Op{Kind: OpRetire, Actor: bob}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("retire without a reason: %v", err)
	}
}

func TestLimits(t *testing.T) {
	s := NewMemStore()
	for i := 0; i < MaxDocsPerTenant; i++ {
		newDoc(t, s, tA, alice, fmt.Sprintf("k%d", i), drBody)
	}
	if _, err := s.Create(context.Background(), tA, alice, NewDoc{Scope: ScopeTenant, Kind: KindTopologyNote, Key: "one-more", Body: drBody}); !errors.Is(err, ErrFull) {
		t.Fatalf("doc %d: %v", MaxDocsPerTenant+1, err)
	}
	// The cap is per tenant.
	newDoc(t, s, tB, alice, "k0", drBody)
	// Same (scope, kind, key) twice is a conflict, not a second fact.
	s2 := NewMemStore()
	newDoc(t, s2, tA, alice, "dr", drBody)
	if _, err := s2.Create(context.Background(), tA, bob, NewDoc{Scope: ScopeTenant, Kind: KindTopologyNote, Key: "dr", Body: "x"}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	// Body cap in BYTES: 2000 multi-byte-safe passes, 2001 fails.
	if err := checkNew(tA, alice, NewDoc{Scope: ScopeTenant, Kind: KindTerminology, Key: "k", Body: strings.Repeat("é", MaxBodyBytes/2)}); err != nil {
		t.Fatalf("2000 bytes: %v", err)
	}
	if err := checkNew(tA, alice, NewDoc{Scope: ScopeTenant, Kind: KindTerminology, Key: "k", Body: strings.Repeat("é", MaxBodyBytes/2) + "a"}); err == nil {
		t.Fatal("2001 bytes must be refused")
	}
	// Version cap: a document stops at MaxVersionsPerDoc.
	s3 := NewMemStore()
	d := newDoc(t, s3, tA, alice, "v", drBody)
	for i := 1; i < MaxVersionsPerDoc; i++ {
		do(t, s3, tA, d.ID, Op{Kind: OpSubmit, Actor: alice})
		do(t, s3, tA, d.ID, Op{Kind: OpReject, Actor: bob, Version: i, Reason: "no"})
		do(t, s3, tA, d.ID, Op{Kind: OpDraft, Actor: alice, Body: drBody})
	}
	do(t, s3, tA, d.ID, Op{Kind: OpSubmit, Actor: alice})
	do(t, s3, tA, d.ID, Op{Kind: OpReject, Actor: bob, Version: MaxVersionsPerDoc, Reason: "no"})
	if _, err := s3.Do(context.Background(), tA, d.ID, Op{Kind: OpDraft, Actor: alice, Body: drBody}); !errors.Is(err, ErrFull) {
		t.Fatalf("version %d: %v", MaxVersionsPerDoc+1, err)
	}
}

// §3a at the store: another tenant's id is ErrNotFound for every verb, and a
// tenant's facts are never in another tenant's list or prompt.
func TestStoreTenantIsolation(t *testing.T) {
	s := NewMemStore()
	d := newDoc(t, s, tA, alice, "dr", drBody)
	activate(t, s, tA, d.ID, alice, bob)
	if _, err := s.Get(context.Background(), tB, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	for _, k := range []OpKind{OpDraft, OpDiscard, OpSubmit, OpWithdraw, OpApprove, OpReject, OpRollback, OpRetire} {
		if _, err := s.Do(context.Background(), tB, d.ID, Op{Kind: k, Actor: carol, Body: "x", Version: 1, ToVersion: 1, Reason: "r"}); !errors.Is(err, ErrNotFound) {
			t.Errorf("cross-tenant %s: %v", k, err)
		}
	}
	if l, _ := s.List(context.Background(), tB); len(l) != 0 {
		t.Fatal("tenant B listed tenant A's fact")
	}
	if f, _ := s.ActiveFacts(context.Background(), tB); len(f) != 0 {
		t.Fatal("tenant B's prompt would carry tenant A's fact")
	}
	if f, _ := s.ActiveFacts(context.Background(), tA); len(f) != 1 {
		t.Fatal("tenant A lost its own fact")
	}
}

// Concurrent approvals of one pending version: exactly one wins.
func TestConcurrentApprovalsActivateOnce(t *testing.T) {
	s := NewMemStore()
	d := newDoc(t, s, tA, alice, "dr", drBody)
	d = do(t, s, tA, d.ID, Op{Kind: OpSubmit, Actor: alice})
	v, _ := d.Open()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for _, who := range []string{bob, carol, "u-dan", "u-eve"} {
		wg.Add(1)
		go func(who string) {
			defer wg.Done()
			if _, err := s.Do(context.Background(), tA, d.ID, Op{Kind: OpApprove, Actor: who, Version: v.Version, BodySHA256: v.BodySHA256}); err == nil {
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

func TestFactsRenderInADeterministicOrder(t *testing.T) {
	fs := []Fact{
		{Scope: "site:b", Kind: KindTerminology, Key: "z"},
		{Scope: ScopeTenant, Kind: KindTerminology, Key: "b"},
		{Scope: "site:a", Kind: KindTopologyNote, Key: "y"},
		{Scope: ScopeTenant, Kind: KindTopologyNote, Key: "c"},
		{Scope: ScopeTenant, Kind: KindTopologyNote, Key: "a"},
	}
	SortFacts(fs)
	var got []string
	for _, f := range fs {
		got = append(got, f.Scope+"/"+f.Key)
	}
	want := "tenant/a tenant/c tenant/b site:a/y site:b/z"
	if strings.Join(got, " ") != want {
		t.Fatalf("order %v, want %s", got, want)
	}
}

func TestScopeAndKind(t *testing.T) {
	for s, ok := range map[string]bool{"tenant": true, "site:dfw-hq": true, "site:": false, "site:DFW": false, "platform": false, "site:a b": false} {
		if ValidScope(s) != ok {
			t.Errorf("ValidScope(%q) = %v", s, !ok)
		}
	}
	if len(Kinds()) != 9 {
		t.Fatalf("the plan fixes 9 kinds, got %d", len(Kinds()))
	}
	for _, k := range Kinds() {
		if Label(k) == "" {
			t.Errorf("kind %s has no label", k)
		}
	}
	if ValidKind("system_prompt") {
		t.Fatal("the vocabulary is closed")
	}
}
