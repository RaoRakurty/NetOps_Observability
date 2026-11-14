// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

// active_test.go — what reaches Iris and how it stays proven (active.go).

import (
	"context"
	"errors"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/orgcontext"
)

func list(t *testing.T, s Store, tenant string) []Runbook {
	t.Helper()
	rs, err := s.List(context.Background(), tenant)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	return rs
}

func TestOnlyApprovedProvenInvestigativeRunbooksRun(t *testing.T) {
	h := newFake()
	s := newMem(h)
	draft := create(t, s, tA, alice, named("acme-draft-only"))
	pending := create(t, s, tA, alice, named("acme-pending"))
	do(t, s, tA, pending.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	active := create(t, s, tA, alice, good())
	activate(t, s, tA, active.ID, alice, bob)
	m := create(t, s, tA, alice, mop())
	activate(t, s, tA, m.ID, alice, bob)

	skills, skipped := ActiveSkills(tA, list(t, s, tA), h.Fingerprint(), ai.ToolNames())
	if len(skills) != 1 || skills[0].Name != goodName {
		t.Fatalf("only the approved investigative runbook may run, got %v", names(skills))
	}
	if skills[0].TenantID != tA || skills[0].Origin != ai.SkillOriginTenant {
		t.Fatalf("a runnable runbook is stamped with its own tenant and tenant origin: %+v", skills[0])
	}
	if len(skipped) != 0 {
		t.Fatalf("nothing was stale, got %v", skipped)
	}
	_ = draft
}

func TestAPlatformChangeStopsARunbookUntilItsCasesPassAgain(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	activate(t, s, tA, r.ID, alice, bob)

	h.set(func(f *fakeHarness) { f.fp = "fp-2" }) // a model, prompt or tool change
	skills, skipped := ActiveSkills(tA, list(t, s, tA), h.Fingerprint(), ai.ToolNames())
	if len(skills) != 0 || len(skipped) != 1 || skipped[0].Reason != "stale_cases" {
		t.Fatalf("a stale stamp must keep the runbook out and say so: skills=%v skipped=%v", names(skills), skipped)
	}

	// Re-proving the SAME approved text restores it: no second person, no new version.
	before := h.count()
	res, err := s.Reprove(context.Background(), tA, r.ID, carol)
	if err != nil || !res.Passed || res.AlreadyOK || res.Fingerprint != "fp-2" {
		t.Fatalf("reprove: %+v %v", res, err)
	}
	if h.count() != before+1 {
		t.Fatal("reprove must run the cases exactly once")
	}
	got := list(t, s, tA)[0]
	if len(got.Versions) != 1 {
		t.Fatalf("reprove must not create a version: %d", len(got.Versions))
	}
	if skills, _ := ActiveSkills(tA, list(t, s, tA), h.Fingerprint(), ai.ToolNames()); len(skills) != 1 {
		t.Fatal("after a passing reprove the runbook runs again")
	}

	// A second reprove under the same fingerprint changes nothing and runs nothing.
	res, err = s.Reprove(context.Background(), tA, r.ID, carol)
	if err != nil || !res.AlreadyOK || h.count() != before+1 {
		t.Fatalf("a current stamp is not re-run: %+v %v calls=%d", res, err, h.count())
	}
}

func TestAFailedReproveRecordsTheFailureAndKeepsTheRunbookOut(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	activate(t, s, tA, r.ID, alice, bob)
	h.set(func(f *fakeHarness) { f.fp = "fp-2"; f.fail = true })

	res, err := s.Reprove(context.Background(), tA, r.ID, carol)
	if err != nil || res.Passed || len(res.Problems) == 0 {
		t.Fatalf("a failing reprove is a result with problems, not an error: %+v %v", res, err)
	}
	got := list(t, s, tA)[0]
	v, _ := got.Active()
	if v.State != orgcontext.StateActive {
		t.Fatal("a failed reprove must not change the approval")
	}
	if !got.Harness[v.Version].Passed || got.Harness[v.Version].Fingerprint != "fp-1" {
		t.Fatal("the frozen proof the reviewers approved is never overwritten")
	}
	if st, ok := got.Recheck[v.Version]["fp-2"]; !ok || st.Passed {
		t.Fatalf("the failed re-check is recorded beside it, under the new fingerprint: %+v", got.Recheck)
	}
	if skills, _ := ActiveSkills(tA, list(t, s, tA), h.Fingerprint(), ai.ToolNames()); len(skills) != 0 {
		t.Fatal("a runbook whose cases failed must not run")
	}
}

func TestReproveRefusesNothingApprovedAndForeignIDs(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	if _, err := s.Reprove(context.Background(), tA, r.ID, carol); !errors.Is(err, ErrNothingActive) {
		t.Fatalf("a draft has nothing approved to re-check: %v", err)
	}
	activate(t, s, tA, r.ID, alice, bob)
	if _, err := s.Reprove(context.Background(), tB, r.ID, carol); !errors.Is(err, orgcontext.ErrNotFound) {
		t.Fatalf("another tenant's runbook is not found: %v", err)
	}
}

func TestActiveSkillsNeverStampsAnotherTenantsRow(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	activate(t, s, tA, r.ID, alice, bob)
	rows := list(t, s, tA)
	if skills, _ := ActiveSkills(tB, rows, h.Fingerprint(), ai.ToolNames()); len(skills) != 0 {
		t.Fatalf("CROSS-TENANT: tenant A's runbook was stamped for tenant B: %v", names(skills))
	}
	if skills, _ := ActiveSkills(tA, rows, "", ai.ToolNames()); len(skills) != 0 {
		t.Fatal("with no current fingerprint nothing is proven, so nothing runs")
	}
}

func TestOverlayJoinsTheCompiledSetForOneTenant(t *testing.T) {
	h := newFake()
	s := newMem(h)
	r := create(t, s, tA, alice, good())
	activate(t, s, tA, r.ID, alice, bob)
	skills, _ := ActiveSkills(tA, list(t, s, tA), h.Fingerprint(), ai.ToolNames())
	base, err := ai.LoadSkills()
	if err != nil {
		t.Fatal(err)
	}
	set, err := base.Overlay(skills)
	if err != nil {
		t.Fatalf("an approved, proven runbook must join the compiled set: %v", err)
	}
	if _, ok := set.Get(goodName); !ok {
		t.Fatal("the runbook is in the tenant's set")
	}
	if _, ok := base.Get(goodName); ok {
		t.Fatal("the compiled set itself is never changed")
	}
}

func TestOverlayCache(t *testing.T) {
	var c OverlayCache
	set := &ai.SkillSet{}
	now := time.Now()
	c.Put(tA, "fp-1", set, now)
	if got, ok := c.Get(tA, "fp-1", now); !ok || got != set {
		t.Fatal("a fresh entry is returned")
	}
	if _, ok := c.Get(tB, "fp-1", now); ok {
		t.Fatal("CROSS-TENANT: one tenant's set served to another")
	}
	if _, ok := c.Get(tA, "fp-2", now); ok {
		t.Fatal("a moved fingerprint misses")
	}
	if _, ok := c.Get(tA, "fp-1", now.Add(overlayTTL+time.Second)); ok {
		t.Fatal("an entry past its TTL misses")
	}
	c.Invalidate(tA)
	if _, ok := c.Get(tA, "fp-1", now); ok {
		t.Fatal("an invalidated tenant misses")
	}
	var nilCache *OverlayCache
	nilCache.Put(tA, "x", set, now)
	if _, ok := nilCache.Get(tA, "x", now); ok {
		t.Fatal("a nil cache is a no-op")
	}
}

func names(sks []*ai.Skill) []string {
	out := make([]string, 0, len(sks))
	for _, s := range sks {
		out = append(out, s.Name)
	}
	return out
}
