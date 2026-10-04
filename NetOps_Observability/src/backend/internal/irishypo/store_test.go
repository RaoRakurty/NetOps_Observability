// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irishypo

// store_test.go — the per-tenant hypothesis store (CLAUDE.md §3a).

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func testSet(id string) Set {
	return Set{ID: id, Notice: Notice, Engine: NewEngine("", "", ""), Hypotheses: []Hypothesis{{
		ID: "link-down", Statement: "The interface in scope is down", State: Supported,
		Evidence:    []string{"state:interfaces:dev:1"},
		Transitions: []Transition{{To: Proposed, Round: 1, Reason: "r"}},
	}}}
}

const (
	idA = "11111111-1111-4111-8111-111111111111"
	idB = "22222222-2222-4222-8222-222222222222"
)

func TestStoreIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	if err := s.Put(ctx, "t-a", testSet(idA)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "T-B ", testSet(idB)); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, "t-a", false, idA); err != nil || got.ID != idA {
		t.Fatalf("own read: %v %+v", err, got)
	}
	// Another tenant's id is indistinguishable from one that never existed.
	if _, err := s.Get(ctx, "t-a", false, idB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read: %v, want ErrNotFound", err)
	}
	if _, err := s.Get(ctx, "t-b", false, idA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read: %v, want ErrNotFound", err)
	}
	if _, err := s.Get(ctx, "t-b", false, idB); err != nil {
		t.Fatalf("tenant is normalised: %v", err)
	}
	// Only the platform owner's cross scope reads across tenants.
	if _, err := s.Get(ctx, "*", true, idB); err != nil {
		t.Fatalf("cross read: %v", err)
	}
}

func TestStoreRefusesInvalidInput(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	for _, c := range []struct {
		tenant string
		set    Set
	}{
		{"", testSet(idA)},
		{"t-a", testSet("not-a-uuid")},
		{"t-a", testSet("11111111-1111-4111-8111-11111111111A")}, // uppercase
		{"t-a", Set{ID: idA, Hypotheses: make([]Hypothesis, MaxHypotheses+1)}},
	} {
		if err := s.Put(ctx, c.tenant, c.set); !errors.Is(err, ErrInvalid) {
			t.Errorf("Put(%q, %q) = %v, want ErrInvalid", c.tenant, c.set.ID, err)
		}
	}
	if _, err := s.Get(ctx, "t-a", false, "../../etc"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a malformed id is a plain not-found: %v", err)
	}
}

func TestStoreExpiresAndIsBounded(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if err := s.Put(ctx, "t-a", testSet(idA)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(TTL + time.Minute)
	if _, err := s.Get(ctx, "t-a", false, idA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired set must be gone: %v", err)
	}
	for i := 0; i < MaxPerTenant+3; i++ {
		id := fmt.Sprintf("%08x-0000-4000-8000-000000000000", i)
		if err := s.Put(ctx, "t-a", testSet(id)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.byTen["t-a"]); n != MaxPerTenant {
		t.Fatalf("held %d, bound is %d", n, MaxPerTenant)
	}
	if _, err := s.Get(ctx, "t-a", false, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Error("the oldest set must be evicted first")
	}
}

func TestStoreCopiesInAndOut(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	in := testSet(idA)
	if err := s.Put(ctx, "t-a", in); err != nil {
		t.Fatal(err)
	}
	in.Hypotheses[0].Evidence[0] = "tampered"
	out, err := s.Get(ctx, "t-a", false, idA)
	if err != nil {
		t.Fatal(err)
	}
	if out.Hypotheses[0].Evidence[0] != "state:interfaces:dev:1" {
		t.Fatal("the store must not share slices with the writer")
	}
	out.Hypotheses[0].Transitions[0].Reason = "tampered"
	again, _ := s.Get(ctx, "t-a", false, idA)
	if again.Hypotheses[0].Transitions[0].Reason != "r" {
		t.Fatal("the store must not share slices with a reader")
	}
	// A re-put of the same id replaces, never duplicates.
	if err := s.Put(ctx, "t-a", testSet(idA)); err != nil {
		t.Fatal(err)
	}
	if n := len(s.byTen["t-a"]); n != 1 {
		t.Fatalf("re-put duplicated: %d", n)
	}
}
