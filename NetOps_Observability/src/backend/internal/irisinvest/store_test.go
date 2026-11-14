// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisinvest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"netops/backend/ai"
)

func trace(id, status string) ai.InvestigationTrace {
	return ai.InvestigationTrace{ID: id, Status: status, Target: ai.InvestigationTarget{DeviceName: "edge-1"}}
}

func id(n int) string { return fmt.Sprintf("%08x-0000-4000-8000-%012x", n, n) }

func TestStoreIsolatesTenants(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	if err := s.Put(ctx, "t-a", trace(id(1), "concluded")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "t-a", false, id(1)); err != nil {
		t.Fatalf("owner read: %v", err)
	}
	if _, err := s.Get(ctx, "t-b", false, id(1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant B read tenant A's trace: %v", err)
	}
	if _, err := s.Get(ctx, "T-A ", false, id(1)); err != nil {
		t.Fatalf("tenant names are normalized: %v", err)
	}
	if _, err := s.Get(ctx, "", true, id(1)); err != nil {
		t.Fatalf("the platform owner reads any tenant's: %v", err)
	}
	if l, _ := s.List(ctx, "t-b", false, 10); len(l) != 0 {
		t.Fatalf("tenant B lists %d of tenant A's traces", len(l))
	}
	if l, _ := s.List(ctx, "", false, 10); len(l) != 0 {
		t.Fatalf("an empty tenant lists %d traces", len(l))
	}
}

func TestStoreRefusesBadInput(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	if err := s.Put(ctx, "", trace(id(1), "x")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no tenant: %v", err)
	}
	if err := s.Put(ctx, "t-a", trace("not-a-uuid", "x")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := s.Get(ctx, "t-a", false, "../../etc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed id read: %v", err)
	}
}

func TestStoreIsBoundedAndExpires(t *testing.T) {
	s := NewMemStore()
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < MaxPerTenant+5; i++ {
		if err := s.Put(ctx, "t-a", trace(id(i+1), "concluded")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Get(ctx, "t-a", false, id(1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the oldest trace survived the cap")
	}
	if _, err := s.Get(ctx, "t-a", false, id(MaxPerTenant+5)); err != nil {
		t.Fatalf("the newest trace was dropped: %v", err)
	}
	now = now.Add(TTL + time.Minute)
	if _, err := s.Get(ctx, "t-a", false, id(MaxPerTenant+5)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired trace is still readable")
	}
}

func TestStoreListsNewestFirstAndReplacesOnRePut(t *testing.T) {
	s := NewMemStore()
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { now = now.Add(time.Second); return now }
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		if err := s.Put(ctx, "t-a", trace(id(i), "inconclusive")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Put(ctx, "t-a", trace(id(2), "concluded")); err != nil {
		t.Fatal(err)
	}
	l, err := s.List(ctx, "t-a", false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 3 || l[0].ID != id(2) || l[0].Status != "concluded" {
		t.Fatalf("list = %+v, want 3 traces, the re-put one first and replaced", l)
	}
	if l2, _ := s.List(ctx, "t-a", false, 1); len(l2) != 1 {
		t.Fatalf("limit not applied")
	}
}
