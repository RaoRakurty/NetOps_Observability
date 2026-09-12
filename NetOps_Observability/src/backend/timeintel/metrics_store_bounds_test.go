// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package timeintel

// metrics_store_bounds_test.go — §9 bound proof for the in-memory metrics
// store (storm-s08 regression, 2026-09-01: the backfill catch-up folded 260k
// snapshot rows into an unbounded map and drove the api to 100% of its memory
// cap). These tests are the mutants' executioner: remove the eviction in
// MemMetricsStore.Upsert/compactLocked and the bounded-fold test fails on the
// raw map size.

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func synthRow(tenant string, i int, occurred time.Time) MetricRow {
	return MetricRow{
		TenantID:      tenant,
		CorrelationID: "corr-" + strconv.Itoa(i),
		CalcVersion:   "ti-1",
		OccurredAt:    occurred,
		OwnerDomain:   "provider",
		Owner:         "isp",
		State:         "closed",
		Group:         map[string]string{"device": "wan-r1", "provider": "isp"},
	}
}

// TestMemMetricsStoreBoundedUnderBackfillFold folds 100k synthetic rows —
// the storm-s08 catch-up shape (one tenant, occurred_at ascending, unique
// correlation ids) — and asserts the store stays bounded, the OLD rows are the
// ones evicted, and reads inside the consumer window remain correct.
func TestMemMetricsStoreBoundedUnderBackfillFold(t *testing.T) {
	const folded = 100_000
	m := NewMemMetricsStore()
	ctx := context.Background()
	now := time.Now().UTC()
	base := now.Add(-folded * time.Second) // oldest row ~28h ago, inside retention

	for i := 0; i < folded; i++ {
		if err := m.Upsert(ctx, synthRow("acme", i, base.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}

	// THE bound (the mutant assertion): resident rows may never exceed
	// cap + compaction hysteresis, no matter how many rows are folded.
	if got, max := len(m.by), MemRowCapPerTenant+memCompactSlack; got > max {
		t.Fatalf("store unbounded: %d resident rows after folding %d (max %d)", got, folded, max)
	}
	if m.perTenant["acme"] != len(m.by) {
		t.Fatalf("per-tenant accounting drifted: perTenant=%d, resident=%d", m.perTenant["acme"], len(m.by))
	}
	if m.Evicted() == 0 {
		t.Fatal("expected evictions folding 5x the cap, got none")
	}
	if int(m.Evicted())+len(m.by) != folded {
		t.Fatalf("rows leaked: evicted %d + resident %d != folded %d", m.Evicted(), len(m.by), folded)
	}

	// Old rows are the evicted ones; the newest cap-worth survives entirely.
	if _, ok := m.by[m.key("acme", "corr-0", "ti-1")]; ok {
		t.Error("oldest row survived eviction — compaction is not dropping oldest-first")
	}
	for _, i := range []int{folded - 1, folded - MemRowCapPerTenant} {
		if _, ok := m.by[m.key("acme", "corr-"+strconv.Itoa(i), "ti-1")]; !ok {
			t.Errorf("row corr-%d is inside the newest cap-worth and must survive", i)
		}
	}

	// Reads inside the consumer window stay correct: newest first, own rows
	// only, every returned row inside the window.
	since := base.Add((folded - 5000) * time.Second)
	rows, err := m.ListWindow(ctx, "acme", false, since, "ti-1", SnapshotCap)
	if err != nil {
		t.Fatalf("ListWindow: %v", err)
	}
	if len(rows) != 5000 {
		t.Fatalf("window read returned %d rows, want 5000", len(rows))
	}
	if rows[0].CorrelationID != "corr-"+strconv.Itoa(folded-1) {
		t.Errorf("newest-first violated: first row %q", rows[0].CorrelationID)
	}
	for _, r := range rows {
		if r.OccurredAt.Before(since) {
			t.Fatalf("row %q outside the requested window", r.CorrelationID)
		}
	}
	if got, _ := m.List(ctx, "acme", false, 500); len(got) != 500 {
		t.Fatalf("List limit not honored after eviction: %d", len(got))
	}
}

// TestMemMetricsStoreUpsertStaysIdempotentUnderBound re-folds the same page
// (the backfill's re-scan phase) and asserts the PK overwrite neither grows
// the count nor triggers spurious eviction.
func TestMemMetricsStoreUpsertStaysIdempotentUnderBound(t *testing.T) {
	m := NewMemMetricsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	const rows = 2000 // one backfill page, under cap+slack
	for pass := 0; pass < 3; pass++ {
		for i := 0; i < rows; i++ {
			if err := m.Upsert(ctx, synthRow("acme", i, now.Add(time.Duration(i)*time.Second))); err != nil {
				t.Fatalf("pass %d upsert %d: %v", pass, i, err)
			}
		}
	}
	if len(m.by) != rows {
		t.Fatalf("idempotency broken: %d resident after re-folding %d rows 3x", len(m.by), rows)
	}
	if m.perTenant["acme"] != rows {
		t.Fatalf("per-tenant count drifted on overwrite: %d", m.perTenant["acme"])
	}
	if m.Evicted() != 0 {
		t.Fatalf("overwrites must not evict: evicted=%d", m.Evicted())
	}
}

// TestMemMetricsStoreRetentionEvictsUnreadableRowsFirst pins the compaction
// order: rows older than the retention window (unreadable through every
// consumer surface) are dropped before any readable row is.
func TestMemMetricsStoreRetentionEvictsUnreadableRowsFirst(t *testing.T) {
	m := NewMemMetricsStore()
	m.rowCap = 100
	m.retention = time.Hour
	fixed := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }
	ctx := context.Background()

	const stale, fresh = 50, 1101 // stale + fresh > cap + slack → compaction fires
	for i := 0; i < stale; i++ {
		if err := m.Upsert(ctx, synthRow("acme", i, fixed.Add(-2*time.Hour))); err != nil {
			t.Fatalf("stale upsert %d: %v", i, err)
		}
	}
	for i := 0; i < fresh; i++ {
		if err := m.Upsert(ctx, synthRow("acme", stale+i, fixed.Add(-time.Duration(fresh-i)*time.Second))); err != nil {
			t.Fatalf("fresh upsert %d: %v", i, err)
		}
	}

	// Compaction fired mid-loop (at cap+slack+1); upserts after it stay under
	// the trigger, so the guarantee is the BOUND, not an exact landing.
	if got, max := m.perTenant["acme"], m.rowCap+memCompactSlack; got > max {
		t.Fatalf("tenant not bounded: resident %d, max %d", got, max)
	}
	if m.Evicted() < stale {
		t.Fatalf("retention rows not evicted: evicted=%d, want >= %d", m.Evicted(), stale)
	}
	for i := 0; i < stale; i++ {
		if _, ok := m.by[m.key("acme", "corr-"+strconv.Itoa(i), "ti-1")]; ok {
			t.Fatalf("row corr-%d is past retention and must be evicted", i)
		}
	}
	// The newest cap-worth of FRESH rows survives.
	if _, ok := m.by[m.key("acme", "corr-"+strconv.Itoa(stale+fresh-1), "ti-1")]; !ok {
		t.Error("newest fresh row must survive compaction")
	}
}

// TestMemMetricsStoreBoundIsPerTenant pins that one tenant's overflow can
// never evict another tenant's rows (§3a: eviction must not become a
// cross-tenant side channel).
func TestMemMetricsStoreBoundIsPerTenant(t *testing.T) {
	m := NewMemMetricsStore()
	m.rowCap = 100
	ctx := context.Background()
	now := time.Now().UTC()

	const small = 10
	for i := 0; i < small; i++ {
		if err := m.Upsert(ctx, synthRow("globex", i, now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("globex upsert: %v", err)
		}
	}
	for i := 0; i < m.rowCap+memCompactSlack+500; i++ {
		if err := m.Upsert(ctx, synthRow("acme", i, now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("acme upsert: %v", err)
		}
	}

	rows, err := m.List(ctx, "globex", false, 0)
	if err != nil {
		t.Fatalf("List globex: %v", err)
	}
	if len(rows) != small {
		t.Fatalf("acme's overflow evicted globex rows: %d left, want %d", len(rows), small)
	}
	if got := m.perTenant["acme"]; got > m.rowCap+memCompactSlack {
		t.Fatalf("acme not bounded: %d resident", got)
	}
}
