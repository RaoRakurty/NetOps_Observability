// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package timeintel

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A grounded incident: onset → correlation completed, evidence ready, ISP-owned.
func backfillFacts() CorrTimeFacts {
	base := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	return CorrTimeFacts{
		WindowStart:     base,
		CreatedAt:       base.Add(90 * time.Second),
		VerdictTier:     "suspected",
		Owner:           "isp",
		EvidenceMissing: false,
		Confidence:      0.8,
	}
}

func TestDeriveIncidentTimeMetricRow(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 30, 0, 0, time.UTC)
	facts := backfillFacts()
	group := map[string]string{"provider": "isp", "device": "wan-r2"}

	row := DeriveMetricRow("ACME", "corr-1", "ti-1", facts, group, "DIA", "OPEN", true, now)

	if !row.Maintenance {
		t.Errorf("maintenance stamp must survive derivation: %+v", row)
	}

	if row.TenantID != "acme" { // normalized
		t.Errorf("tenant not normalized: %q", row.TenantID)
	}
	if row.CorrelationID != "corr-1" || row.CalcVersion != "ti-1" {
		t.Errorf("identity wrong: %+v", row)
	}
	if row.SeamType != "DIA" {
		t.Errorf("seam_type = %q, want DIA", row.SeamType)
	}
	if !row.OccurredAt.Equal(facts.WindowStart) {
		t.Errorf("occurred_at = %v, want %v", row.OccurredAt, facts.WindowStart)
	}
	if len(row.Metrics) == 0 {
		t.Error("expected computed phase metrics, got none")
	}
	// The persisted derivation must equal the live derivation (no engine change).
	wantDomain, _ := ClassifyOwnerDomain(facts.Owner, group)
	if row.OwnerDomain != string(wantDomain) {
		t.Errorf("owner_domain = %q, want %q (must match live classification)", row.OwnerDomain, wantDomain)
	}
	if row.Bottleneck == "" {
		t.Error("expected a current-bottleneck driver")
	}
	// Rollup-source fields (migration 0027): the snapshot must carry everything
	// the reliability rollups need to read it instead of a live scan.
	if row.Owner != "isp" {
		t.Errorf("owner = %q, want isp", row.Owner)
	}
	if row.State != "open" { // normalized lowercase
		t.Errorf("state = %q, want open", row.State)
	}
	_, wantInternal := ClassifyOwnerDomain(facts.Owner, group)
	if row.Internal != wantInternal {
		t.Errorf("internal = %v, want %v (must match live classification)", row.Internal, wantInternal)
	}
	if row.Group["device"] != "wan-r2" || row.Group["provider"] != "isp" {
		t.Errorf("group keys not persisted: %+v", row.Group)
	}
	// Snapshot is JSON-serializable and never leaks the tenant id.
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(b); strings.Contains(got, "acme") {
		t.Errorf("serialized row must not carry tenant id: %s", got)
	}
}

func TestMemIncidentTimeMetricsIsolation(t *testing.T) {
	m := NewMemMetricsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	mk := func(tenant, corr string, ts time.Time) MetricRow {
		return MetricRow{TenantID: tenant, CorrelationID: corr, CalcVersion: "ti-1", OccurredAt: ts}
	}
	_ = m.Upsert(ctx, mk("acme", "c1", now.Add(-2*time.Hour)))
	_ = m.Upsert(ctx, mk("acme", "c2", now.Add(-1*time.Hour)))
	_ = m.Upsert(ctx, mk("globex", "c3", now))

	// Default-closed: a tenant sees ONLY its own snapshots.
	acme, _ := m.List(ctx, "acme", false, 0)
	if len(acme) != 2 {
		t.Fatalf("acme should see 2 own rows, got %d", len(acme))
	}
	for _, r := range acme {
		if r.TenantID != "acme" {
			t.Fatalf("cross-tenant leak: acme saw %q", r.TenantID)
		}
	}
	// Newest-first ordering.
	if acme[0].CorrelationID != "c2" {
		t.Errorf("expected newest (c2) first, got %q", acme[0].CorrelationID)
	}
	globex, _ := m.List(ctx, "globex", false, 0)
	if len(globex) != 1 || globex[0].CorrelationID != "c3" {
		t.Fatalf("globex isolation wrong: %+v", globex)
	}
	// Cross-tenant (platform) sees everything.
	all, _ := m.List(ctx, "", true, 0)
	if len(all) != 3 {
		t.Fatalf("cross view should see 3, got %d", len(all))
	}
	// Idempotent upsert: re-writing the same PK doesn't duplicate.
	_ = m.Upsert(ctx, mk("acme", "c1", now))
	if acme2, _ := m.List(ctx, "acme", false, 0); len(acme2) != 2 {
		t.Fatalf("upsert must be idempotent on PK, got %d rows", len(acme2))
	}
}

// TestDeriveMetricRowClosedObjectCarriesRecovery is the snapshot half of the v2
// mapping: the row the backfill persists (and the rollups read) must carry a
// COMPLETE ttr_recovery for a closed object, so /api/reliability/rollups can
// report recovery p50/p90 with no ITSM workflow linked at all.
func TestDeriveMetricRowClosedObjectCarriesRecovery(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 30, 0, 0, time.UTC)
	facts := backfillFacts()
	facts.WindowEnd = facts.WindowStart.Add(6 * time.Minute)
	group := map[string]string{"provider": "isp", "device": "wan-r2"}

	row := DeriveMetricRow("acme", "corr-closed", "ti-1", facts, group, "DIA", "CLOSED", false, now)
	if row.State != "closed" {
		t.Fatalf("state must be normalized onto the row: %q", row.State)
	}
	var ttr TimeMetric
	for _, m := range row.Metrics {
		if m.Name == MetricTTRRecovery {
			ttr = m
		}
	}
	if !ttr.Complete {
		t.Fatalf("a closed object's snapshot must carry a complete ttr_recovery: %+v", ttr)
	}
	if ttr.DurationMs != int64(6*time.Minute/time.Millisecond) {
		t.Fatalf("ttr_recovery = %d ms, want 360000 (window_start → window_end)", ttr.DurationMs)
	}
	if !ttr.IsInferred {
		t.Fatal("an engine-proxied recovery must stay flagged is_inferred in the snapshot")
	}
	if row.Bottleneck == string(DriverWorkflow) {
		t.Fatalf("a recovered incident must not persist the workflow_not_connected driver: %q", row.Bottleneck)
	}

	// The caller cannot desync the two: `state` is the single source, so an OPEN
	// object derived from the same facts still yields no recovery.
	open := DeriveMetricRow("acme", "corr-open", "ti-1", facts, group, "DIA", "open", false, now)
	for _, m := range open.Metrics {
		if m.Name == MetricTTRRecovery && m.Complete {
			t.Fatal("an OPEN object must never persist a complete ttr_recovery")
		}
	}
	// …and a MERGED one never recovers either (it folds into its parent).
	merged := DeriveMetricRow("acme", "corr-merged", "ti-1", facts, group, "DIA", "merged", false, now)
	for _, m := range merged.Metrics {
		if m.Name == MetricTTRRecovery && m.Complete {
			t.Fatal("a MERGED object must never persist a complete ttr_recovery")
		}
	}
}

// TestRollupSurfacesInferredRecoveryPercentiles closes the loop the NOC scorecard
// reads: many closed objects → a ttr_recovery MetricStat with real p50/p90, which
// is exactly what flips the scorecard's `coverage.recovery` chip to "connected".
func TestRollupSurfacesInferredRecoveryPercentiles(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 30, 0, 0, time.UTC)
	var incs []IncidentSummary
	for i := 1; i <= 4; i++ {
		facts := backfillFacts()
		facts.WindowStart = facts.WindowStart.Add(time.Duration(i) * time.Hour)
		facts.CreatedAt = facts.WindowStart.Add(90 * time.Second)
		facts.WindowEnd = facts.WindowStart.Add(time.Duration(i) * time.Minute)
		row := DeriveMetricRow("acme", "c"+strconv.Itoa(i), "ti-1", facts,
			map[string]string{"device": "wan-r2"}, "DIA", "closed", false, now)
		incs = append(incs, SummariesFromSnapshots([]MetricRow{row}, Filters{}, false)...)
	}
	ro := Rollup(incs)
	st, ok := ro.Metrics[MetricTTRRecovery]
	if !ok {
		t.Fatal("rollup must carry ttr_recovery stats once objects close — this is the scorecard's coverage.recovery gate")
	}
	if st.Count != 4 {
		t.Fatalf("ttr_recovery incident_count = %d, want 4", st.Count)
	}
	if st.P50ms != int64(2*time.Minute/time.Millisecond) || st.P90ms != int64(4*time.Minute/time.Millisecond) {
		t.Fatalf("ttr_recovery percentiles wrong: p50=%d p90=%d", st.P50ms, st.P90ms)
	}
	if ro.TopTimeLossPhase == DriverWorkflow {
		t.Fatal("top time-loss phase must no longer be workflow_not_connected once recovery is derivable")
	}
}
