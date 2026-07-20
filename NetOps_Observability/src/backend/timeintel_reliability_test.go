package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/timeintel"
)

// timeintel_reliability_test.go — the #84 tail: reliability rollups read the
// PERSISTED incident_time_metrics snapshots (ListWindow) instead of the old
// 5000-row live ClickHouse scan. Covers: the snapshot→summary conversion (TTD
// exclusion, internal default, filters, merged children), the ListWindow store
// semantics (window, version dedupe, bound), and — CLAUDE.md §3a — that the
// rollup read is tenant-isolated (a tenant only ever aggregates its OWN rows).

func snapMetric(name timeintel.MetricName, ms int64, complete bool) timeintel.TimeMetric {
	return timeintel.TimeMetric{Name: name, Complete: complete, DurationMs: ms}
}

func snapRow(tenant, corr string, at time.Time) incidentTimeMetricRow {
	return incidentTimeMetricRow{
		TenantID: tenant, CorrelationID: corr, CalcVersion: timeIntelCalcVersion,
		OccurredAt: at, CalculatedAt: at,
		Owner: "isp", State: "open", OwnerDomain: "isp",
		Bottleneck: string(timeintel.DriverProviderRepair),
		Group:      map[string]string{"device": "wan-r2", "root_entity": "wan-r2", "provider": "isp"},
		Metrics: []timeintel.TimeMetric{
			snapMetric(timeintel.MetricTTI, 60000, true),
			snapMetric(timeintel.MetricTTD, 5000, true), // must be EXCLUDED from rollups (onset fallback)
			snapMetric(timeintel.MetricTTC, 0, false),   // incomplete → excluded
		},
	}
}

func TestSummariesFromSnapshots(t *testing.T) {
	now := time.Now().UTC()
	rows := []incidentTimeMetricRow{
		snapRow("acme", "c1", now.Add(-1*time.Hour)),
		snapRow("acme", "c2", now.Add(-2*time.Hour)),
	}
	// c2 is a merged child on another device; c3 is internal platform noise.
	rows[1].State = "merged"
	rows[1].Group = map[string]string{"device": "lan-sw1"}
	internalRow := snapRow("acme", "c3", now.Add(-3*time.Hour))
	internalRow.Internal = true
	rows = append(rows, internalRow)

	// Customer-impacting default: internal excluded.
	out := summariesFromSnapshots(rows, reliabilityFilters{}, false)
	if len(out) != 2 {
		t.Fatalf("want 2 summaries (internal excluded), got %d", len(out))
	}
	// include_internal brings it back.
	if all := summariesFromSnapshots(rows, reliabilityFilters{}, true); len(all) != 3 {
		t.Fatalf("include_internal should yield 3, got %d", len(all))
	}
	// TTD is excluded (batch path has no ingest time → onset fallback would be a
	// misleading 0); complete TTI counts; incomplete TTC never yields a duration.
	c1 := out[0]
	if c1.CorrelationID != "c1" {
		c1 = out[1]
	}
	if _, ok := c1.Durations[timeintel.MetricTTD]; ok {
		t.Error("TTD must be excluded from snapshot rollups")
	}
	if d := c1.Durations[timeintel.MetricTTI]; d != 60000 {
		t.Errorf("TTI duration = %d, want 60000", d)
	}
	if _, ok := c1.Durations[timeintel.MetricTTC]; ok {
		t.Error("incomplete TTC must not contribute a duration")
	}
	// Merged → child (excluded from MTBF by the pure rollup).
	for _, in := range out {
		if in.CorrelationID == "c2" && !in.IsChild {
			t.Error("merged snapshot must map to IsChild")
		}
	}
	// Dimension filter: device narrows to the matching incident only.
	dev := summariesFromSnapshots(rows, reliabilityFilters{Device: "lan-sw1"}, false)
	if len(dev) != 1 || dev[0].CorrelationID != "c2" {
		t.Fatalf("device filter wrong: %+v", dev)
	}
	// Owner filter is case-normalized.
	if o := summariesFromSnapshots(rows, reliabilityFilters{Owner: "isp"}, false); len(o) != 2 {
		t.Fatalf("owner filter should keep both non-internal rows, got %d", len(o))
	}
}

func TestMemIncidentTimeMetricsListWindow(t *testing.T) {
	m := &memIncidentTimeMetricsStore{by: map[string]incidentTimeMetricRow{}}
	ctx := context.Background()
	now := time.Now().UTC()

	_ = m.Upsert(ctx, snapRow("acme", "in-window", now.Add(-1*time.Hour)))
	_ = m.Upsert(ctx, snapRow("acme", "too-old", now.Add(-90*24*time.Hour)))
	_ = m.Upsert(ctx, snapRow("globex", "other-tenant", now.Add(-1*time.Hour)))
	// Two calc versions for one incident: the CURRENT version must win and the
	// incident must count exactly once (no double-counting on a version bump).
	oldVer := snapRow("acme", "versioned", now.Add(-2*time.Hour))
	oldVer.CalcVersion = "ti-0"
	oldVer.Owner = "stale"
	_ = m.Upsert(ctx, oldVer)
	newVer := snapRow("acme", "versioned", now.Add(-2*time.Hour))
	_ = m.Upsert(ctx, newVer)

	since := now.Add(-30 * 24 * time.Hour)
	rows, err := m.ListWindow(ctx, "acme", false, since, timeIntelCalcVersion, 100)
	if err != nil {
		t.Fatalf("ListWindow: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (window + dedupe + tenant scope), got %d: %+v", len(rows), rows)
	}
	seen := map[string]incidentTimeMetricRow{}
	for _, r := range rows {
		if r.TenantID != "acme" {
			t.Fatalf("cross-tenant leak: %q", r.TenantID)
		}
		seen[r.CorrelationID] = r
	}
	if _, ok := seen["too-old"]; ok {
		t.Error("row older than the window must be excluded")
	}
	v, ok := seen["versioned"]
	if !ok {
		t.Fatal("versioned incident missing")
	}
	if v.CalcVersion != timeIntelCalcVersion || v.Owner == "stale" {
		t.Errorf("version dedupe must prefer the current calc version, got %+v", v)
	}
	// Bound: limit applies (newest first).
	one, _ := m.ListWindow(ctx, "acme", false, since, timeIntelCalcVersion, 1)
	if len(one) != 1 || one[0].CorrelationID != "in-window" {
		t.Fatalf("limit/newest-first wrong: %+v", one)
	}
	// Cross-tenant (platform) view spans tenants.
	all, _ := m.ListWindow(ctx, "", true, since, timeIntelCalcVersion, 100)
	if len(all) != 3 {
		t.Fatalf("cross view want 3, got %d", len(all))
	}
}

// reliabilityReq builds an authenticated GET with the given principal claims —
// the same context injection every other handler test uses.
func reliabilityReq(claims jwtClaims) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/reliability/rollups?since=2592000", nil)
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, claims))
}

// TestBuildIncidentSummariesSnapshotIsolation is the §3a isolation test for the
// snapshot-backed rollup read: a tenant aggregates ONLY its own persisted rows;
// the platform owner (cross) sees all; the source is reported honestly.
func TestBuildIncidentSummariesSnapshotIsolation(t *testing.T) {
	m := &memIncidentTimeMetricsStore{by: map[string]incidentTimeMetricRow{}}
	now := time.Now().UTC()
	_ = m.Upsert(context.Background(), snapRow("acme", "a1", now.Add(-1*time.Hour)))
	_ = m.Upsert(context.Background(), snapRow("acme", "a2", now.Add(-2*time.Hour)))
	_ = m.Upsert(context.Background(), snapRow("globex", "g1", now.Add(-1*time.Hour)))
	s := &server{incidentTimeMetrics: m}

	// Tenant-bound caller: own rows only, served from snapshots (no live scan).
	res, err := s.buildIncidentSummaries(reliabilityReq(jwtClaims{Role: "admin", Tenant: "acme", Sub: "u"}),
		30*86400, reliabilityFilters{}, false)
	if err != nil {
		t.Fatalf("buildIncidentSummaries: %v", err)
	}
	if res.Source != "snapshots" {
		t.Fatalf("source = %q, want snapshots", res.Source)
	}
	if res.ScanCap != timeIntelBackfillCap || res.Capped {
		t.Errorf("cap reporting wrong: cap=%d capped=%v", res.ScanCap, res.Capped)
	}
	if len(res.Incidents) != 2 {
		t.Fatalf("acme should aggregate 2 own incidents, got %d", len(res.Incidents))
	}
	for _, in := range res.Incidents {
		if in.CorrelationID == "g1" {
			t.Fatal("cross-tenant leak: acme rollup includes globex incident")
		}
	}

	// Platform owner (cross-tenant) aggregates all.
	resAll, err := s.buildIncidentSummaries(reliabilityReq(jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal, Sub: "root"}),
		30*86400, reliabilityFilters{}, false)
	if err != nil {
		t.Fatalf("cross buildIncidentSummaries: %v", err)
	}
	if resAll.Source != "snapshots" || len(resAll.Incidents) != 3 {
		t.Fatalf("cross view want 3 snapshot-sourced incidents, got %d (%s)", len(resAll.Incidents), resAll.Source)
	}

	// The rollup over the snapshot summaries carries real phase stats (TTI present,
	// TTD honestly absent).
	ro := timeintel.Rollup(res.Incidents)
	if _, ok := ro.Metrics[timeintel.MetricTTI]; !ok {
		t.Error("rollup from snapshots must include TTI stats")
	}
	if _, ok := ro.Metrics[timeintel.MetricTTD]; ok {
		t.Error("rollup from snapshots must not include TTD (onset-fallback zero)")
	}
}
