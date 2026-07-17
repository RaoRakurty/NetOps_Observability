package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/timeintel"
)

// A grounded incident: onset → correlation completed, evidence ready, ISP-owned.
func backfillFacts() corrTimeFacts {
	base := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	return corrTimeFacts{
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

	row := deriveIncidentTimeMetricRow("ACME", "corr-1", "ti-1", facts, group, "DIA", "OPEN", now)

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
	wantDomain, _ := timeintel.ClassifyOwnerDomain(facts.Owner, group)
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
	_, wantInternal := timeintel.ClassifyOwnerDomain(facts.Owner, group)
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
	m := &memIncidentTimeMetricsStore{by: map[string]incidentTimeMetricRow{}}
	ctx := context.Background()
	now := time.Now().UTC()

	mk := func(tenant, corr string, ts time.Time) incidentTimeMetricRow {
		return incidentTimeMetricRow{TenantID: tenant, CorrelationID: corr, CalcVersion: "ti-1", OccurredAt: ts}
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

func TestHandleReliabilityTimeMetricsGet(t *testing.T) {
	m := &memIncidentTimeMetricsStore{by: map[string]incidentTimeMetricRow{}}
	_ = m.Upsert(context.Background(), incidentTimeMetricRow{
		TenantID: "acme", CorrelationID: "c1", CalcVersion: "ti-1",
		OccurredAt: time.Now().UTC(), SeamType: "DIA", OwnerDomain: "isp",
	})
	s := &server{incidentTimeMetrics: m}

	// GET with no permission gate available in this lightweight server: requirePerm
	// will reject (no auth) → we assert it does NOT 200 without auth, proving the
	// read is gated (full positive-path auth is covered by the route-isolation
	// ledger + the store isolation test above).
	r := httptest.NewRequest(http.MethodGet, "/api/reliability/time-metrics", nil)
	w := httptest.NewRecorder()
	s.handleReliabilityTimeMetrics(w, r)
	if w.Code == http.StatusOK {
		t.Fatalf("unauthenticated GET must be gated, got 200")
	}

	// An unknown method is rejected.
	r2 := httptest.NewRequest(http.MethodDelete, "/api/reliability/time-metrics", nil)
	w2 := httptest.NewRecorder()
	s.handleReliabilityTimeMetrics(w2, r2)
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE want 405, got %d", w2.Code)
	}
}
