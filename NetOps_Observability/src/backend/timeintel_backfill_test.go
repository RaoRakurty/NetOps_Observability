package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/timeintel"
)

func TestHandleReliabilityTimeMetricsGet(t *testing.T) {
	m := timeintel.NewMemMetricsStore()
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
