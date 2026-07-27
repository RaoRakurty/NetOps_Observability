package main

import (
	"net/http/httptest"
	"testing"
)

// 12. Tenant scoping: the endpoint refuses an unauthenticated request BEFORE
// any data read (the dispatch layer additionally gates on requirePerm, and the
// slice reads run under chTenantScope + ClickHouse row policies).
func TestRcaReportEndpointRequiresPrincipal(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("GET", "/api/correlations/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/rca-report", nil)
	w := httptest.NewRecorder()
	s.serveRcaReport(w, r, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	if w.Code != 401 {
		t.Fatalf("unauthenticated rca-report = %d, want 401", w.Code)
	}
}
