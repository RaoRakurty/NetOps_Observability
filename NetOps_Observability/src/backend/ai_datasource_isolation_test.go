// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/discovery"
	"strings"
	"testing"

	"netops/backend/ai"
)

// ai_datasource_isolation_test.go — regression tests for the 2026-07-02 live
// finding: the CH row policies deliberately share untagged rows to every tenant
// scope (hybrid model), and the AI DataSource relied on them alone — so a
// foreign tenant's assistant could read the platform's correlation intel.
// These tests pin the two-layer fix:
//
//   - correlation reads are STRICT app-side (corrRowVisible): a scoped
//     principal sees only rows stamped with its own tenant, never untagged;
//   - telemetry module reads narrow to the principal's own devices and
//     fail CLOSED (no devices → nothing) BEFORE any ClickHouse dial.

func TestAICorrRowVisibleStrict(t *testing.T) {
	scoped := aiDataSource{claims: jwtClaims{Role: "viewer", Tenant: "t-a", Sub: "u"}}
	if scoped.corrRowVisible(map[string]any{"tenant_id": ""}) {
		t.Fatal("LEAK: untagged (platform) correlation row visible to a scoped principal")
	}
	if scoped.corrRowVisible(map[string]any{"tenant_id": "t-b"}) {
		t.Fatal("LEAK: foreign tenant's correlation row visible")
	}
	if !scoped.corrRowVisible(map[string]any{"tenant_id": "t-a"}) {
		t.Fatal("own tenant's row must be visible")
	}
	cross := aiDataSource{claims: jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal, Sub: "root"}}
	if !cross.corrRowVisible(map[string]any{"tenant_id": ""}) || !cross.corrRowVisible(map[string]any{"tenant_id": "t-a"}) {
		t.Fatal("the platform owner sees untagged and tagged rows")
	}
}

// TestAIModulesFailClosedWithoutDevices: a scoped principal with no visible
// devices reads NOTHING from any telemetry module — short-circuited before any
// ClickHouse query (the unreachable URL turns an attempted dial into an error).
func TestAIModulesFailClosedWithoutDevices(t *testing.T) {
	t.Setenv("CLICKHOUSE_URL", "http://127.0.0.1:9") // dial = guard failed
	s := aiCfgTestServer(t)
	s.discovery = &discovery.DiscoveryAggregator{} // no devices exist
	d := aiDataSource{
		srv: s, ctx: context.Background(), scope: "t-a",
		claims: jwtClaims{Role: "viewer", Tenant: "t-a", Sub: "u"},
	}
	for _, q := range []string{
		"top_talkers", "flow_summary", "service_flow_summary",
		"metric_anomalies", "app_identity_summary", "low_confidence_apps",
	} {
		res, err := d.ModuleQuery(context.Background(), ai.Principal{Tenant: "t-a"}, q, nil)
		if err != nil {
			t.Fatalf("%s: must fail closed to empty, not error (guard missing? %v)", q, err)
		}
		if len(res.Items) != 0 {
			t.Fatalf("%s: no-device principal must read nothing, got %d items", q, len(res.Items))
		}
	}
}

// TestAIAskStrictForForeignTenant: end-to-end through the HTTP handler — a
// foreign tenant user asking for status must get an answer derived from ZERO
// problems (the strict guards), never the platform's incidents. ClickHouse is
// stubbed to return the platform's untagged rows, simulating the hybrid row
// policy handing them over.
func TestAIAskStrictForForeignTenant(t *testing.T) {
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Whatever is asked, answer with an untagged (platform) corr row — the
		// exact shape the OR-untagged row policy leaks to a tenant scope.
		w.Write([]byte(`{"data":[{"correlation_id":"485accd1-0000-4000-8000-000000000001","tenant_id":"",
			"top_hypothesis":"sig.ent.isp","top_confidence":1,"verdict_tier":"suspected",
			"affected":"[]","signal_count":3,"node_count":2,"state":"open","created_at":"2026-07-02"}]}`))
	}))
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	t.Setenv("FEATURE_AI", "true")
	s := aiCfgTestServer(t)
	s.discovery = &discovery.DiscoveryAggregator{}

	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", strings.NewReader(`{"question":"what is going on right now?"}`))
	w := httptest.NewRecorder()
	s.handleAIAsk(w, claimsCtx(r, jwtClaims{Role: "viewer", Tenant: "t-foreign", Sub: "u"}))
	if w.Code != http.StatusOK {
		t.Fatalf("ask failed: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "485accd1") || strings.Contains(body, "sig.ent.isp") {
		t.Fatalf("LEAK: platform correlation intel reached a foreign tenant's answer: %s", body)
	}
}
