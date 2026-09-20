// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"io"
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

// TestAIListActiveProblemsIsolation — §3a for the active-problems read after it
// moved from netops.corr_objects to the netops.corr_current hot projection
// (2026-09-19 memory-limit defect). The projection carries its OWN strict row
// policy (tenant_iso_corr_current, chschema.StrictRowPolicyDDL), and it is
// applied by exactly the same mechanism as before — the tenant_scope setting
// chRowsScope puts on the wire — so this test pins BOTH layers on the new
// query:
//
//	layer 1 — the read carries the caller's scope (a fake ClickHouse that
//	          enforces the policy returns nothing for a foreign scope);
//	layer 2 — even when the store hands over foreign and untagged rows anyway
//	          (the hybrid-policy leak of 2026-07-02), corrRowVisible drops them.
func TestAIListActiveProblemsIsolation(t *testing.T) {
	const own, foreign = "t-own", "t-foreign"
	ownRow := `{"correlation_id":"11111111-2222-4333-8444-555555555555","tenant_id":"` + own + `",
		"top_hypothesis":"sig.wan.flap","top_confidence":0.9,"verdict_tier":"suspected",
		"affected":"[]","signal_count":3,"node_count":2}`
	foreignRow := `{"correlation_id":"22222222-3333-4444-8555-666666666666","tenant_id":"` + foreign + `",
		"top_hypothesis":"sig.ent.isp","top_confidence":0.8,"verdict_tier":"confirmed",
		"affected":"[]","signal_count":5,"node_count":4}`
	untaggedRow := `{"correlation_id":"33333333-4444-4555-8666-777777777777","tenant_id":"",
		"top_hypothesis":"sig.core.bgp","top_confidence":0.7,"verdict_tier":"confirmed",
		"affected":"[]","signal_count":7,"node_count":6}`

	var gotScope, gotSQL string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotSQL, gotScope = string(body), r.URL.Query().Get("tenant_scope")
		// Deliberately hostile store: it answers with EVERY row regardless of
		// scope, so anything the caller gets back is the app layer's doing.
		_, _ = w.Write([]byte(`{"data":[` + ownRow + `,` + foreignRow + `,` + untaggedRow + `]}`))
	}))
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	s := aiCfgTestServer(t)

	d := aiDataSource{
		srv: s, ctx: context.Background(), scope: own,
		claims: jwtClaims{Role: "viewer", Tenant: own, Sub: "u"},
	}
	probs, err := d.ListActiveProblems(context.Background(), ai.Principal{Tenant: own}, 25)
	if err != nil {
		t.Fatalf("ListActiveProblems: %v", err)
	}
	// Layer 1: the caller's scope reached ClickHouse, against the projection.
	if gotScope != own {
		t.Fatalf("read did not carry the caller's tenant_scope: got %q, want %q", gotScope, own)
	}
	if !strings.Contains(gotSQL, "netops.corr_current") {
		t.Fatalf("active-problems read is not on the hot projection:\n%s", gotSQL)
	}
	// Layer 2: own rows only — a foreign tenant's and the platform's are dropped.
	if len(probs) != 1 {
		t.Fatalf("own-only list: got %d problems, want 1 — %+v", len(probs), probs)
	}
	if probs[0].ID != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("LEAK: wrong problem returned to %s: %+v", own, probs[0])
	}
	for _, p := range probs {
		if strings.Contains(p.Title, "isp") || strings.Contains(p.Title, "bgp") {
			t.Fatalf("LEAK: foreign/platform correlation intel in a scoped answer: %+v", p)
		}
	}
	// The platform owner (cross-tenant) legitimately sees all three.
	cross := aiDataSource{
		srv: s, ctx: context.Background(), scope: "__all__",
		claims: jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal, Sub: "root"},
	}
	all, err := cross.ListActiveProblems(context.Background(), ai.Principal{Cross: true}, 25)
	if err != nil {
		t.Fatalf("cross-tenant ListActiveProblems: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("cross-tenant list: got %d problems, want 3", len(all))
	}
	if gotScope != "__all__" {
		t.Fatalf("cross-tenant read carried scope %q, want __all__", gotScope)
	}
}

// TestAIListActiveProblemsEmptyWhenStoreEnforcesPolicy: the row policy alone
// (a store that answers a foreign scope with nothing) already yields an honest
// empty answer — not an error, and never another tenant's rows.
func TestAIListActiveProblemsEmptyWhenStoreEnforcesPolicy(t *testing.T) {
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("tenant_scope") == "t-owner" {
			_, _ = w.Write([]byte(`{"data":[{"correlation_id":"11111111-2222-4333-8444-555555555555",
				"tenant_id":"t-owner","top_hypothesis":"sig.wan.flap","top_confidence":0.9,
				"verdict_tier":"suspected","affected":"[]","signal_count":1,"node_count":1}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	s := aiCfgTestServer(t)

	d := aiDataSource{
		srv: s, ctx: context.Background(), scope: "t-other",
		claims: jwtClaims{Role: "viewer", Tenant: "t-other", Sub: "u"},
	}
	probs, err := d.ListActiveProblems(context.Background(), ai.Principal{Tenant: "t-other"}, 25)
	if err != nil {
		t.Fatalf("a scoped caller with no rows must get an honest empty list, not an error: %v", err)
	}
	if len(probs) != 0 {
		t.Fatalf("LEAK: %d problems reached a tenant the row policy excluded: %+v", len(probs), probs)
	}
}

// TestAIListProblemsInWindowIsolation — §3a for the time-range read ("what
// happened last night", /history) after the 2026-09-20 memory-limit fix
// reshaped it into the three-stage narrow-pick/keyed-wide-fetch query. The
// reshape multiplied the places the tenant boundary has to hold — the page
// pick, the latest-version resolve and the wide fetch are three reads of
// netops.corr_objects in ONE statement — so this pins both layers on the new
// shape, exactly as TestAIListActiveProblemsIsolation does for the sibling:
//
//	layer 1 — the statement rides the caller's tenant_scope (the corr_objects
//	          row policy is what prunes a scoped caller to its own partitions);
//	layer 2 — even when the store hands over foreign and untagged rows anyway
//	          (the hybrid-policy leak of 2026-07-02), corrRowVisible drops them.
//
// It also pins that the ai.Principal ARGUMENT cannot widen the read: the seam
// derives its scope from the authenticated claims (d.scope/d.claims), never
// from the caller-supplied principal — the `as_tenant`-into-another-org case.
func TestAIListProblemsInWindowIsolation(t *testing.T) {
	const own, foreign = "t-own", "t-foreign"
	ownRow := `{"correlation_id":"11111111-2222-4333-8444-555555555555","tenant_id":"` + own + `",
		"top_hypothesis":"sig.wan.flap","top_confidence":0.9,"verdict_tier":"suspected","state":"closed",
		"affected":"[]","signal_count":3,"node_count":2}`
	foreignRow := `{"correlation_id":"22222222-3333-4444-8555-666666666666","tenant_id":"` + foreign + `",
		"top_hypothesis":"sig.ent.isp","top_confidence":0.8,"verdict_tier":"confirmed","state":"open",
		"affected":"[]","signal_count":5,"node_count":4}`
	untaggedRow := `{"correlation_id":"33333333-4444-4555-8666-777777777777","tenant_id":"",
		"top_hypothesis":"sig.core.bgp","top_confidence":0.7,"verdict_tier":"confirmed","state":"open",
		"affected":"[]","signal_count":7,"node_count":6}`

	var gotScope, gotSQL string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotSQL, gotScope = string(body), r.URL.Query().Get("tenant_scope")
		// Deliberately hostile store: every row regardless of scope, so
		// anything the caller gets back is the app layer's doing.
		_, _ = w.Write([]byte(`{"data":[` + ownRow + `,` + foreignRow + `,` + untaggedRow + `]}`))
	}))
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	s := aiCfgTestServer(t)

	d := aiDataSource{
		srv: s, ctx: context.Background(), scope: own,
		claims: jwtClaims{Role: "viewer", Tenant: own, Sub: "u"},
	}
	// A forged principal — another org's tenant, claiming cross-tenant reach —
	// is passed deliberately: it must change NOTHING.
	probs, err := d.ListProblemsInWindow(context.Background(),
		ai.Principal{Tenant: foreign, Cross: true}, 30*24*3600)
	if err != nil {
		t.Fatalf("ListProblemsInWindow: %v", err)
	}
	// Layer 1: the caller's own scope reached ClickHouse, not the argument's.
	if gotScope != own {
		t.Fatalf("read did not carry the caller's tenant_scope: got %q, want %q", gotScope, own)
	}
	// …and it is still the bounded three-stage shape that goes on the wire.
	for _, must := range []string{"WITH page AS", "max(version) AS version", "FROM picked"} {
		if !strings.Contains(gotSQL, must) {
			t.Fatalf("time-range read lost its bounded shape on the wire (missing %q):\n%s", must, gotSQL)
		}
	}
	// Layer 2: own rows only — a foreign tenant's and the platform's are dropped.
	if len(probs) != 1 {
		t.Fatalf("own-only list: got %d problems, want 1 — %+v", len(probs), probs)
	}
	if probs[0].ID != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("LEAK: wrong problem returned to %s: %+v", own, probs[0])
	}
	if probs[0].State != "closed" {
		t.Fatalf("the time-range read must carry state so a summary can tell open from resolved: %+v", probs[0])
	}
	for _, p := range probs {
		if strings.Contains(p.Title, "isp") || strings.Contains(p.Title, "bgp") {
			t.Fatalf("LEAK: foreign/platform correlation intel in a scoped answer: %+v", p)
		}
	}
	// The platform owner (cross-tenant) legitimately sees all three — this is
	// the principal the 30 d read used to 502 for.
	cross := aiDataSource{
		srv: s, ctx: context.Background(), scope: "__all__",
		claims: jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal, Sub: "root"},
	}
	all, err := cross.ListProblemsInWindow(context.Background(), ai.Principal{Cross: true}, 30*24*3600)
	if err != nil {
		t.Fatalf("cross-tenant ListProblemsInWindow: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("cross-tenant list: got %d problems, want 3", len(all))
	}
	if gotScope != "__all__" {
		t.Fatalf("cross-tenant read carried scope %q, want __all__", gotScope)
	}
}

// TestAIListProblemsInWindowEmptyWhenStoreEnforcesPolicy: the row policy alone
// (a store that answers a foreign scope with nothing) already yields an honest
// empty time-range answer — not an error, and never another tenant's history.
func TestAIListProblemsInWindowEmptyWhenStoreEnforcesPolicy(t *testing.T) {
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("tenant_scope") == "t-owner" {
			_, _ = w.Write([]byte(`{"data":[{"correlation_id":"11111111-2222-4333-8444-555555555555",
				"tenant_id":"t-owner","top_hypothesis":"sig.wan.flap","top_confidence":0.9,
				"verdict_tier":"suspected","state":"open","affected":"[]","signal_count":1,"node_count":1}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	s := aiCfgTestServer(t)

	d := aiDataSource{
		srv: s, ctx: context.Background(), scope: "t-other",
		claims: jwtClaims{Role: "viewer", Tenant: "t-other", Sub: "u"},
	}
	probs, err := d.ListProblemsInWindow(context.Background(), ai.Principal{Tenant: "t-other"}, 12*3600)
	if err != nil {
		t.Fatalf("a scoped caller with no rows must get an honest empty list, not an error: %v", err)
	}
	if len(probs) != 0 {
		t.Fatalf("LEAK: %d problems reached a tenant the row policy excluded: %+v", len(probs), probs)
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
