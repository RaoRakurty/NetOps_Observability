// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_mcp_isolation_test.go — Iris's read-only MCP gateway (tracker 337
// N-I5, D17) end to end through the real route:
//
//   - the IRIS_MCP switch off → 404 (the endpoint does not exist);
//   - only an API key with the exact iris:mcp scope is a credential: a
//     session, a key without the scope (even read:*), a revoked key → 401;
//     an administrative key → 403; a workspace that has not opted in → 403;
//   - §3a: the key's OWN tenant decides — an acting-tenant rewrite in the
//     claims never moves it, and tenant A's key never reads tenant B's data;
//   - tools/list holds read tools only (no device-session probe, no write);
//   - tools/call goes through the tool gateway and lands in the decision
//     ledger (surface mcp) and the audit trail; the per-key budget holds.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/aientitlement"
	"netops/backend/internal/apikey"
	"netops/backend/internal/featureflags"
	"netops/backend/internal/irismcp"
)

type mcpFixture struct {
	s       *server
	h       http.Handler
	keyA    jwtClaims // t-a, read:* + iris:mcp
	keyB    jwtClaims // t-b, read:* + iris:mcp
	noScope jwtClaims // t-a, read:* only
	admin   jwtClaims // t-a, admin:* + iris:mcp
	revoked jwtClaims // t-a, iris:mcp, revoked
	session jwtClaims // t-a human session
}

func mcpKey(t *testing.T, s *server, tenant string, scopes ...string) jwtClaims {
	t.Helper()
	pub, _, err := s.apiKeys.Create(apikey.Input{TenantID: tenant, Label: "mcp-test", Scopes: scopes}, "admin-"+tenant)
	if err != nil {
		t.Fatal(err)
	}
	// What the auth layer hands the handler for this key (auth.go).
	return jwtClaims{Sub: "apikey:" + pub.ID, Role: roleFromScopes(scopes), Tenant: tenant, Scopes: scopes}
}

func newMCPFixture(t *testing.T, switchOn bool) *mcpFixture {
	t.Helper()
	t.Setenv("FEATURE_AI", "true")
	s, h, a, _ := aiEntFixture(t)
	s.features = featureflags.New(featureflags.PlatformSpecs(), &memEnv{m: map[string]string{}}, &memStore{})
	if switchOn {
		if seeded, err := s.features.Seed(aientitlement.SwitchMCP, true, "test", time.Now()); err != nil || !seeded {
			t.Fatalf("seed IRIS_MCP: %v %v", seeded, err)
		}
	}
	s.aiDecisions = aidecision.NewMemStore()
	// newServer wires the per-key budget; this fixture builds the server
	// literal itself (a nil limiter refuses every call — fail closed).
	s.mcpLimiter = irismcp.NewLimiter(nil)
	s.aiDecisionMetrics = aidecision.NewMetrics()
	for _, tn := range []string{"t-a", "t-b"} {
		if _, err := s.aiTenantCfg.SetMCP(tn, true); err != nil {
			t.Fatal(err)
		}
	}
	f := &mcpFixture{s: s, h: h, session: a}
	f.keyA = mcpKey(t, s, "t-a", "read:*", apikey.ScopeIrisMCP)
	f.keyB = mcpKey(t, s, "t-b", "read:*", apikey.ScopeIrisMCP)
	f.noScope = mcpKey(t, s, "t-a", "read:*")
	f.admin = mcpKey(t, s, "t-a", "admin:*", apikey.ScopeIrisMCP)
	f.revoked = mcpKey(t, s, "t-a", apikey.ScopeIrisMCP)
	if err := s.apiKeys.Revoke(strings.TrimPrefix(f.revoked.Sub, "apikey:")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *mcpFixture) rpc(t *testing.T, c jwtClaims, body string) (int, map[string]json.RawMessage) {
	t.Helper()
	r := newMCPRequest(body)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := newRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		return w.Code, nil
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %s", w.Body.String())
	}
	return w.Code, out
}

const mcpPing = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
const mcpList = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

func mcpToolNames(t *testing.T, res map[string]json.RawMessage) []string {
	t.Helper()
	var r struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(res["result"], &r); err != nil {
		t.Fatalf("tools/list result: %s", res["result"])
	}
	out := make([]string, 0, len(r.Tools))
	for _, x := range r.Tools {
		out = append(out, x.Name)
	}
	return out
}

func TestMCPSwitchOffIsNotFound(t *testing.T) {
	f := newMCPFixture(t, false)
	if code, _ := f.rpc(t, f.keyA, mcpPing); code != http.StatusNotFound {
		t.Fatalf("switch off: %d, want 404", code)
	}
}

func TestMCPCredentialRules(t *testing.T) {
	f := newMCPFixture(t, true)
	for name, tc := range map[string]struct {
		c    jwtClaims
		want int
	}{
		"session token":       {f.session, http.StatusUnauthorized},
		"key without scope":   {f.noScope, http.StatusUnauthorized},
		"revoked key":         {f.revoked, http.StatusUnauthorized},
		"administrative key":  {f.admin, http.StatusForbidden},
		"workspace key":       {f.keyA, http.StatusOK},
		"other workspace key": {f.keyB, http.StatusOK},
	} {
		if code, _ := f.rpc(t, tc.c, mcpPing); code != tc.want {
			t.Errorf("%s: %d, want %d", name, code, tc.want)
		}
	}
	// A workspace that has not opted in is refused even with a good key.
	if _, err := f.s.aiTenantCfg.SetMCP("t-b", false); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.rpc(t, f.keyB, mcpPing); code != http.StatusForbidden {
		t.Fatalf("workspace not opted in: %d, want 403", code)
	}
	// The tier mapping still gates first: without ai.mcp the shared refusal.
	f.s.aiEntitlementPolicy = policyWithout(t, f.s, aientitlement.MCP)
	if code, _ := f.rpc(t, f.keyA, mcpPing); code != http.StatusForbidden {
		t.Fatalf("without ai.mcp: %d, want 403", code)
	}
}

func TestMCPToolsListIsReadOnly(t *testing.T) {
	f := newMCPFixture(t, true)
	_, res := f.rpc(t, f.keyA, mcpList)
	names := mcpToolNames(t, res)
	if len(names) == 0 {
		t.Fatal("no tools listed — the curated set must intersect this deployment's registry")
	}
	curated := mcpToolTitles()
	for _, n := range names {
		if _, ok := curated[n]; !ok {
			t.Errorf("%s listed but not in the curated set", n)
		}
		switch n {
		case "get_device_state", "run_protocol_diagnostic", "compile_query", "get_config_diff", "get_security_findings", "recall_investigations":
			t.Errorf("%s must never be listed over MCP", n)
		}
	}
	// Every curated tool that is registered is a read — never a probe.
	orch := f.s.newOrchestrator(newMCPRequest(""), f.keyA)
	reg, _ := agentToolbox(orch)
	for n := range curated {
		if tl, ok := reg.Get(n); ok && tl.Capability() != ai.CapRead {
			t.Errorf("curated tool %s has capability %s", n, tl.Capability())
		}
	}
}

// §3a: the key's own tenant decides. The claims the auth layer passes may
// carry an acting-tenant rewrite (as_tenant / X-Acting-Tenant); the gateway
// re-reads the key and answers for t-a only.
func TestMCPKeyTenantDecidesNotTheActingTenant(t *testing.T) {
	f := newMCPFixture(t, true)
	moved := f.keyA
	moved.Tenant = "t-b" // what withActingTenant would write for a key that reaches t-b
	mc, err := f.s.mcpPrincipal(moved)
	if err != nil {
		t.Fatal(err)
	}
	if tn, cross := principalTenant(mc); tn != "t-a" || cross {
		t.Fatalf("principal tenant %q cross=%v — the key's own tenant must win", tn, cross)
	}
	// And the switch-off of t-a (the key's tenant) refuses even when the
	// claims point at an opted-in t-b.
	if _, err := f.s.aiTenantCfg.SetMCP("t-a", false); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.rpc(t, moved, mcpPing); code != http.StatusForbidden {
		t.Fatalf("acting-tenant rewrite moved the opt-in check: %d", code)
	}
}

func TestMCPCrossTenantReadsStayInTheKeysWorkspace(t *testing.T) {
	f := newMCPFixture(t, true)
	// search_docs is tenant-neutral; the device-scoped lookups are the
	// isolation surface. get_topology_context takes a device id: tenant B's
	// device through tenant A's key must read as "not found".
	_, res := f.rpc(t, f.keyA, mcpList)
	listed := map[string]bool{}
	for _, n := range mcpToolNames(t, res) {
		listed[n] = true
	}
	argFor := map[string]string{"get_topology_context": "device_id", "get_overlay_state": "device_id", "get_tunnel_state": "device_id", "get_device_health": "device"}
	tool := ""
	for _, cand := range []string{"get_topology_context", "get_device_health", "get_overlay_state", "get_tunnel_state"} {
		if listed[cand] {
			tool = cand
			break
		}
	}
	if tool == "" {
		t.Fatalf("no device-scoped tool listed (%v) — the isolation surface would be untested", listed)
	}
	call := func(c jwtClaims, dev string) (bool, string) {
		_, out := f.rpc(t, c, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+tool+`","arguments":{"`+argFor[tool]+`":"`+dev+`"}}}`)
		var r struct {
			Content []struct{ Text string } `json:"content"`
			IsError bool                    `json:"isError"`
		}
		if err := json.Unmarshal(out["result"], &r); err != nil || len(r.Content) != 1 {
			t.Fatalf("%s: %s %s", tool, out["result"], out["error"])
		}
		return r.IsError, r.Content[0].Text
	}
	for _, tc := range []struct {
		key  jwtClaims
		dev  string
		name string
	}{{f.keyA, "dev-b", "edge-b"}, {f.keyA, "edge-b", "edge-b"}, {f.keyB, "dev-a", "edge-a"}} {
		isErr, text := call(tc.key, tc.dev)
		if !isErr || text != "not found" {
			t.Fatalf("%s(%s) across tenants answered %v %q — want the not-found refusal (it must reach the tool and be scoped out)", tool, tc.dev, isErr, text)
		}
		if strings.Contains(text, tc.name) {
			t.Fatalf("%s leaked %s across tenants", tool, tc.name)
		}
	}
	t.Logf("isolation surface: %s", tool)
}

func TestMCPToolCallIsLedgeredAndBudgeted(t *testing.T) {
	t.Setenv("IRIS_MCP_CALLS_PER_MIN", "1")
	f := newMCPFixture(t, true)
	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search_docs","arguments":{"query":"add a device"}}}`
	_, res := f.rpc(t, f.keyA, mcpList)
	listed := false
	for _, n := range mcpToolNames(t, res) {
		listed = listed || n == "search_docs"
	}
	if !listed {
		t.Skip("search_docs not registered in this fixture")
	}
	_, out := f.rpc(t, f.keyA, body)
	var r1 struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(out["result"], &r1); err != nil {
		t.Fatalf("call 1: %s", out["result"])
	}
	entries, err := f.s.aiDecisions.List(context.Background(), "t-a", false, aidecision.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	gotTool, gotAnswer := false, false
	for _, e := range entries {
		if e.Surface != aidecision.SurfaceMCP {
			t.Fatalf("ledger surface %q, want mcp", e.Surface)
		}
		gotTool = gotTool || e.EventType == aidecision.ToolExecuted || e.EventType == aidecision.ToolSelected
		gotAnswer = gotAnswer || e.EventType == aidecision.AnswerReturned
	}
	if !gotTool || !gotAnswer {
		t.Fatalf("ledger entries for the MCP call: %+v (call answered %s %s)", entries, out["result"], out["error"])
	}
	if other, _ := f.s.aiDecisions.List(context.Background(), "t-b", false, aidecision.ListFilter{}); len(other) != 0 {
		t.Fatalf("t-a's MCP call ledgered under t-b: %+v", other)
	}
	// The per-key budget is 1/min: the second call is a tool error, not a run.
	_, out = f.rpc(t, f.keyA, body)
	if !strings.Contains(string(out["result"]), "per-minute limit") {
		t.Fatalf("second call not budgeted: %s", out["result"])
	}
	// Another key has its own budget.
	_, out = f.rpc(t, f.keyB, body)
	if strings.Contains(string(out["result"]), "per-minute limit") {
		t.Fatalf("budget leaked across keys: %s", out["result"])
	}
}

func TestMCPWorkspaceAccessToggleIsPlatformOwnerOnly(t *testing.T) {
	f := newMCPFixture(t, true)
	// A tenant admin cannot grant their own workspace MCP (§3a.3).
	w := serveAs(f.h, f.session, http.MethodPut, "/api/ai/tenants/t-a", `{"assistant_enabled":true,"investigations_enabled":false,"mcp_enabled":true}`)
	if w.Code != http.StatusForbidden && w.Code != http.StatusNotFound && w.Code != http.StatusUnauthorized {
		t.Fatalf("tenant admin set MCP: %d %s", w.Code, w.Body.String())
	}
	// Omitting mcp_enabled keeps the stored value (an older client never
	// switches it off by omission).
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	tn, err := f.s.tenants.Create("MCP Workspace", "mcp-ws", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.aiTenantCfg.SetMCP(tn.ID, true); err != nil {
		t.Fatal(err)
	}
	path := "/api/ai/tenants/" + tn.ID
	w = serveAs(f.h, owner, http.MethodPut, path, `{"assistant_enabled":true,"investigations_enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("owner PUT: %d %s", w.Code, w.Body.String())
	}
	if !f.s.aiTenantCfg.MCPEnabled(tn.ID) {
		t.Fatal("omitting mcp_enabled switched MCP off")
	}
	w = serveAs(f.h, owner, http.MethodPut, path, `{"assistant_enabled":true,"investigations_enabled":false,"mcp_enabled":false}`)
	if w.Code != http.StatusOK || f.s.aiTenantCfg.MCPEnabled(tn.ID) {
		t.Fatalf("owner could not switch MCP off: %d %s", w.Code, w.Body.String())
	}
}

func newMCPRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/ai/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	return r
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
