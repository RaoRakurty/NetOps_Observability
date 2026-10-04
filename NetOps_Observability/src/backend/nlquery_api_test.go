// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_api_test.go — /api/ai/query/compile and /execute (tracker 337 N-C5),
// §3a end to end: a device name another tenant owns does not compile; a query
// naming a foreign device is refused with the same error as a missing one; a
// smuggled tenant field is a 400; an action is declined; and an executed
// query reaches VictoriaMetrics only with the caller's own scope filter.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/nlquery/catalog"
)

func nlqAPI(t *testing.T, s *server, c jwtClaims, path, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	if strings.Contains(path, "/compile") {
		s.handleAIQueryCompile(w, r)
	} else {
		s.handleAIQueryExecute(w, r)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // best-effort: error bodies are asserted by status
	return w.Code, out
}

func nlqAPIFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := nlqFixture(t)
	s.nlqCatalog = catalog.MustLoad()
	a.Role, b.Role = "admin", "admin"
	return s, a, b
}

func TestQueryCompileIsTenantScoped(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, b := nlqAPIFixture(t)
	code, out := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"show cpu on edge-a for the last hour"}`)
	if code != 200 || out["ast"] == nil {
		t.Fatalf("tenant A compile: %d %v", code, out)
	}
	if ast, _ := json.Marshal(out["ast"]); !strings.Contains(string(ast), "device:dev-a") {
		t.Fatalf("tenant A's own device must resolve: %s", ast)
	}
	code, out = nlqAPI(t, s, b, "/api/ai/query/compile", `{"question":"show cpu on edge-a for the last hour"}`)
	if code != 200 || out["ast"] != nil || out["unparsed"] != true {
		t.Fatalf("tenant B must not compile tenant A's device name: %d %v", code, out)
	}
}

func TestQueryCompileDeclinesAndRejects(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, _ := nlqAPIFixture(t)
	if _, out := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"restart edge-a"}`); out["decline"] != "not_a_query" {
		t.Fatalf("an action must be declined: %v", out)
	}
	for name, body := range map[string]string{
		"tenant field":    `{"question":"cpu","tenant":"t-b"}`,
		"tenant in prior": `{"question":"only dallas","prior_ast":{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","time_range":{},"tenant":"t-b"}}`,
		"bad tz":          `{"question":"cpu","tz":"Mars/Olympus"}`,
		"bad incident id": `{"question":"what happened","incident_id":"x' OR 1=1"}`,
		"empty question":  `{"question":"  "}`,
	} {
		if code, _ := nlqAPI(t, s, a, "/api/ai/query/compile", body); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, code)
		}
	}
}

func TestQueryExecuteRefusesForeignAndReadsScoped(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	var mu sync.Mutex
	var filters [][]string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		filters = append(filters, r.URL.Query()["extra_filters[]"])
		mu.Unlock()
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"values":[[1,"12"]]}]}}`))
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, b := nlqAPIFixture(t)
	q := `{"ast":{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"device","id":"device:dev-a"}],"time_range":{"kind":"relative","last":"1h"}}}`

	// Tenant B naming tenant A's device: refused as unknown, like a missing one.
	code, out := nlqAPI(t, s, b, "/api/ai/query/execute", q)
	if code != http.StatusUnprocessableEntity || !strings.Contains(nlqJSON(out), "unknown_entity") {
		t.Fatalf("foreign device must be unknown_entity: %d %v", code, out)
	}
	missing := strings.Replace(q, "device:dev-a", "device:no-such", 1)
	_, outMissing := nlqAPI(t, s, b, "/api/ai/query/execute", missing)
	if !strings.Contains(nlqJSON(outMissing), "unknown_entity") {
		t.Fatal("a missing device must read the same as a foreign one")
	}
	if len(filters) != 0 {
		t.Fatal("a refused query must never reach VictoriaMetrics")
	}

	code, out = nlqAPI(t, s, a, "/api/ai/query/execute", q)
	if code != 200 || out["result"] == nil {
		t.Fatalf("tenant A execute: %d %v", code, out)
	}
	if len(filters) != 1 || len(filters[0]) == 0 || strings.Contains(strings.Join(filters[0], " "), "dev-b") {
		t.Fatalf("the read must carry ONLY tenant A's scope filter: %v", filters)
	}
	if strings.Contains(nlqJSON(out), "device_cpu_percent") {
		t.Fatal("the physical backend query must never be in the answer")
	}

	if code, _ := nlqAPI(t, s, a, "/api/ai/query/execute", strings.Replace(q, `"v":1,`, `"v":1,"tenant":"t-b",`, 1)); code != http.StatusBadRequest {
		t.Fatalf("a smuggled tenant in the query must be a 400, got %d", code)
	}
}

// CLAUDE.md §3a rule 5: a non-owner cannot walk into another tenant — neither
// with ?as_tenant= on the URL nor with an ActingTenant smuggled into its
// claims (principalTenant ignores it for a non-owner). The cross-tenant read
// stays unknown, exactly as without the attempt.
func TestQueryRoutesIgnoreAsTenantForANonOwner(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, b := nlqAPIFixture(t)
	b.ActingTenant = a.Tenant
	for _, path := range []string{"/api/ai/query/compile?as_tenant=" + a.Tenant, "/api/ai/query/compile"} {
		code, out := nlqAPI(t, s, b, path, `{"question":"show cpu on edge-a for the last hour"}`)
		if code != 200 || out["ast"] != nil || out["unparsed"] != true {
			t.Fatalf("%s: tenant B must not reach tenant A's device: %d %v", path, code, out)
		}
	}
	q := `{"ast":{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"device","id":"device:dev-a"}],"time_range":{"kind":"relative","last":"1h"}}}`
	code, out := nlqAPI(t, s, b, "/api/ai/query/execute?as_tenant="+a.Tenant, q)
	if code != http.StatusUnprocessableEntity || !strings.Contains(nlqJSON(out), "unknown_entity") {
		t.Fatalf("cross-tenant execute via as_tenant must stay unknown_entity: %d %v", code, out)
	}
}

func TestQueryRoutesArePOSTOnly(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, _ := nlqAPIFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/api/ai/query/compile", nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, a))
	w := httptest.NewRecorder()
	s.handleAIQueryCompile(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d", w.Code)
	}
}

func nlqJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
