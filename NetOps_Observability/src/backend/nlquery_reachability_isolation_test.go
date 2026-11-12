// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_reachability_isolation_test.go — "which devices are down" (phrasing
// eval, 2026-11-12) through the real /api/ai/query routes, §3a across two
// tenants (CLAUDE.md §3a rule 5, org_isolation_test.go is the template):
//
//   - the liveness read carries the caller's own metric scope filter, and
//     even a VictoriaMetrics that answered for EVERY tenant's device cannot put
//     another tenant's device in the answer (the list is the caller's visible
//     devices, the verdict only annotates it);
//   - tenant B never sees tenant A's down device, with or without
//     ?as_tenant= / an ActingTenant smuggled into its claims;
//   - the compile route reads the question as the liveness query in the
//     caller's scope only.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A device whose every poll failed (max 0) is DOWN and one with a failing
// collector (min 0) is PARTIAL — the zero is the answer. The running-max
// reader this used before dropped zeros, so "down" could never be observed.
func TestCollectorReachabilityKeepsZeros(t *testing.T) {
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Query().Get("query"), "max by") {
			_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"value":[1,"0"]},{"metric":{"device":"dev-p"},"value":[1,"1"]},{"metric":{"device":"dev-u"},"value":[1,"1"]}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"value":[1,"0"]},{"metric":{"device":"dev-p"},"value":[1,"0"]},{"metric":{"device":"dev-u"},"value":[1,"1"]}]}}`))
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, _ := nlqFixture(t)
	got, err := s.nlqScopeFor(newAITestRequest(t, a), a).DeviceReachability(context.Background(), []string{"dev-a", "dev-p", "dev-u", "dev-none"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"dev-a": "down", "dev-p": "partial", "dev-u": "up", "dev-none": "unknown"}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s = %q, want %q (all: %v)", id, got[id], w, got)
		}
	}
}

func TestDeviceLivenessIsTenantScoped(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	var mu sync.Mutex
	var filters [][]string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		filters = append(filters, r.URL.Query()["extra_filters[]"])
		mu.Unlock()
		// A VictoriaMetrics that ignores the filter: BOTH tenants' devices
		// read down. The answer must still hold only the caller's own.
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"value":[1,"0"]},{"metric":{"device":"dev-b"},"value":[1,"0"]}]}}`))
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, b := nlqAPIFixture(t)
	const down = `{"ast":{"v":1,"query_type":"entity_list","target":"device","filters":[{"field":"reachability","op":"eq","values":["down"]}],"time_range":{}}}`

	code, out := nlqAPI(t, s, a, "/api/ai/query/execute", down)
	if code != http.StatusOK {
		t.Fatalf("tenant A execute: %d %v", code, out)
	}
	if got := nlqJSON(out["result"]); !strings.Contains(got, "device:dev-a") || !strings.Contains(got, `"reachability":"down"`) || strings.Contains(got, "dev-b") || strings.Contains(got, "edge-b") {
		t.Fatalf("tenant A must see exactly its own down device: %s", got)
	}
	mu.Lock()
	for i, f := range filters {
		joined := strings.Join(f, " ")
		if len(f) == 0 || !strings.Contains(joined, "dev-a") || strings.Contains(joined, "dev-b") {
			mu.Unlock()
			t.Fatalf("liveness read %d extra_filters = %v — must be present and name only tenant A's devices", i, f)
		}
	}
	filters = nil
	mu.Unlock()

	// Tenant B: its own device only — never A's — however it asks.
	walker := b
	walker.ActingTenant = a.Tenant
	for name, tc := range map[string]struct {
		c    jwtClaims
		path string
	}{
		"own":           {b, "/api/ai/query/execute"},
		"as_tenant":     {b, "/api/ai/query/execute?as_tenant=" + a.Tenant},
		"acting tenant": {walker, "/api/ai/query/execute"},
	} {
		code, out := nlqAPI(t, s, tc.c, tc.path, down)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		got := nlqJSON(out["result"])
		if strings.Contains(got, "dev-a") || strings.Contains(got, "edge-a") || !strings.Contains(got, "device:dev-b") {
			t.Fatalf("%s: ISOLATION — tenant B's liveness answer must hold only its own device: %s", name, got)
		}
	}
	mu.Lock()
	for _, f := range filters {
		if strings.Contains(strings.Join(f, " "), "dev-a") {
			mu.Unlock()
			t.Fatalf("tenant B's liveness read carried tenant A's scope: %v", filters)
		}
	}
	mu.Unlock()

	// A named foreign device is refused like a missing one (404-equivalent).
	foreign := `{"ast":{"v":1,"query_type":"entity_list","target":"device","entities":[{"type":"device","id":"device:dev-a"}],"time_range":{}}}`
	if code, out := nlqAPI(t, s, b, "/api/ai/query/execute", foreign); code != http.StatusUnprocessableEntity || !strings.Contains(nlqJSON(out), "unknown_entity") {
		t.Fatalf("tenant B naming tenant A's device must be unknown_entity: %d %v", code, out)
	}

	// The question compiles to the liveness query in the caller's scope.
	code, out = nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"which devices are down right now?"}`)
	if code != http.StatusOK || !strings.Contains(nlqJSON(out["ast"]), `"field":"reachability"`) {
		t.Fatalf("the liveness question must compile: %d %v", code, out)
	}
	if _, out := nlqAPI(t, s, b, "/api/ai/query/compile", `{"question":"is edge-a up?"}`); strings.Contains(nlqJSON(out["ast"]), "dev-a") {
		t.Fatalf("tenant B's question about tenant A's device name must not resolve it: %v", out)
	}
}
