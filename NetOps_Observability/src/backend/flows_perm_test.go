// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// One module gate for the whole flow plane (2026-11-12, Flows page redesign P1).
//
// Before this, the nine /api/flows/* analytics handlers were registered with
// withAuth only — no requirePerm — while /api/flows/apps and /api/flows/services
// asked for infrastructure:read and Iris mapped flows:read to explore. So a
// principal holding NO grant (the zero-permission ingest role, whose key is
// served inside a public web page) could read every flow conversation. These
// tests pin the fix: every flow handler answers 403 to a principal without
// explore:read, BEFORE any query runs, and serves a principal that holds it.
// Tenant scoping is untouched and pinned elsewhere (flows_test.go,
// flows_apps_isolation_test.go, flows_iface_names_isolation_test.go).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/rbac"
)

type flowRoute struct {
	path string
	h    func(s *server) http.HandlerFunc
	// okStatus is what an allowed caller gets with the fixture server: 200,
	// except services, which has no catalog store here and answers 501 — past
	// the gate, which is what this test is about.
	okStatus int
}

func flowRoutes() []flowRoute {
	return []flowRoute{
		{"/api/flows/top", func(s *server) http.HandlerFunc { return s.handleFlowsTopTalkers }, http.StatusOK},
		{"/api/flows/topn?by=in_if", func(s *server) http.HandlerFunc { return s.handleFlowsTopN }, http.StatusOK},
		{"/api/flows/timeseries", func(s *server) http.HandlerFunc { return s.handleFlowsTimeseries }, http.StatusOK},
		{"/api/flows/by-proto", func(s *server) http.HandlerFunc { return s.handleFlowsByProto }, http.StatusOK},
		{"/api/flows/by-type", func(s *server) http.HandlerFunc { return s.handleFlowsByType }, http.StatusOK},
		{"/api/flows/flags", func(s *server) http.HandlerFunc { return s.handleFlowsFlags }, http.StatusOK},
		{"/api/flows/geo", func(s *server) http.HandlerFunc { return s.handleFlowsGeo }, http.StatusOK},
		{"/api/flows/coverage", func(s *server) http.HandlerFunc { return s.handleFlowsCoverage }, http.StatusOK},
		{"/api/flows/fanout", func(s *server) http.HandlerFunc { return s.handleFlowsFanout }, http.StatusOK},
		{"/api/flows/apps", func(s *server) http.HandlerFunc { return s.handleFlowsApps }, http.StatusOK},
		{"/api/flows/services", func(s *server) http.HandlerFunc { return s.handleFlowsServices }, http.StatusNotImplemented},
		{"/api/flows/links", func(s *server) http.HandlerFunc { return s.handleFlowsLinks }, http.StatusOK},
		{"/api/flows/links/series?device=10.1.0.1&if=7", func(s *server) http.HandlerFunc { return s.handleFlowsLinkSeries }, http.StatusOK},
		{"/api/flows/links/movers?device=10.1.0.1&if=7", func(s *server) http.HandlerFunc { return s.handleFlowsLinkMovers }, http.StatusOK},
	}
}

// flowsPermServer is the flows fixture plus a custom role that can read the
// infrastructure area but NOT Explore — the grant apps/services used to accept.
func flowsPermServer(t *testing.T) *server {
	t.Helper()
	s := flowsAppsTestServer(t)
	if _, err := s.roles.Upsert(rbac.Role{
		ID: "infra-reader", Name: "Infra reader",
		Permissions: map[string]int{"infrastructure": LevelRead, "explore": LevelNone},
	}); err != nil {
		t.Fatalf("upsert role: %v", err)
	}
	return s
}

func TestFlowHandlersRefuseCallerWithoutExploreRead(t *testing.T) {
	denied := map[string]jwtClaims{
		"ingest (no grant at all)":       {Sub: "rum-key", Role: RoleIngest, Tenant: "acme"},
		"infrastructure without explore": {Sub: "i@acme", Role: "infra-reader", Tenant: "acme"},
		"unknown role":                   {Sub: "x@acme", Role: "no-such-role", Tenant: "acme"},
	}
	for who, claims := range denied {
		for _, rt := range flowRoutes() {
			calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
			s := flowsPermServer(t)
			w := httptest.NewRecorder()
			rt.h(s)(w, req(http.MethodGet, rt.path, "", claims))
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s: status %d, want 403 (body %s)", who, rt.path, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "explore read permission required") {
				t.Errorf("%s %s: refusal must name the module, got %s", who, rt.path, w.Body.String())
			}
			if n := len(*calls); n != 0 {
				t.Errorf("%s %s: %d queries ran before the refusal, want 0", who, rt.path, n)
			}
		}
	}
}

func TestFlowHandlersServeCallerWithExploreRead(t *testing.T) {
	allowed := map[string]jwtClaims{
		"read-only (scoped)":  {Sub: "r@acme", Role: RoleReadOnly, Tenant: "acme"},
		"operator (scoped)":   acme(),
		"api client (scoped)": {Sub: "svc@acme", Role: RoleAPIClient, Tenant: "acme"},
		"super-admin":         superA(),
	}
	for who, claims := range allowed {
		for _, rt := range flowRoutes() {
			calls := fakeCHScoped(t, `{"meta":[],"data":[{"k":"x"}],"rows":1}`)
			s := flowsPermServer(t)
			w := httptest.NewRecorder()
			rt.h(s)(w, req(http.MethodGet, rt.path, "", claims))
			if w.Code != rt.okStatus {
				t.Errorf("%s %s: status %d, want %d (body %s)", who, rt.path, w.Code, rt.okStatus, w.Body.String())
				continue
			}
			if rt.okStatus != http.StatusOK {
				continue // services: past the gate, no catalog in this fixture
			}
			if len(*calls) == 0 {
				t.Errorf("%s %s: allowed caller got no query", who, rt.path)
			}
			// The scoped caller's queries still carry its tenant clause: the gate
			// adds a refusal, it never replaces scoping.
			if claims.Tenant == "acme" {
				for _, c := range *calls {
					if strings.Contains(c.sql, "netops.flows") && !strings.Contains(c.sql, "10.1.0.1") {
						t.Errorf("%s %s: scoped query lost its tenant clause:\n%s", who, rt.path, c.sql)
					}
				}
			}
		}
	}
}

// The gate is the Explore module, the same one the Logs page and Iris's
// flows:read use — one answer for "may this caller read flows".
func TestFlowsReadModuleIsExplore(t *testing.T) {
	if flowsReadModule != logsReadModule {
		t.Fatalf("flowsReadModule = %q, logsReadModule = %q: Explore pages must share one gate", flowsReadModule, logsReadModule)
	}
	s := flowsPermServer(t)
	p := s.aiPrincipal(jwtClaims{Sub: "i@acme", Role: "infra-reader", Tenant: "acme"})
	if p.Perms["flows:read"] {
		t.Fatal("Iris flows:read must follow the same module as the HTTP gate")
	}
}
