package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/cloud"
)

// ── Tenant isolation (CLAUDE.md §3a) ─────────────────────────────────────────
// The service-map read surface is scoped by the CALLER's principal: the scope
// literal is what the corr_signals FORCE row policy enforces on, a request
// without claims fails closed, and no query reaches ClickHouse unscoped or
// unbounded. Mirrors the cloud_signals_test.go isolation contract. (The pure
// graph-builder and SQL-contract suites live in cloud/service_map_test.go.)
func TestServiceMapQueriesAreTenantScoped(t *testing.T) {
	scopeFor := func(c *jwtClaims) string {
		r := httptest.NewRequest(http.MethodGet, "/api/cloud/service-map", nil)
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), userCtxKey, *c))
		}
		return cloud.SafeScopeLiteral(chTenantScope(r))
	}
	cases := []struct {
		name  string
		claim *jwtClaims
		want  string
	}{
		{"platform owner", &jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, "__all__"},
		{"tenant admin", &jwtClaims{Role: "admin", Tenant: "acme"}, "acme"},
		{"tenant super-admin is NOT cross-tenant", &jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}, "acme"},
		{"no claims fails closed", nil, "__none__"},
		{"tenantless viewer fails closed", &jwtClaims{Role: "viewer", Tenant: ""}, "__none__"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := scopeFor(tc.claim)
			if scope != tc.want {
				t.Fatalf("scope = %q, want %q", scope, tc.want)
			}
			for _, q := range []string{
				cloud.ServiceMapPairSQL(24, cloud.ServiceMapMaxPairRows, scope),
				cloud.ServiceMapRejectSQL(24, cloud.ServiceMapMaxRejectRows, scope),
			} {
				if !strings.Contains(q, "SETTINGS tenant_scope = '"+tc.want+"'") {
					t.Fatalf("query is not scoped to %q:\n%s", tc.want, q)
				}
				if tc.want == "acme" && strings.Contains(q, "globex") {
					t.Fatalf("query leaked another tenant:\n%s", q)
				}
				// bounded by construction (§9 / #100 read budgets)
				if !strings.Contains(q, "LIMIT") || !strings.Contains(q, "INTERVAL") {
					t.Fatalf("query is unbounded:\n%s", q)
				}
				if strings.Contains(q, "SELECT *") {
					t.Fatalf("query must name its columns (#100 contract):\n%s", q)
				}
			}
		})
	}
}
