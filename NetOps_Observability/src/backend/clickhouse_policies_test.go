package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func reqWithClaims(c jwtClaims) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/flows/top", nil)
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
}

// TestChTenantScope locks down the security-critical mapping from a caller to the
// ClickHouse tenant_scope the row policies enforce. Getting this wrong is a
// cross-tenant data leak, so the cases are exhaustive.
func TestChTenantScope(t *testing.T) {
	cases := []struct {
		name  string
		claim *jwtClaims // nil = no claims on the request
		want  string
	}{
		{"platform owner (super-admin, global)", &jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, "__all__"},
		{"platform owner (super-admin, 'global')", &jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal}, "__all__"},
		{"scoped tenant admin", &jwtClaims{Role: "admin", Tenant: "acme"}, "acme"},
		// The key one: a tenant's OWN super-admin is NOT cross-tenant — must be
		// confined to its tenant, never '__all__'.
		{"tenant super-admin (scoped)", &jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}, "acme"},
		{"viewer in tenant", &jwtClaims{Role: "viewer", Tenant: "globex"}, "globex"},
		// Fail-closed cases — see only untagged rows, never another tenant's.
		{"empty tenant, not cross", &jwtClaims{Role: "viewer", Tenant: ""}, "__none__"},
	}
	for _, c := range cases {
		var r *http.Request
		if c.claim != nil {
			r = reqWithClaims(*c.claim)
		} else {
			r = httptest.NewRequest(http.MethodGet, "/api/flows/top", nil)
		}
		if got := chTenantScope(r); got != c.want {
			t.Errorf("%s: chTenantScope = %q, want %q", c.name, got, c.want)
		}
	}

	// No claims at all (should never reach an authed handler) → fail closed.
	if got := chTenantScope(httptest.NewRequest(http.MethodGet, "/api/flows/top", nil)); got != "__none__" {
		t.Errorf("no-claims request scope = %q, want __none__ (fail closed)", got)
	}
}
