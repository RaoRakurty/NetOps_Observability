// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Infra-stack monitoring is platform-owner-only: a tenant-scoped principal —
// even a tenant super-admin — gets 403, while the cross-tenant platform owner is
// allowed through. (We don't assert component status here; the probes hit the
// network and we only care about the access boundary.)
func TestStackHealthPlatformOwnerOnly(t *testing.T) {
	s := &server{}

	cases := []struct {
		name   string
		claims jwtClaims
		want   int
	}{
		{"tenant operator", jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: "acme"}, http.StatusForbidden},
		{"tenant super-admin", jwtClaims{Sub: "alice", Role: RoleSuperAdmin, Tenant: "acme"}, http.StatusForbidden},
		{"platform owner (global super-admin)", jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}, http.StatusOK},
		{"platform owner (unbound super-admin)", jwtClaims{Sub: "root", Role: RoleSuperAdmin}, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleStackHealth(w, req("GET", "/api/stack/health", "", tc.claims))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// An unauthenticated request (no claims in context) is rejected before any probe.
func TestStackHealthRequiresAuth(t *testing.T) {
	s := &server{}
	w := httptest.NewRecorder()
	s.handleStackHealth(w, httptest.NewRequest("GET", "/api/stack/health", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}
