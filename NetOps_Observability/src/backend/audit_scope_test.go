package main

import (
	"testing"
	"time"
)

// TestScopedAuditVisibility (PBAC Phase E): an org-admin sees the audit events of
// every tenant in its org — but not other orgs', and not platform/global events;
// the platform owner sees all; a tenant admin sees only its own.
func TestScopedAuditVisibility(t *testing.T) {
	s := newPBACTestServer(t)
	au, err := newAuditStore(t.TempDir() + "/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	s.audit = au
	seed := seedOrgTenants(t, s) // org acme-corp{acme-prod,acme-dev} + globex (global org)

	// boss administers acme-corp (bind by slug → canonicalizes to the opaque org id).
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: "boss", RoleID: "org-admin", ScopeID: scopeOrg("acme-corp")}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	rec := func(tenant string, i int) {
		au.Record(AuditEvent{Time: now.Add(time.Duration(i) * time.Second), Tenant: tenant, Method: "POST", Path: "/api/test", Actor: "x"})
	}
	// Events are tagged with the OPAQUE tenant id (as the audit middleware records
	// the actor's resolved tenant).
	rec(seed.acmeProd, 1)
	rec(seed.acmeDev, 2)
	rec(seed.globex, 3)  // different org
	rec(TenantGlobal, 4) // platform/global

	count := func(claims jwtClaims) (perTenant map[string]int) {
		perTenant = map[string]int{}
		for _, e := range auditScoped(t, s, claims, auditQuery{Limit: 100}) {
			perTenant[e.Tenant]++
		}
		return
	}

	// Org-admin: acme-prod + acme-dev only.
	boss := count(jwtClaims{Sub: "boss", Role: RoleOrgAdmin, Tenant: seed.acmeProd})
	if boss[seed.acmeProd] != 1 || boss[seed.acmeDev] != 1 {
		t.Errorf("org-admin should see its org's tenants, got %v", boss)
	}
	if boss[seed.globex] != 0 || boss[TenantGlobal] != 0 {
		t.Errorf("org-admin must NOT see other orgs / global events, got %v", boss)
	}

	// Platform owner: everything.
	owner := count(jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal})
	if len(owner) < 4 || owner[seed.globex] != 1 || owner[TenantGlobal] != 1 {
		t.Errorf("platform owner should see all events, got %v", owner)
	}

	// Tenant admin: only its own tenant.
	ta := count(jwtClaims{Sub: "u", Role: RoleSuperAdmin, Tenant: seed.globex})
	if ta[seed.globex] != 1 || ta[seed.acmeProd] != 0 {
		t.Errorf("tenant admin should see only its own tenant, got %v", ta)
	}
}

// auditList / auditScoped unwrap the (events, error) pairs F-73 introduced. A
// test that ignored the error would be the very shape the finding was about.
func auditList(t *testing.T, s *server, tenant string, cross bool, q auditQuery) []AuditEvent {
	t.Helper()
	events, err := s.audit.List(tenant, cross, q)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	return events
}

func auditScoped(t *testing.T, s *server, claims jwtClaims, q auditQuery) []AuditEvent {
	t.Helper()
	events, err := s.auditScopedList(claims, q)
	if err != nil {
		t.Fatalf("scoped audit list: %v", err)
	}
	return events
}
