package rbac

// access_test.go — the deny-wins reachability algorithms over pure fixtures.
// The server-wired conformance suite (Phase A parity, HTTP switcher) stays in
// main; these pin the algorithm's contract at the package boundary.

import (
	"reflect"
	"testing"
	"time"
)

var accNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

// accDir is a two-org fixture directory: org o1 owns t1/t2, org o2 owns t3.
// Slug "acme" resolves to t1; org slug "acme-org" resolves to o1.
func accDir() Directory {
	return Directory{
		ResolveTenantID: func(ref string) (string, bool) {
			if ref == "acme" || ref == "t1" {
				return "t1", true
			}
			for _, id := range []string{"t2", "t3", "global"} {
				if ref == id {
					return id, true
				}
			}
			return "", false
		},
		TenantIDsByOrg: func(orgID string) []string {
			switch orgID {
			case "o1":
				return []string{"t1", "t2"}
			case "o2":
				return []string{"t3"}
			}
			return nil
		},
		CanonicalOrgID: func(ref string) string {
			if ref == "acme-org" || ref == "o1" {
				return "o1"
			}
			return ref
		},
		GlobalTenant: "global",
	}
}

func TestAccessibleTenantsDenyWins(t *testing.T) {
	bs := []RoleBinding{
		{RoleID: RoleOrgAdmin, ScopeID: "org:o1", Effect: EffectAllow},
		{RoleID: RoleReadOnly, ScopeID: "tenant:t2", Effect: EffectDeny},
	}
	got, all := AccessibleTenants(bs, accNow, accDir())
	if all {
		t.Fatalf("all=true for an org-scoped principal")
	}
	if !reflect.DeepEqual(got, []string{"t1"}) {
		t.Fatalf("deny not honored: %v", got)
	}
}

func TestAccessibleTenantsOrgReachNeedsManagerRole(t *testing.T) {
	bs := []RoleBinding{{RoleID: RoleOperator, ScopeID: "org:o1", Effect: EffectAllow}}
	if got, _ := AccessibleTenants(bs, accNow, accDir()); len(got) != 0 {
		t.Fatalf("operator at org scope conferred tenant reach: %v", got)
	}
}

func TestAccessibleTenantsSuperAdminAll(t *testing.T) {
	for _, scope := range []string{"platform", "tenant:global", "tenant:"} {
		bs := []RoleBinding{{RoleID: RoleSuperAdmin, ScopeID: scope, Effect: EffectAllow}}
		if _, all := AccessibleTenants(bs, accNow, accDir()); !all {
			t.Fatalf("super-admin at %q did not reach all", scope)
		}
	}
	// A DENY super-admin binding must not grant all.
	bs := []RoleBinding{{RoleID: RoleSuperAdmin, ScopeID: "platform", Effect: EffectDeny}}
	if _, all := AccessibleTenants(bs, accNow, accDir()); all {
		t.Fatalf("denied super-admin binding granted all")
	}
}

func TestAccessibleTenantsSlugCanonicalizationDedups(t *testing.T) {
	// A legacy slug tenant binding and org-scope reach over the same tenant must
	// produce ONE entry under the opaque id.
	bs := []RoleBinding{
		{RoleID: RoleOrgAdmin, ScopeID: "org:acme-org", Effect: EffectAllow},
		{RoleID: RoleReadOnly, ScopeID: "tenant:acme", Effect: EffectAllow},
	}
	got, _ := AccessibleTenants(bs, accNow, accDir())
	if !reflect.DeepEqual(got, []string{"t1", "t2"}) {
		t.Fatalf("slug did not dedup against org reach: %v", got)
	}
}

func TestAccessibleTenantsGlobalFirstSort(t *testing.T) {
	bs := []RoleBinding{
		{RoleID: RoleReadOnly, ScopeID: "tenant:t3", Effect: EffectAllow},
		{RoleID: RoleReadOnly, ScopeID: "tenant:global", Effect: EffectAllow},
		{RoleID: RoleReadOnly, ScopeID: "tenant:t2", Effect: EffectAllow},
	}
	got, _ := AccessibleTenants(bs, accNow, accDir())
	if !reflect.DeepEqual(got, []string{"global", "t2", "t3"}) {
		t.Fatalf("global-first sort broken: %v", got)
	}
}

func TestAccessibleTenantsExpiryHonored(t *testing.T) {
	past := accNow.Add(-time.Hour)
	bs := []RoleBinding{{RoleID: RoleReadOnly, ScopeID: "tenant:t2", Effect: EffectAllow, ExpiresAt: &past}}
	if got, _ := AccessibleTenants(bs, accNow, accDir()); len(got) != 0 {
		t.Fatalf("expired binding conferred reach: %v", got)
	}
}

func TestReachesTenantDenyWins(t *testing.T) {
	ancestor := func(a, d string) bool { return a == d || a == "org:o1" && d == "tenant:t1" }
	allow := []RoleBinding{{RoleID: RoleReadOnly, ScopeID: "tenant:t1", Effect: EffectAllow}}
	if !ReachesTenant(allow, accNow, "t1", ancestor) {
		t.Fatalf("direct tenant allow did not reach")
	}
	denied := append(allow, RoleBinding{RoleID: RoleOrgAdmin, ScopeID: "org:o1", Effect: EffectDeny})
	if ReachesTenant(denied, accNow, "t1", ancestor) {
		t.Fatalf("covering org deny did not win")
	}
	// Org-scope allow requires a manager-grade role.
	opOnly := []RoleBinding{{RoleID: RoleOperator, ScopeID: "org:o1", Effect: EffectAllow}}
	if ReachesTenant(opOnly, accNow, "t1", ancestor) {
		t.Fatalf("operator org binding conferred reach")
	}
	if ReachesTenant(allow, accNow, "t1", nil) {
		t.Fatalf("nil walker must fail closed")
	}
}

func TestCanManageBindingNoEscalation(t *testing.T) {
	orgOf := func(scopeID string) string {
		if scopeID == "tenant:t1" || scopeID == "org:o1" {
			return "o1"
		}
		return "o9"
	}
	isAdmin := func(orgID string) bool { return orgID == "o1" }

	if ok, _ := CanManageBinding(true, "platform", RoleSuperAdmin, nil, nil); !ok {
		t.Fatalf("platform owner refused")
	}
	if ok, why := CanManageBinding(false, "platform", RoleReadOnly, orgOf, isAdmin); ok || why != "platform-scope bindings require the platform owner" {
		t.Fatalf("platform scope allowed for non-owner: %v %q", ok, why)
	}
	for _, role := range []string{RoleSuperAdmin, "admin", "SUPER-ADMIN"} {
		if ok, _ := CanManageBinding(false, "org:o1", role, orgOf, isAdmin); ok {
			t.Fatalf("org-admin granted super-admin (%q)", role)
		}
	}
	if ok, _ := CanManageBinding(false, "tenant:t1", RoleReadOnly, orgOf, isAdmin); !ok {
		t.Fatalf("org-admin refused within own org")
	}
	if ok, _ := CanManageBinding(false, "tenant:t9", RoleReadOnly, orgOf, isAdmin); ok {
		t.Fatalf("org-admin allowed outside own org")
	}
	if ok, _ := CanManageBinding(false, "org:o1", RoleReadOnly, nil, nil); ok {
		t.Fatalf("nil closures must fail closed")
	}
	empty := func(string) string { return "" }
	if ok, _ := CanManageBinding(false, "org:o1", RoleReadOnly, empty, isAdmin); ok {
		t.Fatalf("empty org resolution must fail closed")
	}
}

func TestOrgAdminOrgsCanonicalizedSorted(t *testing.T) {
	bs := []RoleBinding{
		{RoleID: RoleOrgAdmin, ScopeID: "org:acme-org", Effect: EffectAllow}, // → o1
		{RoleID: RoleOrgAdmin, ScopeID: "org:o2", Effect: EffectAllow},
		{RoleID: RoleOrgAdmin, ScopeID: "org:o1", Effect: EffectAllow}, // dup of acme-org
		{RoleID: RoleOperator, ScopeID: "org:o3", Effect: EffectAllow}, // not manager
		{RoleID: RoleOrgAdmin, ScopeID: "org:o4", Effect: EffectDeny},  // deny ≠ admin
	}
	got := OrgAdminOrgs(bs, accNow, accDir())
	if !reflect.DeepEqual(got, []string{"o1", "o2"}) {
		t.Fatalf("org admin set wrong: %v", got)
	}
}
