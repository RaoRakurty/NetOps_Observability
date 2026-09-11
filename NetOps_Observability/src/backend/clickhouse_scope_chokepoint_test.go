// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// clickhouse_scope_chokepoint_test.go — the ClickHouse lane's §3a invariant.
//
// Thirty request-serving reads derive their ClickHouse tenant_scope, across the
// correlation family, RCA, time intelligence, verify, cloud, ticketing and the
// assistant's seams. Teaching thirty call sites about the operator-visibility
// restriction would have left thirty places to forget it, and the thirty-first
// would have started wrong.
//
// So the restriction is folded into the derivation itself: s.chTenantScopeFor
// hands an operator that scoped INTO a restricted tenant the read-nothing
// scope, and every corr_*/rca_*/cloud_* STRICT row policy enforces that
// server-side. This test pins that the PURE rule, chScopeRule, stays unreachable
// from anywhere else — because a lane that called it directly would get the
// scope and skip the compliance overlay, which is exactly the drift the metrics
// lane had.

import (
	"regexp"
	"strings"
	"testing"
)

const chScopeChokepointFile = "clickhouse_client.go"

func TestClickHouseScopeIsDerivedOnlyAtTheChokepoint(t *testing.T) {
	sources := packageGoSources(t)
	seen := 0
	for file, lines := range sources {
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.Contains(trimmed, "func chScopeRule(") {
				continue
			}
			if !regexp.MustCompile(`\bchScopeRule\(`).MatchString(line) {
				continue
			}
			seen++
			if file != chScopeChokepointFile {
				t.Errorf("%s:%d calls chScopeRule directly.\n"+
					"  %s\n"+
					"  That is the PURE principal-to-scope rule: it knows nothing about the\n"+
					"  operator-visibility restriction, so this read serves a restricted tenant's\n"+
					"  rows to an operator who scoped into it. Call s.chTenantScopeFor(claims)\n"+
					"  (or s.chTenantScope(r)) instead.", file, i+1, trimmed)
			}
		}
	}
	if seen == 0 {
		t.Error("the sweep found no call to chScopeRule — its regex has drifted away from the code and this guard proves nothing")
	}
}

// The chokepoint's own answers, pinned.
func TestChTenantScopeForFoldsTheRestriction(t *testing.T) {
	s, acme, globex := restrictionFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// Nothing restricted yet: unchanged from the pure rule everywhere.
	for _, c := range []jwtClaims{owner, ownerActing(owner, acme), {Sub: "a", Role: RoleOperator, Tenant: acme}} {
		if got, want := s.chTenantScopeFor(c), chScopeRule(c); got != want {
			t.Fatalf("with nothing restricted the scope must be the pure rule: got %q want %q", got, want)
		}
	}

	if _, err := s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// The operator walking in with as_tenant reads NOTHING.
	if got := s.chTenantScopeFor(ownerActing(owner, acme)); got != chScopeNone {
		t.Fatalf("operator scoped INTO a restricted tenant: scope = %q, want %q", got, chScopeNone)
	}
	// The Global view stays '__all__' — the exclusion for that half is in the
	// SQL, because the row-policy grammar has no "all except".
	if got := s.chTenantScopeFor(owner); got != "__all__" {
		t.Fatalf("the Global view must stay __all__, got %q", got)
	}
	// The unrestricted tenant is untouched.
	if got := s.chTenantScopeFor(ownerActing(owner, globex)); got != globex {
		t.Fatalf("as_tenant into an unrestricted tenant: scope = %q, want %q", got, globex)
	}
	// The restricted tenant's OWN users still read their own rows.
	if got := s.chTenantScopeFor(jwtClaims{Sub: "a", Role: RoleOperator, Tenant: acme}); got != acme {
		t.Fatalf("the tenant's own user: scope = %q, want %q", got, acme)
	}
}

// The Global-half exclusion fragment.
func TestTenantIDExcludeCondForNamesOnlyRestrictedTenants(t *testing.T) {
	s, acme, globex := restrictionFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	if got := s.tenantIDExcludeCondFor(owner, "tenant_id"); got != "" {
		t.Fatalf("nothing restricted must yield no condition, got %q", got)
	}
	if _, err := s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
	got := s.tenantIDExcludeCondFor(owner, "tenant_id")
	if !strings.Contains(got, "tenant_id NOT IN ('"+acme+"')") {
		t.Fatalf("the Global view must exclude acme, got %q", got)
	}
	if strings.Contains(got, globex) {
		t.Fatalf("globex is not restricted and must not be excluded, got %q", got)
	}
	// A denied caller needs no fragment: the read-nothing scope already answered.
	if got := s.tenantIDExcludeCondFor(ownerActing(owner, acme), "tenant_id"); got != "" {
		t.Fatalf("a denied caller is answered by the scope, not a fragment, got %q", got)
	}
	// A tenant's own user is never given an exclusion.
	if got := s.tenantIDExcludeCondFor(jwtClaims{Sub: "a", Role: RoleOperator, Tenant: acme}, "tenant_id"); got != "" {
		t.Fatalf("the tenant's own user must never be restricted, got %q", got)
	}
}
