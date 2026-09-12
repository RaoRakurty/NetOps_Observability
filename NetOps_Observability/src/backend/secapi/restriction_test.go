// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secapi

// restriction_test.go — the unit half of the operator-visibility restriction on
// this plane. The end-to-end half (every route, through the real wiring and a
// real tenant store) is security_findings_restriction_test.go in package
// backend; these are the three primitives it rests on, pinned where they can be
// read without a server:
//
//   - the principal a denied read is answered under,
//   - the OpenSearch clause the Global view carries,
//   - the SQL predicate the Postgres control plane carries, which no test can
//     reach without a database.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrincipalExcluded(t *testing.T) {
	p := Principal{Cross: true, ExcludeTenants: []string{"  T_ACME  ", ""}}
	if !p.Excluded("t_acme") {
		t.Error("a restricted tenant must be excluded; the two ids are minted by different stores, so the match is case- and space-insensitive")
	}
	if p.Excluded("t_globex") {
		t.Error("an unrestricted tenant must not be excluded")
	}
	if p.Excluded("") {
		t.Error("an unowned row is not a restricted tenant's row")
	}
	if (Principal{Cross: true}).Excluded("t_acme") {
		t.Error("with nothing restricted the rule is a no-op, which is every normal deployment")
	}
}

// A denied principal owns nothing: no tenant, no cross-tenant grant, and no
// device keys that could match an untagged document.
func TestRestrictedPrincipalOwnsNothing(t *testing.T) {
	p := Principal{
		Tenant: "t_acme", Cross: true, Subject: "root",
		DeviceKeys: []string{"acme-core"}, DeviceAddrs: []string{"10.1.0.1"},
		Deny: true, ExcludeTenants: []string{"t_acme"},
	}.restricted()

	if p.Tenant != RestrictedScope || p.Cross {
		t.Fatalf("restricted principal = %+v, want the sentinel scope and no cross-tenant grant", p)
	}
	if len(p.DeviceKeys) != 0 || len(p.DeviceAddrs) != 0 {
		t.Errorf("restricted principal kept device identifiers %v/%v — they would match untagged documents", p.DeviceKeys, p.DeviceAddrs)
	}
	if !p.Deny {
		t.Error("Deny must survive: the exposure stories and the posture denominator read it, not scope()")
	}
	if p.Subject != "root" {
		t.Error("the actor is still the actor — audit must not lose who asked")
	}

	index, clause := scope(p)
	if !strings.Contains(index, RestrictedScope) || strings.Contains(index, "t_acme") {
		t.Errorf("denied index pattern = %q, want the scope that owns nothing and nothing of acme's", index)
	}
	raw, err := json.Marshal(clause)
	if err != nil {
		t.Fatalf("marshal clause: %v", err)
	}
	if strings.Contains(string(raw), "acme") {
		t.Errorf("denied tenant clause names acme: %s", raw)
	}
	if !strings.Contains(string(raw), `"match_none"`) {
		t.Errorf("denied tenant clause does not close the untagged branch: %s", raw)
	}
}

// The Global (cross-tenant) view carries NO per-doc tenant clause by design, so
// the exclusion has to stand on its own — and it must still be ANDed under the
// tenant clause when one is present.
func TestScopeExcludesRestrictedTenants(t *testing.T) {
	_, clause := scope(Principal{Tenant: TenantGlobalScope, Cross: true, ExcludeTenants: []string{"T_Acme"}})
	raw, err := json.Marshal(clause)
	if err != nil {
		t.Fatalf("marshal clause: %v", err)
	}
	if !strings.Contains(string(raw), `"must_not":[{"terms":{"tenant_id":["t_acme"]}}]`) {
		t.Fatalf("the Global clause does not exclude the restricted tenant: %s", raw)
	}

	_, scoped := scope(Principal{Tenant: "t_globex", ExcludeTenants: []string{"t_acme"}, DeviceKeys: []string{"globex-core"}})
	rawScoped, err := json.Marshal(scoped)
	if err != nil {
		t.Fatalf("marshal scoped clause: %v", err)
	}
	if !strings.Contains(string(rawScoped), `"must_not"`) || !strings.Contains(string(rawScoped), `"filter"`) {
		t.Fatalf("a scoped caller's clause lost either the tenant boundary or the exclusion: %s", rawScoped)
	}

	if _, none := scope(Principal{Tenant: "t_globex"}); none == nil {
		t.Fatal("a scoped caller must still carry the per-doc tenant clause when nothing is restricted")
	}
}

// TenantGlobalScope is the platform tenant's id as this package sees it. It is
// spelled here rather than imported: package backend owns the constant, and this
// package must not depend on it to state what a cross-tenant caller looks like.
const TenantGlobalScope = "global"

// The Postgres control plane's exclusion is a BOUND parameter, never an
// interpolated id, and it is absent entirely when nothing is restricted — so
// the normal deployment runs the query it always ran.
func TestExcludeSQL(t *testing.T) {
	base := `SELECT rule_id, enabled FROM security_rule_state`

	sql, args := excludeSQL(base, Principal{Tenant: "t_acme"})
	if sql != base || args != nil {
		t.Fatalf("unrestricted read = %q with %v, want the query untouched", sql, args)
	}

	sql, args = excludeSQL(base, Principal{Cross: true, ExcludeTenants: []string{" T_Acme ", ""}})
	if !strings.HasSuffix(sql, ` WHERE tenant_id <> ALL($1::text[])`) {
		t.Fatalf("restricted read = %q, want the tenant_id exclusion", sql)
	}
	if strings.Contains(sql, "acme") {
		t.Fatalf("the tenant id was interpolated into the SQL: %q", sql)
	}
	if len(args) != 1 {
		t.Fatalf("args = %v, want exactly the exclusion list", args)
	}
	ids, ok := args[0].([]string)
	if !ok || len(ids) != 1 || ids[0] != "t_acme" {
		t.Fatalf("bound exclusion = %#v, want the normalized [t_acme]", args[0])
	}
}

// The store itself hides a restricted tenant's rows from a cross-tenant read —
// §3a rule 4: the storage layer enforces it, not only the handler above it.
func TestFileStoreHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	rule := Catalog()[0].RuleID
	if err := s.SetRuleStates(ctx, "t_acme", false, "t_acme", []RuleState{{RuleID: rule, Enabled: false}}); err != nil {
		t.Fatalf("seed acme rule: %v", err)
	}
	if _, err := s.AddView(ctx, "t_acme", false, SavedView{TenantID: "t_acme", Name: "Acme PCI gaps"}); err != nil {
		t.Fatalf("seed acme view: %v", err)
	}
	if _, err := s.AddView(ctx, "t_globex", false, SavedView{TenantID: "t_globex", Name: "Globex baseline"}); err != nil {
		t.Fatalf("seed globex view: %v", err)
	}

	platform := Principal{Tenant: TenantGlobalScope, Cross: true}
	if views, _ := s.Views(ctx, platform); len(views) != 2 {
		t.Fatalf("baseline: the platform view holds %d saved views, want both", len(views))
	}

	restricted := Principal{Tenant: TenantGlobalScope, Cross: true, ExcludeTenants: []string{"t_acme"}}
	views, err := s.Views(ctx, restricted)
	if err != nil {
		t.Fatalf("views: %v", err)
	}
	if len(views) != 1 || views[0].Name != "Globex baseline" {
		t.Fatalf("RESTRICTION LEAK: the platform view still holds %+v, want globex's alone", views)
	}
	states, err := s.RuleStates(ctx, restricted)
	if err != nil {
		t.Fatalf("rule states: %v", err)
	}
	if _, ok := states[rule]; ok {
		t.Fatalf("RESTRICTION LEAK: the platform view still reports acme's override for %q", rule)
	}
	// The denied principal owns no row, so it reads nothing without the store
	// having to know what a restriction is.
	if views, _ := s.Views(ctx, Principal{Tenant: RestrictedScope}); len(views) != 0 {
		t.Fatalf("the restricted scope owns %d saved views, want none", len(views))
	}
	// And acme's own user is never restricted from acme's own state.
	if views, _ := s.Views(ctx, Principal{Tenant: "t_acme"}); len(views) != 1 {
		t.Fatalf("acme's own user reads %d of its own saved views, want 1", len(views))
	}
}

func TestFrameworkFileStoreHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	ctx := context.Background()
	s := NewFrameworkFileStore("")
	if err := s.SetFrameworkStates(ctx, "t_acme", false, "t_acme",
		[]FrameworkState{{FrameworkID: "hipaa-security-rule", Enabled: true}}); err != nil {
		t.Fatalf("seed acme: %v", err)
	}
	platform := Principal{Tenant: TenantGlobalScope, Cross: true}
	if states, configured, _ := s.FrameworkStates(ctx, platform); !configured || !states["hipaa-security-rule"] {
		t.Fatal("baseline: the platform view does not see acme's selection at all")
	}
	states, configured, err := s.FrameworkStates(ctx, Principal{Tenant: TenantGlobalScope, Cross: true, ExcludeTenants: []string{"t_acme"}})
	if err != nil {
		t.Fatalf("framework states: %v", err)
	}
	if configured || states["hipaa-security-rule"] {
		t.Fatalf("RESTRICTION LEAK: the platform view still reports acme's HIPAA selection: %v (configured=%v)", states, configured)
	}
}
