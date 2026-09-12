// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// ch_scope_isolation_test.go — the CLAUDE.md §3a rule-5 isolation test for the
// ClickHouse scope this package reads under.
//
// The scope used to be derived by a Deps hook that package backend handed in,
// and that hook could only see Principal.Tenant and Principal.Cross — so the
// only thing it could do was write the tenant/cross rule out again:
//
//	if p.Cross { return "__all__" }
//	if p.Tenant == "" { return "__none__" }
//	return p.Tenant
//
// That is chScopeRule's body, the PURE rule with no compliance overlay. A
// platform admin who scoped INTO a tenant that had switched the
// operator-visibility restriction on therefore read that tenant's
// corr_evidence and flow rows anyway, because the overlay lives in
// s.chTenantScopeFor and the hand-rolled copy never reached it.
//
// The scope is now DERIVED BY THE CALLER at that chokepoint and carried on the
// principal, so there is nothing here left to hand-roll. These tests pin the
// two properties that makes the seam safe: the scope on the wire is the one the
// caller derived (never one this package reconstructed), and an ABSENT scope
// fails closed rather than reading unscoped.

import (
	"strings"
	"testing"
)

// The scope that reaches ClickHouse is the caller's derived scope verbatim —
// including the read-nothing sentinel a denied operator is handed, which a rule
// reconstructed from (Tenant, Cross) could never have produced.
func TestClickHouseReadsCarryTheCallersDerivedScopeVerbatim(t *testing.T) {
	cases := []struct {
		name string
		p    Principal
	}{
		{"platform owner, nothing restricted", Principal{Subject: "root", Cross: true, CHScope: "__all__"}},
		{"scoped tenant", Principal{Subject: "a", Tenant: "t_acme", CHScope: "t_acme"}},
		// The one a re-typed rule gets WRONG: the principal still looks like an
		// ordinary as_tenant caller (Tenant set, Cross false), and only the
		// chokepoint knows that tenant is restricted.
		{"operator scoped INTO a restricted tenant", Principal{Subject: "root", Tenant: "t_acme", CHScope: "__none__"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, stage := range []string{"clickhouse", "correlation"} {
				f := newFakeBackend()
				f.principal = tc.p
				api := New(f.deps())
				path := "/api/debug/stage/" + stage + "?marker=" + testMarker
				if stage == "clickhouse" {
					path += "&kind=flow"
				}
				stageOf(t, api, path)
				seen := f.snap().chSeen
				if len(seen) != 1 {
					t.Fatalf("%s stage issued %d ClickHouse reads, want 1 — this test proves nothing", stage, len(seen))
				}
				if got, _, _ := strings.Cut(seen[0], "|"); got != tc.p.CHScope {
					t.Errorf("ISOLATION LEAK: the %s stage read at scope %q, want the caller's derived %q",
						stage, got, tc.p.CHScope)
				}
			}
		})
	}
}

// An absent scope must read NOTHING, not everything. A caller that failed to
// derive a scope is a bug, and the safe interpretation of a bug is refusal —
// the honest NOT-OBSERVABLE verdict this package already uses for a missing
// client, never a silent unscoped query.
func TestAnAbsentScopeFailsClosedRatherThanReadingUnscoped(t *testing.T) {
	for _, stage := range []string{"clickhouse", "correlation"} {
		f := newFakeBackend()
		f.principal = Principal{Subject: "root", Tenant: "t_acme"} // no CHScope
		api := New(f.deps())
		path := "/api/debug/stage/" + stage + "?marker=" + testMarker
		if stage == "clickhouse" {
			path += "&kind=flow"
		}
		e := stageOf(t, api, path)
		if n := len(f.snap().chSeen); n != 0 {
			t.Errorf("ISOLATION LEAK: the %s stage issued %d ClickHouse read(s) with no derived scope: %v",
				stage, n, f.snap().chSeen)
		}
		if e.Verdict != VerdictNotObservable {
			t.Errorf("the %s stage answered %q for a scopeless caller, want %q",
				stage, e.Verdict, VerdictNotObservable)
		}
		if !strings.Contains(e.Reason, "tenant scope") {
			t.Errorf("the %s stage did not name the missing scope as the reason: %q", stage, e.Reason)
		}
	}
}
