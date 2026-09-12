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

// ── The re-typed-rule guard ─────────────────────────────────────────────────
//
// TestClickHouseScopeIsDerivedOnlyAtTheChokepoint above catches a lane that
// CALLS chScopeRule from outside the chokepoint. It does not catch a lane that
// TYPES THE BODY OUT AGAIN, and a real leak walked through that hole: the
// manual ticket path carried
//
//	scope := tenant
//	if cross {
//		scope = "__all__"
//	}
//
// in its own file, so it never reached the compliance overlay the chokepoint
// had grown — and the structural test stayed green the whole time, because no
// identifier it knew about was ever mentioned.
//
// This is the guard for the SHAPE rather than the name. The decision is a
// widening: a cross-tenant flag is consulted and the scope becomes the
// everything sentinel. Wherever those two appear together, package backend has
// exactly one place that is allowed to say it.
//
// SCOPE OF THIS GUARD, stated so the next reader does not over-trust it: it
// sweeps package backend, which is where the chokepoint lives and where every
// bypass found so far lived (the manual ticket path, the Active Verification
// subresource, the pipeline debugger's Deps hook). It does NOT reach the
// subpackages, and there is exactly one derivation out there today —
// pathgraph.ScopeFor, which package pathgraph cannot avoid because it cannot
// import package backend to reach the chokepoint. That one is covered a
// different way: rcaPathSpine resolves the restriction into a pathVisibility
// BEFORE the store is touched, refuses a denied caller outright and filters
// every returned row by the observation's own tenant. That is a discipline at
// the caller rather than a structure at the storage layer, so if a second
// pathgraph reader is ever added it must repeat it — there is no test that
// would notice if it did not.

// chWidenSentinel is the ClickHouse tenant_scope that unlocks every tenant. It
// is the load-bearing half of the rule — the half whose loss is a LEAK — so it
// is what this guard keys on. ('__none__' re-typed elsewhere fails closed and
// is not a disclosure.)
const chWidenSentinel = `"__all__"`

// chCrossFlagPattern matches a line that BRANCHES on a cross-tenant flag: the
// local `cross` / `crossTenant` of principalTenant's second return, and the
// field form (`p.Cross`, `spec.Cross`, `v.cross`) a struct-carried principal
// uses. Anchored on `if`/`else if` so a mere mention of the word — a comment
// stripped above, a parameter list, a struct literal — is not a branch.
var chCrossFlagPattern = regexp.MustCompile(`\b(?:if|else if)\b[^{]*\b!?\s*(?:\w+\.)?[Cc]ross(?:Tenant)?\b`)

// chWidenLookbehind is how many preceding non-comment, non-blank lines of the
// same file are searched for the branch. The rule is four lines long at its
// longest (`tenant, cross := …` / `scope := tenant` / `if cross {` / `scope =
// "__all__"`), so three lines of lookbehind reaches the branch from the
// sentinel in every arrangement of it — including the `if !cross { … } else {`
// inversion, where the branch is further away than in the original.
const chWidenLookbehind = 3

func TestChokepointScopeRuleIsNotRetypedOutsideTheChokepoint(t *testing.T) {
	sources := packageGoSources(t)

	scanned, sentinels, chokepointHits := 0, 0, 0
	for file, lines := range sources {
		// The recent non-comment, non-blank lines, most recent last.
		var recent []string
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			scanned++
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(trimmed, chWidenSentinel) {
				sentinels++
				branch, where := "", -1
				for back := len(recent) - 1; back >= 0 && back >= len(recent)-chWidenLookbehind; back-- {
					if chCrossFlagPattern.MatchString(recent[back]) {
						branch, where = recent[back], back
						break
					}
				}
				// The sentinel and the branch can also share one line
				// (`if cross { return "__all__" }`).
				if where < 0 && chCrossFlagPattern.MatchString(trimmed) {
					branch = trimmed
				}
				if branch != "" {
					if file == chScopeChokepointFile {
						chokepointHits++
					} else {
						t.Errorf("%s:%d re-types the ClickHouse scope decision instead of calling the chokepoint.\n"+
							"  %s\n"+
							"  %s\n"+
							"  Branching on a cross-tenant flag to widen the scope to %s IS chScopeRule's\n"+
							"  body. A local copy of it is the PURE rule: it knows nothing about the\n"+
							"  operator-visibility restriction, so this read serves a restricted tenant's\n"+
							"  rows to an operator who scoped into it — and unlike a direct chScopeRule\n"+
							"  call, nothing named gives it away.\n"+
							"  Call s.chTenantScopeFor(claims) (or s.chTenantScope(r)) instead, and pair it\n"+
							"  with s.tenantIDExcludeCondFor(claims, \"tenant_id\") for the Global half the\n"+
							"  scope cannot express. If this read genuinely spans tenants (a background\n"+
							"  worker), pass the sentinel unconditionally — the branch is what makes it a\n"+
							"  principal's scope.",
							file, i+1, strings.TrimSpace(branch), trimmed, chWidenSentinel)
					}
				}
			}
			recent = append(recent, trimmed)
			if len(recent) > chWidenLookbehind {
				recent = recent[1:]
			}
		}
	}

	// ── Anti-vacuity. A sweep that matches nothing must FAIL, not pass. ──
	//
	// Three separate ways this guard could go quiet, each asserted: no files
	// (packageGoSources already fatals), no lines, no sentinel anywhere in the
	// package, and — the one that actually matters — the detector no longer
	// firing on the SANCTIONED shape. The chokepoint itself writes the rule, so
	// if this scan cannot find it there, the patterns have drifted away from the
	// code and every silent file below is silent for the wrong reason.
	if scanned == 0 {
		t.Fatal("the sweep read no lines — it would pass vacuously")
	}
	if sentinels == 0 {
		t.Fatalf("the sweep found no %s anywhere in the package — the sentinel has been renamed and this guard proves nothing", chWidenSentinel)
	}
	if chokepointHits == 0 {
		t.Fatalf("the sweep did not recognise the rule in %s, the one file that is SUPPOSED to write it.\n"+
			"  Scanned %d lines and %d %s occurrences without matching the chokepoint's own derivation,\n"+
			"  so this guard is passing because it recognises nothing — not because nothing is wrong.\n"+
			"  Re-aim chCrossFlagPattern/chWidenLookbehind at chScopeRule as it is written today.",
			chScopeChokepointFile, scanned, sentinels, chWidenSentinel)
	}
}
