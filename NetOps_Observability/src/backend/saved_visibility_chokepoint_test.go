// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// saved_visibility_chokepoint_test.go — the structural guard that keeps the
// saved-object rule whole. The sibling of
// TestAlertTenancyRuleIsNotCalledOutsideTheChokepoint, aimed at the same failure
// for the same reason.
//
// Correlix has two rules on a saved object. canSeeSavedTenantOnly /
// canMutateSavedTenantOnly answer TENANCY: may this caller's tenant see or
// change this object? savedVisibility.visible / .mutable answer that PLUS the
// per-tenant operator-visibility restriction (Tenant.OperatorRestricted), which
// says platform staff may administer a restricted tenant but must not read its
// data.
//
// The tenancy-only halves are not a surface's answer, and the failure mode is
// that they LOOK like one: they return true for everything on the cross-tenant
// path — correctly, the platform owner may see every tenant — so a surface that
// calls one passes ordinary tenant-isolation tests and silently serves the one
// class of tenant that asked not to be readable. visibleSaved did not even ask
// them cross-tenant: it returned the whole store (tracker 306), so GET
// /api/saved, GET/PUT/DELETE /api/saved/{id} and the omnibox all handed over a
// restricted tenant's saved searches, dashboards and report definitions — query
// text, panel definitions, schedules and the recipient contact points inside a
// report body — and the writes renamed and deleted them.
//
// So the rule is structural, not a convention: each tenancy-only half is called
// in ONE place, inside savedVisibility, and this test fails the build on a
// second.

import (
	"regexp"
	"strings"
	"testing"
)

// savedRuleChokepointFile is the file allowed to call the tenancy-only rules —
// the one that wraps them in the restriction.
const savedRuleChokepointFile = "tenancy.go"

// savedTenancyRules are the names the guard keys on. A rename that does not
// update this list trips the anti-vacuity check below rather than going quiet.
var savedTenancyRules = []string{"canSeeSavedTenantOnly", "canMutateSavedTenantOnly"}

func TestSavedTenancyRulesAreNotCalledOutsideTheChokepoint(t *testing.T) {
	sources := packageGoSources(t)

	for _, rule := range savedTenancyRules {
		// Matches a CALL, not the declaration and not a mention in prose
		// (comment lines are stripped before matching anyway).
		call := regexp.MustCompile(`(^|[^\w.])` + rule + `\(`)
		scanned, declarations, chokepointCalls := 0, 0, 0

		for file, lines := range sources {
			for i, line := range lines {
				scanned++
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "//") {
					continue
				}
				if strings.HasPrefix(trimmed, "func "+rule+"(") {
					declarations++
					continue
				}
				if !call.MatchString(trimmed) {
					continue
				}
				if file == savedRuleChokepointFile {
					chokepointCalls++
					continue
				}
				t.Errorf(`%s:%d calls %s directly.

  %s

  That is TENANCY ONLY. It answers true for everything on the cross-tenant path,
  so this read or write reaches a restricted tenant's saved objects — the query
  text of a saved search, a dashboard's panels, a report's schedule and the
  contact points it is delivered to — for platform staff the tenant has
  excluded, and GET /api/saved hides the very same rows.

  Resolve the rule ONCE for the caller and ask it:

      vis := s.savedVisibilityFor(claims)
      rows := s.visibleSavedFor(claims, typ)   // the whole list, store included
      if !vis.visible(o) { ... }               // one object, read
      if !vis.mutable(o) { ... }               // one object, update or delete

  A background reader with no principal (the report pipeline delivering on a
  timer) is a different question and must say whose scope it carries — it does
  not fall back to the tenancy-only rule, which is how the scheduled reports came
  to deliver a restricted tenant's incidents to a notify channel on a clock.`,
					file, i+1, rule, trimmed)
			}
		}

		// ── Anti-vacuity. A sweep that matches nothing must FAIL, not pass. ──
		if scanned == 0 {
			t.Fatalf("the sweep for %s read no lines — it would pass vacuously", rule)
		}
		if declarations != 1 {
			t.Fatalf("found %d declarations of %s, want exactly 1 — the guard is aimed at a name that no longer "+
				"exists (or exists twice) and proves nothing", declarations, rule)
		}
		if chokepointCalls == 0 {
			t.Fatalf("the sweep found no call to %s in %s, the ONE file that is supposed to make it.\n"+
				"  Scanned %d lines without recognising the sanctioned call, so this guard is passing because it\n"+
				"  recognises nothing — not because nothing is wrong. Re-aim it at savedVisibility as written today.",
				rule, savedRuleChokepointFile, scanned)
		}
		if chokepointCalls != 1 {
			t.Errorf("%s calls %s %d times, want exactly 1 (inside savedVisibility). A second call inside the "+
				"chokepoint is a second copy of the decision.", savedRuleChokepointFile, rule, chokepointCalls)
		}
	}
}
