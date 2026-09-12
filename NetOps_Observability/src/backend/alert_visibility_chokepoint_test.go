// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// alert_visibility_chokepoint_test.go — the structural guard that keeps the
// alert rule whole.
//
// Correlix has two rules on an alert. alertVisibleTenantOnly answers TENANCY:
// may this caller's tenant see this alert? alertVisibility.visible answers that
// PLUS the per-tenant operator-visibility restriction (Tenant.OperatorRestricted),
// which says platform staff may administer a restricted tenant but must not read
// its data.
//
// The first is not a surface's answer, and the failure mode is that it LOOKS
// like one. It returns true for everything on the cross-tenant path — correctly,
// the platform owner may see every tenant — so a surface that calls it passes
// ordinary tenant-isolation tests and silently serves the one class of tenant
// that asked not to be readable. Every direct caller it ever had has now been
// wrong at least once: /api/graphql and /api/topology/view read it, and the
// report scheduler DELIVERED it to a notify channel on a timer (tracker 297).
//
// So the rule is structural, not a convention: alertVisibleTenantOnly is called
// in ONE place, alertVisibility.visible, and this test fails the build on a
// second.

import (
	"regexp"
	"strings"
	"testing"
)

// alertRuleChokepointFile is the file allowed to call the tenancy-only rule —
// the one that wraps it in the restriction.
const alertRuleChokepointFile = "tenancy.go"

// alertTenancyRule is the name the guard keys on. A rename that does not update
// this constant trips the anti-vacuity check below rather than going quiet.
const alertTenancyRule = "alertVisibleTenantOnly"

// alertTenancyCallPattern matches a CALL, not the declaration and not a mention
// of the name in prose (comment lines are stripped before matching anyway).
var alertTenancyCallPattern = regexp.MustCompile(`(^|[^\w.])` + alertTenancyRule + `\(`)

func TestAlertTenancyRuleIsNotCalledOutsideTheChokepoint(t *testing.T) {
	sources := packageGoSources(t)

	scanned, declarations, chokepointCalls := 0, 0, 0
	for file, lines := range sources {
		for i, line := range lines {
			scanned++
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.HasPrefix(trimmed, "func "+alertTenancyRule+"(") {
				declarations++
				continue
			}
			if !alertTenancyCallPattern.MatchString(trimmed) {
				continue
			}
			if file == alertRuleChokepointFile {
				chokepointCalls++
				continue
			}
			t.Errorf(`%s:%d calls %s directly.

  %s

  That is TENANCY ONLY. It answers true for everything on the cross-tenant path,
  so this read serves a restricted tenant's alerts — the rule that fired, the
  device it fired on and a summary naming that device — to platform staff the
  tenant has excluded, and GET /api/alerts hides the very same rows.

  Resolve the rule ONCE for the caller and filter through it:

      vis := s.alertVisibilityFor(claims)   // or, with no live caller, s.alertVisibilityForScope(...)
      out := vis.filter(active)             // or vis.visible(a) per alert

  If this read genuinely has no principal (a background worker), say whose scope
  it carries by passing it to alertVisibilityForScope — do not fall back to the
  tenancy-only rule, which is how the scheduled reports came to deliver a
  restricted tenant's incidents to a notify channel on a timer.`,
				file, i+1, alertTenancyRule, trimmed)
		}
	}

	// ── Anti-vacuity. A sweep that matches nothing must FAIL, not pass. ──
	if scanned == 0 {
		t.Fatal("the sweep read no lines — it would pass vacuously")
	}
	if declarations != 1 {
		t.Fatalf("found %d declarations of %s, want exactly 1 — the guard is aimed at a name that no longer exists "+
			"(or exists twice) and proves nothing", declarations, alertTenancyRule)
	}
	if chokepointCalls == 0 {
		t.Fatalf("the sweep found no call to %s in %s, the ONE file that is supposed to make it.\n"+
			"  Scanned %d lines without recognising the sanctioned call, so this guard is passing because it\n"+
			"  recognises nothing — not because nothing is wrong. Re-aim alertTenancyCallPattern at\n"+
			"  alertVisibility.visible as it is written today.",
			alertTenancyRule, alertRuleChokepointFile, scanned)
	}
	if chokepointCalls != 1 {
		t.Errorf("%s calls %s %d times, want exactly 1 (alertVisibility.visible). A second call inside the "+
			"chokepoint is a second copy of the decision.", alertRuleChokepointFile, alertTenancyRule, chokepointCalls)
	}
}
