// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// configdrift_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for
// the per-tenant OPERATOR-VISIBILITY restriction (Tenant.OperatorRestricted) on
// the configuration-drift bulk list, GET /api/config/drift
// (internal/configdrift).
//
// The drift list is the same data family as the configuration backup the
// sibling test covers. Each row names a device and the fingerprint of the
// configuration running on it: device_id, device_name, last_sha, golden_sha,
// last_capture_at, the drift verdict and the scrubbed last_error. A restricted
// tenant's fleet, and the fact that its boxes have drifted from their baseline,
// is exactly what the compliance switch hides.
//
// Run through the REAL wiring: buildConfigBackup(), the production
// s.configDriftAuthz gate mapping and a REAL tenant store, so the switch under
// test is the production one (Tenant.OperatorRestricted →
// effectiveRestrictedIDs → operatorTelemetryRestriction).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// driftList drives the bulk list through the production handler.
func driftList(t *testing.T, s *server, claims jwtClaims) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.configDrift.HandleDriftList(w, req(http.MethodGet, "/api/config/drift?limit=100", "", claims))
	return w
}

// driftTotal reads the list's `total`, which is a COUNT of the caller-visible
// rows and therefore a disclosure in its own right.
func driftTotal(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var body struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode drift list: %v (%s)", err, w.Body.String())
	}
	return body.Total
}

// TestConfigDriftHonoursTheOperatorVisibilityRestriction asserts BOTH halves:
// the restricted tenant's rows are absent from the platform owner's Global
// list, and an as_tenant list into that tenant returns nothing at all.
func TestConfigDriftHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedCfgFixture(t)
	owner := platformOwner()

	// Before anything is restricted the owner's Global list holds BOTH tenants'
	// rows, so the assertions below cannot pass on an endpoint that serves
	// nothing.
	pre := driftList(t, f.s, owner)
	if pre.Code != http.StatusOK {
		t.Fatalf("owner drift list: %d %s", pre.Code, pre.Body.String())
	}
	for _, want := range []string{"acme-core", "globex-core", cfgAcmeSHA2, cfgGlobexSHA} {
		if !strings.Contains(pre.Body.String(), want) {
			t.Fatalf("the fixture does not reach the owner's Global list at all (missing %q): %s", want, pre.Body.String())
		}
	}
	if got := driftTotal(t, pre); got != 2 {
		t.Fatalf("baseline total = %d, want 2 (one row per tenant)", got)
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// The fields that must not cross: acme's device identity and the
	// fingerprints of the configuration running on it.
	hidden := []string{"acme-core", cfgAcmeSHA2}

	// ── half 1: the owner's GLOBAL view. acme's row is gone, globex's stays,
	//    and the COUNT drops with it (a count is a disclosure).
	global := driftList(t, f.s, owner)
	if global.Code != http.StatusOK {
		t.Fatalf("owner drift list after restriction: %d %s", global.Code, global.Body.String())
	}
	for _, leak := range hidden {
		if strings.Contains(global.Body.String(), leak) {
			t.Errorf("RESTRICTION LEAK on GET /api/config/drift (Global view) — the platform owner saw %q: %s",
				leak, global.Body.String())
		}
	}
	if !strings.Contains(global.Body.String(), "globex-core") {
		t.Errorf("the unrestricted tenant's drift row disappeared from the Global list: %s", global.Body.String())
	}
	if got := driftTotal(t, global); got != 1 {
		t.Errorf("RESTRICTION LEAK: the Global list's total = %d, want 1 — the count still includes the restricted tenant's device", got)
	}

	// ── half 2: the owner walks in with as_tenant=acme. It sees nothing, and
	//    not a 403 either: a refusal would confirm acme has drift rows.
	acting := driftList(t, f.s, ownerActing(owner, f.acme))
	if acting.Code != http.StatusOK {
		t.Fatalf("as_tenant drift list: %d %s (want 200 with an empty page, not a refusal)", acting.Code, acting.Body.String())
	}
	for _, leak := range hidden {
		if strings.Contains(acting.Body.String(), leak) {
			t.Errorf("RESTRICTION LEAK on GET /api/config/drift?as_tenant=acme — the platform owner saw %q: %s",
				leak, acting.Body.String())
		}
	}
	if got := driftTotal(t, acting); got != 0 {
		t.Errorf("RESTRICTION LEAK: the as_tenant list's total = %d, want 0", got)
	}

	// ── the owner scoped into the UNRESTRICTED tenant still reads it.
	un := driftList(t, f.s, ownerActing(owner, f.globex))
	if un.Code != http.StatusOK || !strings.Contains(un.Body.String(), "globex-core") {
		t.Errorf("as_tenant into the unrestricted tenant broke: %d %s", un.Code, un.Body.String())
	}

	// ── acme's OWN operator is never restricted from acme's own drift rows.
	own := driftList(t, f.s, jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme})
	if own.Code != http.StatusOK {
		t.Fatalf("acme's own operator: %d %s", own.Code, own.Body.String())
	}
	if !strings.Contains(own.Body.String(), "acme-core") || !strings.Contains(own.Body.String(), cfgAcmeSHA2) {
		t.Fatalf("acme's own operator lost its own drift row: %s", own.Body.String())
	}
	if got := driftTotal(t, own); got != 1 {
		t.Fatalf("acme's own operator's total = %d, want 1", got)
	}
}
