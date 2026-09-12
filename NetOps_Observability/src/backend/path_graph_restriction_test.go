// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// path_graph_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for the
// operator-visibility restriction (Tenant.OperatorRestricted) on the RCA path spine.
//
// A measured path is the customer's network: the hops are that tenant's addresses,
// the terminal is that tenant's application, the seams name that tenant's providers.
// Logs, flows, metrics, igpmon and the BMP feed all hide a restricted tenant from
// the platform owner. This lane must hide it too — in the Global view AND when the
// owner walks in with ?as_tenant.

import (
	"strings"
	"testing"
	"time"

	"netops/backend/pathgraph"
)

// TestPathGraphHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test.
func TestPathGraphHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	srv, s := newTestServerState(t)
	s.pathGraph = pathgraph.NewMemStore()

	owner := login(t, srv, "admin", "Passw0rd!2345").Token

	type fix struct{ org, tenant, user, token string }
	f := map[string]*fix{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", owner, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", owner, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "restricted-user-" + name
		st, b = do(t, srv, "POST", "/api/users", owner, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		f[name] = &fix{org: orgID, tenant: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := f["A"], f["B"]

	factsA := tenantFacts(a.tenant, "i-AAAAAAAA", "i-NVA-AAAA", "lan-sw-A", "wan-edge-A")
	factsB := tenantFacts(b.tenant, "i-BBBBBBBB", "i-NVA-BBBB", "lan-sw-B", "wan-edge-B")
	s.pathFacts = stubFacts{byTenant: map[string]pathgraph.PathFacts{a.tenant: factsA, b.tenant: factsB}, nc: labNetContext()}

	// Both tenants measure the SAME destination address, which is the worst case:
	// a cross-tenant read matches on address, so the two runs compete. Tenant A's
	// run is the NEWER one, so the platform owner's Global read picks A while
	// nothing is restricted — and must pick B, not A, once A is hidden.
	recA := ingestFor(t, s, a.tenant, factsA, pathgraph.DataClassLive, ingestNow, "restricted-run-A", "")
	recB := ingestFor(t, s, b.tenant, factsB, pathgraph.DataClassLive, ingestNow.Add(-time.Minute), "restricted-run-B", "")

	corrA := "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
	corrB := "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
	unknown := "cccccccc-3333-4333-8333-cccccccccccc"
	s.corrPath = stubCorrPath{byID: map[string]struct {
		tenant string
		dst    string
	}{
		corrA: {tenant: a.tenant, dst: "10.60.10.10"},
		corrB: {tenant: b.tenant, dst: "10.60.10.10"}, // the SAME address in both tenants
	}}

	// Baseline: with nothing restricted the platform owner reads tenant A's whole
	// spine — its LAN switch, its WAN edge, its NVA, its application. So this test
	// cannot pass by serving nothing.
	st, raw, sp := getPath(t, srv, owner, corrA, "")
	if st != 200 || !sp.SpineAvailable {
		t.Fatalf("baseline owner GET A: %d available=%v (%s)", st, sp.SpineAvailable, raw)
	}
	for _, want := range []string{"i-AAAAAAAA", "i-NVA-AAAA", "lan-sw-A", "wan-edge-A"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("baseline owner spine for A does not name %s: %s", want, raw)
		}
	}
	if st, raw, sp := getPath(t, srv, owner, corrB, ""); st != 200 || !sp.SpineAvailable {
		t.Fatalf("baseline owner GET B: %d available=%v (%s)", st, sp.SpineAvailable, raw)
	}

	// The answer for a correlation object that has no measured path at all. The
	// restricted answer must be INDISTINGUISHABLE from it.
	_, _, absent := getPath(t, srv, owner, unknown, "")
	if absent.SpineAvailable || absent.Reason == "" {
		t.Fatalf("an unknown correlation id should answer with a reason and no spine: %+v", absent)
	}

	if _, err := s.tenants.SetOperatorRestricted(a.tenant, true); err != nil {
		t.Fatalf("restrict tenant A: %v", err)
	}

	// ── half 1: the Global view. Tenant A's path is gone; B's is untouched.
	st, raw, sp = getPath(t, srv, owner, corrA, "")
	if st != 200 {
		t.Fatalf("owner GET restricted path: %d %s", st, raw)
	}
	if sp.SpineAvailable {
		t.Errorf("RESTRICTION LEAK: the platform owner still reads the restricted tenant's spine: %s", raw)
	}
	if sp.Reason != absent.Reason {
		t.Errorf("the restricted answer (%q) differs from the no-path answer (%q) — it confirms the tenant has a path",
			sp.Reason, absent.Reason)
	}
	for _, leak := range []string{"i-AAAAAAAA", "i-NVA-AAAA", "lan-sw-A", "wan-edge-A",
		recA.Observation.ObservationID, recA.Definition.PathID, "restricted-run-A"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("RESTRICTION LEAK: the owner's response names tenant A's %q: %s", leak, raw)
		}
	}

	// Tenant B's object still resolves — and to B's OWN run, not A's, even though
	// both measured the same destination address.
	st, raw, sp = getPath(t, srv, owner, corrB, "")
	if st != 200 || !sp.SpineAvailable {
		t.Fatalf("restricting A also broke B: %d available=%v (%s)", st, sp.SpineAvailable, raw)
	}
	if !strings.Contains(string(raw), "i-BBBBBBBB") {
		t.Errorf("tenant B's spine lost its own resources: %s", raw)
	}
	for _, leak := range []string{"i-AAAAAAAA", recA.Observation.ObservationID, recA.Definition.PathID} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("RESTRICTION LEAK: tenant B's spine served tenant A's %q: %s", leak, raw)
		}
	}
	if !strings.Contains(string(raw), recB.Observation.ObservationID) {
		t.Errorf("tenant B's spine is not tenant B's own run: %s", raw)
	}

	// ── half 2: ?as_tenant into the restricted tenant. Nothing, and the same
	// bytes an object with no path gets.
	st, raw, sp = getPath(t, srv, owner, corrA, "?as_tenant="+a.tenant)
	if st != 200 {
		t.Fatalf("owner→A GET: %d %s", st, raw)
	}
	if sp.SpineAvailable {
		t.Errorf("RESTRICTION LEAK: owner→A read the restricted tenant's spine: %s", raw)
	}
	if sp.Reason != absent.Reason {
		t.Errorf("owner→A reason %q differs from the no-path reason %q", sp.Reason, absent.Reason)
	}
	for _, leak := range []string{"i-AAAAAAAA", "lan-sw-A", recA.Observation.ObservationID, "restricted-run-A"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("RESTRICTION LEAK: owner→A response names %q: %s", leak, raw)
		}
	}

	// The owner scoped into the UNRESTRICTED tenant still reads it.
	st, raw, sp = getPath(t, srv, owner, corrB, "?as_tenant="+b.tenant)
	if st != 200 || !sp.SpineAvailable || !strings.Contains(string(raw), "i-BBBBBBBB") {
		t.Errorf("owner→B: %d available=%v (%s)", st, sp.SpineAvailable, raw)
	}

	// And tenant A's OWN user is never restricted from its own path — the switch
	// hides a tenant from the PLATFORM, never from itself.
	st, raw, sp = getPath(t, srv, a.token, corrA, "")
	if st != 200 || !sp.SpineAvailable {
		t.Fatalf("tenant A lost its own spine: %d available=%v (%s)", st, sp.SpineAvailable, raw)
	}
	if !strings.Contains(string(raw), "i-AAAAAAAA") {
		t.Fatalf("tenant A's own spine does not name its own resources: %s", raw)
	}
}
