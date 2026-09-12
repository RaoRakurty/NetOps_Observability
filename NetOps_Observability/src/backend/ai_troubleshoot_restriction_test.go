// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_troubleshoot_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for
// the operator-visibility restriction (Tenant.OperatorRestricted) on the IRIS
// Phase-A assistant seams.
//
// The assistant is the widest read in the product. Its Phase-A seams resolve a
// device out of the inventory, run live show-commands on it, list its security
// findings, walk a correlation case timeline, describe its topology and report its
// BGP posture. Logs, flows, metrics, igpmon and the BMP feed all hide a restricted
// tenant from the platform owner. The assistant did not, in either direction.
//
// The rule lives in aiTroubleshootDeps, the sole constructor for every seam: when
// the restriction applies, no seam is wired, so no troubleshooting tool is
// registered and the assistant cannot ground an answer on a restricted tenant.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// restrictedAIFixture is the assistant fixture plus a REAL tenant store, so the
// switch under test is the production one and the devices are keyed on the OPAQUE
// tenant ids the store mints.
type restrictedAIFixture struct {
	s      *server
	acme   string
	globex string
}

func newRestrictedAIFixture(t *testing.T) *restrictedAIFixture {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID, Vendor: "cisco", OS: "ios-xe"},
		{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID, Vendor: "juniper"},
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("seed %s: %v", dev.ID, err)
		}
	}
	return &restrictedAIFixture{s: &server{roles: roles, discovery: d, tenants: ts}, acme: acme.ID, globex: globex.ID}
}

// wiredTools is the set of TROUBLESHOOTING tools the orchestrator would actually
// expose for these claims — the observable effect of a seam being wired or not.
// The registry's own always-on tools are excluded: they belong to the correlation
// data source, not to this lane.
func wiredTools(t *testing.T, s *server, claims jwtClaims) map[string]bool {
	t.Helper()
	troubleshoot := map[string]bool{}
	for _, n := range ai.TroubleshootToolNames() {
		troubleshoot[n] = true
	}
	reg := ai.Tools(nil)
	reg.AddTroubleshootTools(nil, s.aiTroubleshootDeps(aiTSRequest(claims), claims))
	out := map[string]bool{}
	for _, n := range reg.Names() {
		if troubleshoot[n] {
			out[n] = true
		}
	}
	return out
}

// assertCannotReach fails with the FIELD that crossed, so a regression names the
// leak rather than saying a boolean changed.
func assertCannotReach(t *testing.T, s *server, claims jwtClaims, who, device string) {
	t.Helper()
	deps := s.aiTroubleshootDeps(aiTSRequest(claims), claims)
	if deps.ResolveDevice != nil {
		ref, err := deps.ResolveDevice(context.Background(), aiTSPrincipal(), device)
		if !errors.Is(err, ai.ErrNotFound) {
			t.Errorf("RESTRICTION LEAK: %s resolved the restricted tenant's device — id=%q name=%q vendor=%q platform=%q (err %v)",
				who, ref.ID, ref.Name, ref.Vendor, ref.Platform, err)
		}
	}
	if deps.TopologyContext != nil {
		tc, err := deps.TopologyContext(context.Background(), aiTSPrincipal(), device)
		if !errors.Is(err, ai.ErrNotFound) {
			t.Errorf("RESTRICTION LEAK: %s read the restricted tenant's topology context — device=%q site=%q (err %v)",
				who, tc.DeviceName, tc.Site, err)
		}
	}
	if deps.DeviceState != nil {
		t.Errorf("RESTRICTION LEAK: %s still holds the live device-state seam for the restricted tenant", who)
	}
	if deps.ProtocolDiagnostic != nil {
		t.Errorf("RESTRICTION LEAK: %s still holds the live protocol-diagnostic seam for the restricted tenant", who)
	}
	if deps.CaseTimeline != nil {
		t.Errorf("RESTRICTION LEAK: %s still holds the case-timeline seam for the restricted tenant", who)
	}
	if got := wiredTools(t, s, claims); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: %s still has troubleshooting tools registered: %v", who, got)
	}
}

// TestAITroubleshootHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test.
func TestAITroubleshootHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedAIFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// Baseline: with nothing restricted the platform owner reaches acme's device
	// through the assistant, so this test cannot pass by wiring nothing.
	deps := f.s.aiTroubleshootDeps(aiTSRequest(owner), owner)
	if deps.ResolveDevice == nil {
		t.Fatal("baseline: the inventory is wired, so ResolveDevice must be filled")
	}
	ref, err := deps.ResolveDevice(context.Background(), aiTSPrincipal(), "acme-core")
	if err != nil || ref.ID != "acme-core" {
		t.Fatalf("baseline owner ResolveDevice(acme-core) = %+v, %v", ref, err)
	}
	if got := wiredTools(t, f.s, owner); !got["get_topology_context"] || !got["get_device_state"] || !got["get_case_timeline"] {
		t.Fatalf("baseline owner tools = %v, want the Phase-A set", got)
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the Global (cross-tenant) view. A row-level exclusion cannot be
	// proven on this lane, so the whole Phase-A set is unwired while any tenant is
	// restricted. Fail closed: the operator narrows to a tenant, or asks something
	// these tools do not answer.
	assertCannotReach(t, f.s, owner, "the platform owner in the Global view", "acme-core")

	// ── half 2: ?as_tenant into the restricted tenant.
	assertCannotReach(t, f.s, owner, "the platform owner scoped into acme", "acme-core")

	// The owner scoped into the UNRESTRICTED tenant keeps the whole toolset and
	// still reaches globex's own device.
	scopedB := ownerActing(owner, f.globex)
	depsB := f.s.aiTroubleshootDeps(aiTSRequest(scopedB), scopedB)
	if depsB.ResolveDevice == nil {
		t.Fatal("owner→globex lost the inventory seam")
	}
	refB, err := depsB.ResolveDevice(context.Background(), aiTSPrincipal(), "globex-core")
	if err != nil || refB.ID != "globex-core" {
		t.Fatalf("owner→globex ResolveDevice(globex-core) = %+v, %v", refB, err)
	}
	if _, err := depsB.ResolveDevice(context.Background(), aiTSPrincipal(), "acme-core"); !errors.Is(err, ai.ErrNotFound) {
		t.Errorf("owner→globex reached acme's device: %v", err)
	}
	if got := wiredTools(t, f.s, scopedB); !got["get_topology_context"] {
		t.Errorf("owner→globex tools = %v, want the Phase-A set", got)
	}

	// And acme's OWN operator is never restricted from its own assistant — the
	// switch hides a tenant from the PLATFORM, never from itself.
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	depsA := f.s.aiTroubleshootDeps(aiTSRequest(acmeUser), acmeUser)
	if depsA.ResolveDevice == nil {
		t.Fatal("acme's own operator lost the inventory seam")
	}
	refA, err := depsA.ResolveDevice(context.Background(), aiTSPrincipal(), "acme-core")
	if err != nil || refA.ID != "acme-core" {
		t.Fatalf("acme's own operator lost its own device: %+v, %v", refA, err)
	}
	if _, err := depsA.ResolveDevice(context.Background(), aiTSPrincipal(), "globex-core"); !errors.Is(err, ai.ErrNotFound) {
		t.Errorf("acme's own operator reached globex's device: %v", err)
	}
	if got := wiredTools(t, f.s, acmeUser); !got["get_topology_context"] || !got["get_device_state"] {
		t.Errorf("acme's own operator tools = %v, want the Phase-A set", got)
	}
}
