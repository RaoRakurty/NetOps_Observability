// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tenant_scope_enrichment_test.go — what device_tenant.csv says while a box is
// found by BOTH the platform scan and a customer's own scan (the transition of
// moving a customer onto its own discovery channel), and after the platform
// copy is retired. The registry's rule (an identity two owners hold is left
// out) is fail-closed by design: during the transition the shared address and
// name attribute to NOBODY — never to the wrong owner — and each owner's own
// device id still attributes to that owner.

import (
	"context"
	"sync"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

func TestTenantScopeSiblingRegistryRowsFailClosedThenMoveToTheTenant(t *testing.T) {
	const retail = "t_retail"
	var mu sync.Mutex
	scopes := []discovery.ScanScope{
		{ID: discovery.PlatformScopeID, Ranges: []string{"10.70.0.80/30"}, Credentials: []discovery.ScanCredential{{ProfileID: "plat", Target: collectors.Target{Community: "p"}}}},
		{ID: "scope-retail", TenantID: retail, Ranges: []string{"10.70.0.80/30"}, Credentials: []discovery.ScanCredential{{ProfileID: "retail", Target: collectors.Target{Community: "r"}}}},
	}
	setScopes := func(s []discovery.ScanScope) { mu.Lock(); scopes = s; mu.Unlock() }
	clock := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	src := discovery.NewSNMPSource(func() discovery.ScanSettings {
		mu.Lock()
		defer mu.Unlock()
		return discovery.ScanSettings{Enabled: true, Scopes: append([]discovery.ScanScope(nil), scopes...)}
	}, nil)
	src.SetProbeForTest(func(_ context.Context, tg collectors.Target) (string, string, string, bool) {
		return "cEDGE-81", "cisco", "Cisco IOS XE", tg.Address == "10.70.0.81"
	})
	src.SetClockForTest(func() time.Time { mu.Lock(); defer mu.Unlock(); return clock })
	a := discovery.NewDiscoveryAggregator()
	a.SetStore(discovery.NewDevStore(t.TempDir()+"/devices.json", platformKV{}, nil))
	a.Register(src)
	poll := func() []models.Device {
		mu.Lock()
		clock = clock.Add(discovery.ScanCooldown + time.Second)
		mu.Unlock()
		a.PollOnceForTest(context.Background(), src)
		return a.Devices()
	}

	platID := discovery.ScanDeviceID("cEDGE-81", "10.70.0.81")
	sibID := discovery.ScanDeviceIDFor(retail, "cEDGE-81", "10.70.0.81")
	if n := len(poll()); n != 2 {
		t.Fatalf("both owners' devices must be in the inventory, got %d", n)
	}
	rows := map[string]string{}
	for _, r := range buildEnrichmentRows(a.Devices()) {
		rows[r.Identity] = r.Tenant
	}
	// Transition: the shared address and name are omitted (fail-closed), each
	// owner's own id attributes to that owner.
	if _, leaked := rows["10.70.0.81"]; leaked {
		t.Fatalf("an address two owners hold must be left out of the registry: %v", rows)
	}
	if _, leaked := rows["cEDGE-81"]; leaked {
		t.Fatalf("a name two owners hold must be left out of the registry: %v", rows)
	}
	if rows[platID] != "" || rows[sibID] != retail {
		t.Fatalf("each id attributes to its own owner: platform %q→%q, sibling %q→%q", platID, rows[platID], sibID, rows[sibID])
	}
	if _, ok := rows[platID]; !ok {
		t.Fatal("the platform id row must be present")
	}

	// Retirement (runbook §6 step 4): the platform scan drops the address and
	// the platform row is deleted in the Provider scope.
	setScopes([]discovery.ScanScope{scopes[1]})
	if err := a.Delete(platID); err != nil {
		t.Fatal(err)
	}
	poll()
	rows = map[string]string{}
	for _, r := range buildEnrichmentRows(a.Devices()) {
		rows[r.Identity] = r.Tenant
	}
	for _, id := range []string{"10.70.0.81", "cEDGE-81", sibID} {
		if got, ok := rows[id]; !ok || got != retail {
			t.Fatalf("after retirement %q must attribute to the customer, got %q (present %v): %v", id, got, ok, rows)
		}
	}
	if _, ok := rows[platID]; ok {
		t.Fatal("the retired platform id must leave the registry")
	}
}
