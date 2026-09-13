// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery_test

// monitoring_isolation_test.go — the withheld-monitoring list is tenant-scoped
// (CLAUDE.md §3a rule 1, tracker 292).
//
// The list names devices: id, tenant and NAME. Before this test the registry
// answered with every tenant's rows and nothing in the signature said so, so
// the first surface to render it would have been a cross-tenant leak with no
// review signal. The property proved here is the one that has to hold BEFORE
// such a surface exists: a scoped caller is answered with its own rows only,
// and the platform-wide answer requires typing cross=true.

import (
	"context"
	"strings"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// withheldEverything builds a registry whose ceiling admits nothing, so every
// device polled from the source lands on the withheld list.
func withheldEverything(t *testing.T, devs ...models.Device) *discovery.DiscoveryAggregator {
	t.Helper()
	a := discovery.NewDiscoveryAggregator()
	a.SetMonitorGate(func(int) error { return errNotPersisted })
	a.PollOnceForTest(context.Background(), &fixedSource{name: "static", devices: devs})
	if got := a.MonitoringWithheldCount(); got != len(devs) {
		t.Fatalf("withheld = %d, want %d — the fixture must actually withhold, or this test proves nothing", got, len(devs))
	}
	return a
}

func TestMonitoringWithheldIsScopedToTheCallersTenant(t *testing.T) {
	acme := models.Device{ID: "acme-1", Name: "acme-core-sw01", Address: "10.1.0.1", TenantID: "acme"}
	globex := models.Device{ID: "globex-1", Name: "globex-edge-rtr01", Address: "10.2.0.1", TenantID: "globex"}
	platform := models.Device{ID: "plat-1", Name: "unassigned-lab-sw", Address: "10.3.0.1"}
	a := withheldEverything(t, acme, globex, platform)

	// Own-only list: acme sees its row and nothing else.
	got := a.MonitoringWithheldFor("acme", false)
	if len(got) != 1 || got[0].DeviceID != "acme-1" {
		t.Fatalf("acme must see exactly its own withheld device, got %+v", got)
	}
	// The leak this row is about is the IDENTITIES, so assert on the values:
	// neither the other tenant's id nor its NAME may appear anywhere.
	for _, w := range got {
		blob := w.DeviceID + " " + w.TenantID + " " + w.Name
		for _, forbidden := range []string{"globex", "globex-1", "globex-edge-rtr01", "plat-1", "unassigned-lab-sw"} {
			if strings.Contains(blob, forbidden) {
				t.Fatalf("cross-tenant leak: %q appears in acme's withheld list (%+v)", forbidden, w)
			}
		}
	}

	// Symmetry: globex sees only globex.
	if got := a.MonitoringWithheldFor("globex", false); len(got) != 1 || got[0].DeviceID != "globex-1" {
		t.Fatalf("globex must see exactly its own withheld device, got %+v", got)
	}

	// Untagged/platform-owned devices are their own partition: a scoped tenant
	// never sees them, exactly as the device registry treats them.
	for _, tenant := range []string{"acme", "globex"} {
		for _, w := range a.MonitoringWithheldFor(tenant, false) {
			if w.TenantID == "" {
				t.Fatalf("%s was shown the untagged platform device %+v", tenant, w)
			}
		}
	}

	// A tenant that owns nothing gets an empty list, not everything.
	if got := a.MonitoringWithheldFor("initech", false); len(got) != 0 {
		t.Fatalf("a tenant with no withheld devices must get an empty list, got %+v", got)
	}

	// The platform-wide view still exists — it just has to be asked for.
	all := a.MonitoringWithheldFor("", true)
	if len(all) != 3 {
		t.Fatalf("cross-tenant must see all 3 withheld devices, got %d (%+v)", len(all), all)
	}
}

// A scoped caller must not be able to widen its view by naming another tenant's
// id in a way the registry would honour: the tenant argument IS the scope, and
// the only widening switch is the explicit cross flag.
func TestMonitoringWithheldScopedCallerCannotReachAnotherTenant(t *testing.T) {
	a := withheldEverything(t,
		models.Device{ID: "acme-1", Name: "acme-core-sw01", Address: "10.1.0.1", TenantID: "acme"},
		models.Device{ID: "globex-1", Name: "globex-edge-rtr01", Address: "10.2.0.1", TenantID: "globex"},
	)
	// Case and whitespace must not open a hole (the registry normalises both).
	for _, spelling := range []string{"ACME", "  acme  ", "AcMe"} {
		got := a.MonitoringWithheldFor(spelling, false)
		if len(got) != 1 || got[0].DeviceID != "acme-1" {
			t.Fatalf("spelling %q resolved to %+v, want acme's single row", spelling, got)
		}
	}
	// The empty tenant is NOT a wildcard for a scoped caller: it is the
	// untagged/platform partition, which holds nothing here.
	if got := a.MonitoringWithheldFor("", false); len(got) != 0 {
		t.Fatalf("the empty tenant must not act as a wildcard, got %+v", got)
	}
}
