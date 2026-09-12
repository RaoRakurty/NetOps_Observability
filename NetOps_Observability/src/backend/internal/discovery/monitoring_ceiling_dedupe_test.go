// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery_test

// monitoring_ceiling_dedupe_test.go — ONE PHYSICAL DEVICE, ONE ENTITLEMENT
// (owner decision C4), on the POLL path.
//
// TestOneDeviceReportedByTwoSourcesIsOneMonitoredDevice already pins the COUNT.
// This file pins the gate, which is the half that used to disagree with it: the
// ceiling is asked about a RAW cache record while the count it is measured
// against is over the DEDUPED canonical device. A second source reporting a box
// the platform is already collecting from was therefore charged a second
// entitlement, and at a full ceiling the refusal was folded into the whole owner
// group — switching an already-collected device OFF with a "licence ceiling
// full" reason that was not true.
//
// The two halves that must both hold:
//   - a record that is the SAME physical device as a monitored one is free;
//   - a record that is a DIFFERENT device (including the same hostname in
//     another tenant) is still charged, so the fix is not a hole in the ceiling.

import (
	"context"
	"testing"

	"netops/backend/internal/devmon"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// ceilingOf returns a monitor gate that permits exactly n monitored devices.
func ceilingOf(n int) func(current int) error {
	return func(current int) error {
		if current >= n {
			return errNotPersisted // any refusal
		}
		return nil
	}
}

func TestASecondSourceForAnAlreadyMonitoredDeviceIsNotChargedAgain(t *testing.T) {
	ctx := context.Background()
	a := discovery.NewDiscoveryAggregator()
	// A HARD ceiling of exactly one monitored device.
	a.SetMonitorGate(ceilingOf(1))

	// The same physical box, reported by two sources under different raw ids.
	// They share a management address AND a hostname, so dedupe folds them.
	static := &fixedSource{name: devmon.SourceStatic, devices: []models.Device{
		{ID: "static-leaf1", Name: "leaf1", Address: "10.0.0.1"},
	}}
	netbox := &fixedSource{name: devmon.SourceNetbox, devices: []models.Device{
		{ID: "netbox-leaf1", Name: "leaf1", Address: "10.0.0.1"},
	}}

	a.PollOnceForTest(ctx, static)
	if got := a.MonitoredCount(); got != 1 {
		t.Fatalf("precondition: monitored = %d, want 1", got)
	}

	// The SECOND source now reports the device the platform is ALREADY
	// collecting from. Nothing about the fleet changed, so nothing may.
	a.PollOnceForTest(ctx, netbox)

	if got := len(a.Devices()); got != 1 {
		t.Fatalf("the two records are one device, got %d", got)
	}
	if got := a.MonitoredCount(); got != 1 {
		t.Fatalf("monitored = %d, want 1 — the device was already being collected from", got)
	}
	if w := a.MonitoringWithheld(); len(w) != 0 {
		t.Fatalf("a device the platform is already collecting from was reported as withheld by the licence ceiling: %+v", w)
	}
	for _, d := range a.Devices() {
		if !d.Monitored {
			t.Fatalf("%s was switched OFF with reason %q — one physical device is one entitlement (C4)", d.ID, d.MonitorReason)
		}
	}
}

// TestTwoRecordsOfOneDeviceInOnePollAreChargedOnce covers the in-poll half: a
// single source reporting the same physical box under two ids must charge once,
// which means the running identity set has to grow as devices are admitted.
func TestTwoRecordsOfOneDeviceInOnePollAreChargedOnce(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	a.SetMonitorGate(ceilingOf(1))
	src := &fixedSource{name: devmon.SourceStatic, devices: []models.Device{
		// Different ids and different addresses — a second management
		// interface on the same box. They union on the hostname, so they are
		// one device and one entitlement.
		{ID: "static-a", Name: "leaf1", Address: "10.0.0.1"},
		{ID: "static-b", Name: "leaf1", Address: "10.0.0.2"},
	}}
	a.PollOnceForTest(context.Background(), src)

	if got := len(a.Devices()); got != 1 {
		t.Fatalf("the two records are one device, got %d", got)
	}
	if got := a.MonitoredCount(); got != 1 {
		t.Fatalf("monitored = %d, want 1", got)
	}
	if w := a.MonitoringWithheld(); len(w) != 0 {
		t.Fatalf("one device was charged twice inside one poll: %+v", w)
	}
}

// TestTheCeilingStillRefusesAGenuinelyNewDevice is the guard on the fix: the
// free admission is for the SAME physical device only. A different box at a full
// ceiling is still withheld, listed and explained.
func TestTheCeilingStillRefusesAGenuinelyNewDevice(t *testing.T) {
	ctx := context.Background()
	a := discovery.NewDiscoveryAggregator()
	a.SetMonitorGate(ceilingOf(1))

	first := &fixedSource{name: devmon.SourceStatic, devices: []models.Device{
		{ID: "static-leaf1", Name: "leaf1", Address: "10.0.0.1"},
	}}
	second := &fixedSource{name: devmon.SourceNetbox, devices: []models.Device{
		// A DIFFERENT device: different name, different address, no serial.
		{ID: "netbox-leaf2", Name: "leaf2", Address: "10.0.0.2"},
	}}
	a.PollOnceForTest(ctx, first)
	a.PollOnceForTest(ctx, second)

	if got := len(a.Devices()); got != 2 {
		t.Fatalf("both devices must be in the inventory, got %d — the ceiling never blocks discovery", got)
	}
	if got := a.MonitoredCount(); got != 1 {
		t.Fatalf("monitored = %d, want 1 — the ceiling must still hold", got)
	}
	w := a.MonitoringWithheld()
	if len(w) != 1 || w[0].DeviceID != "netbox-leaf2" {
		t.Fatalf("the second DEVICE must be withheld and listed, got %+v", w)
	}
	if w[0].Reason == "" {
		t.Fatalf("a withheld device must say why: %+v", w[0])
	}
}

// TestTheSameHostnameInAnotherTenantIsADifferentDevice keeps the entitlement
// dedupe inside the tenant boundary (§3a). Two tenants legitimately run a
// `leaf1` on 10.0.0.1; folding them would both under-charge the licence and
// merge one tenant's row into the other's.
func TestTheSameHostnameInAnotherTenantIsADifferentDevice(t *testing.T) {
	ctx := context.Background()
	a := discovery.NewDiscoveryAggregator()
	a.SetMonitorGate(ceilingOf(1))

	acme := &fixedSource{name: devmon.SourceStatic, devices: []models.Device{
		{ID: "static-acme-leaf1", Name: "leaf1", Address: "10.0.0.1", TenantID: "acme"},
	}}
	globex := &fixedSource{name: devmon.SourceNetbox, devices: []models.Device{
		{ID: "netbox-globex-leaf1", Name: "leaf1", Address: "10.0.0.1", TenantID: "globex"},
	}}
	a.PollOnceForTest(ctx, acme)
	a.PollOnceForTest(ctx, globex)

	if got := len(a.Devices()); got != 2 {
		t.Fatalf("two tenants' devices must never merge, got %d device(s)", got)
	}
	if got := a.MonitoredCount(); got != 1 {
		t.Fatalf("monitored = %d, want 1 — a second tenant's box is a second entitlement", got)
	}
	w := a.MonitoringWithheld()
	if len(w) != 1 || w[0].DeviceID != "netbox-globex-leaf1" {
		t.Fatalf("the second TENANT's device must be withheld, got %+v", w)
	}
}

// TestRaisingTheCeilingStillReleasesAWithheldDevice pins that the free-admission
// path did not break the resume: a device withheld at a full ceiling starts
// being collected from on the next poll after the ceiling rises, with no
// operator action.
func TestRaisingTheCeilingStillReleasesAWithheldDevice(t *testing.T) {
	ctx := context.Background()
	a := discovery.NewDiscoveryAggregator()
	limit := 1
	a.SetMonitorGate(func(current int) error {
		if current >= limit {
			return errNotPersisted
		}
		return nil
	})
	src := &fixedSource{name: devmon.SourceStatic, devices: []models.Device{
		{ID: "static-leaf1", Name: "leaf1", Address: "10.0.0.1"},
		{ID: "static-leaf2", Name: "leaf2", Address: "10.0.0.2"},
	}}
	a.PollOnceForTest(ctx, src)
	if got := a.MonitoringWithheldCount(); got != 1 {
		t.Fatalf("withheld = %d, want 1", got)
	}
	limit = 2
	a.PollOnceForTest(ctx, src)
	if got := a.MonitoredCount(); got != 2 {
		t.Fatalf("monitored = %d, want 2 after the ceiling rose", got)
	}
	if got := a.MonitoringWithheldCount(); got != 0 {
		t.Fatalf("withheld = %d, want 0", got)
	}
}
