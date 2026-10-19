// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"testing"
	"time"
)

func dev(key, name string) ControllerDevice {
	return ControllerDevice{KeyKind: KeySystemIP, Key: key, Name: name, SourceSystem: "vmanage", Managed: true}
}

func keysOf(t *testing.T, ds []ControllerDevice) []string {
	t.Helper()
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Key)
	}
	return out
}

func TestDeviceStoreSnapshotRules(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	t0 := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	if err := m.ReplaceDevices(ctx, "t-retail", "int-vm", []ControllerDevice{dev("10.0.0.1", "a"), dev("10.0.0.2", "b")}, t0); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Devices(ctx, "t-retail", false, "int-vm")
	if len(got) != 2 {
		t.Fatalf("%v", keysOf(t, got))
	}

	// An EMPTY snapshot deletes nothing.
	_ = m.ReplaceDevices(ctx, "t-retail", "int-vm", nil, t0.Add(10*time.Minute))
	if got, _ := m.Devices(ctx, "t-retail", false, "int-vm"); len(got) != 2 {
		t.Fatalf("empty snapshot pruned: %v", keysOf(t, got))
	}

	// A device no longer listed stays through the grace, then goes.
	_ = m.ReplaceDevices(ctx, "t-retail", "int-vm", []ControllerDevice{dev("10.0.0.1", "a")}, t0.Add(20*time.Minute))
	if got, _ := m.Devices(ctx, "t-retail", false, "int-vm"); len(got) != 2 {
		t.Fatalf("absent device dropped before its grace: %v", keysOf(t, got))
	}
	_ = m.ReplaceDevices(ctx, "t-retail", "int-vm", []ControllerDevice{dev("10.0.0.1", "a")}, t0.Add(20*time.Minute+DeviceAbsentGrace))
	if got, _ := m.Devices(ctx, "t-retail", false, "int-vm"); len(got) != 1 || got[0].Key != "10.0.0.1" {
		t.Fatalf("absent device kept past its grace: %v", keysOf(t, got))
	}

	// Coming back resets the clock.
	_ = m.ReplaceDevices(ctx, "t-retail", "int-vm", []ControllerDevice{dev("10.0.0.1", "a"), dev("10.0.0.3", "c")}, t0.Add(3*time.Hour))
	_ = m.ReplaceDevices(ctx, "t-retail", "int-vm", []ControllerDevice{dev("10.0.0.3", "c")}, t0.Add(3*time.Hour+time.Minute))
	_ = m.ReplaceDevices(ctx, "t-retail", "int-vm", []ControllerDevice{dev("10.0.0.1", "a"), dev("10.0.0.3", "c")}, t0.Add(3*time.Hour+30*time.Minute))
	_ = m.ReplaceDevices(ctx, "t-retail", "int-vm", []ControllerDevice{dev("10.0.0.3", "c")}, t0.Add(4*time.Hour+15*time.Minute))
	if got, _ := m.Devices(ctx, "t-retail", false, "int-vm"); len(got) != 2 {
		t.Fatalf("a device that came back kept its old absence clock: %v", keysOf(t, got))
	}
}

// §3a: the owner is the INTEGRATION's, never what a row claims; one tenant's
// read never returns another's; deleting the integration removes its devices.
func TestDeviceStoreIsOwnedByTheIntegration(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	now := time.Now().UTC()
	forged := dev("10.255.255.40", "edge")
	forged.TenantID = "t-other" // a controller (or bug) claiming another tenant
	_ = m.ReplaceDevices(ctx, "t-retail", "int-vm", []ControllerDevice{forged}, now)
	_ = m.ReplaceDevices(ctx, "t-acme", "int-acme", []ControllerDevice{dev("10.255.255.40", "same system-ip, other tenant")}, now)

	mine, _ := m.Devices(ctx, "t-retail", false, "int-vm")
	if len(mine) != 1 || mine[0].TenantID != "t-retail" {
		t.Fatalf("owner not stamped from the integration: %+v", mine)
	}
	if other, _ := m.Devices(ctx, "t-other", false, "int-vm"); len(other) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: the forged tenant reads the row: %+v", other)
	}
	if acmeSeesRetail, _ := m.Devices(ctx, "t-acme", false, "int-vm"); len(acmeSeesRetail) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: acme reads retail's integration: %+v", acmeSeesRetail)
	}
	if all, _ := m.Devices(ctx, "", true, "int-acme"); len(all) != 1 || all[0].Name != "same system-ip, other tenant" {
		t.Fatalf("same key in two tenants must be two rows: %+v", all)
	}

	_ = m.Upsert(ctx, Integration{Tenant: "t-retail", ID: "int-vm", Vendor: "vmanage"})
	if ok, _ := m.Delete(ctx, "t-retail", false, "int-vm"); !ok {
		t.Fatal("delete")
	}
	if left, _ := m.Devices(ctx, "", true, "int-vm"); len(left) != 0 {
		t.Fatalf("an integration's devices must leave with it: %+v", left)
	}
	if acme, _ := m.Devices(ctx, "t-acme", false, "int-acme"); len(acme) != 1 {
		t.Fatal("deleting one tenant's integration touched another's devices")
	}
}

// The scheduler applies a snapshot ONLY when it is complete.
func TestSinkAppliesOnlyCompleteSnapshots(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	rt := NewRuntime(m, Sinks{}, 0)
	ic := Integration{Tenant: "t-retail", ID: "int-vm", Vendor: "vmanage"}
	rt.sinkRouted(ctx, ic, Routed{Devices: []ControllerDevice{dev("10.0.0.9", "partial")}})
	if got, _ := m.Devices(ctx, "t-retail", false, "int-vm"); len(got) != 0 {
		t.Fatalf("an incomplete snapshot was stored: %+v", got)
	}
	rt.sinkRouted(ctx, ic, Routed{Devices: []ControllerDevice{dev("10.0.0.9", "full")}, DevicesComplete: true})
	if got, _ := m.Devices(ctx, "t-retail", false, "int-vm"); len(got) != 1 || got[0].Name != "full" {
		t.Fatalf("a complete snapshot was not stored: %+v", got)
	}
}
