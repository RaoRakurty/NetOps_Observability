// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"testing"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/models"
	"netops/backend/nms"
)

// The discovery source name and the licence-counting source constant must be
// the same string, or controller devices would be counted as SNMP devices and
// fed to the SNMP collectors.
func TestControllerSourceNameMatchesDevmon(t *testing.T) {
	if nms.ControllerSourceName != devmon.SourceController {
		t.Fatalf("nms %q != devmon %q", nms.ControllerSourceName, devmon.SourceController)
	}
}

// VManage-only devices are collected through the vManage API, never by
// Correlix's own collectors (owner 2026-10-19); an SNMP-found device still is.
func TestControllerDevicesAreNeverPolledDirectly(t *testing.T) {
	if collectedDirectly(models.Device{Source: nms.ControllerSourceName, Address: "10.255.255.20"}) {
		t.Fatal("a controller-sourced device was offered to the SNMP/gNMI/NETCONF collectors")
	}
	if !collectedDirectly(models.Device{Source: "snmp", Address: "192.168.222.104"}) {
		t.Fatal("an SNMP device must stay on the collectors")
	}
}

// §3a: tenant A's controller never creates or reveals a device in tenant B.
// Same system-ip in two tenants = two devices with different ids, each
// visible only to its owner; a platform-owned integration's devices are the
// platform's.
func TestControllerInventoryIsTenantIsolated(t *testing.T) {
	ctx := context.Background()
	store := nms.NewMemStore()
	now := time.Now().UTC()
	edge := func(name string) nms.ControllerDevice {
		return nms.ControllerDevice{KeyKind: nms.KeySystemIP, Key: "10.255.255.20", MgmtAddr: "10.255.255.20", Name: name,
			SourceSystem: "vmanage", Managed: true, Role: "edge"}
	}
	for _, ic := range []nms.Integration{
		{Tenant: "t_retail", ID: "int-r", Vendor: "vmanage", Enabled: true},
		{Tenant: "t_acme", ID: "int-a", Vendor: "vmanage", Enabled: true},
		{Tenant: TenantGlobal, ID: "int-p", Vendor: "vmanage", Enabled: true},
	} {
		if err := store.Upsert(ctx, ic); err != nil {
			t.Fatal(err)
		}
		if err := store.ReplaceDevices(ctx, ic.Tenant, ic.ID, []nms.ControllerDevice{edge("vEdge-20 of " + ic.Tenant)}, now); err != nil {
			t.Fatal(err)
		}
	}
	devs, err := nms.NewControllerDeviceSource(store, 0).Poll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 3 {
		t.Fatalf("%d devices, want one per owner", len(devs))
	}
	ids := map[string]bool{}
	for _, d := range devs {
		if ids[d.ID] {
			t.Fatalf("two owners share device id %s", d.ID)
		}
		ids[d.ID] = true
	}
	visible := func(tenant string, cross bool) []string {
		var out []string
		for _, d := range devs {
			if canSeeDevice(d, tenant, cross) {
				out = append(out, d.Name)
			}
		}
		return out
	}
	if got := visible("t_retail", false); len(got) != 1 || got[0] != "vEdge-20 of t_retail" {
		t.Fatalf("CROSS-TENANT: retail sees %v", got)
	}
	if got := visible("t_acme", false); len(got) != 1 || got[0] != "vEdge-20 of t_acme" {
		t.Fatalf("CROSS-TENANT: acme sees %v", got)
	}
	if got := visible("", true); len(got) != 3 {
		t.Fatalf("the platform view sees %v, want all three", got)
	}
	for _, d := range devs {
		if d.Name == "vEdge-20 of "+TenantGlobal && d.TenantID != "" {
			t.Fatalf("a platform-owned integration's device must be the platform's (\"\"), got %q", d.TenantID)
		}
	}
}
