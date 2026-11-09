// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

import (
	"testing"

	"netops/backend/models"
)

// Constituents hands back every source's own record of one device — the values
// mergeDevices' gap-fill hides — and never another tenant's record.
func TestConstituentsAreThePerSourceRecordsOfOneDevice(t *testing.T) {
	a := NewDiscoveryAggregator()
	snmp := models.Device{ID: "vedge-20-1e95f00f", Name: "vEdge-20", Address: "192.168.222.104", Source: "snmp", OSVersion: "20.6.2", TenantID: "t-a"}
	ctl := models.Device{ID: "ctl-vmanage-0a1b", Name: "vEdge-20", Address: "10.255.255.20", Source: "api", OSVersion: "20.6.1", TenantID: "t-a",
		Labels: map[string]string{"serial": "S1"}}
	other := models.Device{ID: "vedge-20-other", Name: "vEdge-20", Address: "192.168.222.104", Source: "snmp", OSVersion: "66.6", TenantID: "t-b"}
	alone := models.Device{ID: "core-1", Name: "core-1", Address: "10.0.0.1", Source: "snmp", TenantID: "t-a"}
	a.cache = map[string]models.Device{snmp.ID: snmp, ctl.ID: ctl, other.ID: other, alone.ID: alone}

	merged := ""
	for _, d := range a.Devices() {
		if d.Name == "vEdge-20" && d.TenantID == "t-a" {
			merged = d.ID
			if d.OSVersion != "20.6.2" {
				t.Fatalf("precondition: the merged row keeps the base's value: %+v", d)
			}
		}
	}
	got := a.Constituents(merged)
	if len(got) != 2 || got[0].ID != ctl.ID || got[1].ID != snmp.ID {
		t.Fatalf("constituents = %+v — want the controller and SNMP records of tenant A, sorted by id", got)
	}
	if got[0].OSVersion != "20.6.1" {
		t.Fatalf("the losing value must be visible: %+v", got[0])
	}
	got[0].Labels["serial"] = "tampered"
	if a.cache[ctl.ID].Labels["serial"] != "S1" {
		t.Fatal("a caller changed the cached labels")
	}
	if c := a.Constituents("core-1"); len(c) != 1 || c[0].ID != "core-1" {
		t.Fatalf("a single-source device is its own constituent: %+v", c)
	}
	if c := a.Constituents(ctl.ID); len(c) != 0 && merged != ctl.ID {
		t.Fatalf("an absorbed record's id serves no device: %+v", c)
	}
	if c := a.Constituents("no-such"); c != nil {
		t.Fatalf("unknown id: %+v", c)
	}
}
