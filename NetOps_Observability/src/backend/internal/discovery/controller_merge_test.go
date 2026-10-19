// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

import (
	"testing"

	"netops/backend/models"
)

// A controller-reported device and the SAME box found by SNMP are one device,
// and the SNMP record is the base whatever the id order: its id is the one
// syslog, traps and flows key on, and its source keeps it on the collectors.
// ("ctl-…" sorts before "vedge-…", which used to make it the base.)
func TestMergeNeverMakesAControllerRecordTheBase(t *testing.T) {
	snmp := models.Device{ID: "vedge-20-1e95f00f", Name: "vEdge-20", Address: "192.168.222.104", Source: "snmp"}
	ctl := models.Device{ID: "ctl-vmanage-0a1b2c3d4e5f", Name: "vEdge-20", Address: "10.255.255.20", Source: "api",
		Model: "vedge-cloud", OSVersion: "20.6.1", OSVersionSource: "api:vmanage", Labels: map[string]string{"system_ip": "10.255.255.20"}}
	for _, pair := range [][2]models.Device{{ctl, snmp}, {snmp, ctl}} {
		m := mergeDevices(pair[0], pair[1])
		if m.ID != snmp.ID || m.Source != "snmp" || m.Address != snmp.Address {
			t.Fatalf("base = %s/%s/%s — want the SNMP record", m.ID, m.Source, m.Address)
		}
		if m.Model != "vedge-cloud" || m.OSVersion != "20.6.1" || m.OSVersionSource != "api:vmanage" {
			t.Fatalf("the controller record must still fill the gaps: %+v", m)
		}
		if m.Labels["system_ip"] != "10.255.255.20" {
			t.Fatalf("the controller key must survive the merge (the resolver matches on it): %v", m.Labels)
		}
	}
	// NetBox stays the source of truth over both.
	nb := models.Device{ID: "zz-netbox", Name: "vEdge-20", Source: "netbox"}
	if m := mergeDevices(mergeDevices(ctl, snmp), nb); m.ID != "zz-netbox" {
		t.Fatalf("netbox must remain the base: %s", m.ID)
	}
}

// The tenant-partitioned union still never folds two tenants' records — a
// RETAIL controller device and a platform SNMP device of the same name stay
// two devices.
func TestControllerAndSNMPOfDifferentOwnersNeverMerge(t *testing.T) {
	a := models.Device{ID: "ctl-vmanage-aaaaaaaaaaaa", Name: "vEdge-20", Address: "10.255.255.20", Source: "api", TenantID: "t_retail"}
	b := models.Device{ID: "vedge-20-1e95f00f", Name: "vEdge-20", Address: "10.255.255.20", Source: "snmp"}
	cache := map[string]models.Device{a.ID: a, b.ID: b}
	out, _ := dedupeWithOwners(cache)
	if len(out) != 2 {
		t.Fatalf("%d devices — two owners must stay two devices", len(out))
	}
}
