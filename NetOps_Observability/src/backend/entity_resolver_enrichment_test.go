// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// entity_resolver_enrichment_test.go — the join between the inventory and the
// tenant-less SNMP maps. A row reaches the engine under its device's current tenant,
// or not at all (§3a).

import (
	"testing"

	"netops/backend/models"
)

func erAddrRows(t *testing.T, out entityResolverExport, ip string) []erIfaceIP {
	t.Helper()
	var got []erIfaceIP
	for _, r := range out.InterfaceIPs {
		if r.IP == ip {
			got = append(got, r)
		}
	}
	return got
}

func TestEntityResolverExportStampsTheCurrentTenant(t *testing.T) {
	devs := []models.Device{
		{ID: "a", TenantID: " Acme ", Address: "192.0.2.1"},
		{ID: "b", TenantID: "bravo", Address: "192.0.2.2"},
		{ID: "g", Address: "192.0.2.3"},
	}
	out := buildEntityResolverExport(devs,
		map[string]map[string]string{
			"a": {"10.0.0.1": "Gi1"},
			"b": {"10.0.0.2": "Gi2"},
			"g": {"10.0.0.3": "Gi3"},
		},
		map[string]map[string]string{"a": {"7": "Gi1"}, "b": {"8": "Gi2"}},
	)
	for ip, want := range map[string]string{"10.0.0.1": "acme", "10.0.0.2": "bravo", "10.0.0.3": ""} {
		got := erAddrRows(t, out, ip)
		if len(got) != 1 || got[0].TenantID != want {
			t.Fatalf("%s: %+v, want tenant %q", ip, got, want)
		}
	}
	if len(out.IfIndex) != 2 {
		t.Fatalf("ifindex rows: %+v", out.IfIndex)
	}
	for _, r := range out.IfIndex {
		if (r.Device == "a" && r.TenantID != "acme") || (r.Device == "b" && r.TenantID != "bravo") {
			t.Fatalf("ifindex row under the wrong tenant: %+v", r)
		}
	}
}

// A device no longer in the inventory has no tenant to stamp. "" would be GLOBAL: the
// row would enter every tenant's resolver.
func TestEntityResolverExportOmitsARowWithNoInventoryDevice(t *testing.T) {
	devs := []models.Device{{ID: "a", TenantID: "acme", Address: "192.0.2.1"}}
	out := buildEntityResolverExport(devs,
		map[string]map[string]string{"gone": {"10.0.0.9": "Gi9"}, "a": {"10.0.0.1": "Gi1"}},
		map[string]map[string]string{"gone": {"9": "Gi9"}},
	)
	if got := erAddrRows(t, out, "10.0.0.9"); len(got) != 0 {
		t.Fatalf("a removed device's row was exported: %+v", got)
	}
	if len(out.IfIndex) != 0 {
		t.Fatalf("a removed device's ifIndex row was exported: %+v", out.IfIndex)
	}
	if got := erAddrRows(t, out, "10.0.0.1"); len(got) != 1 {
		t.Fatalf("own row lost: %+v", out.InterfaceIPs)
	}
}

// Two devices claiming one address both export: the resolver is what refuses to pick,
// and it can only refuse a conflict it can see.
func TestEntityResolverExportKeepsBothClaimsOfASharedAddress(t *testing.T) {
	devs := []models.Device{{ID: "a", TenantID: "acme"}, {ID: "b", TenantID: "acme"}}
	out := buildEntityResolverExport(devs,
		map[string]map[string]string{"a": {"192.168.1.1": "Gi1"}, "b": {"192.168.1.1": "Gi1"}}, nil)
	if got := erAddrRows(t, out, "192.168.1.1"); len(got) != 2 {
		t.Fatalf("a claim was dropped before the resolver saw it: %+v", got)
	}
}
