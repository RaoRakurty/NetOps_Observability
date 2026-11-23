// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devname

import "testing"

func TestNamesUsesTheHostnameNeverTheInternalID(t *testing.T) {
	got := Names([]Entry{{ID: "cedge-40-fdf7b64f", Name: "cEDGE-40", Address: "10.255.255.40", Tenant: "t1"}})
	if got["cedge-40-fdf7b64f"] != "cEDGE-40" {
		t.Fatalf("got %q", got["cedge-40-fdf7b64f"])
	}
}

func TestSameNameInOneTenantIsToldApartByAddress(t *testing.T) {
	got := Names([]Entry{
		{ID: "edge-1-aaaa", Name: "edge-1", Address: "10.0.0.1", Tenant: "t1"},
		{ID: "edge-1-bbbb", Name: "edge-1", Address: "10.0.0.2", Tenant: "T1 "},
	})
	if got["edge-1-aaaa"] != "edge-1 (10.0.0.1)" || got["edge-1-bbbb"] != "edge-1 (10.0.0.2)" {
		t.Fatalf("got %v", got)
	}
}

// §3a: a same-name device in ANOTHER tenant never changes how this one reads,
// so its existence is not revealed by a disambiguating suffix.
func TestAnotherTenantsSameNameDeviceChangesNothing(t *testing.T) {
	got := Names([]Entry{
		{ID: "edge-1-aaaa", Name: "edge-1", Address: "10.0.0.1", Tenant: "acme"},
		{ID: "edge-1-cccc", Name: "edge-1", Address: "10.0.0.1", Tenant: "globex"},
	})
	if got["edge-1-aaaa"] != "edge-1" || got["edge-1-cccc"] != "edge-1" {
		t.Fatalf("got %v", got)
	}
}

func TestNoUsableNameMeansNoEntry(t *testing.T) {
	got := Names([]Entry{
		{ID: "a-1", Name: ""},
		{ID: "b-2", Name: "  "},
		{ID: "c-3", Name: "c-3"},
		{ID: "", Name: "orphan"},
	})
	if len(got) != 0 {
		t.Fatalf("want no entries, got %v", got)
	}
}

func TestDuplicateWithoutAddressKeepsThePlainName(t *testing.T) {
	got := Names([]Entry{{ID: "x-1", Name: "sw"}, {ID: "x-2", Name: "sw"}})
	if got["x-1"] != "sw" || got["x-2"] != "sw" {
		t.Fatalf("got %v", got)
	}
}
