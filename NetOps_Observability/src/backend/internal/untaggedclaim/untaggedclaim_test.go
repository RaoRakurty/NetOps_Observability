// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package untaggedclaim

import (
	"reflect"
	"testing"

	"netops/backend/models"
)

func ownedBy(tenant string) func(models.Device) bool {
	return func(d models.Device) bool { return d.TenantID == tenant }
}

func TestUnambiguousDropsWhatAnotherOwnerHolds(t *testing.T) {
	devs := []models.Device{
		{ID: "a1", Name: "core-rtr-1", Address: "10.0.0.1", TenantID: "acme"},
		{ID: "a2", Name: "acme-edge", Address: "10.1.0.2", TenantID: "acme"},
		{ID: "g1", Name: "core-rtr-1", Address: "10.0.0.1", TenantID: "globex"},
	}
	got := Unambiguous(devs, ownedBy("acme"), false)
	want := Claim{Keys: []string{"a1", "a2", "acme-edge"}, Addrs: []string{"10.1.0.2"}, Devices: 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// The platform scope keeps every one of its own identities.
	plat := Unambiguous(devs, ownedBy("globex"), true)
	if !reflect.DeepEqual(plat.Keys, []string{"g1", "core-rtr-1"}) || !reflect.DeepEqual(plat.Addrs, []string{"10.0.0.1"}) {
		t.Fatalf("platform scope dropped its own identities: %+v", plat)
	}
}

func TestUnambiguousNilOwnsClaimsNothing(t *testing.T) {
	if got := Unambiguous([]models.Device{{ID: "x", TenantID: "acme"}}, nil, false); !reflect.DeepEqual(got, Claim{}) {
		t.Fatalf("nil owns must claim nothing: %+v", got)
	}
}

func TestForms(t *testing.T) {
	cases := map[string][]string{
		"":                     nil,
		"  ":                   nil,
		"Core-RTR-1":           {"core-rtr-1"},
		"core-rtr-1.Lab.Local": {"core-rtr-1.lab.local", "core-rtr-1"},
		"::ffff:10.9.9.9":      {"10.9.9.9"},
		"10.9.9.9":             {"10.9.9.9"},
		"FE80::1":              {"fe80::1"},
		"fe80::1%eth0":         {"fe80::1%eth0"}, // zoned: not canonicalised, compared as text
	}
	for in, want := range cases {
		if got := Forms(in); !reflect.DeepEqual(got, want) {
			t.Errorf("Forms(%q) = %v, want %v", in, got, want)
		}
	}
}
