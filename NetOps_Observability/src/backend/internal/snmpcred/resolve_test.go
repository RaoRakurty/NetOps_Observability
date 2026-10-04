// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package snmpcred

import (
	"path/filepath"
	"testing"
	"time"

	"netops/backend/models"
)

func resolveFixture(t *testing.T) (*Store, *OverrideStore) {
	t.Helper()
	dir := t.TempDir()
	cs, err := NewStore(filepath.Join(dir, "snmp.json"), nil, fileKV{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Credential{
		{ID: "plat", Name: "Shared", Version: "v2c", Community: "platform"},
		{ID: "acme", Name: "Shared", Version: "v2c", Community: "acme", TenantID: "acme"},
		{ID: "globex", Name: "Globex", Version: "v2c", Community: "globex", TenantID: "globex"},
		{ID: "b-global", Name: "beta", Version: "v2c", Community: "g", TenantID: "Global"},
	} {
		if _, err := cs.Upsert(c); err != nil {
			t.Fatal(err)
		}
	}
	ov, err := NewOverrideStore(filepath.Join(dir, "ov.json"))
	if err != nil {
		t.Fatal(err)
	}
	return cs, ov
}

func TestResolveForIsTenantScoped(t *testing.T) {
	cs, _ := resolveFixture(t)
	cases := []struct {
		ref, tenant, want string
	}{
		{"acme", "acme", "acme"},
		{"acme", "globex", ""},
		{"acme", "", ""},
		{"globex", " GLOBEX ", "globex"},
		{"plat", "acme", "plat"},
		{"Shared", "acme", "acme"}, // own tenant's profile wins a shared name
		{"shared", "globex", "plat"},
		{"Shared", "", "plat"},
		{"", "acme", ""},
		{"nope", "acme", ""},
	}
	for _, c := range cases {
		got, ok := cs.ResolveFor(c.ref, c.tenant)
		if (c.want == "") == ok || (ok && got.ID != c.want) {
			t.Errorf("ResolveFor(%q, %q) = %q,%v want %q", c.ref, c.tenant, got.ID, ok, c.want)
		}
	}
	var nilStore *Store
	if _, ok := nilStore.ResolveFor("plat", ""); ok {
		t.Fatal("nil store must resolve nothing")
	}
}

func TestScanCandidatesPlatformOnlyNameOrder(t *testing.T) {
	cs, _ := resolveFixture(t)
	got := cs.ScanCandidates()
	if len(got) != 2 || got[0].ID != "b-global" || got[1].ID != "plat" {
		ids := []string{}
		for _, c := range got {
			ids = append(ids, c.ID)
		}
		t.Fatalf("scan candidates = %v, want [b-global plat]", ids)
	}
}

func TestResolveForDeviceOverrideAppliesWithoutBoundRef(t *testing.T) {
	cs, ov := resolveFixture(t)
	dev := models.Device{ID: "d1", TenantID: "acme"}
	if _, ok := ResolveForDevice(cs, ov, dev); ok {
		t.Fatal("unbound, no override → no profile")
	}
	if err := ov.Set(Override{DeviceID: "d1", ProfileID: "acme", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if c, ok := ResolveForDevice(cs, ov, dev); !ok || c.ID != "acme" {
		t.Fatalf("override must apply to an unbound device, got %q %v", c.ID, ok)
	}
	// An override naming another tenant's profile falls back to the bound ref.
	if err := ov.Set(Override{DeviceID: "d1", ProfileID: "globex", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	dev.CredentialRef = "plat"
	if c, ok := ResolveForDevice(cs, ov, dev); !ok || c.ID != "plat" {
		t.Fatalf("cross-tenant override must be ignored, got %q %v", c.ID, ok)
	}
	if _, ok := ResolveForDevice(nil, ov, dev); ok {
		t.Fatal("nil creds store → no profile")
	}
}
