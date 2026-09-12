// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package advisory

import (
	"errors"
	"testing"

	"netops/backend/internal/vendorprofile"
)

func TestProviderNameForKnownPlatforms(t *testing.T) {
	reg := vendorprofile.Default()
	for _, c := range []struct{ vendor, platform string }{
		{"cisco", "ios_xe"}, {"cisco", "nx-os"}, {"juniper", "junos"},
		{"arista", "eos"}, {"nokia", "srlinux"}, {"nokia", "sros"},
	} {
		name, err := ProviderNameFor(reg, c.vendor, c.platform)
		if err != nil {
			t.Errorf("ProviderNameFor(%s/%s): %v", c.vendor, c.platform, err)
			continue
		}
		if name != SourceOfflineFeed {
			t.Errorf("ProviderNameFor(%s/%s) = %q, want %q (the air-gap canonical path)", c.vendor, c.platform, name, SourceOfflineFeed)
		}
		ids, err := ProductIDsFor(reg, c.vendor, c.platform)
		if err != nil || len(ids) == 0 || ids[0] != c.platform {
			t.Errorf("ProductIDsFor(%s/%s) = %v, %v", c.vendor, c.platform, ids, err)
		}
	}
	// The catalog's own platform alias must select the same binding.
	if name, err := ProviderNameFor(reg, "arista", "ceos"); err != nil || name != SourceOfflineFeed {
		t.Errorf("ProviderNameFor(arista/ceos) = %q, %v", name, err)
	}
}

// TestUnknownPlatformIsUnassessed — the honesty rule. No profile means no
// provider: an error the caller reports as UNASSESSED, never a silently
// substituted default provider that would produce a false "no advisories".
func TestUnknownPlatformIsUnassessed(t *testing.T) {
	reg := vendorprofile.Default()
	for _, c := range []struct{ vendor, platform string }{
		{"sonicwall", "sonicos"}, {"cisco", "widgetos"}, {"", ""}, {"extreme", "exos"},
	} {
		if _, err := ProviderNameFor(reg, c.vendor, c.platform); !errors.Is(err, ErrNoProvider) {
			t.Errorf("ProviderNameFor(%s/%s) = %v, want ErrNoProvider", c.vendor, c.platform, err)
		}
		if _, err := ProductIDsFor(reg, c.vendor, c.platform); !errors.Is(err, ErrNoProvider) {
			t.Errorf("ProductIDsFor(%s/%s) = %v, want ErrNoProvider", c.vendor, c.platform, err)
		}
	}
	if _, err := ProviderNameFor(nil, "cisco", "ios"); !errors.Is(err, ErrNoProvider) {
		t.Errorf("nil registry = %v, want ErrNoProvider", err)
	}
}

func TestSelectProvider(t *testing.T) {
	reg := vendorprofile.Default()
	other := NewMockProvider("mock") // deliberately NOT the provider the profile binds
	wired := []VendorAdvisoryProvider{nil, other}

	// The profile binds "offline-feed"; a wired set that lacks it must ERROR
	// rather than fall through to whatever provider happens to be first.
	if p, err := SelectProvider(reg, wired, Query{Vendor: "cisco", Platform: "ios_xe", Version: "17.9.4a"}); err == nil {
		t.Fatalf("SelectProvider returned %q for an unwired binding — it must never guess", p.Name())
	} else if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("SelectProvider err = %v, want ErrNoProvider", err)
	}

	// With the bound provider present it is selected by name.
	feed := NewMockProvider(SourceOfflineFeed)
	got, err := SelectProvider(reg, []VendorAdvisoryProvider{other, feed}, Query{Vendor: "cisco", Platform: "ios_xe"})
	if err != nil {
		t.Fatalf("SelectProvider: %v", err)
	}
	if got.Name() != SourceOfflineFeed {
		t.Fatalf("SelectProvider chose %q, want %q", got.Name(), SourceOfflineFeed)
	}

	// An unknown platform never selects anything.
	if _, err := SelectProvider(reg, []VendorAdvisoryProvider{feed}, Query{Vendor: "sonicwall", Platform: "sonicos"}); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("unknown platform err = %v, want ErrNoProvider", err)
	}
}
