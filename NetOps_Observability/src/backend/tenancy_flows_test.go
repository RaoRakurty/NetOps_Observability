package main

import (
	"sort"
	"strings"
	"testing"

	"netops/backend/models"
)

func serverWithDevices() *server {
	d := NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "core-1", Name: "core-1", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "edge-2", Name: "edge-2", Address: "10.2.0.1", TenantID: "globex"})
	d.Upsert(models.Device{ID: "shared", Name: "shared", Address: "10.9.0.1"}) // global/shared
	return &server{discovery: d}
}

func TestVisibleDeviceAddrsTenantIsolation(t *testing.T) {
	s := serverWithDevices()
	addrs, cross := s.visibleDeviceAddrs(jwtClaims{Role: RoleOperator, Tenant: "acme"})
	if cross {
		t.Fatal("scoped acme operator must not be cross-tenant")
	}
	set := map[string]bool{}
	for _, a := range addrs {
		set[a] = true
	}
	if !set["10.1.0.1"] {
		t.Error("acme should see its own device address")
	}
	if set["10.2.0.1"] {
		t.Error("TENANT LEAK: acme must NOT see globex device address in flow scoping")
	}
	if !set["10.9.0.1"] {
		t.Error("shared device address should be visible to a scoped tenant")
	}
}

func TestVisibleDeviceAddrsCrossTenant(t *testing.T) {
	s := serverWithDevices()
	addrs, cross := s.visibleDeviceAddrs(jwtClaims{Role: RoleSuperAdmin})
	if !cross || addrs != nil {
		t.Fatalf("super-admin should be cross-tenant (nil addrs), got cross=%v addrs=%v", cross, addrs)
	}
}

func TestVisibleDeviceKeysTenantIsolation(t *testing.T) {
	s := serverWithDevices()
	keys, cross := s.visibleDeviceKeys(jwtClaims{Role: RoleReadOnly, Tenant: "globex"})
	if cross {
		t.Fatal("scoped globex must not be cross-tenant")
	}
	set := map[string]bool{}
	for _, k := range keys {
		set[k] = true
	}
	// globex sees its own id+name and the shared device, never acme's.
	if !set["edge-2"] {
		t.Error("globex should see its own device keys")
	}
	if set["core-1"] {
		t.Error("TENANT LEAK: globex must NOT see acme device keys in findings scoping")
	}
}

func TestSQLInListEscapes(t *testing.T) {
	got := sqlInList([]string{"a", "o'brien"})
	want := []string{"'a'", "'o''brien'"}
	parts := strings.Split(got, ", ")
	sort.Strings(parts)
	sort.Strings(want)
	if strings.Join(parts, "|") != strings.Join(want, "|") {
		t.Errorf("sqlInList escaping: got %q", got)
	}
}
