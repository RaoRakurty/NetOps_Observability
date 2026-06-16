package main

import (
	"testing"

	"netops/backend/collectors"
)

// owned inventory fixture: leaf1 + spine1 are the caller's devices.
func ownedFixture() (id, name, addr map[string]string) {
	id = map[string]string{"leaf1": "leaf1", "spine1": "spine1"}
	name = map[string]string{"leaf1": "leaf1", "spine1": "spine1"}
	addr = map[string]string{"10.0.0.2": "spine1"}
	return
}

func findLink(links []topoLink, src, tgt string) *topoLink {
	for i := range links {
		if links[i].Source == src && links[i].Target == tgt {
			return &links[i]
		}
	}
	return nil
}

// A→B and B→A collapse into ONE undirected, bidirectional, resolved link, and the
// reverse direction fills the remote port.
func TestNormalizeLLDP_BidirectionalDedup(t *testing.T) {
	id, name, addr := ownedFixture()
	neighbors := []collectors.LLDPNeighbor{
		{LocalDevice: "leaf1", LocalPort: "Ethernet1", RemSysName: "spine1", RemPort: "", TS: 100},
		{LocalDevice: "spine1", LocalPort: "Ethernet2", RemSysName: "leaf1", RemPort: "Ethernet1", TS: 200},
	}
	links := normalizeLLDP(neighbors, id, name, addr)
	if len(links) != 1 {
		t.Fatalf("expected 1 deduped link, got %d: %+v", len(links), links)
	}
	l := links[0]
	if !l.Bidirectional {
		t.Error("link should be bidirectional (both ends reported it)")
	}
	if !l.Resolved {
		t.Error("both endpoints are managed → resolved")
	}
	if l.RemotePort != "Ethernet2" {
		t.Errorf("remote port should be filled from the reverse direction; got %q", l.RemotePort)
	}
	if l.LastSeen != 200 {
		t.Errorf("last-seen should be the newest of the pair; got %d", l.LastSeen)
	}
}

// A neighbour that isn't in the caller's inventory becomes an EXTERNAL node, never
// silently dropped and never resolved to a managed id.
func TestNormalizeLLDP_ExternalNeighbor(t *testing.T) {
	id, name, addr := ownedFixture()
	neighbors := []collectors.LLDPNeighbor{
		{LocalDevice: "leaf1", LocalPort: "Ethernet9", RemSysName: "isp-pe-7", TS: 50},
	}
	links := normalizeLLDP(neighbors, id, name, addr)
	l := findLink(links, "leaf1", "ext:isp-pe-7")
	if l == nil {
		t.Fatalf("expected an external link leaf1→ext:isp-pe-7; got %+v", links)
	}
	if l.Resolved {
		t.Error("an unmanaged neighbour must not be marked resolved")
	}
	if l.TargetName != "isp-pe-7" {
		t.Errorf("external target name = %q, want isp-pe-7", l.TargetName)
	}
}

// TENANT ISOLATION: a half-link whose LOCAL device the caller does not own is
// dropped entirely — the caller never learns another tenant's adjacencies.
func TestNormalizeLLDP_TenantIsolation(t *testing.T) {
	id, name, addr := ownedFixture()
	neighbors := []collectors.LLDPNeighbor{
		// foreign device (not owned) reporting a neighbour → must be dropped
		{LocalDevice: "other-tenant-rtr", LocalPort: "xe-0/0/0", RemSysName: "leaf1", TS: 10},
		// owned device's real link → kept
		{LocalDevice: "leaf1", LocalPort: "Ethernet1", RemSysName: "spine1", TS: 20},
	}
	links := normalizeLLDP(neighbors, id, name, addr)
	for _, l := range links {
		if l.Source == "other-tenant-rtr" || l.Target == "other-tenant-rtr" {
			t.Fatalf("foreign device leaked into topology: %+v", l)
		}
	}
	if findLink(links, "leaf1", "spine1") == nil {
		t.Errorf("owned link leaf1→spine1 should be present; got %+v", links)
	}
}

// No owned devices → no links (the whole set is foreign to this caller).
func TestNormalizeLLDP_NoOwnedDevices(t *testing.T) {
	neighbors := []collectors.LLDPNeighbor{
		{LocalDevice: "leaf1", RemSysName: "spine1", TS: 1},
	}
	if links := normalizeLLDP(neighbors, map[string]string{}, map[string]string{}, map[string]string{}); len(links) != 0 {
		t.Errorf("no owned devices → 0 links; got %+v", links)
	}
}

// Resolution: system-name (incl. FQDN leading label) and mgmt-address fallback.
func TestResolveNeighbor(t *testing.T) {
	_, name, addr := ownedFixture()
	if id, ok := resolveNeighbor(collectors.LLDPNeighbor{RemSysName: "spine1"}, name, addr); !ok || id != "spine1" {
		t.Errorf("sysname resolve = %q,%v", id, ok)
	}
	if id, ok := resolveNeighbor(collectors.LLDPNeighbor{RemSysName: "SPINE1.lab.example.com"}, name, addr); !ok || id != "spine1" {
		t.Errorf("FQDN leading-label resolve = %q,%v", id, ok)
	}
	if id, ok := resolveNeighbor(collectors.LLDPNeighbor{RemSysName: "", RemChassis: "10.0.0.2"}, name, addr); !ok || id != "spine1" {
		t.Errorf("mgmt-address resolve = %q,%v", id, ok)
	}
	if _, ok := resolveNeighbor(collectors.LLDPNeighbor{RemSysName: "stranger"}, name, addr); ok {
		t.Error("unknown neighbour must not resolve")
	}
}
