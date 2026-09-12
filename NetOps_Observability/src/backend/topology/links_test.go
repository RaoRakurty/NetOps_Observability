// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

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

func findLink(links []TopoLink, src, tgt string) *TopoLink {
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
	links := NormalizeLLDP(neighbors, id, name, addr, nil)
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
	links := NormalizeLLDP(neighbors, id, name, addr, nil)
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
	links := NormalizeLLDP(neighbors, id, name, addr, nil)
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
	if links := NormalizeLLDP(neighbors, map[string]string{}, map[string]string{}, map[string]string{}, nil); len(links) != 0 {
		t.Errorf("no owned devices → 0 links; got %+v", links)
	}
}

// BGP-LS links resolve BOTH endpoints by name/addr (neither is the polled device)
// and are anchored on a device the caller owns.
func TestNormalizeBGPLS_BothEndpointsResolved(t *testing.T) {
	id, name, addr := ownedFixture()
	neighbors := []collectors.LLDPNeighbor{
		{Proto: "bgp_ls", IGP: "isis-l2", LocalName: "spine1", LocalPort: "10.0.0.1",
			RemSysName: "leaf1", RemPort: "10.0.0.2", TS: 300},
	}
	links := NormalizeLLDP(neighbors, id, name, addr, nil)
	l := findLink(links, "leaf1", "spine1") // endpoints sorted → leaf1 < spine1
	if l == nil {
		l = findLink(links, "spine1", "leaf1")
	}
	if l == nil {
		t.Fatalf("expected a resolved bgp_ls link between spine1 and leaf1; got %+v", links)
	}
	if !l.Resolved {
		t.Error("both endpoints managed → resolved")
	}
	if l.SourceProto != "bgp_ls" {
		t.Errorf("source_protocol = %q, want bgp_ls", l.SourceProto)
	}
	if l.IGP != "isis-l2" {
		t.Errorf("igp = %q, want isis-l2", l.IGP)
	}
}

// TENANT ISOLATION (bgp_ls): a link whose LOCAL node is not owned is dropped —
// BGP-LS hands us the whole IGP graph, but a caller only sees links anchored on
// its own devices.
func TestNormalizeBGPLS_TenantIsolation(t *testing.T) {
	id, name, addr := ownedFixture()
	neighbors := []collectors.LLDPNeighbor{
		{Proto: "bgp_ls", LocalName: "foreign-core", RemSysName: "spine1", TS: 1},
	}
	if links := NormalizeLLDP(neighbors, id, name, addr, nil); len(links) != 0 {
		t.Fatalf("a bgp_ls link not anchored on an owned device must be dropped; got %+v", links)
	}
}

// Cross-protocol confirmation: the SAME adjacency seen by both BGP-LS and LLDP
// collapses into one link whose source_protocol unions both (strongest evidence).
func TestNormalizeBGPLS_CrossProtocolUnion(t *testing.T) {
	id, name, addr := ownedFixture()
	neighbors := []collectors.LLDPNeighbor{
		{Proto: "bgp_ls", IGP: "isis-l2", LocalName: "spine1", RemSysName: "leaf1", TS: 100},
		{Proto: "lldp", LocalDevice: "leaf1", LocalPort: "Ethernet1", RemSysName: "spine1", TS: 200},
	}
	links := NormalizeLLDP(neighbors, id, name, addr, nil)
	if len(links) != 1 {
		t.Fatalf("same adjacency from two protocols → 1 link; got %d: %+v", len(links), links)
	}
	if links[0].SourceProto != "bgp_ls+lldp" {
		t.Errorf("source_protocol = %q, want bgp_ls+lldp", links[0].SourceProto)
	}
	if !links[0].Bidirectional {
		t.Error("multi-observer link should be bidirectional")
	}
	if links[0].IGP != "isis-l2" {
		t.Errorf("igp origin should carry over from bgp_ls; got %q", links[0].IGP)
	}
}

// BGP-LS port enrichment: link descriptors carry interface IPs, not port names.
// With the SNMP-published interface-address map, both ends' IP ports resolve to
// real ifNames; without the map they fall through unchanged (best-effort).
func TestNormalizeBGPLS_IfAddrEnrichment(t *testing.T) {
	id, name, addr := ownedFixture()
	neighbors := []collectors.LLDPNeighbor{
		{Proto: "bgp_ls", IGP: "ospfv2", LocalName: "spine1", LocalPort: "10.0.0.1",
			RemSysName: "leaf1", RemPort: "10.0.0.2", TS: 300},
	}
	ifaddr := map[string]map[string]string{
		"spine1": {"10.0.0.1": "Ethernet1/1"},
		"leaf1":  {"10.0.0.2": "Ethernet49"},
	}
	links := NormalizeLLDP(neighbors, id, name, addr, ifaddr)
	l := findLink(links, "leaf1", "spine1")
	if l == nil {
		l = findLink(links, "spine1", "leaf1")
	}
	if l == nil {
		t.Fatalf("expected a bgp_ls link between spine1 and leaf1; got %+v", links)
	}
	// The link was created with src=spine1 → LocalPort is spine1's interface,
	// RemotePort is leaf1's; both IPs must resolve to ifNames.
	if l.LocalPort != "Ethernet1/1" {
		t.Errorf("local IP port should resolve to ifName; got %q", l.LocalPort)
	}
	if l.RemotePort != "Ethernet49" {
		t.Errorf("remote IP port should resolve to ifName; got %q", l.RemotePort)
	}

	// No map → IP ports pass through untouched (no panic, no error).
	plain := NormalizeLLDP(neighbors, id, name, addr, nil)
	if len(plain) != 1 || plain[0].LocalPort != "10.0.0.1" {
		t.Errorf("without ifaddr, IP ports must pass through unchanged; got %+v", plain)
	}
}

// Enrichment must NOT touch non-BGP-LS links — LLDP/CDP already carry real port
// names, and an LLDP port that happens to collide with the map must be left as-is.
func TestNormalizeLLDP_NoIfAddrEnrichment(t *testing.T) {
	id, name, addr := ownedFixture()
	neighbors := []collectors.LLDPNeighbor{
		{LocalDevice: "leaf1", LocalPort: "Ethernet1", RemSysName: "spine1", TS: 10},
	}
	ifaddr := map[string]map[string]string{"leaf1": {"Ethernet1": "WRONG"}}
	links := NormalizeLLDP(neighbors, id, name, addr, ifaddr)
	if findLink(links, "leaf1", "spine1") == nil || links[0].LocalPort != "Ethernet1" {
		t.Errorf("LLDP ports must never be rewritten by ifaddr enrichment; got %+v", links)
	}
}

// Resolution: system-name (incl. FQDN leading label) and mgmt-address fallback.
func TestResolveNeighbor(t *testing.T) {
	_, name, addr := ownedFixture()
	if id, ok := resolveNeighborID(collectors.LLDPNeighbor{RemSysName: "spine1"}, name, addr); !ok || id != "spine1" {
		t.Errorf("sysname resolve = %q,%v", id, ok)
	}
	if id, ok := resolveNeighborID(collectors.LLDPNeighbor{RemSysName: "SPINE1.lab.example.com"}, name, addr); !ok || id != "spine1" {
		t.Errorf("FQDN leading-label resolve = %q,%v", id, ok)
	}
	if id, ok := resolveNeighborID(collectors.LLDPNeighbor{RemSysName: "", RemChassis: "10.0.0.2"}, name, addr); !ok || id != "spine1" {
		t.Errorf("mgmt-address resolve = %q,%v", id, ok)
	}
	if _, ok := resolveNeighborID(collectors.LLDPNeighbor{RemSysName: "stranger"}, name, addr); ok {
		t.Error("unknown neighbour must not resolve")
	}
}
