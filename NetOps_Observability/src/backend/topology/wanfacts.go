// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

// wanfacts.go — the WAN-edge flavor facts the role classifier reads
// (tracker 349, docs/design/SDWAN_OVERLAY_TOPOLOGY_2026-10-10.md). Pure; the
// caller gathers the raw inputs (interface names, BGP peers, addresses) from
// the collectors and injects them.
//
// TENANT RULE (§3a): "external" means outside the device's OWN tenant. A BGP
// peer that happens to be another tenant's device is external to this one, so
// another tenant's inventory can never change this tenant's classification.

import (
	"sort"
	"strings"
)

// BGPPeerInputs is what ExternalBGPPeerCounts needs, keyed by device id.
type BGPPeerInputs struct {
	DevTenant map[string]string   // device id → tenant
	DevAddrs  map[string][]string // device id → its own addresses (management + interface IPs)
	Peers     map[string][]string // device id → BGP peer addresses it reports
}

// ExternalBGPPeerCounts returns, per device, how many distinct BGP peer
// addresses belong to no device of the SAME tenant. Devices with no peers are
// absent from the result.
func ExternalBGPPeerCounts(in BGPPeerInputs) map[string]int {
	owned := map[string]map[string]bool{} // tenant → address set
	for dev, addrs := range in.DevAddrs {
		t := in.DevTenant[dev]
		set := owned[t]
		if set == nil {
			set = map[string]bool{}
			owned[t] = set
		}
		for _, a := range addrs {
			if a = normAddr(a); a != "" {
				set[a] = true
			}
		}
	}
	out := map[string]int{}
	for dev, peers := range in.Peers {
		set := owned[in.DevTenant[dev]]
		seen := map[string]bool{}
		for _, p := range peers {
			p = normAddr(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			if !set[p] {
				out[dev]++
			}
		}
	}
	return out
}

// normAddr trims an address and drops a prefix length ("10.0.0.1/30").
func normAddr(a string) string {
	a = strings.TrimSpace(a)
	if i := strings.IndexByte(a, '/'); i >= 0 {
		a = a[:i]
	}
	return strings.ToLower(a)
}

// FabricNeighborCounts returns, per device, how many of its neighbors classify
// as data-center leaf or spine. The neighbor roles are classified from the
// facts WITHOUT their own fabric count (a leaf/spine is decided by name, type
// and fabric OS, never by its neighbors), so there is no circularity.
func FabricNeighborCounts(facts []DeviceFact, links []TopoLink) map[string]int {
	fabric := map[string]bool{}
	for _, f := range facts {
		switch ClassifyDeviceRole(f).Role {
		case DevRoleDCLeaf, DevRoleDCSpine:
			fabric[f.ID] = true
		}
	}
	if len(fabric) == 0 {
		return map[string]int{}
	}
	nbrs := map[string]map[string]bool{}
	add := func(a, b string) {
		if !fabric[b] || a == b {
			return
		}
		if nbrs[a] == nil {
			nbrs[a] = map[string]bool{}
		}
		nbrs[a][b] = true
	}
	for _, l := range links {
		if l.Source == "" || l.Target == "" {
			continue
		}
		add(l.Source, l.Target)
		if l.Resolved {
			add(l.Target, l.Source)
		}
	}
	out := make(map[string]int, len(nbrs))
	for dev, set := range nbrs {
		out[dev] = len(set)
	}
	return out
}

// SortedIfNames returns the interface names of one device's ifIndex map in a
// stable order (the classifier only scans them; stable order keeps evidence
// text deterministic).
func SortedIfNames(byIndex map[string]string) []string {
	out := make([]string, 0, len(byIndex))
	for _, n := range byIndex {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
