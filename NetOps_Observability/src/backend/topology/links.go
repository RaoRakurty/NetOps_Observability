// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

// links.go — LLDP/CDP/BGP-LS adjacency normalization (extracted P2 RA.16).
// The pure read-side fold that turns raw directed half-links into deduped
// undirected topology links, ENCODING the tenant-isolation rule: only links
// anchored on a device the caller owns are kept, and a neighbour is resolved
// ONLY within the caller's own inventory (a neighbour matching another
// tenant's device stays "external" — never revealed as managed). The handler,
// visibility resolution and collector fetches stay with the entrypoint; the
// owned/name/addr maps arrive already caller-scoped.

import (
	"sort"
	"strings"

	"netops/backend/collectors"
)

type TopoLink struct {
	Source        string `json:"source"`           // local device id (always a managed device)
	Target        string `json:"target"`           // managed device id, or "ext:<sysname>"
	SourceName    string `json:"source_name"`      // display name
	TargetName    string `json:"target_name"`      // display name (neighbour sysname)
	LocalPort     string `json:"local_port"`       // port on the source device
	RemotePort    string `json:"remote_port"`      // port on the neighbour
	SourceProto   string `json:"source_protocol"`  // "lldp" | "cdp" | "bgp_ls"; "+"-joined when confirmed by several
	IGP           string `json:"igp,omitempty"`    // bgp_ls IGP origin (isis-l2 / ospfv2 …)
	Area          string `json:"area,omitempty"`   // bgp_ls IGP area
	Resolved      bool   `json:"resolved"`         // target is a managed device in inventory
	Bidirectional bool   `json:"bidirectional"`    // both ends reported the adjacency
	LastSeen      int64  `json:"last_observed_at"` // unix millis
}

// NormalizeLLDP turns raw directed half-links into deduped undirected topology
// links, scoped to the owned device set. Pure (unit-tested) — no I/O.
func NormalizeLLDP(neighbors []collectors.LLDPNeighbor, ownedID, byName, byAddr map[string]string, ifaddr map[string]map[string]string) []TopoLink {
	// key (sorted endpoints) → link, so A→B and B→A collapse and mark bidirectional.
	merged := map[string]*TopoLink{}
	order := []string{}

	for _, n := range neighbors {
		proto := n.Proto
		if proto == "" {
			proto = "lldp"
		}

		// Resolve the LOCAL endpoint to a managed device the caller owns.
		// LLDP/CDP: the local end IS the polled device (LocalDevice is its id).
		// BGP-LS: the local end is just another node in the learned graph, so it
		// resolves through the same name/addr maps — and is kept only if it lands
		// on a device the caller owns (the tenant-scope anchor).
		var src string
		if proto == "bgp_ls" {
			id, ok := resolveIdentityID(n.LocalName, byName, byAddr, n.LocalAddr)
			if !ok {
				continue
			}
			src = id
		} else {
			src = n.LocalDevice
			if _, owned := ownedID[src]; !owned {
				continue // only links anchored on a device the caller can see
			}
		}

		// resolve the neighbour within the caller's own inventory only.
		var tgtID string
		var resolved bool
		if proto == "bgp_ls" {
			tgtID, resolved = resolveIdentityID(n.RemSysName, byName, byAddr, n.RemChassis)
		} else {
			tgtID, resolved = resolveNeighborID(n, byName, byAddr)
		}
		targetName := strings.TrimSpace(n.RemSysName)
		if targetName == "" {
			targetName = n.RemChassis
		}
		if !resolved {
			if targetName == "" {
				continue // nothing to identify the neighbour by
			}
			tgtID = "ext:" + strings.ToLower(targetName)
		}
		if tgtID == src {
			continue // self-loop guard
		}

		// Port enrichment. BGP-LS link descriptors identify interfaces by IP, not
		// name (LocalPort/RemPort carry IPv4 interface addresses); resolve them to
		// real ifNames via the per-device interface-address map so the link reads
		// like an LLDP/CDP one and can join to interface metrics. No-op for other
		// protocols and when the map lacks the device/IP.
		localPort, remPort := n.LocalPort, n.RemPort
		if proto == "bgp_ls" {
			if nm := ifNameForIP(ifaddr, src, localPort); nm != "" {
				localPort = nm
			}
			if resolved {
				if nm := ifNameForIP(ifaddr, tgtID, remPort); nm != "" {
					remPort = nm
				}
			}
		}

		key := linkKey(src, tgtID)
		if ex, dup := merged[key]; dup {
			ex.Bidirectional = true
			if n.TS > ex.LastSeen {
				ex.LastSeen = n.TS
			}
			// fill a missing remote-port from the reverse direction's local port
			if ex.RemotePort == "" && localPort != "" && ex.Source != src {
				ex.RemotePort = localPort
			}
			// union the source protocols: a link confirmed by several observers
			// (e.g. "bgp_ls+lldp") is the strongest topology evidence. Carry over
			// the IGP origin if BGP-LS contributed it.
			ex.SourceProto = addProto(ex.SourceProto, proto)
			if ex.IGP == "" {
				ex.IGP = n.IGP
			}
			if ex.Area == "" {
				ex.Area = n.Area
			}
			continue
		}
		l := &TopoLink{
			Source: src, Target: tgtID,
			SourceName: ownedID[src], TargetName: targetName,
			LocalPort: localPort, RemotePort: remPort,
			SourceProto: proto, IGP: n.IGP, Area: n.Area,
			Resolved: resolved, LastSeen: n.TS,
		}
		if resolved {
			l.TargetName = ownedID[tgtID]
		}
		merged[key] = l
		order = append(order, key)
	}

	out := make([]TopoLink, 0, len(order))
	for _, k := range order {
		out = append(out, *merged[k])
	}
	// stable order for deterministic responses + tests
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// resolveNeighborID maps an LLDP/CDP neighbour to a managed device id within the
// owned set: by system-name first (the common case — hostnames match inventory),
// then by a chassis/port-id that looks like a management address.
func resolveNeighborID(n collectors.LLDPNeighbor, byName, byAddr map[string]string) (string, bool) {
	return resolveIdentityID(n.RemSysName, byName, byAddr, n.RemChassis, n.RemPort)
}

// resolveIdentityID maps a (name, candidate-addresses…) pair to a managed device id
// within the owned set: by name first (full, then leading FQDN label), then by any
// candidate that matches a management address. "" + false when unknown. Shared by
// LLDP/CDP (remote end) and BGP-LS (both ends — neither is the polled device).
func resolveIdentityID(name string, byName, byAddr map[string]string, addrs ...string) (string, bool) {
	if nm := strings.ToLower(strings.TrimSpace(name)); nm != "" {
		if id, ok := byName[nm]; ok {
			return id, true
		}
		if i := strings.IndexByte(nm, '.'); i > 0 {
			if id, ok := byName[nm[:i]]; ok {
				return id, true
			}
		}
	}
	for _, cand := range addrs {
		if c := strings.TrimSpace(cand); c != "" {
			if id, ok := byAddr[c]; ok {
				return id, true
			}
		}
	}
	return "", false
}

// ifNameForIP resolves an interface IPv4 address to its ifName for a given device,
// using the SNMP-published interface-address map. "" when the device, the IP, or
// the whole map is absent (best-effort enrichment, never an error). The candidate
// is only treated as an IP — a value that's already a port name is left untouched
// by the caller via the empty-string return.
func ifNameForIP(ifaddr map[string]map[string]string, deviceID, ip string) string {
	if ifaddr == nil || deviceID == "" || ip == "" {
		return ""
	}
	if m := ifaddr[deviceID]; m != nil {
		return m[strings.TrimSpace(ip)]
	}
	return ""
}

// addProto unions a source-protocol token into a "+"-joined set, keeping a stable
// order and never duplicating ("lldp" + "bgp_ls" → "bgp_ls+lldp"). A link reported
// by several observers is the strongest topology evidence.
func addProto(existing, add string) string {
	if add == "" {
		return existing
	}
	set := map[string]bool{}
	for _, p := range strings.Split(existing, "+") {
		if p != "" {
			set[p] = true
		}
	}
	if set[add] {
		return existing
	}
	set[add] = true
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, "+")
}

// LinkSources reports which discovery protocols contributed the returned links,
// as a stable "+"-joined set (e.g. "bgp_ls+lldp"). Empty set → "none".
func LinkSources(links []TopoLink) string {
	set := map[string]bool{}
	for _, l := range links {
		for _, p := range strings.Split(l.SourceProto, "+") {
			if p != "" {
				set[p] = true
			}
		}
	}
	if len(set) == 0 {
		return "none"
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, "+")
}

// linkKey is the order-independent key for an adjacency between two endpoints.
func linkKey(a, b string) string {
	if a <= b {
		return a + "\x00" + b
	}
	return b + "\x00" + a
}
