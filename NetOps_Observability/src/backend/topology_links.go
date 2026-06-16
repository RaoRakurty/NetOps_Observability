package main

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"netops/backend/collectors"
)

// topology_links.go — GET /api/topology/links : real Layer-1 adjacencies from the
// LLDP collector, normalized for the Device Topology map.
//
// The collector publishes raw directed half-links (device A saw neighbour B on a
// local port). This read-side handler:
//   - TENANT-SCOPES: only links whose local device is visible to the caller, and
//     only resolves a neighbour to a managed device within the CALLER's own
//     inventory (a neighbour matching another tenant's device stays "external" —
//     its hostname was advertised to the caller's own device, so no cross-tenant
//     leak, but we never reveal it's a managed device of another tenant);
//   - RESOLVES remote system-name → device id (name → mgmt-address fallback),
//     mirroring the inventory dedup order;
//   - DEDUPS bidirectional adjacencies (A→B and B→A → one undirected link).
//
// Source-agnostic: the link shape carries source_protocol so CDP / BGP-LS links
// can be merged in later without changing the contract or the frontend.

type topoLink struct {
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

func (s *server) handleTopologyLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}

	// Tenant-scoped device inventory → resolution maps (all keyed within the
	// caller's own visible devices, so resolution can never reach another tenant).
	devs := visibleDevices(s.discovery.Devices(), claims)
	ownedID := make(map[string]string, len(devs)) // id → display name
	byName := make(map[string]string, len(devs))  // lower(name) → id
	byAddr := make(map[string]string, len(devs))  // address → id
	for _, d := range devs {
		ownedID[d.ID] = d.Name
		if d.Name != "" {
			byName[strings.ToLower(strings.TrimSpace(d.Name))] = d.ID
		}
		if d.Address != "" {
			byAddr[strings.TrimSpace(d.Address)] = d.ID
		}
	}

	// Merged neighbour records from every discovery protocol (LLDP, CDP, …).
	// Absent data (collectors off / Redis down) → empty set; the UI falls back to
	// labelled tier-inference. Not an error condition.
	neighbors, _ := collectors.FetchTopologyLinks(r.Context())

	links := normalizeLLDP(neighbors, ownedID, byName, byAddr)
	writeJSON(w, http.StatusOK, map[string]any{"links": links, "count": len(links), "source": topoSources(links)})
}

// normalizeLLDP turns raw directed half-links into deduped undirected topology
// links, scoped to the owned device set. Pure (unit-tested) — no I/O.
func normalizeLLDP(neighbors []collectors.LLDPNeighbor, ownedID, byName, byAddr map[string]string) []topoLink {
	// key (sorted endpoints) → link, so A→B and B→A collapse and mark bidirectional.
	merged := map[string]*topoLink{}
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
			id, ok := resolveIdentity(n.LocalName, byName, byAddr, n.LocalAddr)
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
			tgtID, resolved = resolveIdentity(n.RemSysName, byName, byAddr, n.RemChassis)
		} else {
			tgtID, resolved = resolveNeighbor(n, byName, byAddr)
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

		key := linkKey(src, tgtID)
		if ex, dup := merged[key]; dup {
			ex.Bidirectional = true
			if n.TS > ex.LastSeen {
				ex.LastSeen = n.TS
			}
			// fill a missing remote-port from the reverse direction's local port
			if ex.RemotePort == "" && n.LocalPort != "" && ex.Source != src {
				ex.RemotePort = n.LocalPort
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
		l := &topoLink{
			Source: src, Target: tgtID,
			SourceName: ownedID[src], TargetName: targetName,
			LocalPort: n.LocalPort, RemotePort: n.RemPort,
			SourceProto: proto, IGP: n.IGP, Area: n.Area,
			Resolved: resolved, LastSeen: n.TS,
		}
		if resolved {
			l.TargetName = ownedID[tgtID]
		}
		merged[key] = l
		order = append(order, key)
	}

	out := make([]topoLink, 0, len(order))
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

// resolveNeighbor maps an LLDP/CDP neighbour to a managed device id within the
// owned set: by system-name first (the common case — hostnames match inventory),
// then by a chassis/port-id that looks like a management address.
func resolveNeighbor(n collectors.LLDPNeighbor, byName, byAddr map[string]string) (string, bool) {
	return resolveIdentity(n.RemSysName, byName, byAddr, n.RemChassis, n.RemPort)
}

// resolveIdentity maps a (name, candidate-addresses…) pair to a managed device id
// within the owned set: by name first (full, then leading FQDN label), then by any
// candidate that matches a management address. "" + false when unknown. Shared by
// LLDP/CDP (remote end) and BGP-LS (both ends — neither is the polled device).
func resolveIdentity(name string, byName, byAddr map[string]string, addrs ...string) (string, bool) {
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

// topoSources reports which discovery protocols contributed the returned links,
// as a stable "+"-joined set (e.g. "bgp_ls+lldp"). Empty set → "none".
func topoSources(links []topoLink) string {
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
