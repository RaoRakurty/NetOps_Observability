package main

import (
	"errors"
	"net/http"
	"strings"

	"netops/backend/collectors"
	"netops/backend/topology"
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

// The TopoLink shape and the pure normalization live in topology/links.go
// (P2 RA.16); this file keeps the handler (visibility + collector fetches).

type topoLink = topology.TopoLink

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

	// Interface-address map (deviceID → interface IP → ifName), published by the
	// SNMP metrics collector. Lets BGP-LS links (whose descriptors identify
	// interfaces by IP, not name) show real port names. Best-effort: empty when
	// the collector is off / Redis is down — enrichment simply no-ops.
	ifaddr, _ := collectors.FetchIfAddrMap(r.Context())

	links := topology.NormalizeLLDP(neighbors, ownedID, byName, byAddr, ifaddr)
	writeJSON(w, http.StatusOK, map[string]any{"links": links, "count": len(links), "source": topology.LinkSources(links)})
}
