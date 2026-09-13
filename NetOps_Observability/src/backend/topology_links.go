// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"errors"
	"fmt"
	"net/http"

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
	// visibleDevicesFor also applies the operator-visibility restriction, so a
	// restricted tenant's devices anchor no link and resolve no neighbour; the
	// edge half — a neighbour that stays "ext:<its hostname>" — is closed by
	// gatherTopoLinksFor, which is also the ONE place /view derives links.
	devs := s.visibleDevicesFor(claims)

	// Merged neighbour records from every discovery protocol (LLDP, CDP, …) plus
	// the interface-address map that gives BGP-LS links real port names. Absent
	// data (no discovery collector deployed) → empty set; the UI falls back to
	// labelled tier-inference. Not an error condition.
	//
	// A READ THAT FAILED IS A REFUSAL HERE, not a banner (tracker 290). The link
	// set is this endpoint's ENTIRE payload: there is no inventory, no alert
	// overlay, nothing else in the response to hang a caveat on, so
	// `{"links":[],"count":0}` with a 200 is the silent failure in its purest
	// form — every consumer, ours and anyone's script, reads count:0 as "this
	// estate has no adjacencies". 502 is the same call handleTopologyView already
	// makes for the dependency projection: never a confident empty.
	links, err := s.gatherTopoLinksFor(r.Context(), claims, devs)
	if err != nil {
		logWarn("topology", "adjacency evidence unread for /api/topology/links", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, fmt.Errorf("%s: %w", topoLinksUnreadNote, err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": links, "count": len(links), "source": topology.LinkSources(links)})
}
