// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/topology"
)

// topology_graph.go — GET /api/topology/graph : the PERSISTED topology graph
// (#77). Where /api/topology/view recomputes an ephemeral live projection each
// request, /graph serves the reconciler-maintained spine: STABLE node/edge ids
// with first_seen/last_seen and a stale flag (change_state), tenant-scoped, plus a
// coverage summary. The structural spine is read-enriched with live health/
// utilization from the SAME signals /view uses (EnrichLive below) — the persisted
// first_seen/last_seen/stale is authoritative, only Health/Metrics/Status/Util are
// overlaid. Reuses the canonical Node/Edge render contract so the frontend needs no
// new type.

type topologyGraphResponse struct {
	topology.View
	Coverage topology.Coverage `json:"coverage"`
}

func (s *server) handleTopologyGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	now := time.Now()
	if s.topology == nil { // store unavailable → well-formed empty graph (graceful)
		writeJSON(w, http.StatusOK, topologyGraphResponse{View: topology.GraphRecords{}.ToView(tenant, now)})
		return
	}
	snap, err := s.topology.Snapshot(r.Context(), tenant, cross)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// The operator-visibility restriction, BEFORE anything is projected or
	// counted. The store isolates one tenant from another — the in-memory backend
	// by tenant, the pg backend by FORCE-RLS — but the operator's cross-tenant
	// door is "__all__", and neither a row policy nor FilterTenant has an "all
	// except". Coverage is summarized from the filtered records too: a count is a
	// disclosure.
	snap = s.visibleGraphRecords(claims, snap)
	view := snap.ToView(tenant, now)

	// Live enrichment: overlay current health/util onto the structural spine, from
	// the SAME signals /view uses. The persisted first_seen/last_seen/stale (already
	// in the view) is kept; only Health/Metrics/Status/Utilization are filled.
	alertsByDevice := s.activeAlertsByDevice(claims)
	lm := s.gatherTopoMetrics(r.Context(), claims)
	// Item 121: persisted records carry their own tenant + declared site, so the
	// window check needs no inventory join here.
	maintItems := make([]maintTriple, 0, len(snap.Nodes))
	for _, n := range snap.Nodes {
		maintItems = append(maintItems, maintTriple{id: n.ID, tenant: n.TenantID, site: n.Site})
	}
	view.EnrichLive(alertsByDevice, lm.cpu, lm.mem, s.maintenanceCoveredIDs(maintItems))
	for i := range view.Edges {
		e := &view.Edges[i]
		util, hasUtil, status := resolveLinkMetricBy(e.Source, e.SourcePort, e.Target, e.TargetPort, lm.operStatus, lm.inUtil, lm.outUtil)
		if status != "" {
			e.Status = status
		}
		if hasUtil {
			e.Utilization = util
		}
	}

	writeJSON(w, http.StatusOK, topologyGraphResponse{View: view, Coverage: snap.Summarize()})
}

// visibleGraphRecords applies the operator-visibility restriction
// (Tenant.OperatorRestricted) to the PERSISTED graph.
//
// It needs BOTH forms of the rule, because the reconciler resolves adjacencies
// PER TENANT: a link from a visible device to a restricted tenant's device is
// stored under the VISIBLE tenant, with target "ext:<the hidden hostname>".
// Dropping rows by tenant_id alone therefore leaves an edge that still names the
// device whose node it just removed — the same edge half the live /links surface
// has. Both identifier sets come from the shared resolvers, never from a second
// copy of the rule.
func (s *server) visibleGraphRecords(claims jwtClaims, g topology.GraphRecords) topology.GraphRecords {
	tenant, cross := principalTenant(claims)
	exclude, deny := s.operatorTelemetryRestriction(claims, tenant, cross)
	if deny {
		return topology.GraphRecords{} // scoped into a restricted tenant: nothing
	}
	rt := s.restrictedTelemetry(claims)
	if len(exclude) == 0 && len(rt.keys) == 0 && len(rt.addrs) == 0 {
		return g
	}
	hiddenTenant := make(map[string]bool, len(exclude))
	for _, id := range exclude {
		hiddenTenant[strings.ToLower(strings.TrimSpace(id))] = true
	}
	hiddenDevice := make(map[string]bool, len(rt.keys)+len(rt.addrs))
	for _, k := range append(append([]string{}, rt.keys...), rt.addrs...) {
		hiddenDevice[strings.ToLower(strings.TrimSpace(k))] = true
	}
	names := func(vals ...string) bool {
		for _, v := range vals {
			v = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(v, "ext:")))
			if v != "" && hiddenDevice[v] {
				return true
			}
		}
		return false
	}
	out := topology.GraphRecords{}
	for _, n := range g.Nodes {
		if hiddenTenant[strings.ToLower(strings.TrimSpace(n.TenantID))] || names(n.ID, n.Label, n.MgmtIP) {
			continue
		}
		out.Nodes = append(out.Nodes, n)
	}
	for _, e := range g.Edges {
		if hiddenTenant[strings.ToLower(strings.TrimSpace(e.TenantID))] || names(e.Source, e.Target) {
			continue
		}
		out.Edges = append(out.Edges, e)
	}
	return out
}

// activeAlertsByDevice returns the caller's visible active alerts grouped by device
// id (the input EnrichLive needs). Scoped exactly like /api/alerts and /view, by
// asking the same RESOLVED object they ask: alertVisibility is tenancy PLUS the
// operator-visibility restriction.
//
// The tenancy half alone was not a live leak here — EnrichLive only writes onto
// nodes, and visibleGraphRecords has already removed a restricted tenant's nodes
// from the view these facts decorate. It was a trap waiting for the next caller:
// this is a named seam returning alert SUMMARIES keyed by device, and nothing
// about it says the set has not been restricted.
func (s *server) activeAlertsByDevice(claims jwtClaims) map[string][]topology.AlertFact {
	out := map[string][]topology.AlertFact{}
	if s.alerts == nil {
		return out
	}
	vis := s.alertVisibilityFor(claims)
	for _, a := range s.alerts.Active() {
		if a.DeviceID == "" {
			continue // device-less (stack-level) alerts don't bind to a node
		}
		if !vis.visible(a) {
			continue
		}
		out[a.DeviceID] = append(out[a.DeviceID], topology.AlertFact{
			DeviceID: a.DeviceID, Severity: a.Severity, Summary: a.Summary, FiredAt: a.FiredAt,
		})
	}
	return out
}
