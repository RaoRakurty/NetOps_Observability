package main

import (
	"errors"
	"net/http"
	"time"

	"netops/backend/topology"
)

// topology_graph.go — GET /api/topology/graph : the PERSISTED topology graph
// (#77). Where /api/topology/view recomputes an ephemeral live projection each
// request, /graph serves the reconciler-maintained spine: STABLE node/edge ids
// with first_seen/last_seen and a stale flag (change_state), tenant-scoped, plus a
// coverage summary. Structural by design — live health/utilization stays on /view
// (folding it in is the next enrichment step). Reuses the canonical Node/Edge
// render contract so the frontend needs no new type.

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
	view := snap.ToView(tenant, now)

	// Live enrichment: overlay current health/util onto the structural spine, from
	// the SAME signals /view uses. The persisted first_seen/last_seen/stale (already
	// in the view) is kept; only Health/Metrics/Status/Utilization are filled.
	alertsByDevice := s.activeAlertsByDevice(claims)
	lm := s.gatherTopoMetrics(r.Context())
	view.EnrichLive(alertsByDevice, lm.cpu, lm.mem)
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

// activeAlertsByDevice returns the caller's visible active alerts grouped by device
// id (the input EnrichLive needs). Scoped exactly like /api/alerts and /view: a
// non-cross caller sees only its tenant's devices' alerts.
func (s *server) activeAlertsByDevice(claims jwtClaims) map[string][]topology.AlertFact {
	out := map[string][]topology.AlertFact{}
	if s.alerts == nil {
		return out
	}
	alerts := s.alerts.Active()
	ids, cross := s.visibleDeviceIDs(claims)
	for _, a := range alerts {
		if a.DeviceID == "" {
			continue // device-less (stack-level) alerts don't bind to a node
		}
		if !cross && !ids[a.DeviceID] {
			continue
		}
		out[a.DeviceID] = append(out[a.DeviceID], topology.AlertFact{
			DeviceID: a.DeviceID, Severity: a.Severity, Summary: a.Summary, FiredAt: a.FiredAt,
		})
	}
	return out
}
