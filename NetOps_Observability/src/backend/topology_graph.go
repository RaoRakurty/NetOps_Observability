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
	writeJSON(w, http.StatusOK, topologyGraphResponse{View: snap.ToView(tenant, now), Coverage: snap.Summarize()})
}
