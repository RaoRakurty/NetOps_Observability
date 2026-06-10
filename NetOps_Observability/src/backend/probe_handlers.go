package main

import (
	"encoding/json"
	"net/http"

	"netops/backend/collectors"
)

// probe_handlers.go — read API for active-measurement results. STAMP metrics go
// to VictoriaMetrics (queried via /api/metrics); the traceroute path topology is
// held in-memory by the collector and exposed here for the Network Path UI.

// handleProbePaths returns the latest traceroute path per destination, newest
// first. Authenticated (the whole /api mux is wrapped by withAuth).
func (s *server) handleProbePaths(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(collectors.Paths.All())
}
