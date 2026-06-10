package main

import (
	"encoding/json"
	"net/http"
	"os"

	"netops/backend/collectors"
)

// probe_handlers.go — read API for active-measurement results. STAMP metrics go
// to VictoriaMetrics (queried via /api/metrics); the traceroute path topology is
// served here for the Network Path UI.

// handleProbePaths returns the latest traceroute path per destination. When the
// prober runs as a sidecar it shares topology via PROBE_PATHS_FILE (a shared
// volume) — serve that file if present; otherwise serve the in-process store
// (collector running inside the API). Authenticated (the /api mux is withAuth).
func (s *server) handleProbePaths(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Primary: Redis (sidecar prober publishes here — ADR 0001).
	if collectors.RedisAddr() != "" {
		if s, err := collectors.FetchProbePaths(); err == nil && s != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(s))
			return
		}
	}
	// Fallback: shared file, then the in-process store.
	if path := os.Getenv("PROBE_PATHS_FILE"); path != "" {
		// #nosec G304 -- path is the operator-configured PROBE_PATHS_FILE, not user input
		if data, err := os.ReadFile(path); err == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(collectors.Paths.All())
}
