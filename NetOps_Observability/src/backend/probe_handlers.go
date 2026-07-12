package main

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"netops/backend/collectors"
)

// probe_handlers.go — read API for active-measurement results. STAMP metrics go
// to VictoriaMetrics (queried via /api/metrics); the traceroute path topology is
// served here for the Network Path UI.

// handleProbePaths returns the latest traceroute path per (VANTAGE, destination,
// method). Every path carries the vantage that measured it: two probers observing
// the same destination from different places are two DISTINCT paths (contract §2.2)
// and both are returned — they used to overwrite each other in one shared key.
// When the prober runs as a sidecar it shares topology via PROBE_PATHS_FILE (a
// shared volume) — serve that file if present; otherwise serve the in-process store
// (collector running inside the API). Authenticated (the /api mux is withAuth).
func (s *server) handleProbePaths(w http.ResponseWriter, r *http.Request) {
	// POST = a REMOTE vantage publishing its own traces (probe_paths_ingest.go): the
	// only transport a prober inside a customer LAN has, since it cannot reach the
	// platform's key-value store and we will not expose one to an untrusted segment.
	if r.Method == http.MethodPost {
		s.handleProbePathsPush(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Primary: the key-value store (sidecar probers publish here — ADR 0001), merged
	// across every vantage that has published.
	if collectors.RedisAddr() != "" {
		if paths, err := collectors.FetchProbePathsAll(r.Context()); err == nil && len(paths) > 0 {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(paths)
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
	_ = json.NewEncoder(w).Encode(s.mergedProbePaths(collectors.Paths.All()))
}

// mergedProbePaths folds the remote vantages' pushed traces into whatever the local
// transport produced. Same-vantage duplicates keep the newest measurement.
func (s *server) mergedProbePaths(local []collectors.PathResult) []collectors.PathResult {
	if s.remotePaths == nil {
		return local
	}
	out := append([]collectors.PathResult{}, local...)
	return append(out, s.remotePaths.all(time.Now().UTC())...)
}
