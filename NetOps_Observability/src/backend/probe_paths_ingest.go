// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// probe_paths_ingest.go — main-side wiring for the remote-vantage path
// transport (pathgraph/remote_paths.go, extracted P2 RA.10). The store, the
// bounds and the admissibility validator live in the package; this file keeps
// the authenticated HTTP boundary. See the package doc for the transport
// choice rationale (authenticated push, never a datastore on the LAN).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"netops/backend/collectors"
	"netops/backend/pathgraph"
)

type remotePathStore = pathgraph.RemotePathStore

func newRemotePathStore() *remotePathStore { return pathgraph.NewRemotePathStore() }

// handleProbePathsPush serves POST /api/probe/paths — a remote vantage publishing
// its own traceroutes. Authenticated + authorized like every other write; the body
// is bounded; every path is validated before it can become evidence (§3 zero trust:
// the prober is an input, not a trusted peer).
func (s *server) handleProbePathsPush(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, pathgraph.MaxPushBytes)
	var in []collectors.PathResult
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid path payload"))
		return
	}
	if len(in) == 0 || len(in) > pathgraph.MaxPushedPaths {
		writeError(w, http.StatusBadRequest, errors.New("path count out of range"))
		return
	}
	vantage, clean, err := pathgraph.ValidatePushedPaths(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.remotePaths == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("path ingest is not enabled"))
		return
	}
	s.remotePaths.Put(vantage, clean, time.Now().UTC())
	logInfo("pathgraph", "remote vantage published paths", map[string]any{
		"vantage": vantage, "paths": len(clean),
	})
	writeJSON(w, http.StatusAccepted, map[string]any{"vantage_id": vantage, "paths": len(clean)})
}
