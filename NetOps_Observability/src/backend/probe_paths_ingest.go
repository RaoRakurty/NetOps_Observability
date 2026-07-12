package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
)

// probe_paths_ingest.go — the REMOTE-VANTAGE path transport.
//
// THE PROBLEM. A prober deployed inside a customer LAN segment (the lan-vantage on
// 172.40.40.200) is the only thing that can measure the CLIENT end of the path — the
// co-located prober's traceroute starts at the WAN edge, so a spine built from it can
// never legitimately start at the client (contract §10). But a LAN vantage cannot
// reach the platform's key-value store, which is how probers have always published
// their traces.
//
// THE TRANSPORT CHOICE (and why). Three options were on the table:
//
//	(a) publish Valkey to the client LAN — REJECTED. That puts an unauthenticated
//	    datastore on an untrusted segment, where anything on the LAN could read and
//	    REWRITE every tenant's measured paths. A path that anyone can forge is not
//	    evidence. This is exactly the "no internal trust shortcuts" rule (§3).
//	(b) ship paths over the existing :8689 event sink — the sink works from the LAN
//	    (the vantage's probe EVENTS already arrive that way), but it lands in Kafka →
//	    the correlation engine, not in the Go API that owns the path store. Getting it
//	    back would mean a new Kafka consumer in the API. Kept as future work.
//	(c) an AUTHENTICATED HTTP push to the API — CHOSEN. The vantage already reaches the
//	    platform host; it now posts its own traces to POST /api/probe/paths with an API
//	    key. Zero-trust: authenticated, authorized, bounded, and every path is stamped
//	    with the vantage that pushed it. No new network exposure of a datastore.
//
// The pushed paths join the same merged read the local collector and the key-value
// store feed, so the path ingester treats a remote vantage exactly like a local one:
// one vantage, one set of distinct paths (§2.2).

// remotePathTTL bounds how long a pushed path set stays live. A vantage that dies
// stops mattering within one TTL — the same self-expiring property the key-value
// store's TTL gives the local probers, rebuilt here in memory.
const remotePathTTL = 10 * time.Minute

// maxPushedPaths / maxPushBytes bound the request (§9: everything bounded).
const (
	maxPushedPaths = 200
	maxPushBytes   = 1 << 20 // 1 MiB
	maxPushedHops  = 64
)

// remotePathStore holds the latest push per vantage. Not tenant-keyed: a pushed
// path set is raw MEASUREMENT, and the tenant is stamped by the ingester from its
// own configuration (§1: the owner is stamped by the platform, never taken from the
// payload). It is bounded and self-expiring.
type remotePathStore struct {
	mu sync.RWMutex
	by map[string]remotePathEntry // vantage → its latest published set
}

type remotePathEntry struct {
	paths []collectors.PathResult
	at    time.Time
}

func newRemotePathStore() *remotePathStore {
	return &remotePathStore{by: map[string]remotePathEntry{}}
}

func (s *remotePathStore) put(vantage string, paths []collectors.PathResult, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.by) >= 64 && s.by[vantage].at.IsZero() {
		// Bounded fleet: refuse to grow without limit on unknown vantages rather than
		// letting a misconfigured pusher exhaust memory.
		return
	}
	s.by[vantage] = remotePathEntry{paths: paths, at: now}
}

// all returns every non-expired pushed path, attributed to its vantage.
func (s *remotePathStore) all(now time.Time) []collectors.PathResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []collectors.PathResult{}
	for v, e := range s.by {
		if now.Sub(e.at) > remotePathTTL {
			continue // stale: a dead vantage's paths simply stop being current
		}
		for _, p := range e.paths {
			p.VantageID = v // authoritative attribution: the vantage we authenticated
			out = append(out, p)
		}
	}
	return out
}

// handleProbePathsPush serves POST /api/probe/paths — a remote vantage publishing
// its own traceroutes. Authenticated + authorized like every other write; the body
// is bounded; every path is validated before it can become evidence (§3 zero trust:
// the prober is an input, not a trusted peer).
func (s *server) handleProbePathsPush(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPushBytes)
	var in []collectors.PathResult
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid path payload"))
		return
	}
	if len(in) == 0 || len(in) > maxPushedPaths {
		writeError(w, http.StatusBadRequest, errors.New("path count out of range"))
		return
	}
	vantage, clean, err := validatePushedPaths(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.remotePaths == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("path ingest is not enabled"))
		return
	}
	s.remotePaths.put(vantage, clean, time.Now().UTC())
	logInfo("pathgraph", "remote vantage published paths", map[string]any{
		"vantage": vantage, "paths": len(clean),
	})
	writeJSON(w, http.StatusAccepted, map[string]any{"vantage_id": vantage, "paths": len(clean)})
}

// validatePushedPaths enforces the shape a pushed measurement must have. It also
// requires ONE vantage per push: a payload that mixes vantages cannot be attributed,
// and an unattributable path is not admissible evidence.
func validatePushedPaths(in []collectors.PathResult) (string, []collectors.PathResult, error) {
	vantage := ""
	out := make([]collectors.PathResult, 0, len(in))
	for _, p := range in {
		v := strings.TrimSpace(p.VantageID)
		if v == "" || !isPathToken(v) {
			return "", nil, errors.New("every pushed path must carry a valid vantage_id")
		}
		if vantage == "" {
			vantage = v
		} else if vantage != v {
			return "", nil, errors.New("a push must come from ONE vantage")
		}
		if strings.TrimSpace(p.Dst) == "" || !isAddressToken(p.Dst) {
			return "", nil, errors.New("pushed path has an invalid destination")
		}
		if len(p.Hops) > maxPushedHops {
			return "", nil, errors.New("pushed path has too many hops")
		}
		for _, h := range p.Hops {
			// A non-responding hop legitimately has an EMPTY ip — that is the fact being
			// reported and it must survive (§2.4). Anything non-empty must be an address.
			if h.IP != "" && !isAddressToken(h.IP) {
				return "", nil, errors.New("pushed hop has an invalid address")
			}
		}
		if p.TS.IsZero() {
			p.TS = time.Now().UTC()
		}
		out = append(out, p)
	}
	return vantage, out, nil
}
