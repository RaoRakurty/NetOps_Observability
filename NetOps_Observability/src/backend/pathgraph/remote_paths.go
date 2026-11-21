// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pathgraph

// remote_paths.go — the REMOTE-VANTAGE path transport's store + admissibility
// validator (extracted P2 RA.10). A prober inside a customer LAN posts its own
// traceroutes over authenticated HTTP (the zero-trust transport choice — no
// datastore ever faces the untrusted segment); THIS is what decides whether
// unauthenticated-LAN-origin data becomes admissible path EVIDENCE: one
// vantage per push (an unattributable path is not evidence), token-validated
// addresses, bounded hops, and authoritative vantage re-stamping on read. The
// HTTP handler, authn/authz and body bounds stay with the entrypoint.

import (
	"errors"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
)

// RemotePathTTL bounds how long a pushed path set stays live. A vantage that
// dies stops mattering within one TTL — the same self-expiring property the
// key-value store's TTL gives the local probers, rebuilt here in memory.
const RemotePathTTL = 10 * time.Minute

// MaxPushedPaths / MaxPushBytes / MaxPushedHops bound the request (§9).
const (
	MaxPushedPaths = 200
	MaxPushBytes   = 1 << 20 // 1 MiB
	MaxPushedHops  = 64
)

// maxRemoteVantages bounds the fleet: refuse to grow without limit on unknown
// vantages rather than letting a misconfigured pusher exhaust memory.
const maxRemoteVantages = 64

// RemotePathStore holds the latest push per (OWNER, vantage). The owner is the
// pushing principal's tenant, stamped by the handler from the token — never the
// payload (§3a rule 2) — and it is part of the key (Paths redesign P3): before,
// the store was keyed by vantage alone, so a second tenant pushing under the
// same vantage id replaced the first tenant's traces. It is bounded and
// self-expiring.
type RemotePathStore struct {
	mu sync.RWMutex
	by map[string]remotePathEntry // owner \x00 vantage → its latest published set
}

type remotePathEntry struct {
	owner, vantage string
	paths          []collectors.PathResult
	at             time.Time
}

func remoteKey(owner, vantage string) string { return owner + "\x00" + vantage }

// NewRemotePathStore builds the bounded in-memory store.
func NewRemotePathStore() *RemotePathStore {
	return &RemotePathStore{by: map[string]remotePathEntry{}}
}

// Put records one owner's vantage's latest set (full replace per owner and
// vantage). owner is the pushing principal's tenant ("" = the platform).
func (s *RemotePathStore) Put(owner, vantage string, paths []collectors.PathResult, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := remoteKey(owner, vantage)
	if len(s.by) >= maxRemoteVantages && s.by[k].at.IsZero() {
		return
	}
	s.by[k] = remotePathEntry{owner: owner, vantage: vantage, paths: paths, at: now}
}

// All returns every non-expired pushed path, attributed to its vantage.
func (s *RemotePathStore) All(now time.Time) []collectors.PathResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []collectors.PathResult{}
	for _, e := range s.by {
		if now.Sub(e.at) > RemotePathTTL {
			continue // stale: a dead vantage's paths simply stop being current
		}
		for _, p := range e.paths {
			// Authoritative attribution: the vantage and the owner we
			// authenticated, whatever the stored copy says.
			p.VantageID, p.TenantID = e.vantage, e.owner
			out = append(out, p)
		}
	}
	return out
}

// ValidatePushedPaths enforces the shape a pushed measurement must have. It
// also requires ONE vantage per push: a payload that mixes vantages cannot be
// attributed, and an unattributable path is not admissible evidence.
func ValidatePushedPaths(in []collectors.PathResult) (string, []collectors.PathResult, error) {
	vantage := ""
	out := make([]collectors.PathResult, 0, len(in))
	for _, p := range in {
		v := strings.TrimSpace(p.VantageID)
		if v == "" || !IsPathToken(v) {
			return "", nil, errors.New("every pushed path must carry a valid vantage_id")
		}
		if vantage == "" {
			vantage = v
		} else if vantage != v {
			return "", nil, errors.New("a push must come from ONE vantage")
		}
		if strings.TrimSpace(p.Dst) == "" || !IsAddressToken(p.Dst) {
			return "", nil, errors.New("pushed path has an invalid destination")
		}
		if len(p.Hops) > MaxPushedHops {
			return "", nil, errors.New("pushed path has too many hops")
		}
		for _, h := range p.Hops {
			// A non-responding hop legitimately has an EMPTY ip — that is the fact
			// being reported and it must survive (§2.4). Anything non-empty must be
			// an address.
			if h.IP != "" && !IsAddressToken(h.IP) {
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
