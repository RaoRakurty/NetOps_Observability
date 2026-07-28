package main

// cred_cache_reload.go — multi-instance cache coherence for the two stores that
// stay in-memory by design: API keys and SNMP credentials (see TRACKER #33,
// "bounded config stays cached"). Each API replica holds its own copy of these
// sets hydrated from the shared kvBackend. A revoke/rotate/delete on instance A
// writes through to the shared store immediately, but instance B keeps serving
// from its stale map until restart — a security gap for revocation (a revoked
// API key would keep authenticating on B).
//
// This loop closes that gap: every reload interval each store re-reads the
// persisted set and atomically swaps its map, so a revoked/expired key or a
// rotated/deleted credential converges across all instances within one interval.
// It is NOT a substitute for per-row repositories — concurrent writes from two
// instances still follow blob last-writer-wins — but revocation, the security-
// critical direction, converges. Single-writer (file) deployments don't need it.

import (
	"context"
	"os"
	"time"
)

// credCacheReloadInterval resolves the reload cadence from CRED_CACHE_RELOAD_SEC.
// Dormant by default (0 = off), like the rest of the platform's infra features —
// a SINGLE instance is the only writer, so reloading would just overwrite its own
// in-memory usage stats every tick for no benefit. Operators running MULTIPLE API
// replicas against a shared backend set this (e.g. 30) so a revoke/rotate on one
// replica converges across the others. Suggested value: 30 (seconds). Negative or
// non-numeric values are treated as off.
func credCacheReloadInterval() time.Duration {
	v := os.Getenv("CRED_CACHE_RELOAD_SEC")
	if v == "" {
		return 0
	}
	n, err := parseIntStrict(v)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// startCredCacheReload runs the periodic reload until ctx is cancelled. A
// reload error is logged (observability rule: no silent failures) and the loop
// continues — a transient backend blip must not wedge cache refresh, and the
// last-known-good map keeps serving until the next successful reload.
func (s *server) startCredCacheReload(ctx context.Context) {
	interval := credCacheReloadInterval()
	if interval <= 0 {
		return // single-instance (file backend) or explicitly disabled
	}
	// A reload loop means a shared backend with potentially >1 writer. Switch the
	// API-key store off per-call usage flushing so a stale replica can't write its
	// map back over a peer's revocation (see apikey.Store.SetMultiWriter).
	if s.apiKeys != nil {
		s.apiKeys.SetMultiWriter(true)
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if s.apiKeys != nil {
					if err := s.apiKeys.Reload(); err != nil {
						logError("apikeys", "cache reload", errf(err))
					}
				}
				if s.snmpCreds != nil {
					if err := s.snmpCreds.reload(); err != nil {
						logError("snmp_creds", "cache reload", errf(err))
					}
				}
			}
		}
	}()
}
