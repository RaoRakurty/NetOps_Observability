// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discoveryscope

// registry.go — the in-memory snapshot of every scope that the scanner reads on
// each poll, so the sweep path never does store IO. Loaded at boot (the one
// cross-tenant read besides the platform owner's list), and reloaded after every
// write through the API.
//
// A load failure is remembered and never mistaken for "no scopes": the last
// good snapshot stays in force (a store blip must not turn every customer's scan
// off and drop its devices from the inventory), the failure is logged and
// reported by the API, and RetryLoop reloads until it succeeds. At boot there is
// no last good snapshot, so tenant scans stay off until the first good read —
// the platform scan is unaffected.

import (
	"context"
	"log"
	"sync"
	"time"

	"netops/backend/internal/discovery"
)

// Registry is the scanner's view of the stored scopes.
type Registry struct {
	store   Store
	mu      sync.RWMutex
	all     []Scope
	loaded  bool
	loadErr error
}

// NewRegistry wraps st. Call Reload before the scanner's first poll.
func NewRegistry(st Store) *Registry { return &Registry{store: st} }

// Store is the backing store (reads for the API go to it directly, scoped).
func (r *Registry) Store() Store { return r.store }

// Reload re-reads every scope (cross-tenant). On failure the previous snapshot
// stays in force and the error is returned and remembered.
func (r *Registry) Reload(ctx context.Context) error {
	all, err := r.store.List(ctx, "", true)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.loadErr = err
		log.Printf("discovery scopes: reload failed (the last good set stays in force): %v", err)
		return err
	}
	r.all, r.loaded, r.loadErr = all, true, nil
	return nil
}

// LoadError is the last reload failure, nil once a reload succeeds.
func (r *Registry) LoadError() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loadErr
}

// Snapshot returns a copy of every scope.
func (r *Registry) Snapshot() []Scope {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Scope, len(r.all))
	for i, sc := range r.all {
		sc.Ranges = append([]string(nil), sc.Ranges...)
		sc.CredentialRefs = append([]string(nil), sc.CredentialRefs...)
		out[i] = sc
	}
	return out
}

// ScanScopes maps the TURNED-ON scopes onto the scanner's channels; creds
// supplies each scope's credentials (its own tenant's profiles only — the
// caller resolves them, see snmpcred.ScanCandidatesFor).
func (r *Registry) ScanScopes(creds func(Scope) []discovery.ScanCredential) []discovery.ScanScope {
	var out []discovery.ScanScope
	for _, sc := range r.Snapshot() {
		if !sc.Enabled {
			continue
		}
		out = append(out, discovery.ScanScope{
			ID: sc.ID, TenantID: sc.TenantID, Ranges: sc.Ranges, AllowNonPrivate: sc.AllowNonPrivate,
			Credentials: creds(sc),
		})
	}
	return out
}

// RetryLoop reloads every interval while the last reload failed, until ctx ends.
func (r *Registry) RetryLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if r.LoadError() == nil {
				r.mu.RLock()
				loaded := r.loaded
				r.mu.RUnlock()
				if loaded {
					continue
				}
			}
			rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			if err := r.Reload(rctx); err == nil {
				log.Printf("discovery scopes: reload recovered")
			}
			cancel()
		}
	}
}
