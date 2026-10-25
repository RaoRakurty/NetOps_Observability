// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenant

// tenantkv.go — a default-closed, tenant-scoped kv store for file/in-memory app
// state. It exists so new per-tenant features are isolated BY CONSTRUCTION
// (CLAUDE.md §3a): there is intentionally NO unscoped "list all" — every read
// takes (tenant, cross) and a non-cross caller only ever sees its own tenant's
// records. This is the safe default for the file/kv plane, which has no RLS
// backstop (the plane where the sites store leaked before it was fixed).
//
// Persistence is the injected KV (the platform's shared file/Postgres backend),
// so a store built on this inherits the same durable-write contract as every
// other.
//
// Usage:
//   kv, _ := NewCollection[Site]("/data/sites.json", kv,
//       func(s Site) string { return s.TenantID },
//       func(s Site) string { return s.Slug })
// The CALLER stamps the tenant on each record from the authenticated principal
// (principalTenant), NEVER from request input, before Upsert.

import (
	"encoding/json"
	"errors"
	"sort"
	"sync"

	"netops/backend/internal/applog"
	"netops/backend/internal/owner"
)

type Collection[T any] struct {
	mu       sync.RWMutex
	path     string
	kv       KV
	items    map[string]T   // (tenant\x00id) → record
	tenantOf func(T) string // owning tenant of a record
	idOf     func(T) string // within-tenant stable id (slug/id)
}

func NewCollection[T any](path string, kv KV, tenantOf, idOf func(T) string) (*Collection[T], error) {
	if kv == nil {
		return nil, errors.New("tenant.NewCollection: kv is required")
	}
	s := &Collection[T]{path: path, kv: kv, items: map[string]T{}, tenantOf: tenantOf, idOf: idOf}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Collection[T]) key(tenant, id string) string { return tenant + "\x00" + id }

// Path reports the backend key this collection persists under.
func (s *Collection[T]) Path() string { return s.path }

func (s *Collection[T]) load() error {
	b, err := s.kv.Load(s.path)
	if err != nil {
		return nil // absent store → empty
	}
	var list []T
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, r := range list {
		if s.idOf(r) != "" {
			s.items[s.key(s.tenantOf(r), s.idOf(r))] = r
		}
	}
	return nil
}

func (s *Collection[T]) flushLocked() error {
	list := make([]T, 0, len(s.items))
	for _, r := range s.items {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		ti, tj := s.tenantOf(list[i]), s.tenantOf(list[j])
		if ti != tj {
			return ti < tj
		}
		return s.idOf(list[i]) < s.idOf(list[j])
	})
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return s.kv.Save(s.path, b)
}

// All returns the records VISIBLE to the (tenant, cross) principal, sorted by id.
// A non-cross caller sees ONLY its own OWNER's records — "" and "global" are one
// owner, the platform (internal/owner; the Provider scope, tracker 365), and
// real tenant ids never collapse. There is deliberately no unscoped variant —
// that absence is the isolation guarantee.
func (s *Collection[T]) All(tenant string, cross bool) []T {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]T, 0, len(s.items))
	for _, r := range s.items {
		if cross || owner.Same(s.tenantOf(r), tenant) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return s.idOf(out[i]) < s.idOf(out[j]) })
	return out
}

// Get returns a record only if the (tenant, cross) principal may see it. A
// non-cross caller can never read another tenant's id (caller maps !ok → 404).
func (s *Collection[T]) Get(tenant string, cross bool, id string) (T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.items[s.key(tenant, id)]; ok {
		return r, true
	}
	if k, ok := s.platformAliasKeyLocked(tenant, id); ok {
		return s.items[k], true
	}
	if cross {
		for _, r := range s.items { // platform owner: id may live under any tenant
			if s.idOf(r) == id {
				return r, true
			}
		}
	}
	var zero T
	return zero, false
}

// Upsert stores rec keyed by (tenantOf(rec), idOf(rec)). The caller MUST have
// stamped tenantOf(rec) from the authenticated principal before calling.
func (s *Collection[T]) Upsert(rec T) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[s.key(s.tenantOf(rec), s.idOf(rec))] = rec
	return s.flushLocked()
}

// Delete removes a record within the caller's tenant (cross may delete any
// tenant's). Returns false when the id isn't visible to the caller.
func (s *Collection[T]) Delete(tenant string, cross bool, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[s.key(tenant, id)]; ok {
		delete(s.items, s.key(tenant, id))
		if err := s.flushLocked(); err != nil {
			// F-30 class: the delete answered true but persisted nothing —
			// the record resurrects on restart. Visible, never silent.
			applog.Error("tenantkv", "delete not persisted; record resurrects on restart", map[string]any{
				"path": s.path, "id": id, "error": err.Error()})
		}
		return true
	}
	if k, ok := s.platformAliasKeyLocked(tenant, id); ok {
		delete(s.items, k)
		if err := s.flushLocked(); err != nil {
			// F-30 class, as above: visible, never silent.
			applog.Error("tenantkv", "delete not persisted; record resurrects on restart", map[string]any{
				"path": s.path, "id": id, "error": err.Error()})
		}
		return true
	}
	if cross {
		for k, r := range s.items {
			if s.idOf(r) == id {
				delete(s.items, k)
				if err := s.flushLocked(); err != nil {
					// F-30 class: the delete answered true but persisted nothing —
					// the record resurrects on restart. Visible, never silent.
					applog.Error("tenantkv", "delete not persisted; record resurrects on restart", map[string]any{
						"path": s.path, "id": id, "error": err.Error()})
				}
				return true
			}
		}
	}
	return false
}

// platformAliasKeyLocked finds id under the platform's OTHER spelling when the
// caller is the platform ("" ≡ "global", internal/owner): a record keyed under
// "" is the Provider scope's own, and vice versa. A real tenant id never takes
// this path, so two tenants can never reach each other's records through it.
// Caller holds s.mu.
func (s *Collection[T]) platformAliasKeyLocked(tenant, id string) (string, bool) {
	if !owner.IsPlatform(tenant) {
		return "", false
	}
	for k, r := range s.items {
		if s.idOf(r) == id && owner.IsPlatform(s.tenantOf(r)) {
			return k, true
		}
	}
	return "", false
}

// Count is the total record count across all tenants (admin/metrics use only).
func (s *Collection[T]) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}
