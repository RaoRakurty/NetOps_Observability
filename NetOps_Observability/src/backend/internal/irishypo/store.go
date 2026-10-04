// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irishypo

// store.go — where a finished investigation's hypotheses are held so they can
// be read back by id (GET /api/ai/hypotheses/{id}).
//
// TENANT-SCOPED BY CONSTRUCTION (CLAUDE.md §3a). Sets are keyed by tenant
// first: a Put writes in exactly the writer's tenant (from the token, never
// the request), and a Get in another tenant's scope finds nothing — the same
// ErrNotFound as an id that never existed, so a foreign id's existence is never
// revealed. Only the platform owner's cross-tenant scope reads across tenants.
// There is no "list all" method.
//
// BOUNDED AND NOT DURABLE. Each tenant keeps its newest MaxPerTenant sets for
// at most TTL, and a restart starts empty. The durable record of an
// investigation is the decision ledger (HYPOTHESIS_* entries, hashes only);
// this store exists so the trace can be re-opened while it is fresh.

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Store bounds.
const (
	MaxPerTenant = 500
	TTL          = 7 * 24 * time.Hour
)

// Errors.
var (
	ErrNotFound = errors.New("irishypo: not found")
	ErrInvalid  = errors.New("irishypo: invalid")
)

var reID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidID reports whether id is a lowercase UUID — the only id shape a Set is
// stored under.
func ValidID(id string) bool { return reID.MatchString(id) }

// Store holds finished Sets. tenant and cross always come from the
// authenticated principal.
type Store interface {
	Put(ctx context.Context, tenant string, set Set) error
	Get(ctx context.Context, tenant string, cross bool, id string) (Set, error)
}

type memEntry struct {
	set Set
	at  time.Time
}

// MemStore is the bounded in-memory Store.
type MemStore struct {
	mu    sync.Mutex
	now   func() time.Time
	byTen map[string][]memEntry // tenant → entries, oldest first
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{now: time.Now, byTen: map[string][]memEntry{}}
}

func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// Put stores set under tenant. A set with an invalid id, no tenant, or more
// hypotheses than the bound is refused. A second Put of the same id in the
// same tenant replaces the first.
func (m *MemStore) Put(_ context.Context, tenant string, set Set) error {
	tenant = normTenant(tenant)
	if tenant == "" || !ValidID(set.ID) || len(set.Hypotheses) > MaxHypotheses {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	cur := m.pruneLocked(tenant, now)
	for i := range cur {
		if cur[i].set.ID == set.ID {
			cur = append(cur[:i], cur[i+1:]...)
			break
		}
	}
	cur = append(cur, memEntry{set: cloneSet(set), at: now})
	if excess := len(cur) - MaxPerTenant; excess > 0 {
		cur = append([]memEntry(nil), cur[excess:]...)
	}
	m.byTen[tenant] = cur
	return nil
}

// Get returns the set with id in tenant's scope (every tenant's when cross).
func (m *MemStore) Get(_ context.Context, tenant string, cross bool, id string) (Set, error) {
	if !ValidID(id) {
		return Set{}, ErrNotFound
	}
	tenant = normTenant(tenant)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if !cross {
		for _, e := range m.pruneLocked(tenant, now) {
			if e.set.ID == id {
				return cloneSet(e.set), nil
			}
		}
		return Set{}, ErrNotFound
	}
	for t := range m.byTen {
		for _, e := range m.pruneLocked(t, now) {
			if e.set.ID == id {
				return cloneSet(e.set), nil
			}
		}
	}
	return Set{}, ErrNotFound
}

// pruneLocked drops expired entries for tenant and returns what is left.
func (m *MemStore) pruneLocked(tenant string, now time.Time) []memEntry {
	cur := m.byTen[tenant]
	i := 0
	for i < len(cur) && now.Sub(cur[i].at) > TTL {
		i++
	}
	if i > 0 {
		cur = append([]memEntry(nil), cur[i:]...)
		if len(cur) == 0 {
			delete(m.byTen, tenant)
		} else {
			m.byTen[tenant] = cur
		}
	}
	return cur
}

// cloneSet deep-copies a Set so no caller shares slices with the store.
func cloneSet(s Set) Set {
	out := s
	out.Hypotheses = make([]Hypothesis, len(s.Hypotheses))
	for i, h := range s.Hypotheses {
		h.Evidence = append([]string(nil), h.Evidence...)
		h.Transitions = append([]Transition(nil), h.Transitions...)
		out.Hypotheses[i] = h
	}
	return out
}

var _ Store = (*MemStore)(nil)
