// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aidecision

// mem.go — the in-memory Store for file-mode deployments (no platform
// database). It is NOT durable and NOT unbounded: each tenant keeps its newest
// MaxMemPerTenant entries and a restart starts it empty. The durable,
// append-only ledger is the Postgres store; this one exists so the read API and
// the wiring behave the same on a file-mode lab, and the bound is the honest
// price of keeping it in memory.

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemStore is the in-memory Store.
type MemStore struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string][]Entry // tenant → entries, oldest first
	evicted uint64
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{now: func() time.Time { return time.Now().UTC() }, entries: map[string][]Entry{}}
}

// Append stores one decision's entries.
func (m *MemStore) Append(_ context.Context, tenant string, entries []Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	es, err := NormalizeBatch(tenant, entries, m.now())
	if err != nil || len(es) == 0 {
		return err
	}
	cur := append(m.entries[es[0].TenantID], es...)
	if excess := len(cur) - MaxMemPerTenant; excess > 0 {
		cur = append([]Entry(nil), cur[excess:]...)
		m.evicted += uint64(excess)
	}
	m.entries[es[0].TenantID] = cur
	return nil
}

// Evicted is how many entries the per-tenant bound has pushed out.
func (m *MemStore) Evicted() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evicted
}

// List returns entries newest first (one decision: seq order).
func (m *MemStore) List(_ context.Context, tenant string, cross bool, f ListFilter) ([]Entry, error) {
	if f.DecisionID != "" && !ValidID(f.DecisionID) {
		return []Entry{}, nil
	}
	limit := clampLimit(f.Limit)
	m.mu.Lock()
	var pool []Entry
	if cross {
		for _, es := range m.entries {
			pool = append(pool, es...)
		}
	} else {
		pool = append(pool, m.entries[tenant]...)
	}
	m.mu.Unlock()

	out := []Entry{}
	for _, e := range pool {
		if f.DecisionID != "" && e.DecisionID != f.DecisionID {
			continue
		}
		if !f.Before.IsZero() && !e.At.Before(f.Before) {
			continue
		}
		out = append(out, e)
	}
	if f.DecisionID != "" {
		sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	} else {
		sort.SliceStable(out, func(i, j int) bool {
			if !out[i].At.Equal(out[j].At) {
				return out[i].At.After(out[j].At)
			}
			if out[i].DecisionID != out[j].DecisionID {
				return out[i].DecisionID < out[j].DecisionID
			}
			return out[i].Seq > out[j].Seq
		})
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

var _ Store = (*MemStore)(nil)
