// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package irisinvest holds the traces of finished Iris investigations (tracker
// 337 N-I1) so an operator can open one again by its id.
//
// The investigation's CONCLUSION is already persisted by the investigation
// memory (iris_investigations, Phase B) and its tool calls by the decision
// ledger; what is held here is the structured trace the Iris panel draws —
// bounded, per tenant, for a week. Keys are the tenant FIRST: there is no way
// to read a trace without naming the tenant it was stored under, and the
// tenant always comes from the caller's token (§3a). Another tenant's id, an
// expired one and a malformed one are the same ErrNotFound.
package irisinvest

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"netops/backend/ai"
)

// Store bounds.
const (
	MaxPerTenant = 500
	TTL          = 7 * 24 * time.Hour
)

// Errors.
var (
	ErrNotFound = errors.New("irisinvest: not found")
	ErrInvalid  = errors.New("irisinvest: invalid")
)

var reID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidID reports whether id is a lowercase UUID — the only id shape a trace
// is stored under.
func ValidID(id string) bool { return reID.MatchString(id) }

// Store holds finished traces. tenant and cross always come from the caller's
// token, never from the request.
type Store interface {
	Put(ctx context.Context, tenant string, tr ai.InvestigationTrace) error
	Get(ctx context.Context, tenant string, cross bool, id string) (ai.InvestigationTrace, error)
	// List returns the tenant's most recent traces, newest first (cross: every
	// tenant's). limit is clamped to [1, 50].
	List(ctx context.Context, tenant string, cross bool, limit int) ([]Summary, error)
}

// Summary is one line of the recent-investigations list.
type Summary struct {
	ID         string                 `json:"id"`
	Status     string                 `json:"status"`
	Target     ai.InvestigationTarget `json:"target"`
	Passes     int                    `json:"passes"`
	StartedAt  time.Time              `json:"started_at"`
	FinishedAt time.Time              `json:"finished_at"`
}

type entry struct {
	tr     ai.InvestigationTrace
	stored time.Time
}

// MemStore is the in-process Store: bounded per tenant, expired by TTL.
type MemStore struct {
	mu  sync.Mutex
	by  map[string][]entry // tenant → entries, oldest first
	now func() time.Time
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{by: map[string][]entry{}, now: time.Now}
}

func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// Put stores tr under tenant. The trace must carry a valid id and a tenant.
func (m *MemStore) Put(_ context.Context, tenant string, tr ai.InvestigationTrace) error {
	tenant = normTenant(tenant)
	if tenant == "" || !ValidID(tr.ID) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	list := m.pruneLocked(tenant, now)
	out := list[:0]
	for _, e := range list {
		if e.tr.ID != tr.ID { // a re-put replaces, never duplicates
			out = append(out, e)
		}
	}
	out = append(out, entry{tr: tr, stored: now})
	if len(out) > MaxPerTenant {
		out = out[len(out)-MaxPerTenant:]
	}
	m.by[tenant] = out
	return nil
}

// Get returns one trace. A non-cross caller sees only its own tenant's.
func (m *MemStore) Get(_ context.Context, tenant string, cross bool, id string) (ai.InvestigationTrace, error) {
	if !ValidID(id) {
		return ai.InvestigationTrace{}, ErrNotFound
	}
	tenant = normTenant(tenant)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	tenants := []string{tenant}
	if cross {
		tenants = tenants[:0]
		for t := range m.by {
			tenants = append(tenants, t)
		}
	}
	for _, t := range tenants {
		if t == "" {
			continue
		}
		for _, e := range m.pruneLocked(t, now) {
			if e.tr.ID == id {
				return e.tr, nil
			}
		}
	}
	return ai.InvestigationTrace{}, ErrNotFound
}

// List returns recent summaries, newest first.
func (m *MemStore) List(_ context.Context, tenant string, cross bool, limit int) ([]Summary, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 50 {
		limit = 50
	}
	tenant = normTenant(tenant)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var all []entry
	if cross {
		for t := range m.by {
			all = append(all, m.pruneLocked(t, now)...)
		}
	} else if tenant != "" {
		all = append(all, m.pruneLocked(tenant, now)...)
	}
	// newest first
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if cross {
		sortByStored(all)
	}
	out := make([]Summary, 0, limit)
	for _, e := range all {
		if len(out) >= limit {
			break
		}
		out = append(out, Summary{ID: e.tr.ID, Status: e.tr.Status, Target: e.tr.Target,
			Passes: e.tr.Used.Passes, StartedAt: e.tr.StartedAt, FinishedAt: e.tr.FinishedAt})
	}
	return out, nil
}

// pruneLocked drops expired entries for tenant and returns what is left.
func (m *MemStore) pruneLocked(tenant string, now time.Time) []entry {
	list := m.by[tenant]
	keep := list[:0]
	for _, e := range list {
		if now.Sub(e.stored) < TTL {
			keep = append(keep, e)
		}
	}
	if len(keep) == 0 {
		delete(m.by, tenant)
		return nil
	}
	m.by[tenant] = keep
	return keep
}

// sortByStored orders entries newest first (insertion sort: lists are small).
func sortByStored(es []entry) {
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && es[j].stored.After(es[j-1].stored); j-- {
			es[j], es[j-1] = es[j-1], es[j]
		}
	}
}
