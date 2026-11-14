// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irislearning

// store.go — the Store contract and the memory implementation (tests and
// previews; production uses PGStore). Both share Merge and the limits.

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store holds proposals. tenant is ALWAYS the principal's own.
type Store interface {
	// List returns the tenant's proposals, newest first.
	List(ctx context.Context, tenant string) ([]Proposal, error)
	// Get returns one proposal (ErrNotFound for another tenant's).
	Get(ctx context.Context, tenant, id string) (Proposal, error)
	// Offer records what a refresh generated: a new subject becomes a
	// proposal; a subject still "proposed" gets the fresh draft and
	// evidence; a subject a person already decided is left alone.
	// It returns how many were added and refreshed.
	Offer(ctx context.Context, tenant string, ps []Proposal, now time.Time) (added, refreshed int, err error)
	// Update applies fn to one proposal under a row lock and persists the
	// result. fn sees a copy; returning an error stores nothing.
	Update(ctx context.Context, tenant, id string, fn func(*Proposal) error) (Proposal, error)
}

// Merge decides what one Offer does to an existing proposal: refresh it while
// nobody has acted on it, otherwise keep it as decided. Returns the row to
// store and whether it changed.
func Merge(cur, fresh Proposal, now time.Time) (Proposal, bool) {
	if cur.State != StateProposed {
		return cur, false // adopted, applied or dismissed: a person decided
	}
	if cur.EvidenceCount == fresh.EvidenceCount && cur.Title == fresh.Title {
		return cur, false
	}
	cur.Title, cur.Why = fresh.Title, fresh.Why
	cur.Context, cur.Runbook, cur.Alias = fresh.Context, fresh.Runbook, fresh.Alias
	cur.Evidence, cur.EvidenceCount = fresh.Evidence, fresh.EvidenceCount
	cur.UpdatedAt = now
	return cur, true
}

// checkOffered validates one generated proposal before it is stored.
func checkOffered(p Proposal) error {
	if !ValidTarget(p.Target) || strings.TrimSpace(p.Subject) == "" || !p.draftOK() {
		return ErrInvalid
	}
	return nil
}

func newestFirst(ps []Proposal) {
	sort.SliceStable(ps, func(i, j int) bool {
		if !ps[i].UpdatedAt.Equal(ps[j].UpdatedAt) {
			return ps[i].UpdatedAt.After(ps[j].UpdatedAt)
		}
		return ps[i].ID < ps[j].ID
	})
}

func clone(p Proposal) Proposal {
	p.Evidence = append([]Evidence(nil), p.Evidence...)
	if p.Context != nil {
		c := *p.Context
		p.Context = &c
	}
	if p.Runbook != nil {
		r := *p.Runbook
		p.Runbook = &r
	}
	if p.Alias != nil {
		a := *p.Alias
		p.Alias = &a
	}
	return p
}

// MemStore keeps proposals in memory, keyed by tenant.
type MemStore struct {
	mu   sync.Mutex
	rows map[string]map[string]Proposal // tenant → id → proposal
}

// NewMemStore builds an empty memory store.
func NewMemStore() *MemStore { return &MemStore{rows: map[string]map[string]Proposal{}} }

// List implements Store.
func (m *MemStore) List(_ context.Context, tenant string) ([]Proposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Proposal, 0, len(m.rows[tenant]))
	for _, p := range m.rows[tenant] {
		out = append(out, clone(p))
	}
	newestFirst(out)
	return out, nil
}

// Get implements Store.
func (m *MemStore) Get(_ context.Context, tenant, id string) (Proposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.rows[tenant][id]
	if !ok {
		return Proposal{}, ErrNotFound
	}
	return clone(p), nil
}

// Offer implements Store.
func (m *MemStore) Offer(_ context.Context, tenant string, ps []Proposal, now time.Time) (int, int, error) {
	if strings.TrimSpace(tenant) == "" {
		return 0, 0, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.rows[tenant]
	if rows == nil {
		rows = map[string]Proposal{}
		m.rows[tenant] = rows
	}
	bySubject := map[string]string{}
	open := 0
	for id, p := range rows {
		bySubject[string(p.Generator)+"\x00"+p.Subject] = id
		if p.State == StateProposed {
			open++
		}
	}
	added, refreshed := 0, 0
	for _, f := range ps {
		if err := checkOffered(f); err != nil {
			return added, refreshed, err
		}
		if id, ok := bySubject[string(f.Generator)+"\x00"+f.Subject]; ok {
			if out, changed := Merge(rows[id], f, now); changed {
				rows[id] = out
				refreshed++
			}
			continue
		}
		if len(rows) >= MaxProposalsPerTenant || open >= MaxOpenPerTenant {
			continue // full: the rest waits for people to decide what is there
		}
		id, err := NewID()
		if err != nil {
			return added, refreshed, err
		}
		f = clone(f)
		f.ID, f.TenantID, f.State, f.CreatedAt, f.UpdatedAt = id, tenant, StateProposed, now, now
		rows[id] = f
		bySubject[string(f.Generator)+"\x00"+f.Subject] = id
		open++
		added++
	}
	return added, refreshed, nil
}

// Update implements Store.
func (m *MemStore) Update(_ context.Context, tenant, id string, fn func(*Proposal) error) (Proposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.rows[tenant][id]
	if !ok {
		return Proposal{}, ErrNotFound
	}
	next := clone(cur)
	if err := fn(&next); err != nil {
		return Proposal{}, err
	}
	next.ID, next.TenantID = cur.ID, cur.TenantID // never re-keyed
	m.rows[tenant][id] = next
	return clone(next), nil
}
