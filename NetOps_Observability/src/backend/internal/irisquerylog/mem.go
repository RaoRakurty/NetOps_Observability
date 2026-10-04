// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisquerylog

// mem.go — the in-memory Store (file-mode deployments). The query log is
// evaluation telemetry, not a system of record: without the platform database
// it lives in memory, bounded exactly like the Postgres store, and a restart
// starts it empty.

import (
	"context"
	"sync"
	"time"
)

// MemStore is the in-memory Store. Records are kept per tenant in arrival
// order (oldest first), so age and the per-tenant cap prune from the front.
type MemStore struct {
	mu   sync.Mutex
	now  func() time.Time
	recs map[string][]Record // tenant → records, oldest first
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{now: func() time.Time { return time.Now().UTC() }, recs: map[string][]Record{}}
}

// pruneLocked drops every tenant's expired records and, past MaxPerTenant,
// the writing tenant's oldest ones (room = records about to be added).
func (m *MemStore) pruneLocked(tenant string, room int) {
	cut := m.now().Add(-Retention)
	for t, rs := range m.recs {
		i := 0
		for i < len(rs) && rs[i].At.Before(cut) {
			i++
		}
		if i > 0 {
			rs = append([]Record(nil), rs[i:]...)
		}
		if t == tenant {
			if excess := len(rs) + room - MaxPerTenant; excess > 0 {
				rs = append([]Record(nil), rs[excess:]...)
			}
		}
		if len(rs) == 0 {
			delete(m.recs, t)
			continue
		}
		m.recs[t] = rs
	}
}

// Record stores one record.
func (m *MemStore) Record(_ context.Context, tenant string, r Record) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := Normalize(tenant, r, m.now())
	if err != nil {
		return Record{}, err
	}
	m.pruneLocked(tenant, 1)
	for _, have := range m.recs[tenant] {
		if have.ID == r.ID {
			return Record{}, ErrInvalid // ids are server-generated; a repeat is a bug
		}
	}
	m.recs[tenant] = append(m.recs[tenant], r)
	return cloneRecord(r), nil
}

// List returns the tenant's live records, newest first.
func (m *MemStore) List(_ context.Context, tenant string, f ListFilter) ([]Record, error) {
	limit := clampLimit(f.Limit)
	m.mu.Lock()
	defer m.mu.Unlock()
	cut := m.now().Add(-Retention)
	rs := m.recs[tenant]
	out := []Record{}
	for i := len(rs) - 1; i >= 0 && len(out) < limit; i-- {
		r := rs[i]
		if r.At.Before(cut) {
			break // oldest-first order: everything earlier is older still
		}
		if f.Principal != "" && r.Principal != f.Principal {
			continue
		}
		out = append(out, cloneRecord(r))
	}
	return out, nil
}

// Get returns one live record of the tenant (of principal, unless "").
func (m *MemStore) Get(_ context.Context, tenant, principal, id string) (Record, error) {
	if !ValidID(id) {
		return Record{}, ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cut := m.now().Add(-Retention)
	for _, r := range m.recs[tenant] {
		if r.ID != id || r.At.Before(cut) || (principal != "" && r.Principal != principal) {
			continue
		}
		return cloneRecord(r), nil
	}
	return Record{}, ErrNotFound
}

// Correct attaches a correction to the principal's own live record.
func (m *MemStore) Correct(_ context.Context, tenant, principal, id string, c Correction) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	c, err := NormalizeCorrection(c, now)
	if err != nil {
		return Record{}, err
	}
	rs := m.recs[tenant]
	for i := range rs {
		r := &rs[i]
		if r.ID != id || r.Principal != principal || principal == "" || r.At.Before(now.Add(-Retention)) {
			continue
		}
		if len(r.Corrections) >= MaxCorrections {
			return Record{}, ErrFull
		}
		r.Corrections = append(r.Corrections, c)
		return cloneRecord(*r), nil
	}
	return Record{}, ErrNotFound
}

func clampLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultListLimit
	case n > MaxListLimit:
		return MaxListLimit
	}
	return n
}

func cloneRecord(r Record) Record {
	r.ValidationCodes = append([]string{}, r.ValidationCodes...)
	r.Entities = append([]Entity{}, r.Entities...)
	cs := make([]Correction, 0, len(r.Corrections))
	for _, c := range r.Corrections {
		if c.CorrectedAST != nil {
			c.CorrectedAST = c.CorrectedAST.Clone()
		}
		cs = append(cs, c)
	}
	r.Corrections = cs
	if r.Query != nil {
		r.Query = r.Query.Clone()
	}
	return r
}

var _ Store = (*MemStore)(nil)
