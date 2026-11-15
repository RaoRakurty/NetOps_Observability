// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisaction

// store.go — the request register: the Store seam and its in-memory form
// (tests and file-mode builds). Isolation is enforced IN the store: every
// method takes the tenant, and no method lists across tenants.

import (
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"sync"
)

// Store is the request register.
type Store interface {
	// Insert stores a new request. It refuses a new PROPOSED request past
	// MaxOpenPerTenant (ErrTooManyOpen) and evicts the tenant's oldest
	// TERMINAL requests past MaxRequestsPerTenant.
	Insert(ctx context.Context, r Request) error
	// Get returns one request of this tenant; another tenant's id is
	// ErrNotFound.
	Get(ctx context.Context, tenant, id string) (Request, error)
	// List returns this tenant's requests, newest first.
	List(ctx context.Context, tenant string, f Filter) ([]Request, error)
	// Update is a compare-and-set: it applies fn only when the stored status
	// is expect, and stores the result atomically. When the status differs it
	// returns the CURRENT request and ErrNotPending — the idempotency guard
	// every approval relies on.
	Update(ctx context.Context, tenant, id string, expect Status, fn func(*Request) error) (Request, error)
}

// NewID returns a random UUIDv4.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// MemStore is the in-memory Store.
type MemStore struct {
	mu   sync.Mutex
	rows map[string]map[string]Request // tenant → id → request
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore { return &MemStore{rows: map[string]map[string]Request{}} }

func cloneReq(r Request) Request {
	r.Citations = append([]string(nil), r.Citations...)
	r.Payload = append([]byte(nil), r.Payload...)
	if r.DecidedAt != nil {
		t := *r.DecidedAt
		r.DecidedAt = &t
	}
	if r.ExecutedAt != nil {
		t := *r.ExecutedAt
		r.ExecutedAt = &t
	}
	if r.Result != nil {
		x := *r.Result
		r.Result = &x
	}
	return r
}

// Insert implements Store.
func (m *MemStore) Insert(_ context.Context, r Request) error {
	if r.TenantID == "" || r.ID == "" {
		return fmt.Errorf("%w: tenant and id are required", ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.rows[r.TenantID]
	if t == nil {
		t = map[string]Request{}
		m.rows[r.TenantID] = t
	}
	if _, dup := t[r.ID]; dup {
		return fmt.Errorf("%w: duplicate id", ErrInvalid)
	}
	if r.Status == StatusProposed {
		open := 0
		for _, x := range t {
			if x.Status == StatusProposed {
				open++
			}
		}
		if open >= MaxOpenPerTenant {
			return ErrTooManyOpen
		}
	}
	t[r.ID] = cloneReq(r)
	// Evict the oldest TERMINAL rows past the cap; open rows are never evicted.
	if len(t) > MaxRequestsPerTenant {
		var terminal []Request
		for _, x := range t {
			if x.Status.Terminal() {
				terminal = append(terminal, x)
			}
		}
		sort.Slice(terminal, func(i, j int) bool { return terminal[i].CreatedAt.Before(terminal[j].CreatedAt) })
		for i := 0; i < len(terminal) && len(t) > MaxRequestsPerTenant; i++ {
			delete(t, terminal[i].ID)
		}
	}
	return nil
}

// Get implements Store.
func (m *MemStore) Get(_ context.Context, tenant, id string) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[tenant][id]
	if !ok {
		return Request{}, ErrNotFound
	}
	return cloneReq(r), nil
}

// List implements Store.
func (m *MemStore) List(_ context.Context, tenant string, f Filter) ([]Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Request{}
	for _, r := range m.rows[tenant] {
		if f.Status != "" && r.Status != f.Status {
			continue
		}
		out = append(out, cloneReq(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if lim := clampLimit(f.Limit); len(out) > lim {
		out = out[:lim]
	}
	return out, nil
}

// Update implements Store.
func (m *MemStore) Update(_ context.Context, tenant, id string, expect Status, fn func(*Request) error) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[tenant][id]
	if !ok {
		return Request{}, ErrNotFound
	}
	if r.Status != expect {
		return cloneReq(r), ErrNotPending
	}
	next := cloneReq(r)
	if err := fn(&next); err != nil {
		return cloneReq(r), err
	}
	next.TenantID, next.ID = r.TenantID, r.ID
	m.rows[tenant][id] = cloneReq(next)
	return next, nil
}

func clampLimit(n int) int {
	if n <= 0 || n > MaxRequestsPerTenant {
		return MaxRequestsPerTenant
	}
	return n
}
