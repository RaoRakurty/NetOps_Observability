// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package srcauthority

// store.go — the per-tenant policy store contract and the memory
// implementation (tests; production uses PGStore). tenant is ALWAYS the
// principal's own — the store never lists across tenants.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// Policy is one tenant's stored order.
type Policy struct {
	Tenant    string    `json:"-"`
	Order     []Class   `json:"order"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ErrInvalid is a structurally invalid store call (empty tenant or actor).
var ErrInvalid = errors.New("srcauthority: invalid request")

// Store holds at most one Policy per tenant.
type Store interface {
	// Get returns the tenant's policy; ok=false when it has none (the
	// platform default applies).
	Get(ctx context.Context, tenant string) (p Policy, ok bool, err error)
	// Put replaces the tenant's order (validated) and stamps actor + time.
	Put(ctx context.Context, tenant, actor string, order []Class) (Policy, error)
	// Delete removes the tenant's policy (back to the platform default).
	// Deleting a policy that does not exist is not an error.
	Delete(ctx context.Context, tenant string) error
}

func checkPut(tenant, actor string, order []Class) error {
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalid
	}
	return ValidateOrder(order)
}

// MemStore keeps policies in memory, keyed by tenant.
type MemStore struct {
	mu   sync.Mutex
	rows map[string]Policy
	now  func() time.Time
}

// NewMemStore builds an empty memory store.
func NewMemStore() *MemStore {
	return &MemStore{rows: map[string]Policy{}, now: func() time.Time { return time.Now().UTC() }}
}

func clonePolicy(p Policy) Policy {
	p.Order = append([]Class(nil), p.Order...)
	return p
}

// Get implements Store.
func (m *MemStore) Get(_ context.Context, tenant string) (Policy, bool, error) {
	if strings.TrimSpace(tenant) == "" {
		return Policy{}, false, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.rows[tenant]
	if !ok {
		return Policy{}, false, nil
	}
	return clonePolicy(p), true, nil
}

// Put implements Store.
func (m *MemStore) Put(_ context.Context, tenant, actor string, order []Class) (Policy, error) {
	if err := checkPut(tenant, actor, order); err != nil {
		return Policy{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := Policy{Tenant: tenant, Order: append([]Class(nil), order...), UpdatedBy: actor, UpdatedAt: m.now()}
	m.rows[tenant] = p
	return clonePolicy(p), nil
}

// Delete implements Store.
func (m *MemStore) Delete(_ context.Context, tenant string) error {
	if strings.TrimSpace(tenant) == "" {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, tenant)
	return nil
}

// Effective is the order that applies to a tenant and whether it is the
// tenant's own. A store error or a stored order that no longer validates falls
// back to the platform default and is RETURNED (the caller says so and counts
// it) — never a silent default, never an undefined order. A nil store (a
// deployment without the platform database) is the platform default.
func Effective(ctx context.Context, st Store, tenant string) (order []Class, customized bool, err error) {
	if st == nil || strings.TrimSpace(tenant) == "" {
		return DefaultOrder(), false, nil
	}
	p, ok, err := st.Get(ctx, tenant)
	if err != nil {
		return DefaultOrder(), false, err
	}
	if !ok {
		return DefaultOrder(), false, nil
	}
	if verr := ValidateOrder(p.Order); verr != nil {
		return DefaultOrder(), false, verr
	}
	return p.Order, !IsDefault(p.Order), nil
}
