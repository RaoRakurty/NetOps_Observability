// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package orgcontext

// store.go — the Store contract and the memory implementation (tests and
// file-backend previews; production uses PGStore). Both run the same Apply.

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// NewDoc is what a create carries (the tenant and author come from the
// principal, never from here).
type NewDoc struct {
	Scope string
	Kind  Kind
	Key   string
	Body  string
}

// Store is the Org Context Store. tenant is ALWAYS the principal's own.
type Store interface {
	// List returns the tenant's documents with their history.
	List(ctx context.Context, tenant string) ([]Doc, error)
	// Get returns one document (ErrNotFound for another tenant's).
	Get(ctx context.Context, tenant, id string) (Doc, error)
	// Create makes a document whose version 1 is a draft by actor.
	Create(ctx context.Context, tenant, actor string, in NewDoc) (Doc, error)
	// Do applies one transition to a document.
	Do(ctx context.Context, tenant, id string, op Op) (Doc, error)
	// ActiveFacts returns every active version of the tenant, in render order.
	ActiveFacts(ctx context.Context, tenant string) ([]Fact, error)
}

// checkNew validates a create's structure (content rules are the caller's,
// via CheckKey/CheckBody, because they need the tool list).
func checkNew(tenant, actor string, in NewDoc) error {
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalid
	}
	if !ValidKind(in.Kind) || !ValidScope(in.Scope) {
		return ErrInvalid
	}
	if CheckKey(in.Key) != nil || len(in.Body) > MaxBodyBytes || strings.TrimSpace(in.Body) == "" {
		return ErrInvalid
	}
	return nil
}

// SortFacts is the render order: workspace-wide first, then by site, kind
// display order, key — deterministic, so a prompt is reproducible.
func SortFacts(fs []Fact) {
	rank := map[Kind]int{}
	for i, k := range Kinds() {
		rank[k] = i
	}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if (a.Scope == ScopeTenant) != (b.Scope == ScopeTenant) {
			return a.Scope == ScopeTenant
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Kind != b.Kind {
			return rank[a.Kind] < rank[b.Kind]
		}
		return a.Key < b.Key
	})
}

func factsOf(docs []Doc) []Fact {
	var out []Fact
	for _, d := range docs {
		if v, ok := d.Active(); ok {
			out = append(out, Fact{DocID: d.ID, Version: v.Version, Scope: d.Scope, Kind: d.Kind, Key: d.Key, Body: v.Body})
		}
	}
	SortFacts(out)
	return out
}

// MemStore keeps documents in memory, keyed by tenant.
type MemStore struct {
	mu   sync.Mutex
	rows map[string]map[string]Doc // tenant → id → doc
	now  func() time.Time
}

// NewMemStore builds an empty memory store.
func NewMemStore() *MemStore {
	return &MemStore{rows: map[string]map[string]Doc{}, now: func() time.Time { return time.Now().UTC() }}
}

func clone(d Doc) Doc {
	d.Versions = append([]Version(nil), d.Versions...)
	return d
}

// List implements Store.
func (m *MemStore) List(_ context.Context, tenant string) ([]Doc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Doc, 0, len(m.rows[tenant]))
	for _, d := range m.rows[tenant] {
		out = append(out, clone(d))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID < out[j].ID)
	})
	return out, nil
}

// Get implements Store.
func (m *MemStore) Get(_ context.Context, tenant, id string) (Doc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.rows[tenant][id]
	if !ok {
		return Doc{}, ErrNotFound
	}
	return clone(d), nil
}

// Create implements Store.
func (m *MemStore) Create(_ context.Context, tenant, actor string, in NewDoc) (Doc, error) {
	if err := checkNew(tenant, actor, in); err != nil {
		return Doc{}, err
	}
	id, err := NewID()
	if err != nil {
		return Doc{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rows[tenant]) >= MaxDocsPerTenant {
		return Doc{}, ErrFull
	}
	for _, d := range m.rows[tenant] {
		if d.Scope == in.Scope && d.Kind == in.Kind && d.Key == in.Key {
			return Doc{}, ErrExists
		}
	}
	now := m.now()
	d := Doc{ID: id, TenantID: tenant, Scope: in.Scope, Kind: in.Kind, Key: in.Key, CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
		Versions: []Version{{Version: 1, Body: in.Body, BodySHA256: BodySHA256(in.Body), State: StateDraft, Author: actor, CreatedAt: now}}}
	if m.rows[tenant] == nil {
		m.rows[tenant] = map[string]Doc{}
	}
	m.rows[tenant][id] = d
	return clone(d), nil
}

// Do implements Store. A discarded draft that was the document's only
// version removes the document.
func (m *MemStore) Do(_ context.Context, tenant, id string, op Op) (Doc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.rows[tenant][id]
	if !ok {
		return Doc{}, ErrNotFound
	}
	if op.Now.IsZero() {
		op.Now = m.now()
	}
	out, err := Apply(d, op)
	if err != nil {
		return Doc{}, err
	}
	if len(out.Versions) == 0 {
		delete(m.rows[tenant], id)
		return out, nil
	}
	m.rows[tenant][id] = out
	return clone(out), nil
}

// ActiveFacts implements Store.
func (m *MemStore) ActiveFacts(ctx context.Context, tenant string) ([]Fact, error) {
	docs, err := m.List(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return factsOf(docs), nil
}
