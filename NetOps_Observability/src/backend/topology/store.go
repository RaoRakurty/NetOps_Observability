// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"strings"
)

// topology_store.go — persistence seam for the topology graph (#77). The
// reconciler is the single writer: it computes the full platform-wide merged set
// each cycle and ReplaceAll's it; readers Snapshot their tenant-scoped slice.
//
// Two backends, selected like every other store (saved.go): an in-memory map for
// the default dependency-free build, and a Postgres-backed, RLS-scoped repository
// under STORE_BACKEND=postgres. Both enforce tenant isolation in the store itself
// (CLAUDE.md §3a) — the in-memory store filters by tenant, the pg store relies on
// the tenant_iso FORCE-RLS policy via withTenant.

type GraphStore interface {
	// Snapshot returns the persisted graph visible to the (tenant, cross) principal.
	Snapshot(ctx context.Context, tenant string, cross bool) (GraphRecords, error)
	// ReplaceAll replaces the ENTIRE persisted graph with the reconciler's full
	// platform-wide set (the reconciler is the only writer; it always recomputes the
	// whole set with first_seen preserved, so a wholesale replace is correct).
	ReplaceAll(ctx context.Context, g GraphRecords) error
}

// ── in-memory backend ────────────────────────────────────────────────────────

// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// NewMemStore / NewPGStore build the two backends.
func NewMemStore() *memStore { return &memStore{} }

func NewPGStore(db DB) *pgStore { return &pgStore{db: db} }

// normTenant mirrors the integrator's normalization (duplicated).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

type memStore struct {
	mu sync.RWMutex
	g  GraphRecords
}

func (m *memStore) Snapshot(_ context.Context, tenant string, cross bool) (GraphRecords, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.g.FilterTenant(tenant, cross), nil
}

func (m *memStore) ReplaceAll(_ context.Context, g GraphRecords) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.g = g
	return nil
}

// ── Postgres backend ─────────────────────────────────────────────────────────

type pgStore struct {
	db DB
}

func (s *pgStore) Snapshot(ctx context.Context, tenant string, cross bool) (GraphRecords, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var g GraphRecords
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		nrows, err := tx.Query(ctx, `SELECT data FROM topology_nodes ORDER BY tenant_id, id`)
		if err != nil {
			return err
		}
		defer nrows.Close()
		for nrows.Next() {
			var data []byte
			if err := nrows.Scan(&data); err != nil {
				return err
			}
			var n NodeRecord
			if err := json.Unmarshal(data, &n); err != nil {
				return err
			}
			g.Nodes = append(g.Nodes, n)
		}
		if err := nrows.Err(); err != nil {
			return err
		}
		erows, err := tx.Query(ctx, `SELECT data FROM topology_edges ORDER BY tenant_id, id`)
		if err != nil {
			return err
		}
		defer erows.Close()
		for erows.Next() {
			var data []byte
			if err := erows.Scan(&data); err != nil {
				return err
			}
			var e EdgeRecord
			if err := json.Unmarshal(data, &e); err != nil {
				return err
			}
			g.Edges = append(g.Edges, e)
		}
		return erows.Err()
	})
	if err != nil {
		return GraphRecords{}, err
	}
	return g, nil
}

// ReplaceAll rewrites the whole persisted graph in one transaction at platform
// scope ('*' — the reconciler's set spans all tenants, each row carrying its own
// tenant_id which RLS WITH CHECK validates). Delete-then-insert is atomic, so a
// reader never sees a half-written graph.
func (s *pgStore) ReplaceAll(ctx context.Context, g GraphRecords) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM topology_nodes`); err != nil {
			return err
		}
		for _, n := range g.Nodes {
			data, err := json.Marshal(n)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO topology_nodes (tenant_id, id, label, kind, first_seen, last_seen, stale, data)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				normTenant(n.TenantID), n.ID, n.Label, orEmpty(n.Kind), n.FirstSeen, n.LastSeen, n.Stale, data); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM topology_edges`); err != nil {
			return err
		}
		for _, e := range g.Edges {
			data, err := json.Marshal(e)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO topology_edges (tenant_id, id, source, target, protocol, first_seen, last_seen, stale, data)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
				normTenant(e.TenantID), e.ID, e.Source, e.Target, e.Protocol, e.FirstSeen, e.LastSeen, e.Stale, data); err != nil {
				return err
			}
		}
		return nil
	})
}

func orEmpty(s string) string {
	if s == "" {
		return "unresolved"
	}
	return s
}

var _ GraphStore = (*memStore)(nil)
var _ GraphStore = (*pgStore)(nil)
