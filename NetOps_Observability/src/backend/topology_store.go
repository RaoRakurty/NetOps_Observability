package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"netops/backend/topology"
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

type topologyGraphStore interface {
	// Snapshot returns the persisted graph visible to the (tenant, cross) principal.
	Snapshot(ctx context.Context, tenant string, cross bool) (topology.GraphRecords, error)
	// ReplaceAll replaces the ENTIRE persisted graph with the reconciler's full
	// platform-wide set (the reconciler is the only writer; it always recomputes the
	// whole set with first_seen preserved, so a wholesale replace is correct).
	ReplaceAll(ctx context.Context, g topology.GraphRecords) error
}

// newTopologyStore picks the backend: a per-row RLS-scoped pg repository under
// STORE_BACKEND=postgres, else an in-memory store. Always non-nil.
func newTopologyStore() topologyGraphStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgTopologyStore{db: ps.db}
	}
	return &memTopologyStore{}
}

// ── in-memory backend ────────────────────────────────────────────────────────

type memTopologyStore struct {
	mu sync.RWMutex
	g  topology.GraphRecords
}

func (m *memTopologyStore) Snapshot(_ context.Context, tenant string, cross bool) (topology.GraphRecords, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.g.FilterTenant(tenant, cross), nil
}

func (m *memTopologyStore) ReplaceAll(_ context.Context, g topology.GraphRecords) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.g = g
	return nil
}

// ── Postgres backend ─────────────────────────────────────────────────────────

type pgTopologyStore struct {
	db *pgDB
}

func (s *pgTopologyStore) Snapshot(ctx context.Context, tenant string, cross bool) (topology.GraphRecords, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var g topology.GraphRecords
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
			var n topology.NodeRecord
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
			var e topology.EdgeRecord
			if err := json.Unmarshal(data, &e); err != nil {
				return err
			}
			g.Edges = append(g.Edges, e)
		}
		return erows.Err()
	})
	if err != nil {
		return topology.GraphRecords{}, err
	}
	return g, nil
}

// ReplaceAll rewrites the whole persisted graph in one transaction at platform
// scope ('*' — the reconciler's set spans all tenants, each row carrying its own
// tenant_id which RLS WITH CHECK validates). Delete-then-insert is atomic, so a
// reader never sees a half-written graph.
func (s *pgTopologyStore) ReplaceAll(ctx context.Context, g topology.GraphRecords) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
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

var _ topologyGraphStore = (*memTopologyStore)(nil)
var _ topologyGraphStore = (*pgTopologyStore)(nil)
