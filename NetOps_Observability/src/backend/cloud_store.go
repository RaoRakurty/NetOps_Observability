package main

// cloud_store.go — Cloud App Observability inventory store (#81 P3A). Holds the
// per-tenant cloud resources + identity mappings loaded from a CloudInventoryProvider
// (fixtures today; real SDK connectors later). In-memory + tenant-isolated in the
// store itself (CLAUDE.md §3a) — a Postgres-backed store over migration 0016 is the
// next step; this is read-mostly demo/inventory data refreshed from the provider.

import (
	"context"
	"sync"

	"netops/backend/cloud"
)

type cloudStore interface {
	ReplaceInventory(ctx context.Context, tenant string, res []cloud.CloudResource, maps []cloud.CloudIdentityMapping) error
	ListResources(ctx context.Context, tenant string, cross bool) ([]cloud.CloudResource, error)
	ListMappings(ctx context.Context, tenant string, cross bool) ([]cloud.CloudIdentityMapping, error)
	ReplaceConnectors(ctx context.Context, tenant string, conns []cloud.ConnectorInfo) error
	ListConnectors(ctx context.Context, tenant string, cross bool) ([]cloud.ConnectorInfo, error)
}

func newCloudStore() cloudStore {
	return &memCloudStore{
		res:   map[string][]cloud.CloudResource{},
		maps:  map[string][]cloud.CloudIdentityMapping{},
		conns: map[string][]cloud.ConnectorInfo{},
	}
}

type memCloudStore struct {
	mu    sync.RWMutex
	res   map[string][]cloud.CloudResource        // tenant → resources
	maps  map[string][]cloud.CloudIdentityMapping // tenant → mappings
	conns map[string][]cloud.ConnectorInfo        // tenant → inventory-source provenance
}

// ReplaceInventory swaps the whole inventory for a tenant (a provider snapshot is a
// full refresh). The tenant is stamped from the caller, never trusted from a row.
func (m *memCloudStore) ReplaceInventory(_ context.Context, tenant string, res []cloud.CloudResource, maps []cloud.CloudIdentityMapping) error {
	t := normTenant(tenant)
	rc := make([]cloud.CloudResource, len(res))
	copy(rc, res)
	for i := range rc {
		rc[i].TenantID = t
	}
	mc := make([]cloud.CloudIdentityMapping, len(maps))
	copy(mc, maps)
	for i := range mc {
		mc[i].TenantID = t
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res[t] = rc
	m.maps[t] = mc
	return nil
}

func (m *memCloudStore) ListResources(_ context.Context, tenant string, cross bool) ([]cloud.CloudResource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []cloud.CloudResource{}
	if cross {
		for _, rs := range m.res {
			out = append(out, rs...)
		}
		return out, nil
	}
	return append(out, m.res[normTenant(tenant)]...), nil
}

// ReplaceConnectors swaps the inventory-source provenance for a tenant — same
// full-refresh contract as ReplaceInventory (they come from the same load).
func (m *memCloudStore) ReplaceConnectors(_ context.Context, tenant string, conns []cloud.ConnectorInfo) error {
	cc := make([]cloud.ConnectorInfo, len(conns))
	copy(cc, conns)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conns[normTenant(tenant)] = cc
	return nil
}

func (m *memCloudStore) ListConnectors(_ context.Context, tenant string, cross bool) ([]cloud.ConnectorInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []cloud.ConnectorInfo{}
	if cross {
		for _, cs := range m.conns {
			out = append(out, cs...)
		}
		return out, nil
	}
	return append(out, m.conns[normTenant(tenant)]...), nil
}

func (m *memCloudStore) ListMappings(_ context.Context, tenant string, cross bool) ([]cloud.CloudIdentityMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []cloud.CloudIdentityMapping{}
	if cross {
		for _, ms := range m.maps {
			out = append(out, ms...)
		}
		return out, nil
	}
	return append(out, m.maps[normTenant(tenant)]...), nil
}
