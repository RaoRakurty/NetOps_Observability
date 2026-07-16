package main

// cloud_store.go — Cloud App Observability inventory store (#81 P3A; WAVE 1 #1).
// Holds the per-tenant cloud resources + identity mappings + inventory-source
// provenance loaded from a CloudInventoryProvider (fixtures today; real SDK
// connectors later). Two backends, selected like every other store (topology_store):
// an in-memory map for the default file build, and a Postgres-backed, RLS-scoped
// repository under STORE_BACKEND=postgres (cloud_store_pg.go, migration 0025).
//
// Both enforce tenant isolation IN THE STORE ITSELF (CLAUDE.md §3a.4) — the
// in-memory store keys/filters by tenant, the pg store relies on the tenant_iso
// FORCE-RLS policy via withTenant. No unscoped "list all" for a scoped caller.
//
// QueryResources adds server-side filter + keyset pagination for /api/cloud/resources
// (rev #2): filtering and paging happen in the store (SQL for pg, a sorted slice for
// mem), never by loading a tenant's whole inventory into a handler.

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"sync"

	"netops/backend/cloud"
)

// Pagination bounds (reliability §9: bounded queries — never an unbounded SELECT).
// The default page is generous so today's small fixture inventories render in a
// single page (behaviorally identical to the pre-pagination surface); the hard cap
// bounds a hostile/large limit, and cloudListHardCap bounds the whole-inventory
// ListResources read used by the enrichment joins.
const (
	cloudPageDefault = 500
	cloudPageMax     = 1000
	cloudListHardCap = 100000
)

// errBadCursor is returned when an opaque pagination cursor fails to decode
// (mapped to HTTP 400 by the handler — a client-supplied value, so validate it).
var errBadCursor = errors.New("invalid cursor")

// cloudResourceFilter is the server-side filter + pagination for /api/cloud/resources.
// An empty string field means "no filter on this dimension". Limit/Cursor drive the
// keyset page; the caller clamps Limit before handing it to the store.
//
// Provider/Account/Region accept a comma-separated MULTI-VALUE list (Wave 2 #5
// scope bar: "aws,azure" = either cloud) — OR within a dimension, AND across
// dimensions. Values never contain commas (provider enums, account ids, region
// codes), so the separator is unambiguous.
type cloudResourceFilter struct {
	Provider    string // cloud(s), comma-separated (aws|azure|gcp), case-insensitive
	Account     string // account_id | subscription_id | project_id (exact, comma-separated)
	Region      string // exact, comma-separated
	Type        string // resource_type (exact)
	Tag         string // "key" (has tag) or "key=value" (exact value)
	Attribution string // confidence bucket (confirmed|strong|suspected|weak|unknown) or attributed|unattributed
	Limit       int    // page size (0 → cloudPageDefault)
	Cursor      string // opaque keyset cursor; "" = first page
}

// cloudResourcePage is one page of resources plus the opaque cursor for the next
// page (empty when this is the last page).
type cloudResourcePage struct {
	Resources  []cloud.CloudResource
	NextCursor string
}

// encodeCloudCursor / decodeCloudCursor implement a STABLE keyset cursor over the
// (tenant_id, resource_id) sort order both backends share — stable under concurrent
// inserts/deletes (unlike an offset), and it never leaks another tenant's ids
// because the scan is already RLS/tenant-scoped before the cursor is applied.
func encodeCloudCursor(tenant, resourceID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(tenant + "\x00" + resourceID))
}

func decodeCloudCursor(s string) (tenant, resourceID string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", "", false
	}
	t, r, found := strings.Cut(string(raw), "\x00")
	if !found {
		return "", "", false
	}
	return t, r, true
}

// cloudRowAfter reports whether (t,r) sorts strictly after the cursor (curT,curR)
// in the shared (tenant_id, resource_id) order.
func cloudRowAfter(t, r, curT, curR string) bool {
	if t != curT {
		return t > curT
	}
	return r > curR
}

// attributionMatches applies the attribution filter to a resource's confidence.
// "attributed" = evidence supports an app; "unattributed" = first-class unknown.
func attributionMatches(attribution string, c cloud.Confidence) bool {
	switch attribution {
	case "":
		return true
	case "attributed":
		return c != cloud.Unknown && c != ""
	case "unattributed":
		return c == cloud.Unknown || c == ""
	default:
		return string(c) == attribution
	}
}

// filterValues splits a (possibly multi-value) filter field into its non-empty
// parts. "" → nil (no filter); "aws,azure" → the OR set for that dimension.
func filterValues(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// matchesAny reports whether got equals ANY of the filter's values (fold decides
// case sensitivity). An empty filter matches everything.
func matchesAny(got, filter string, fold bool) bool {
	vals := filterValues(filter)
	if len(vals) == 0 {
		return true
	}
	for _, v := range vals {
		if (fold && strings.EqualFold(got, v)) || (!fold && got == v) {
			return true
		}
	}
	return false
}

// matchCloudResource reports whether r passes every SET field of f (the pagination
// fields Limit/Cursor are handled by the caller, not here). Shared by the mem store
// and the isolation/filter tests; the pg store mirrors this predicate in SQL.
func matchCloudResource(r cloud.CloudResource, f cloudResourceFilter) bool {
	if !matchesAny(string(r.Provider), f.Provider, true) {
		return false
	}
	if !matchesAny(r.AccountID, f.Account, false) {
		return false
	}
	if !matchesAny(r.Region, f.Region, false) {
		return false
	}
	if f.Type != "" && r.ResourceType != f.Type {
		return false
	}
	if f.Attribution != "" && !attributionMatches(f.Attribution, r.Confidence) {
		return false
	}
	if f.Tag != "" {
		key, val, hasVal := strings.Cut(f.Tag, "=")
		got, ok := r.Tags[key]
		if !ok {
			return false
		}
		if hasVal && got != val {
			return false
		}
	}
	return true
}

type cloudStore interface {
	ReplaceInventory(ctx context.Context, tenant string, res []cloud.CloudResource, maps []cloud.CloudIdentityMapping) error
	// ListResources returns the WHOLE tenant inventory (bounded by cloudListHardCap)
	// — used by the enrichment joins (path ingest / path graph / apps / coverage).
	ListResources(ctx context.Context, tenant string, cross bool) ([]cloud.CloudResource, error)
	// QueryResources returns one filtered, keyset-paginated page — the /resources surface.
	QueryResources(ctx context.Context, tenant string, cross bool, f cloudResourceFilter) (cloudResourcePage, error)
	// GetResource fetches a single resource by id within the caller's scope. found=false
	// when it does not exist OR belongs to another tenant (the handler maps that to 404 —
	// never reveal another tenant's id, CLAUDE.md §3a.1).
	GetResource(ctx context.Context, tenant string, cross bool, resourceID string) (cloud.CloudResource, bool, error)
	ListMappings(ctx context.Context, tenant string, cross bool) ([]cloud.CloudIdentityMapping, error)
	ReplaceConnectors(ctx context.Context, tenant string, conns []cloud.ConnectorInfo) error
	ListConnectors(ctx context.Context, tenant string, cross bool) ([]cloud.ConnectorInfo, error)
}

// newCloudStore picks the backend: a per-row RLS-scoped pg repository under
// STORE_BACKEND=postgres, else the in-memory store. Always non-nil.
func newCloudStore() cloudStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgCloudStore{db: ps.db}
	}
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
			if len(out) >= cloudListHardCap {
				return out[:cloudListHardCap], nil
			}
		}
		return out, nil
	}
	out = append(out, m.res[normTenant(tenant)]...)
	if len(out) > cloudListHardCap {
		out = out[:cloudListHardCap]
	}
	return out, nil
}

// QueryResources filters + keyset-paginates the tenant's resources in a stable
// (tenant_id, resource_id) order. Mirrors the pg store's SQL semantics so a caller
// gets identical pages regardless of backend.
func (m *memCloudStore) QueryResources(_ context.Context, tenant string, cross bool, f cloudResourceFilter) (cloudResourcePage, error) {
	curT, curR, hasCur := "", "", false
	if f.Cursor != "" {
		t, r, ok := decodeCloudCursor(f.Cursor)
		if !ok {
			return cloudResourcePage{}, errBadCursor
		}
		curT, curR, hasCur = t, r, true
	}
	limit := f.Limit
	if limit <= 0 {
		limit = cloudPageDefault
	}

	m.mu.RLock()
	var all []cloud.CloudResource
	if cross {
		for _, rs := range m.res {
			all = append(all, rs...)
		}
	} else {
		all = append(all, m.res[normTenant(tenant)]...)
	}
	m.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool {
		if all[i].TenantID != all[j].TenantID {
			return all[i].TenantID < all[j].TenantID
		}
		return all[i].ResourceID < all[j].ResourceID
	})

	out := make([]cloud.CloudResource, 0, limit)
	next := ""
	for _, r := range all {
		if hasCur && !cloudRowAfter(r.TenantID, r.ResourceID, curT, curR) {
			continue
		}
		if !matchCloudResource(r, f) {
			continue
		}
		if len(out) == limit {
			// One more match beyond the page → hand back a cursor to resume from.
			last := out[len(out)-1]
			next = encodeCloudCursor(last.TenantID, last.ResourceID)
			break
		}
		out = append(out, r)
	}
	return cloudResourcePage{Resources: out, NextCursor: next}, nil
}

// GetResource returns a single resource within scope. found=false for a missing id
// OR another tenant's id (default-closed) — the handler renders both as 404.
func (m *memCloudStore) GetResource(_ context.Context, tenant string, cross bool, resourceID string) (cloud.CloudResource, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cross {
		for _, rs := range m.res {
			for _, r := range rs {
				if r.ResourceID == resourceID {
					return r, true, nil
				}
			}
		}
		return cloud.CloudResource{}, false, nil
	}
	for _, r := range m.res[normTenant(tenant)] {
		if r.ResourceID == resourceID {
			return r, true, nil
		}
	}
	return cloud.CloudResource{}, false, nil
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

var _ cloudStore = (*memCloudStore)(nil)
