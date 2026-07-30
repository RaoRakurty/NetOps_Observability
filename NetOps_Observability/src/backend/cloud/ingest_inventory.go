package cloud

// ingest_inventory.go — the per-connector snapshot registry + the §3a.2
// tenant-stamping normalizer for the poller-facing ingest surface (extracted
// P2 RA.16). The registry folds per-connector snapshots into per-tenant merged
// inventories so ReplaceInventory (a full tenant refresh by contract) stays
// correct with multiple connectors per tenant — one PUT never clobbers
// siblings, bounded by the store's own hard cap. In-memory by design:
// snapshots are re-PUT every discovery cycle, so a restart converges within
// one cycle. The HTTP boundary, platform-realm authz and broker calls stay
// with the entrypoint.

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// ingestNormTenant mirrors main's normTenant (lock-step: lowercase + trim).
func ingestNormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// NormalizeIngestedResources applies the §3a.2 stamp to one connector
// snapshot: tenant from the CONNECTOR ROW (never the payload),
// provider/account defaults from the header, discovery times defaulted, then
// the same attribution the fixture loader applies — both paths land
// identically shaped rows. Returns the resources plus their identity mappings.
func NormalizeIngestedResources(resources []CloudResource, tenantID string, provider Provider, accountID string, now time.Time) ([]CloudResource, []CloudIdentityMapping) {
	res := make([]CloudResource, 0, len(resources))
	maps := make([]CloudIdentityMapping, 0, len(resources))
	for _, rr := range resources {
		rr.TenantID = tenantID
		if rr.Provider == "" {
			rr.Provider = provider
		}
		if rr.AccountID == "" {
			rr.AccountID = accountID
		}
		if rr.DiscoveredAt.IsZero() {
			rr.DiscoveredAt = now
		}
		if rr.LastSeenAt.IsZero() {
			rr.LastSeenAt = now
		}
		AttributeResource(&rr)
		res = append(res, rr)
		maps = append(maps, IdentityMappings(rr)...)
	}
	return res, maps
}

// ── per-connector snapshot registry ──────────────────────────────────────────

// ingestSnapshot is one connector's last normalized inventory snapshot.
type ingestSnapshot struct {
	tenant string
	res    []CloudResource
	maps   []CloudIdentityMapping
	at     time.Time
}

// IngestInventory folds per-connector snapshots into per-tenant merged
// inventories so ReplaceInventory (a full tenant refresh by contract) stays
// correct with multiple connectors per tenant. In-memory by design: snapshots
// are re-PUT every discovery cycle, so a restart converges within one cycle —
// the same freshness contract the fixture loader keeps.
type IngestInventory struct {
	mu     sync.Mutex
	byConn map[string]ingestSnapshot // connectorID → last snapshot
}

func NewIngestInventory() *IngestInventory {
	return &IngestInventory{byConn: map[string]ingestSnapshot{}}
}

// Put stores connectorID's snapshot and returns the tenant's merged inventory
// (deterministic connector order, bounded by the store's own hard cap).
func (ci *IngestInventory) Put(tenant, connectorID string, res []CloudResource, maps []CloudIdentityMapping) ([]CloudResource, []CloudIdentityMapping) {
	t := ingestNormTenant(tenant)
	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.byConn[connectorID] = ingestSnapshot{tenant: t, res: res, maps: maps, at: time.Now().UTC()}

	ids := make([]string, 0, len(ci.byConn))
	for id, snap := range ci.byConn {
		if snap.tenant == t {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var mergedRes []CloudResource
	var mergedMaps []CloudIdentityMapping
	for _, id := range ids {
		snap := ci.byConn[id]
		if len(mergedRes)+len(snap.res) > ListHardCap {
			break // bounded: never build an unbounded merge (§9)
		}
		mergedRes = append(mergedRes, snap.res...)
		mergedMaps = append(mergedMaps, snap.maps...)
	}
	return mergedRes, mergedMaps
}
