package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CloudInventoryProvider is the provider-neutral seam. The first pass is the
// fixture-driven implementation below; real AWS (Resource Groups Tagging API +
// EC2/ECS/EKS/Lambda/ELB/RDS describe), Azure (Resource Graph), and GCP (Cloud
// Asset Inventory) connectors implement the SAME interface later, with no change
// to the resolver, store, or API. We never claim a real connector we don't have.
type CloudInventoryProvider interface {
	ListResources(ctx context.Context, tenantID, accountID string) ([]CloudResource, error)
	ListIdentityMappings(ctx context.Context, tenantID, accountID string) ([]CloudIdentityMapping, error)
}

// fixtureFile is the on-disk shape: a provider+account header over a resource list
// (resources are stored WITHOUT app attribution — the normalizer derives it, so
// fixtures exercise the real resolution path).
type fixtureFile struct {
	Provider  Provider        `json:"provider"`
	AccountID string          `json:"account_id"`
	Resources []CloudResource `json:"resources"`
}

// FixtureProvider loads cloud inventory from JSON fixtures (stdlib only).
type FixtureProvider struct {
	dir string
	now func() time.Time
}

// NewFixtureProvider reads *.json inventory fixtures from dir.
func NewFixtureProvider(dir string) *FixtureProvider {
	return &FixtureProvider{dir: dir, now: time.Now}
}

func (f *FixtureProvider) load() ([]fixtureFile, error) {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return nil, err
	}
	var out []fixtureFile
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(f.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var ff fixtureFile
		if err := json.Unmarshal(raw, &ff); err != nil {
			return nil, fmt.Errorf("fixture %s: %w", e.Name(), err)
		}
		out = append(out, ff)
	}
	return out, nil
}

// ListResources returns attributed resources for a tenant, optionally narrowed to
// one account. The caller's tenant is STAMPED onto every row (fixtures are
// tenant-agnostic templates) — never trust a tenant id inside the fixture.
func (f *FixtureProvider) ListResources(_ context.Context, tenantID, accountID string) ([]CloudResource, error) {
	files, err := f.load()
	if err != nil {
		return nil, err
	}
	now := f.now()
	var out []CloudResource
	for _, ff := range files {
		if accountID != "" && ff.AccountID != accountID {
			continue
		}
		if !ValidProvider(ff.Provider) {
			continue // unsupported provider fails gracefully (skip, no crash)
		}
		for _, r := range ff.Resources {
			r.TenantID = tenantID // stamp from caller, never the fixture
			if r.Provider == "" {
				r.Provider = ff.Provider
			}
			if r.AccountID == "" {
				r.AccountID = ff.AccountID
			}
			r.DiscoveredAt = nowFallback(r.DiscoveredAt, now)
			r.LastSeenAt = nowFallback(r.LastSeenAt, now)
			AttributeResource(&r)
			out = append(out, r)
		}
	}
	return out, nil
}

// ListIdentityMappings expands the attributed resources into (match_key → app) rows.
func (f *FixtureProvider) ListIdentityMappings(ctx context.Context, tenantID, accountID string) ([]CloudIdentityMapping, error) {
	res, err := f.ListResources(ctx, tenantID, accountID)
	if err != nil {
		return nil, err
	}
	var out []CloudIdentityMapping
	for _, r := range res {
		out = append(out, IdentityMappings(r)...)
	}
	return out, nil
}
