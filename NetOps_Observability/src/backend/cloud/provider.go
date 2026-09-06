// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// Collection is the provenance stamp a live poller writes into the inventory
// file it maintains ("collection": {...}). A hand-authored fixture carries no
// stamp — absence is the honest default, never assumed live.
type Collection struct {
	Mode        string    `json:"mode"` // "live_poller" is the only live mode
	CollectedAt time.Time `json:"collected_at"`
}

// ConnectorKindLive / ConnectorKindFixture — what is actually feeding the
// inventory. Zero-trust on the stamp: any mode we don't recognise stays "fixture".
const (
	ConnectorKindLive    = "live"
	ConnectorKindFixture = "fixture"
	collectionModeLive   = "live_poller"
)

// ConnectorInfo describes one inventory file's provenance, surfaced via the API
// so the UI can say "Live telemetry" vs "Demo tenant" from measurement, not
// assumption (#105 — the fixtures dir is poller-rewritten now; hard-coding
// "fixture" in the UI understated a live deployment).
type ConnectorInfo struct {
	Provider      Provider  `json:"provider"`
	AccountID     string    `json:"account_id"`
	Kind          string    `json:"kind"` // "live" | "fixture"
	CollectedAt   time.Time `json:"collected_at,omitzero"`
	ResourceCount int       `json:"resource_count"`
}

// fixtureFile is the on-disk shape: a provider+account header over a resource list
// (resources are stored WITHOUT app attribution — the normalizer derives it, so
// fixtures exercise the real resolution path).
type fixtureFile struct {
	Provider   Provider        `json:"provider"`
	AccountID  string          `json:"account_id"`
	Collection *Collection     `json:"collection"`
	Resources  []CloudResource `json:"resources"`
}

// FixtureProvider loads cloud inventory from JSON fixtures (stdlib only).
// It reads one or more layered directories: a file in a LATER dir shadows the
// same-named file in an earlier one. This is the static-fixture/runtime split
// (hygiene, 2026-07): tracked demo fixtures stay in the repo, the live
// poller's snapshots land in a gitignored runtime dir, and the runtime file —
// when present — wins.
type FixtureProvider struct {
	dirs []string
	now  func() time.Time
}

// NewFixtureProvider reads *.json inventory fixtures from dir.
func NewFixtureProvider(dir string) *FixtureProvider {
	return &FixtureProvider{dirs: []string{dir}, now: time.Now}
}

// NewLayeredFixtureProvider reads fixtureDir first, then runtimeDir — a
// runtime file shadows the fixture of the same name. Either dir may be empty
// or absent; only when NO configured dir is readable does load() error.
func NewLayeredFixtureProvider(fixtureDir, runtimeDir string) *FixtureProvider {
	var dirs []string
	for _, d := range []string{fixtureDir, runtimeDir} {
		if d != "" {
			dirs = append(dirs, d)
		}
	}
	return &FixtureProvider{dirs: dirs, now: time.Now}
}

func (f *FixtureProvider) load() ([]fixtureFile, error) {
	byName := map[string]fixtureFile{}
	var order []string // stable first-seen order across layers
	readable := 0
	var lastErr error
	for _, dir := range f.dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			lastErr = err
			continue // a missing layer degrades to the other layer(s)
		}
		readable++
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- operator-configured inventory dirs
			if err != nil {
				return nil, err
			}
			var ff fixtureFile
			if err := json.Unmarshal(raw, &ff); err != nil {
				return nil, fmt.Errorf("fixture %s: %w", e.Name(), err)
			}
			if _, seen := byName[e.Name()]; !seen {
				order = append(order, e.Name())
			}
			byName[e.Name()] = ff // later layer shadows earlier
		}
	}
	if readable == 0 && lastErr != nil {
		return nil, lastErr
	}
	out := make([]fixtureFile, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
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

// Connectors reports the provenance of every inventory file that contributes
// resources (topology files share the dir but carry none — skipped). Kind is
// derived from the collection stamp, default-closed: no stamp, or a mode we do
// not recognise, reads "fixture" — a file only earns "live" by carrying the
// live-poller stamp its writer maintains.
func (f *FixtureProvider) Connectors(_ context.Context) ([]ConnectorInfo, error) {
	files, err := f.load()
	if err != nil {
		return nil, err
	}
	var out []ConnectorInfo
	for _, ff := range files {
		if !ValidProvider(ff.Provider) || len(ff.Resources) == 0 {
			continue
		}
		ci := ConnectorInfo{
			Provider:      ff.Provider,
			AccountID:     ff.AccountID,
			Kind:          ConnectorKindFixture,
			ResourceCount: len(ff.Resources),
		}
		if ff.Collection != nil && ff.Collection.Mode == collectionModeLive {
			ci.Kind = ConnectorKindLive
			ci.CollectedAt = ff.Collection.CollectedAt
		}
		out = append(out, ci)
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
