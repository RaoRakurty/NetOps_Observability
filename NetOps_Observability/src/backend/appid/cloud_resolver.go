package appid

// cloud_resolver.go — the cloud identity-map consumer (#81 P3F+1, extracted P2
// RA.15). Indexes the cloud inventory's authoritative identity mappings
// (private IP / ENI / resource-id / ARN / DNS-name → app) into a tenant→key→app
// map — the NGFW resolver pattern: atomic swap, periodic refresh, and the
// DEFAULT-CLOSED per-tenant bucket lookup (a scoped caller reads ONLY its own
// bucket; cross may match across all — mirroring the cloud store's own
// isolation). Signals feed the same Fuse resolver every other source uses.

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	"netops/backend/cloud"
	"netops/backend/internal/applog"
)

// cloudNormTenant mirrors main's normTenant (lock-step: lowercase + trim).
func cloudNormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// cloudKeyMap: tenant → match-key (IP / ENI / resource-id / …) → resolved app signal.
type cloudKeyEntry struct {
	app    string
	source Source
}
type cloudKeyMap map[string]map[string]cloudKeyEntry

type CloudResolver struct {
	store cloud.Store
	cur   atomic.Pointer[cloudKeyMap]
}

func NewCloudResolver(store cloud.Store) *CloudResolver {
	r := &CloudResolver{store: store}
	empty := cloudKeyMap{}
	r.cur.Store(&empty)
	return r
}

func (r *CloudResolver) get() cloudKeyMap {
	if r == nil {
		return nil
	}
	if m := r.cur.Load(); m != nil {
		return *m
	}
	return nil
}

// CountFor reports the cloud identity-map attributions VISIBLE TO ONE CALLER
// (CLAUDE.md §3a), mirroring SignalFor's default-closed scoping: a scoped caller
// counts ONLY its own tenant bucket, so another tenant's inventory size never
// reaches it; the platform owner (cross) counts every bucket, which the status
// surface labels scope:"platform".
func (r *CloudResolver) CountFor(tenant string, cross bool) int {
	m := r.get()
	if cross {
		n := 0
		for _, b := range m {
			n += len(b)
		}
		return n
	}
	return len(m[cloudNormTenant(tenant)])
}

// cloudSrcToAppid maps a cloud attribution source onto the appid resolver's
// provenance ladder — preserving the trust level (tag/operator/firewall =
// authoritative; graph/domain = strong; ip-catalog = medium). Returns ok=false for
// sources that must not assert an app (unknown).
func cloudSrcToAppid(s cloud.Source) (Source, bool) {
	switch s {
	case cloud.SrcCloudTag:
		return SrcCloudTag, true
	case cloud.SrcOperatorCatalog:
		return SrcOperator, true
	case cloud.SrcFirewallAppID:
		return SrcNGFWAppID, true
	case cloud.SrcCloudGraph:
		return SrcCloudGraph, true
	case cloud.SrcDomain:
		return SrcDNS, true
	case cloud.SrcIPCatalog:
		return SrcIPCatalog, true
	default: // SrcUnknown / anything else — no opinion
		return "", false
	}
}

// buildCloudKeyMap folds identity mappings into tenant→key→app. Mappings with no
// app or an unknown attribution are skipped (never assert a guessed app). Pure →
// unit-tested. Keys are exact strings (IPs, ENI ids, resource ids, ARNs, DNS
// names) so a lookup by any of those resolves.
func buildCloudKeyMap(maps []cloud.CloudIdentityMapping) cloudKeyMap {
	out := cloudKeyMap{}
	for _, m := range maps {
		app := m.AppName
		if app == "" {
			app = m.AppID
		}
		if app == "" || m.Confidence == cloud.Unknown || m.MatchKey == "" {
			continue
		}
		src, ok := cloudSrcToAppid(m.Source)
		if !ok {
			continue
		}
		t := cloudNormTenant(m.TenantID)
		if out[t] == nil {
			out[t] = map[string]cloudKeyEntry{}
		}
		// first-seen wins per (tenant,key); the strongest source already sorts in
		// the cloud layer, and ListMappings returns one row per (resource,key).
		if _, exists := out[t][m.MatchKey]; !exists {
			out[t][m.MatchKey] = cloudKeyEntry{app: app, source: src}
		}
	}
	return out
}

// signalFor returns a cloud-inventory app signal for a record key (an IP, ENI,
// resource-id, …). A scoped caller reads ONLY its own tenant bucket; the platform
// owner (cross) may match across all buckets — mirrors the cloud store's own
// isolation (cloud_store.go ListResources), default-closed.
func (r *CloudResolver) SignalFor(tenant string, cross bool, key string) (Signal, bool) {
	m := r.get()
	if m == nil || key == "" {
		return Signal{}, false
	}
	if cross {
		for _, bucket := range m {
			if e, ok := bucket[key]; ok {
				return Signal{Source: e.source, App: e.app, Detail: "cloud inventory identity-map"}, true
			}
		}
		return Signal{}, false
	}
	bucket := m[cloudNormTenant(tenant)]
	if bucket == nil {
		return Signal{}, false
	}
	if e, ok := bucket[key]; ok {
		return Signal{Source: e.source, App: e.app, Detail: "cloud inventory identity-map"}, true
	}
	return Signal{}, false
}

// refresh rebuilds the index from the cloud store (all tenants; the index keeps the
// per-tenant partition for scoped lookups) and swaps it in. Non-fatal.
func (r *CloudResolver) Refresh(ctx context.Context) (int, error) {
	if r == nil || r.store == nil {
		return 0, nil
	}
	maps, err := r.store.ListMappings(ctx, "", true) // cross: all tenants, re-partitioned by buildCloudKeyMap
	if err != nil {
		return 0, err
	}
	m := buildCloudKeyMap(maps)
	r.cur.Store(&m)
	n := 0
	for _, b := range m {
		n += len(b)
	}
	return n, nil
}

// startRefresh runs the initial load + a periodic refresh. Cloud inventory changes
// rarely (fixture load / connector poll), so a 5-minute cadence is ample.
func (r *CloudResolver) StartRefresh(ctx context.Context) {
	go func() {
		if n, err := r.Refresh(ctx); err != nil {
			applog.Warn("cloud-appid", "initial refresh error", map[string]any{"error": err.Error()})
		} else if n > 0 {
			applog.Info("cloud-appid", "indexed cloud identity mappings", map[string]any{"count": n})
		}
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := r.Refresh(ctx); err != nil {
					applog.Warn("cloud-appid", "refresh error", map[string]any{"error": err.Error()})
				}
			}
		}
	}()
}

// SeedForTest builds and swaps in an index from literal mappings (tests).
func (r *CloudResolver) SeedForTest(maps []cloud.CloudIdentityMapping) {
	m := buildCloudKeyMap(maps)
	r.cur.Store(&m)
}
