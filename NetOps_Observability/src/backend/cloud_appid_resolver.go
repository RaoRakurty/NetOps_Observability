package main

// cloud_appid_resolver.go — the bridge that finally CONSUMES the cloud identity-map
// (#81 P3F+1 app-naming completion). The cloud inventory holds the richest
// authoritative identity (private IP / ENI / NIC / resource-id / ARN / DNS-name →
// app, from tags + resource graph), but until now it was exposed at
// /api/cloud/identity-map and consumed by NOTHING — so a flow/log to a tagged cloud
// private IP resolved "unknown" even though the answer was on file.
//
// This indexes those mappings into a tenant→key→app map (mirroring the NGFW
// resolver pattern: atomic swap, periodic refresh, default-closed tenant scoping)
// and feeds them into the SAME appid.Fuse resolver every other source uses — as
// honest cloud_tag (authoritative) / cloud_graph (strong) signals. One resolver,
// every identity type, so records crossing ANY seam can name their app.

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"netops/backend/appid"
	"netops/backend/cloud"
)

// cloudKeyMap: tenant → match-key (IP / ENI / resource-id / …) → resolved app signal.
type cloudKeyEntry struct {
	app    string
	source appid.Source
}
type cloudKeyMap map[string]map[string]cloudKeyEntry

type cloudAppResolver struct {
	store cloudStore
	cur   atomic.Pointer[cloudKeyMap]
}

func newCloudAppResolver(store cloudStore) *cloudAppResolver {
	r := &cloudAppResolver{store: store}
	empty := cloudKeyMap{}
	r.cur.Store(&empty)
	return r
}

func (r *cloudAppResolver) get() cloudKeyMap {
	if r == nil {
		return nil
	}
	if m := r.cur.Load(); m != nil {
		return *m
	}
	return nil
}

func (r *cloudAppResolver) count() int {
	n := 0
	for _, b := range r.get() {
		n += len(b)
	}
	return n
}

// cloudSrcToAppid maps a cloud attribution source onto the appid resolver's
// provenance ladder — preserving the trust level (tag/operator/firewall =
// authoritative; graph/domain = strong; ip-catalog = medium). Returns ok=false for
// sources that must not assert an app (unknown).
func cloudSrcToAppid(s cloud.Source) (appid.Source, bool) {
	switch s {
	case cloud.SrcCloudTag:
		return appid.SrcCloudTag, true
	case cloud.SrcOperatorCatalog:
		return appid.SrcOperator, true
	case cloud.SrcFirewallAppID:
		return appid.SrcNGFWAppID, true
	case cloud.SrcCloudGraph:
		return appid.SrcCloudGraph, true
	case cloud.SrcDomain:
		return appid.SrcDNS, true
	case cloud.SrcIPCatalog:
		return appid.SrcIPCatalog, true
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
		t := normTenant(m.TenantID)
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
func (r *cloudAppResolver) signalFor(tenant string, cross bool, key string) (appid.Signal, bool) {
	m := r.get()
	if m == nil || key == "" {
		return appid.Signal{}, false
	}
	if cross {
		for _, bucket := range m {
			if e, ok := bucket[key]; ok {
				return appid.Signal{Source: e.source, App: e.app, Detail: "cloud inventory identity-map"}, true
			}
		}
		return appid.Signal{}, false
	}
	bucket := m[normTenant(tenant)]
	if bucket == nil {
		return appid.Signal{}, false
	}
	if e, ok := bucket[key]; ok {
		return appid.Signal{Source: e.source, App: e.app, Detail: "cloud inventory identity-map"}, true
	}
	return appid.Signal{}, false
}

// refresh rebuilds the index from the cloud store (all tenants; the index keeps the
// per-tenant partition for scoped lookups) and swaps it in. Non-fatal.
func (r *cloudAppResolver) refresh(ctx context.Context) (int, error) {
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
func (r *cloudAppResolver) startRefresh(ctx context.Context) {
	go func() {
		if n, err := r.refresh(ctx); err != nil {
			log.Printf("cloud-appid: initial refresh error: %v", err)
		} else if n > 0 {
			log.Printf("cloud-appid: indexed %d cloud identity mappings", n)
		}
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := r.refresh(ctx); err != nil {
					log.Printf("cloud-appid: refresh error: %v", err)
				}
			}
		}
	}()
}
