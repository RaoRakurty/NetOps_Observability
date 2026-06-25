package main

// ngfw_resolver.go — Application Identification: the NGFW App-ID overlay (#81
// P-NGFW pt2). The FREE authoritative signal — a firewall does the on-box DPI and
// writes the application into its syslog; Vector normalizes it to .app_id/.app_dst
// (pt1). This periodically aggregates those fw_events from OpenSearch into an
// in-memory dstIP→app map and feeds it into the resolver as an AUTHORITATIVE
// SrcNGFWAppID signal (strength 4 → confirmed), per tenant.
//
// Refresh mirrors the EntityResolver enrichment: a 2-minute ticker, atomic swap,
// non-fatal on error. The map partitions by the tenant_id Vector stamped, and
// signalFor enforces scoping (default-closed) so a tenant never sees another's
// firewall attributions.

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"sync/atomic"
	"time"

	"netops/backend/appid"
)

// ngfwAppMap: tenant → (dstIP → app label).
type ngfwAppMap map[string]map[string]string

type ngfwAppResolver struct {
	cur atomic.Pointer[ngfwAppMap]
}

func newNgfwAppResolver() *ngfwAppResolver {
	r := &ngfwAppResolver{}
	empty := ngfwAppMap{}
	r.cur.Store(&empty)
	return r
}

func (r *ngfwAppResolver) get() ngfwAppMap {
	if r == nil {
		return nil
	}
	if m := r.cur.Load(); m != nil {
		return *m
	}
	return nil
}

// count reports the total (tenant,dst) firewall attributions indexed.
func (r *ngfwAppResolver) count() int {
	n := 0
	for _, b := range r.get() {
		n += len(b)
	}
	return n
}

// signalFor returns an authoritative NGFW app-id signal for (tenant,dstIP) if the
// firewall classified traffic to that destination. A scoped caller reads ONLY its
// own tenant bucket; the platform owner (cross) reads the untagged ("") bucket
// (global telemetry) — default-closed, no cross-tenant mixing.
func (r *ngfwAppResolver) signalFor(tenant string, cross bool, dstIP string) (appid.Signal, bool) {
	m := r.get()
	if m == nil || dstIP == "" {
		return appid.Signal{}, false
	}
	bucket := normTenant(tenant)
	if cross {
		bucket = ""
	}
	apps := m[bucket]
	if apps == nil {
		return appid.Signal{}, false
	}
	app := apps[dstIP]
	if app == "" {
		return appid.Signal{}, false
	}
	return appid.Signal{Source: appid.SrcNGFWAppID, App: app, Detail: "ngfw firewall app-id"}, true
}

// ngfwDoc is the projection we read from each fw_event (_source field names).
type ngfwDoc struct {
	TenantID string `json:"tenant_id"`
	AppID    string `json:"app_id"`
	AppDst   string `json:"app_dst"`
}

// buildNgfwAppMap folds fw_event projections (sorted newest-first) into the
// tenant→dstIP→app map, first-seen-wins so the most recent classification per
// destination sticks. Pure → unit-tested.
func buildNgfwAppMap(docs []ngfwDoc) ngfwAppMap {
	out := ngfwAppMap{}
	for _, d := range docs {
		if d.AppID == "" || d.AppDst == "" {
			continue
		}
		t := normTenant(d.TenantID)
		if out[t] == nil {
			out[t] = map[string]string{}
		}
		if _, exists := out[t][d.AppDst]; !exists { // newest wins (docs are desc by time)
			out[t][d.AppDst] = d.AppID
		}
	}
	return out
}

// refresh queries OpenSearch for recent firewall app-id events and swaps in a fresh
// map. Returns the number of (tenant,dst) attributions indexed. Non-fatal.
func (r *ngfwAppResolver) refresh(ctx context.Context) (int, error) {
	body := map[string]any{
		"size":    5000,
		"_source": []string{"tenant_id", "app_id", "app_dst"},
		"sort":    []any{map[string]any{"timestamp": map[string]string{"order": "desc", "unmapped_type": "date"}}},
		"query": map[string]any{"bool": map[string]any{
			"must":   []any{map[string]any{"exists": map[string]any{"field": "app_id"}}},
			"filter": []any{map[string]any{"range": map[string]any{"timestamp": map[string]string{"gte": "now-24h"}}}},
		}},
	}
	resp, err := openSearch("POST", "/netops-syslog-*/_search", body)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode >= 300 {
		return 0, nil // no index yet / transient — keep the prior map
	}
	var parsed struct {
		Hits struct {
			Hits []struct {
				Source ngfwDoc `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	// _source uses json tags on ngfwDoc below; decode directly.
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return 0, err
	}
	docs := make([]ngfwDoc, 0, len(parsed.Hits.Hits))
	for _, h := range parsed.Hits.Hits {
		docs = append(docs, h.Source)
	}
	m := buildNgfwAppMap(docs)
	r.cur.Store(&m)
	n := 0
	for _, b := range m {
		n += len(b)
	}
	return n, nil
}

// startRefresh runs the periodic refresh (initial load + 2-minute ticker).
func (r *ngfwAppResolver) startRefresh(ctx context.Context) {
	go func() {
		if n, err := r.refresh(ctx); err != nil {
			log.Printf("ngfw-appid: initial refresh error: %v", err)
		} else if n > 0 {
			log.Printf("ngfw-appid: indexed %d firewall app attributions", n)
		}
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := r.refresh(ctx); err != nil {
					log.Printf("ngfw-appid: refresh error: %v", err)
				}
			}
		}
	}()
}
