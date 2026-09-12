// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"os"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
	"netops/backend/topology"
)

// topology_reconcile.go — the background reconciler that gives the topology graph
// a persistent spine (#77). Every interval it gathers the live OBSERVED graph
// platform-wide (all devices + deduped adjacencies, via the same helpers /view
// uses), folds it into the PERSISTED graph (topology.Reconcile: preserve
// first_seen, advance last_seen, mark last-not-observed rows stale after a grace
// window, prune the long-gone), and ReplaceAll's the result. Readers then serve
// from the store (GET /api/topology/graph) with stable ids + freshness metadata.
//
// Single writer by design, so a wholesale replace is correct and race-free. The
// reconciler runs platform-wide (no per-request claims); each record is stamped
// with its device's tenant, and RLS / the in-memory filter scope reads per tenant.

const (
	topologyReconcileDefault = 60 * time.Second
	topologyStaleAfter       = 15 * time.Minute   // unobserved longer than this → stale (smooths a missed poll)
	topologyPruneAfter       = 7 * 24 * time.Hour // stale longer than this → dropped
)

// topologyReconcileInterval resolves the cadence from TOPOLOGY_RECONCILE_SEC
// (default 60s; <=0 disables the loop).
func topologyReconcileInterval() time.Duration {
	v := os.Getenv("TOPOLOGY_RECONCILE_SEC")
	if v == "" {
		return topologyReconcileDefault
	}
	n, err := parseIntStrict(v)
	if err != nil {
		return topologyReconcileDefault
	}
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// startTopologyReconciler runs an initial reconcile then loops until ctx is
// cancelled. Errors are logged and the loop continues (a transient backend blip
// must not wedge the spine; the last good snapshot keeps serving).
func (s *server) startTopologyReconciler(ctx context.Context) {
	interval := topologyReconcileInterval()
	if interval <= 0 || s.topology == nil {
		return
	}
	go func() {
		s.reconcileTopologyOnce(ctx) // seed immediately so the first /graph isn't empty
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.reconcileTopologyOnce(ctx)
			}
		}
	}()
}

func (s *server) reconcileTopologyOnce(ctx context.Context) {
	prev, err := s.topology.Snapshot(ctx, "", true) // platform-wide
	if err != nil {
		logError("topology", "reconcile snapshot", map[string]any{"error": err.Error()})
		return
	}
	observed := s.observeTopology(ctx)
	merged := topology.Reconcile(prev, observed, time.Now(), topologyStaleAfter, topologyPruneAfter)
	if err := s.topology.ReplaceAll(ctx, merged); err != nil {
		logError("topology", "reconcile replace", map[string]any{"error": err.Error()})
	}
}

// observeTopology builds the current OBSERVED graph across ALL tenants: a node per
// managed device (tenant stamped from the device), and an edge per deduped
// adjacency (tenant = the source device's tenant). first_seen/last_seen/stale are
// filled by topology.Reconcile, not here.
func (s *server) observeTopology(ctx context.Context) topology.GraphRecords {
	devs := s.discovery.Devices() // platform-wide (the reconciler has no claims)
	tenantByDev := make(map[string]string, len(devs))
	for _, d := range devs {
		tenantByDev[d.ID] = normTenant(d.TenantID)
	}

	var g topology.GraphRecords
	for _, f := range toDeviceFacts(devs, nil, nil, nil) { // cpu/mem/links nil — structural only
		g.Nodes = append(g.Nodes, topology.NodeRecord{
			TenantID: tenantByDev[f.ID],
			ID:       f.ID,
			Label:    f.Name,
			Kind:     topology.KindOf(f),
			Role:     f.Role,
			Vendor:   f.Vendor,
			Model:    f.Model,
			Site:     f.Site,
			Rack:     f.Rack,
			MgmtIP:   f.MgmtIP,
			Owner:    f.Owner,
		})
	}
	neighbors, _ := collectors.FetchTopologyLinks(ctx) // best-effort: collector off/unreachable → empty map
	ifaddr, _ := collectors.FetchIfAddrMap(ctx)        // best-effort: collector off/unreachable → empty map
	for _, l := range observeTopoLinks(devs, neighbors, ifaddr) {
		g.Edges = append(g.Edges, topology.EdgeRecord{
			TenantID:      tenantByDev[l.Source], // edge belongs to its source device's tenant
			ID:            topoEdgeID(l),
			Source:        l.Source,
			Target:        l.Target,
			SourcePort:    l.LocalPort,
			TargetPort:    l.RemotePort,
			Protocol:      l.SourceProto,
			IGP:           l.IGP,
			Area:          l.Area,
			Resolved:      l.Resolved,
			Bidirectional: l.Bidirectional,
		})
	}
	return g
}

// observeTopoLinks resolves the raw neighbour set into adjacencies PER TENANT
// (§3a). gatherTopoLinks builds its name/address resolution maps from the
// device slice it is given; passing the reconciler's platform-wide slice let a
// neighbour advertised to tenant A resolve to tenant B's device id whenever
// hostnames/mgmt-IPs collided — A's persisted edge then carried another
// tenant's device identifier (and was later pruned client-side, so A also
// silently lost the adjacency /view correctly shows as an ext: boundary). Raw
// neighbours are fetched once by the caller; only the resolution universe is
// partitioned. Pure — unit-tested by topology_reconcile_test.go.
func observeTopoLinks(devs []models.Device, neighbors []collectors.LLDPNeighbor, ifaddr map[string]map[string]string) []topoLink {
	devsByTenant := map[string][]models.Device{}
	for _, d := range devs {
		t := normTenant(d.TenantID)
		devsByTenant[t] = append(devsByTenant[t], d)
	}
	var links []topoLink
	for _, tdevs := range devsByTenant {
		ownedID, byName, byAddr := topoLinkMaps(tdevs)
		links = append(links, topology.NormalizeLLDP(neighbors, ownedID, byName, byAddr, ifaddr)...)
	}
	return links
}

// topoEdgeID is a deterministic, orientation-independent id for an adjacency, so
// the same link keeps the same id across reconcile cycles (required for an RCA
// overlay to bind to it). Endpoints are canonicalized (canonIface) and sorted.
func topoEdgeID(l topoLink) string {
	a := l.Source + "|" + canonIface(l.LocalPort)
	b := l.Target + "|" + canonIface(l.RemotePort)
	if a > b {
		a, b = b, a
	}
	return a + "--" + b
}
