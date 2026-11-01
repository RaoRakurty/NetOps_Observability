// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/ctloverlay"
	"netops/backend/nms"
)

// topology_links_enrichment.go — exports the L2/L3 device adjacency (LLDP/CDP/BGP-LS
// links) to the shared enrichment dir as topology_links.json, so the correlation
// engine can use it as the "L2/L3 adjacent device" grounding rung (G1 —
// correlation-engine.md §4.2). This is what lets a fabric link-flap / IGP adjacency
// fault correlate across the two ENDS of a link (different devices), which seam +
// same-device containment alone cannot.
//
// Mirrors startSeamEnrichment: atomic write, 60s refresh, no-op without the shared
// volume. TENANT-SCOPED: each link carries its local device's tenant so the engine
// grounds within a tenant (a tenant's links ∪ global) — adjacency never crosses
// tenants (zero-leak bar). Absent file → engine falls back to seam/containment.

type topologyLinkExport struct {
	TenantID string `json:"tenant_id"`       // local device's tenant ("" = global)
	A        string `json:"a"`               // local device id (correlation entity device-part)
	B        string `json:"b"`               // neighbour device id
	AIf      string `json:"a_if,omitempty"`  // local interface
	BIf      string `json:"b_if,omitempty"`  // neighbour interface
	Proto    string `json:"proto,omitempty"` // lldp | cdp | bgp_ls | sdwan_bfd (controller tunnel ↔ endpoint)
}

func (s *server) startTopologyLinksEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" || s.discovery == nil {
		return
	}
	write := func() {
		links, err := collectors.FetchTopologyLinks(ctx)
		if err != nil {
			log.Printf("topology-links-enrichment: fetch: %v", err)
			return
		}
		// device id/name → tenant, so each link is scoped to its local device's tenant.
		tenantBy := map[string]string{}
		for _, d := range s.discovery.Devices() {
			t := deviceTenant(d)
			if d.ID != "" {
				tenantBy[d.ID] = t
			}
			if d.Name != "" {
				tenantBy[d.Name] = t
			}
		}
		seen := map[string]bool{}
		out := make([]topologyLinkExport, 0, len(links))
		for _, l := range links {
			a := firstNonEmpty(l.LocalDevice, l.LocalName)
			b := l.RemSysName
			if a == "" || b == "" || a == b {
				continue // need both ends, and a self-link is not an adjacency
			}
			lo, hi := a, b
			if lo > hi {
				lo, hi = hi, lo
			}
			key := lo + "\x00" + hi
			if seen[key] {
				continue // undirected dedup (the engine treats the pair as a set anyway)
			}
			seen[key] = true
			out = append(out, topologyLinkExport{
				TenantID: tenantBy[a], A: a, B: b, AIf: l.LocalPort, BIf: l.RemPort, Proto: l.Proto,
			})
		}
		// NMS-first T4c: controller tunnels ground to their edge devices. An
		// unread session store skips this write and keeps the previous file —
		// dropping the tunnel rows would collapse grounding mid-incident.
		ctl, cerr := s.controllerLinks(ctx)
		if cerr != nil {
			log.Printf("topology-links-enrichment: controller tunnels unread, keeping the previous file: %v", cerr)
			return
		}
		out = append(out, ctl...)
		data, err := json.Marshal(out)
		if err != nil {
			log.Printf("topology-links-enrichment: marshal: %v", err)
			return
		}
		if err := writeFileAtomic(filepath.Join(dir, "topology_links.json"), data, 0o644); err != nil {
			log.Printf("topology-links-enrichment: write: %v", err)
			return
		}
		log.Printf("topology-links-enrichment: exported %d adjacency link(s) (%d controller tunnel)", len(out), len(ctl))
	}
	go func() {
		write()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()
}

// controllerLinks wires ctloverlay.Links to the running NMS framework
// (NMS-first T4c).
func (s *server) controllerLinks(ctx context.Context) ([]topologyLinkExport, error) {
	if s.nms == nil {
		return nil, nil
	}
	var res ctloverlay.KeyResolver
	if s.nmsResolver != nil {
		res = s.nmsResolver
	}
	reg := s.nms.Registry()
	spec := func(vendor string) (nms.ConnectorSpec, bool) {
		c, ok := reg.Get(vendor)
		if !ok {
			return nms.ConnectorSpec{}, false
		}
		return c.Spec(), true
	}
	links, err := ctloverlay.Links(ctx, s.nms.Store(), spec, res, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	out := make([]topologyLinkExport, 0, len(links))
	for _, l := range links {
		out = append(out, topologyLinkExport{TenantID: l.TenantID, A: l.A, B: l.B, Proto: l.Proto})
	}
	return out, nil
}
