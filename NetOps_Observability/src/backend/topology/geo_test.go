// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

import (
	"testing"
	"time"
)

func geoFixture() GeoInput {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	return GeoInput{
		TenantID: "acme",
		Now:      now,
		Sites: []GeoSiteFact{
			{Slug: "nyc", Name: "New York", Lat: 40.71, Lng: -74.0, HasCoords: true, Devices: 10, Up: 10, Down: 0, Source: "netbox"},
			{Slug: "lon", Name: "London", Lat: 51.5, Lng: -0.13, HasCoords: true, Devices: 4, Up: 3, Down: 1, Source: "netbox"},
			{Slug: "sfo", Name: "San Francisco", Lat: 37.77, Lng: -122.42, HasCoords: true, Devices: 2, Up: 0, Down: 2, Source: "netbox"},
			// placed but coordless — should surface as a node WITHOUT coordinates
			{Slug: "den", Name: "Denver", HasCoords: false, Devices: 1, Up: 1, Down: 0, Source: "netbox"},
			// noise: no coords, no devices — dropped
			{Slug: "ghost", Name: "Ghost", HasCoords: false, Devices: 0},
		},
		DeviceSite: map[string]string{
			"d1": "nyc", "d2": "nyc",
			"d3": "lon",
			"d4": "sfo",
			"dx": "", // unplaced device
		},
		Links: []LinkFact{
			// nyc <-> lon, two corroborating links (lldp + bgp_ls), one with util
			{Source: "d1", Target: "d3", Protocol: "lldp", Status: StatusUp, LastSeen: now},
			{Source: "d2", Target: "d3", Protocol: "bgp_ls", Status: StatusUp, Utilization: 42, HasUtil: true, LastSeen: now},
			// nyc <-> sfo, one link, oper-down
			{Source: "d1", Target: "d4", Protocol: "lldp", Status: StatusDown, LastSeen: now},
			// intra-site (both nyc) — must NOT produce a circuit
			{Source: "d1", Target: "d2", Protocol: "lldp", Status: StatusUp, LastSeen: now},
			// endpoint unplaced — dropped
			{Source: "d1", Target: "dx", Protocol: "lldp", Status: StatusUp, LastSeen: now},
		},
	}
}

func nodeByID(v View, id string) *Node {
	for i := range v.Nodes {
		if v.Nodes[i].ID == id {
			return &v.Nodes[i]
		}
	}
	return nil
}

func edgeByID(v View, id string) *Edge {
	for i := range v.Edges {
		if v.Edges[i].ID == id {
			return &v.Edges[i]
		}
	}
	return nil
}

func TestProjectGeo_Nodes(t *testing.T) {
	v := ProjectGeo(geoFixture())

	if v.Mode != ModeExecutiveGeo || v.LayoutType != "wan_geo" {
		t.Fatalf("mode/layout = %q/%q", v.Mode, v.LayoutType)
	}
	if v.Scope.TenantID != "acme" {
		t.Fatalf("tenant = %q", v.Scope.TenantID)
	}
	// ghost (no coords, no devices) is dropped; the other four remain.
	if len(v.Nodes) != 4 {
		t.Fatalf("want 4 nodes, got %d", len(v.Nodes))
	}

	nyc := nodeByID(v, "nyc")
	if nyc == nil || nyc.Kind != KindSite || nyc.Coordinates == nil {
		t.Fatalf("nyc node bad: %+v", nyc)
	}
	if nyc.Coordinates.X != -74.0 || nyc.Coordinates.Y != 40.71 {
		t.Fatalf("nyc coord = %+v (want x=lng,y=lat)", nyc.Coordinates)
	}
	if nyc.Health != HealthOK {
		t.Fatalf("nyc health = %q want ok", nyc.Health)
	}
	if nyc.Metrics["devices"] != 10 {
		t.Fatalf("nyc devices = %v", nyc.Metrics["devices"])
	}
	if len(nyc.Evidence) == 0 || nyc.Evidence[0].Source != "netbox" {
		t.Fatalf("nyc evidence bad: %+v", nyc.Evidence)
	}

	// honest health rollups
	if lon := nodeByID(v, "lon"); lon == nil || lon.Health != HealthWarning {
		t.Fatalf("lon health = %v want warning (some down)", lon)
	}
	if sfo := nodeByID(v, "sfo"); sfo == nil || sfo.Health != HealthCritical {
		t.Fatalf("sfo health want critical (all down)")
	}

	// placed but coordless → node present, no coordinates (surfaces as unplaced in UI)
	den := nodeByID(v, "den")
	if den == nil || den.Coordinates != nil {
		t.Fatalf("den should be present without coordinates: %+v", den)
	}
}

func TestProjectGeo_Circuits(t *testing.T) {
	v := ProjectGeo(geoFixture())

	// exactly two circuits: nyc-lon and nyc-sfo (intra-site + unplaced dropped)
	if len(v.Edges) != 2 {
		t.Fatalf("want 2 circuits, got %d: %+v", len(v.Edges), v.Edges)
	}

	// circuit id is sorted-pair keyed
	nl := edgeByID(v, "wan:lon|nyc")
	if nl == nil {
		t.Fatalf("missing nyc<->lon circuit; edges=%+v", v.Edges)
	}
	if nl.Status != StatusUp {
		t.Fatalf("nyc-lon status = %q want up", nl.Status)
	}
	if nl.Utilization != 42 {
		t.Fatalf("nyc-lon util = %v want 42 (busiest underlying link)", nl.Utilization)
	}
	if nl.Protocol != "bgp_ls+lldp" {
		t.Fatalf("nyc-lon protocol = %q want bgp_ls+lldp", nl.Protocol)
	}
	if len(nl.Evidence) != 2 {
		t.Fatalf("nyc-lon should have 2 evidence (one per source), got %d", len(nl.Evidence))
	}
	// corroborated (2 sources, 2 links) → confidence above the 0.7 base
	if nl.Confidence <= 0.7 {
		t.Fatalf("nyc-lon confidence = %v want >0.7 (corroborated)", nl.Confidence)
	}

	ns := edgeByID(v, "wan:nyc|sfo")
	if ns == nil || ns.Status != StatusDown {
		t.Fatalf("nyc-sfo circuit should be down: %+v", ns)
	}
	// single link, no util measured → utilization omitted (stays 0/empty)
	if ns.Utilization != 0 {
		t.Fatalf("nyc-sfo util = %v want 0 (unmeasured)", ns.Utilization)
	}

	// link_count backfilled: nyc participates in both circuits
	if nyc := nodeByID(v, "nyc"); nyc.Metrics["link_count"] != 2 {
		t.Fatalf("nyc link_count = %v want 2", nyc.Metrics["link_count"])
	}
}

func TestProjectGeo_Empty(t *testing.T) {
	v := ProjectGeo(GeoInput{TenantID: "t", Now: time.Now()})
	if v.Nodes == nil || v.Edges == nil || v.Groups == nil || v.Overlays == nil {
		t.Fatalf("empty view must have non-nil slices: %+v", v)
	}
	if len(v.Nodes) != 0 || len(v.Edges) != 0 {
		t.Fatalf("want empty graph, got %d nodes %d edges", len(v.Nodes), len(v.Edges))
	}
}

func TestProjectGeo_Deterministic(t *testing.T) {
	a := ProjectGeo(geoFixture())
	b := ProjectGeo(geoFixture())
	if len(a.Nodes) != len(b.Nodes) || len(a.Edges) != len(b.Edges) {
		t.Fatalf("non-deterministic shape")
	}
	for i := range a.Edges {
		if a.Edges[i].ID != b.Edges[i].ID || a.Edges[i].Protocol != b.Edges[i].Protocol {
			t.Fatalf("non-deterministic edges at %d: %q vs %q", i, a.Edges[i].ID, b.Edges[i].ID)
		}
	}
}
