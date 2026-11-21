// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

import (
	"strings"
	"testing"
)

// A discovered site groups by its tenant-qualified KEY but reads by its label,
// and the group carries the provenance the SPA marks it with. A plain label site
// keeps its historical shape (no site_label, label = key).
func TestSiteGroupsCarryLabelAndProvenance(t *testing.T) {
	in := Input{Mode: ModeExplore, TenantID: "acme", Devices: []DeviceFact{
		{ID: "ve51", Name: "vEdge-51", Type: "router", Site: "discovered:acme:sdwan:50", SiteLabel: "Site 50 · from vManage", SiteSource: "discovered", SiteOrigin: "vmanage"},
		{ID: "ve52", Name: "vEdge-52", Type: "router", Site: "discovered:acme:sdwan:50", SiteLabel: "Site 50 · from vManage", SiteSource: "discovered", SiteOrigin: "vmanage"},
		{ID: "vs", Name: "vSmart", Type: "router", Site: "discovered:acme:sdwan:250", SiteLabel: "Site 250 · from vManage", SiteSource: "discovered", SiteOrigin: "vmanage"},
		{ID: "core", Name: "core1", Type: "router", Site: "dc-east", SiteLabel: "dc-east", SiteSource: "label"},
		{ID: "nyc1", Name: "nyc1", Type: "router", Site: "nyc", SiteLabel: "New York", SiteSource: "manual", SiteNote: "device reports site 50 (from vManage); the site set by an operator is shown"},
		{ID: "loose", Name: "loose", Type: "router"},
	}}
	v := Project(in)
	groups := map[string]Group{}
	for _, g := range v.Groups {
		groups[g.ID] = g
	}
	g50 := groups["site:discovered:acme:sdwan:50"]
	if g50.Label != "Site 50 · from vManage" || g50.Source != "discovered" || g50.Origin != "vmanage" || len(g50.Children) != 2 {
		t.Fatalf("site 50 group = %+v", g50)
	}
	if g := groups["site:discovered:acme:sdwan:250"]; g.Label != "Site 250 · from vManage" || len(g.Children) != 1 {
		t.Fatalf("site 250 group = %+v", g)
	}
	if g := groups["site:dc-east"]; g.Label != "dc-east" || g.Source != "label" {
		t.Fatalf("label group = %+v", g)
	}
	if g := groups["site:nyc"]; g.Label != "New York" || g.Source != "manual" {
		t.Fatalf("manual group = %+v", g)
	}
	if len(v.Groups) != 4 {
		t.Fatalf("groups = %d (an unsited device must stay ungrouped)", len(v.Groups))
	}
	for _, n := range v.Nodes {
		switch n.ID {
		case "ve51":
			if n.SiteLabel != "Site 50 · from vManage" || n.SiteSource != "discovered" || n.GroupID != "site:discovered:acme:sdwan:50" {
				t.Fatalf("node = %+v", n)
			}
		case "core":
			if n.SiteLabel != "" {
				t.Fatalf("a label site must keep its historical shape: %+v", n)
			}
		case "nyc1":
			if !strings.Contains(n.SiteNote, "reports site 50") {
				t.Fatalf("disagreement note lost: %+v", n)
			}
		case "loose":
			if n.Site != "" || n.SiteSource != "" || n.GroupID != "" {
				t.Fatalf("unsited node = %+v", n)
			}
		}
	}
}

// The Iris summary names sites by what a person reads, says when sites are
// discovered, and keeps two tenants' identically-labelled sites apart.
func TestSummarizeReadsDiscoveredSitesByLabel(t *testing.T) {
	v := View{Nodes: []Node{
		{ID: "a1", Label: "edge-a1", Kind: KindRouter, Site: "discovered:acme:sdwan:50", SiteLabel: "Site 50 · from vManage", SiteSource: "discovered"},
		{ID: "a2", Label: "edge-a2", Kind: KindRouter, Site: "discovered:acme:sdwan:50", SiteLabel: "Site 50 · from vManage", SiteSource: "discovered"},
		{ID: "g1", Label: "edge-g1", Kind: KindRouter, Site: "discovered:globex:sdwan:50", SiteLabel: "Site 50 · from vManage", SiteSource: "discovered"},
		{ID: "c1", Label: "core1", Kind: KindRouter, Site: "dc-east"},
	}}
	sm := Summarize(SummaryInput{View: v})
	counts := map[string]int{}
	for _, c := range sm.Sites {
		counts[c.Name] = c.Count
	}
	if counts["Site 50 · from vManage"] != 2 || counts["dc-east"] != 1 || len(counts) != 3 {
		t.Fatalf("site counts = %v", counts)
	}
	for name := range counts {
		if strings.HasPrefix(name, "discovered:") {
			t.Fatalf("a raw key reached the summary: %q", name)
		}
	}
	noted := false
	for _, n := range sm.Notes {
		if strings.Contains(n, "3 device(s)") && strings.Contains(n, "discovered") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("notes = %v", sm.Notes)
	}
	// The view the summary read is not rewritten.
	if v.Nodes[0].Site != "discovered:acme:sdwan:50" {
		t.Fatalf("summary mutated the view: %q", v.Nodes[0].Site)
	}
}
