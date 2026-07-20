package topology

import (
	"testing"
	"time"
)

func recByID(g GraphRecords, id string) (NodeRecord, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return NodeRecord{}, false
}

// TestReconcileLifecycle covers the first_seen/last_seen/stale/prune merge rules.
func TestReconcileLifecycle(t *testing.T) {
	t0 := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	now := t0.Add(90 * time.Minute)
	prev := GraphRecords{Nodes: []NodeRecord{
		{TenantID: "a", ID: "keep", Label: "old", FirstSeen: t0, LastSeen: t0},               // observed again
		{TenantID: "a", ID: "stale", FirstSeen: t0, LastSeen: t0.Add(40 * time.Minute)},      // unobserved 50m: past grace, within prune
		{TenantID: "a", ID: "fresh-miss", FirstSeen: t0, LastSeen: t0.Add(80 * time.Minute)}, // unobserved 10m: within grace
		{TenantID: "a", ID: "gone", FirstSeen: t0, LastSeen: t0},                             // unobserved 90m: past prune
	}}
	observed := GraphRecords{Nodes: []NodeRecord{
		{TenantID: "a", ID: "keep", Label: "new"},
		{TenantID: "a", ID: "added"},
	}}
	out := Reconcile(prev, observed, now, 15*time.Minute, 60*time.Minute)

	keep, ok := recByID(out, "keep")
	if !ok || keep.Stale || !keep.FirstSeen.Equal(t0) || !keep.LastSeen.Equal(now) || keep.Label != "new" {
		t.Errorf("keep: want fresh, first_seen preserved, label refreshed; got %+v", keep)
	}
	added, ok := recByID(out, "added")
	if !ok || !added.FirstSeen.Equal(now) {
		t.Errorf("added: want new with first_seen=now; got %+v ok=%v", added, ok)
	}
	stale, ok := recByID(out, "stale")
	if !ok || !stale.Stale {
		t.Errorf("stale: want kept+stale (past grace); got %+v ok=%v", stale, ok)
	}
	miss, ok := recByID(out, "fresh-miss")
	if !ok || miss.Stale {
		t.Errorf("fresh-miss: want kept, NOT stale (within grace); got %+v ok=%v", miss, ok)
	}
	if _, ok := recByID(out, "gone"); ok {
		t.Error("gone: want pruned (past prune window)")
	}
}

// TestReconcileDropsDegenerate: zero-id / endpoint-less records are never persisted.
func TestReconcileDropsDegenerate(t *testing.T) {
	now := time.Now()
	out := Reconcile(GraphRecords{}, GraphRecords{
		Nodes: []NodeRecord{{ID: ""}, {ID: "ok"}},
		Edges: []EdgeRecord{{ID: "", Source: "a", Target: "b"}, {ID: "e", Source: "a", Target: ""}, {ID: "good", Source: "a", Target: "b"}},
	}, now, 0, 0)
	if len(out.Nodes) != 1 || out.Nodes[0].ID != "ok" {
		t.Errorf("degenerate node not dropped: %+v", out.Nodes)
	}
	if len(out.Edges) != 1 || out.Edges[0].ID != "good" {
		t.Errorf("degenerate edge not dropped: %+v", out.Edges)
	}
}

// TestFilterTenant: a scoped principal sees only its tenant; cross sees all.
func TestFilterTenant(t *testing.T) {
	g := GraphRecords{
		Nodes: []NodeRecord{{TenantID: "a", ID: "n1"}, {TenantID: "b", ID: "n2"}},
		Edges: []EdgeRecord{{TenantID: "a", ID: "e1"}, {TenantID: "b", ID: "e2"}},
	}
	a := g.FilterTenant("a", false)
	if len(a.Nodes) != 1 || a.Nodes[0].ID != "n1" || len(a.Edges) != 1 || a.Edges[0].ID != "e1" {
		t.Errorf("tenant a scope leaked: %+v", a)
	}
	all := g.FilterTenant("", true)
	if len(all.Nodes) != 2 || len(all.Edges) != 2 {
		t.Errorf("cross scope should see all: %+v", all)
	}
}

// TestToViewAndCoverage: records project to the render contract with change_state,
// relationship by protocol, and a correct coverage summary.
func TestToViewAndCoverage(t *testing.T) {
	now := time.Now()
	g := GraphRecords{
		Nodes: []NodeRecord{
			{TenantID: "a", ID: "n1", Label: "leaf1", Kind: KindRouter, LastSeen: now},
			{TenantID: "a", ID: "n2", Label: "old", Stale: true, LastSeen: now},
		},
		Edges: []EdgeRecord{
			{TenantID: "a", ID: "e1", Source: "n1", Target: "n2", Protocol: "lldp+cdp", Resolved: true},
			{TenantID: "a", ID: "e2", Source: "n1", Target: "ext:x", Protocol: "bgp_ls", Stale: true},
		},
	}
	v := g.ToView("a", now)
	if len(v.Nodes) != 2 || len(v.Edges) != 2 {
		t.Fatalf("view shape: %d nodes %d edges", len(v.Nodes), len(v.Edges))
	}
	if v.Nodes[1].ChangeState != ChangeStale {
		t.Errorf("stale node should carry change_state=stale, got %q", v.Nodes[1].ChangeState)
	}
	// lldp+cdp → connected_to (physical), full confidence (two protocols).
	if v.Edges[0].Relationship != RelConnectedTo || v.Edges[0].Confidence != 1 {
		t.Errorf("e1 want connected_to/conf=1, got %q/%v", v.Edges[0].Relationship, v.Edges[0].Confidence)
	}
	// bgp_ls → routed_adjacency, stale.
	if v.Edges[1].Relationship != RelRoutedAdjacency || v.Edges[1].ChangeState != ChangeStale {
		t.Errorf("e2 want routed_adjacency/stale, got %q/%q", v.Edges[1].Relationship, v.Edges[1].ChangeState)
	}
	c := g.Summarize()
	if c.Nodes != 2 || c.Edges != 2 || c.StaleNodes != 1 || c.StaleEdges != 1 || c.ResolvedEdges != 1 {
		t.Errorf("coverage: %+v", c)
	}
}

// TestEnrichLive: live overlay sets node health from alerts (critical wins),
// OK for a fresh no-alert node, UNKNOWN for a stale no-alert node, + cpu/mem metrics.
func TestEnrichLive(t *testing.T) {
	now := time.Now()
	g := GraphRecords{Nodes: []NodeRecord{
		{ID: "crit", LastSeen: now},                // has a critical alert
		{ID: "warn", LastSeen: now},                // has a warning alert
		{ID: "ok", LastSeen: now},                  // fresh, no alert
		{ID: "staleq", Stale: true, LastSeen: now}, // stale, no alert
	}}
	v := g.ToView("a", now)
	v.EnrichLive(map[string][]AlertFact{
		"crit": {{Severity: "critical"}},
		"warn": {{Severity: "warning"}},
	}, map[string]float64{"crit": 91.5}, map[string]float64{"crit": 40})

	want := map[string]string{"crit": HealthCritical, "warn": HealthWarning, "ok": HealthOK, "staleq": HealthUnknown}
	for _, n := range v.Nodes {
		if n.Health != want[n.ID] {
			t.Errorf("node %s health=%q, want %q", n.ID, n.Health, want[n.ID])
		}
	}
	for _, n := range v.Nodes {
		if n.ID == "crit" {
			if n.Metrics["cpu_pct"] != 91.5 || n.Metrics["mem_pct"] != 40 || n.Metrics["alert_count"] != 1 {
				t.Errorf("crit metrics: %+v", n.Metrics)
			}
		}
	}
}
