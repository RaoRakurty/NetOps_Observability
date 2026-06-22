package main

import (
	"testing"
	"time"

	"netops/backend/models"
)

func depRow(src, dst string, bytes, flows float64) map[string]any {
	return map[string]any{"src": src, "dst": dst, "bytes_total": bytes, "flows": flows}
}

// The flow-derived dependency graph: resolved endpoints become device nodes,
// unknown endpoints become muted host nodes, and each conversation is a directional
// "dependency" edge carrying flow evidence. Pure (no I/O).
func TestBuildDependencyView(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	byAddr := map[string]models.Device{
		"10.0.0.1": {ID: "dev-a", Name: "app1", Address: "10.0.0.1", Vendor: "linux"},
		"10.0.0.2": {ID: "dev-b", Name: "db1", Address: "10.0.0.2"},
	}
	rows := []map[string]any{
		depRow("10.0.0.1", "10.0.0.2", 5e6, 120), // app1 → db1 (both managed)
		depRow("10.0.0.1", "8.8.8.8", 2e3, 4),    // app1 → external host (unresolved)
		depRow("10.0.0.1", "10.0.0.1", 9e9, 1),   // self-loop → dropped
	}
	v := buildDependencyView("t1", now, byAddr, rows)

	if v.Mode != "dependency" || v.LayoutType != "dependency" {
		t.Fatalf("mode/layout wrong: %s %s", v.Mode, v.LayoutType)
	}
	if v.Nodes == nil || v.Edges == nil || v.Groups == nil {
		t.Fatal("slices must be non-nil")
	}
	// 3 nodes: dev-a, dev-b, host:8.8.8.8 (self-loop adds none).
	if len(v.Nodes) != 3 {
		t.Fatalf("want 3 nodes, got %d", len(v.Nodes))
	}
	// 2 edges (self-loop dropped), both relationship=dependency from flow evidence.
	if len(v.Edges) != 2 {
		t.Fatalf("want 2 edges, got %d", len(v.Edges))
	}
	for _, e := range v.Edges {
		if e.Relationship != "dependency" {
			t.Fatalf("edge relationship should be dependency, got %q", e.Relationship)
		}
		if len(e.Evidence) != 1 || e.Evidence[0].Source != "flow" {
			t.Fatalf("edge must carry flow evidence, got %+v", e.Evidence)
		}
	}
	// Endpoint resolution: managed device resolved + confident; external host muted.
	var host, dev bool
	for _, n := range v.Nodes {
		if n.ID == "host:8.8.8.8" {
			host = true
			if n.Resolved || n.Confidence >= 1.0 {
				t.Fatalf("external host must be unresolved/low-confidence, got %+v", n)
			}
		}
		if n.ID == "dev-a" {
			dev = true
			if !n.Resolved || n.Label != "app1" {
				t.Fatalf("managed endpoint should resolve to its device, got %+v", n)
			}
		}
	}
	if !host || !dev {
		t.Fatal("expected both a resolved device node and a muted host node")
	}
}

// Empty flow input → a well-formed empty view (the frontend degrades to a sample).
func TestBuildDependencyViewEmpty(t *testing.T) {
	v := buildDependencyView("t1", time.Now(), nil, nil)
	if len(v.Nodes) != 0 || len(v.Edges) != 0 || v.Nodes == nil || v.Edges == nil {
		t.Fatalf("empty input must yield a non-nil empty view, got %d/%d", len(v.Nodes), len(v.Edges))
	}
}
