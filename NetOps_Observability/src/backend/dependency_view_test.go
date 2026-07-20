package main

import (
	"testing"
	"time"

	"netops/backend/models"
)

func depRow(src, dst string, bytes, flows float64) map[string]any {
	return map[string]any{"src": src, "dst": dst, "bytes_total": bytes, "flows": flows, "dport": float64(5432)}
}

// serviceForPort renders a well-known port as a customer-facing service name.
func TestServiceForPort(t *testing.T) {
	cases := map[int]string{443: "HTTPS (443)", 5432: "PostgreSQL (5432)", 6379: "Redis (6379)", 9999: "port 9999", 0: "service"}
	for port, want := range cases {
		if got := serviceForPort(port); got != want {
			t.Fatalf("serviceForPort(%d) = %q, want %q", port, got, want)
		}
	}
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

// depRowPort is depRow with an explicit destination port (for noise-filter tests).
func depRowPort(src, dst string, dport int) map[string]any {
	return map[string]any{"src": src, "dst": dst, "bytes_total": 1e6, "flows": float64(10), "dport": float64(dport)}
}

// NON-NEGOTIABLE (dependency-map honesty): network plumbing must never appear as a
// service dependency. The SQL filter is primary; this pins the pure-projection guard
// so a weakened query — or rows from any non-ClickHouse source — can't pollute the map.
func TestBuildDependencyViewExcludesNoise(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	byAddr := map[string]models.Device{
		"10.0.0.1": {ID: "dev-a", Name: "app1", Address: "10.0.0.1"},
		"10.0.0.2": {ID: "dev-b", Name: "db1", Address: "10.0.0.2"},
	}
	rows := []map[string]any{
		depRowPort("10.0.0.1", "10.0.0.2", 5432),        // KEEP: real unicast service
		depRowPort("10.0.0.1", "224.0.0.5", 5432),       // DROP: OSPF multicast
		depRowPort("10.0.0.1", "239.255.255.250", 1900), // DROP: SSDP multicast
		depRowPort("10.0.0.1", "255.255.255.255", 67),   // DROP: DHCP broadcast
		depRowPort("10.0.0.1", "169.254.1.1", 5432),     // DROP: link-local
		depRowPort("10.0.0.1", "10.0.0.2", 0),           // DROP: counter/control sample (no port)
		depRowPort("10.0.0.2", "10.0.0.2", 5432),        // DROP: self-talk
	}
	v := buildDependencyView("t1", now, byAddr, rows)
	if len(v.Edges) != 1 {
		t.Fatalf("only the unicast service edge should survive, got %d edges: %+v", len(v.Edges), v.Edges)
	}
	if v.Edges[0].Source != "dev-a" || v.Edges[0].Target != "dev-b" {
		t.Fatalf("surviving edge should be app1→db1, got %s→%s", v.Edges[0].Source, v.Edges[0].Target)
	}
	// No multicast/broadcast/link-local endpoint ever became a node.
	for _, n := range v.Nodes {
		switch n.ID {
		case "host:224.0.0.5", "host:239.255.255.250", "host:255.255.255.255", "host:169.254.1.1":
			t.Fatalf("noise endpoint leaked into the dependency map as a node: %s", n.ID)
		}
	}
}

// isDependencyNoise classifies plumbing vs. real service traffic. Table-pinned so the
// invariant survives a refactor.
func TestIsDependencyNoise(t *testing.T) {
	cases := []struct {
		src, dst string
		dport    int
		noise    bool
	}{
		{"10.0.0.1", "10.0.0.2", 443, false},      // unicast HTTPS
		{"10.0.0.1", "8.8.8.8", 53, false},        // external unicast
		{"10.0.0.1", "db.example", 5432, false},   // hostname → resolver's call, not noise
		{"10.0.0.1", "224.0.0.5", 89, true},       // OSPF
		{"10.0.0.1", "239.1.2.3", 5432, true},     // multicast app
		{"10.0.0.1", "255.255.255.255", 67, true}, // broadcast
		{"10.0.0.1", "169.254.0.1", 443, true},    // link-local
		{"10.0.0.1", "0.0.0.0", 443, true},        // unspecified
		{"10.0.0.1", "10.0.0.2", 0, true},         // no real port
		{"10.0.0.1", "10.0.0.1", 443, true},       // self-talk
		{"", "10.0.0.2", 443, true},               // empty src
	}
	for _, c := range cases {
		if got := isDependencyNoise(c.src, c.dst, c.dport); got != c.noise {
			t.Errorf("isDependencyNoise(%q,%q,%d) = %v, want %v", c.src, c.dst, c.dport, got, c.noise)
		}
	}
}

// Empty flow input → a well-formed empty view (the frontend degrades to a sample).
func TestBuildDependencyViewEmpty(t *testing.T) {
	v := buildDependencyView("t1", time.Now(), nil, nil)
	if len(v.Nodes) != 0 || len(v.Edges) != 0 || v.Nodes == nil || v.Edges == nil {
		t.Fatalf("empty input must yield a non-nil empty view, got %d/%d", len(v.Nodes), len(v.Edges))
	}
}
