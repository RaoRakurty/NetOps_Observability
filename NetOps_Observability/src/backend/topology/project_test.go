package topology

import (
	"testing"
	"time"
)

func baseNow() time.Time { return time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC) }

func findNode(v View, id string) (Node, bool) {
	for _, n := range v.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

func findEdge(v View, id string) (Edge, bool) {
	for _, e := range v.Edges {
		if e.ID == id {
			return e, true
		}
	}
	return Edge{}, false
}

// A two-device fabric with one LLDP link is the happy path: 2 resolved nodes,
// 1 evidence-backed edge, deterministic ids, well-formed (non-nil) slices.
func TestProjectHappyPath(t *testing.T) {
	now := baseNow()
	in := Input{
		Mode: ModeExplore,
		Now:  now,
		Devices: []DeviceFact{
			{ID: "leaf1", Name: "leaf1", Type: "switch", Site: "dc1", LastSeen: now, CPUPct: 12, HasCPU: true},
			{ID: "spine1", Name: "spine1", Type: "router", Site: "dc1", LastSeen: now},
		},
		Links: []LinkFact{
			{Source: "leaf1", Target: "spine1", LocalPort: "Et1", RemotePort: "Et10",
				Protocol: "lldp", Resolved: true, Bidirectional: true, Status: "up", LastSeen: now},
		},
	}
	v := Project(in)

	if v.Mode != ModeExplore || v.LayoutType != "spine_leaf" {
		t.Fatalf("mode/layout wrong: %s %s", v.Mode, v.LayoutType)
	}
	if len(v.Nodes) != 2 || len(v.Edges) != 1 {
		t.Fatalf("want 2 nodes 1 edge, got %d/%d", len(v.Nodes), len(v.Edges))
	}
	if v.Nodes == nil || v.Edges == nil || v.Groups == nil || v.Overlays == nil {
		t.Fatal("slices must be non-nil for clean JSON arrays")
	}
	e, ok := findEdge(v, "lnk:leaf1--spine1")
	if !ok {
		t.Fatal("edge id should be order-independent lnk:leaf1--spine1")
	}
	if e.Relationship != RelConnectedTo || e.Protocol != "lldp" || e.Status != "up" {
		t.Fatalf("edge fields wrong: %+v", e)
	}
	if len(e.Evidence) != 1 || e.Evidence[0].Source != "lldp" {
		t.Fatalf("edge must carry lldp evidence, got %+v", e.Evidence)
	}
	// bidirectional + resolved → confidence 0.5+0.2+0.1 = 0.8
	if e.Confidence < 0.79 || e.Confidence > 0.81 {
		t.Fatalf("expected edge confidence ~0.8, got %v", e.Confidence)
	}
	leaf, _ := findNode(v, "leaf1")
	if leaf.Health != HealthOK || !leaf.Resolved || leaf.Confidence != 1.0 {
		t.Fatalf("leaf1 should be ok/resolved/conf1, got %+v", leaf)
	}
	if leaf.Metrics["link_count"] != 1 || leaf.Metrics["cpu_pct"] != 12 {
		t.Fatalf("leaf metrics wrong: %+v", leaf.Metrics)
	}
	if _, hasMem := leaf.Metrics["mem_pct"]; hasMem {
		t.Fatal("mem_pct must be absent when unmeasured (not 0)")
	}
}

// The core rule: a link with no protocol/evidence is never drawn.
func TestProjectDropsEvidencelessEdge(t *testing.T) {
	now := baseNow()
	in := Input{
		Now: now,
		Devices: []DeviceFact{
			{ID: "a", Name: "a", LastSeen: now}, {ID: "b", Name: "b", LastSeen: now},
		},
		Links: []LinkFact{{Source: "a", Target: "b", Protocol: "", LastSeen: now}},
	}
	v := Project(in)
	if len(v.Edges) != 0 {
		t.Fatalf("evidence-less link must be dropped, got %d edges", len(v.Edges))
	}
}

// An unresolved neighbour (target not in inventory) is materialized as a muted,
// resolved=false unresolved node — and still gets its edge (it has evidence).
func TestProjectUnresolvedNeighbour(t *testing.T) {
	now := baseNow()
	in := Input{
		Now:     now,
		Devices: []DeviceFact{{ID: "leaf1", Name: "leaf1", LastSeen: now}},
		Links: []LinkFact{
			{Source: "leaf1", Target: "ext:corerouter", TargetName: "corerouter",
				Protocol: "cdp", Resolved: false, LastSeen: now},
		},
	}
	v := Project(in)
	if len(v.Edges) != 1 {
		t.Fatalf("want 1 edge to the unresolved node, got %d", len(v.Edges))
	}
	u, ok := findNode(v, "ext:corerouter")
	if !ok {
		t.Fatal("unresolved node not materialized")
	}
	if u.Kind != KindUnresolved || u.Resolved || u.Health != HealthUnknown {
		t.Fatalf("unresolved node wrong: %+v", u)
	}
	if u.Label != "corerouter" {
		t.Fatalf("unresolved label should use TargetName, got %q", u.Label)
	}
}

// Health: a critical alert wins; a stale device with no alert reads unknown, not ok.
func TestProjectHealthDerivation(t *testing.T) {
	now := baseNow()
	in := Input{
		Now: now,
		Devices: []DeviceFact{
			{ID: "crit", Name: "crit", LastSeen: now},
			{ID: "warnonly", Name: "warnonly", LastSeen: now},
			{ID: "stale", Name: "stale", LastSeen: now.Add(-48 * time.Hour)},
			{ID: "fresh", Name: "fresh", LastSeen: now},
		},
		Alerts: []AlertFact{
			{DeviceID: "crit", Severity: "critical", FiredAt: now},
			{DeviceID: "crit", Severity: "warning", FiredAt: now},
			{DeviceID: "warnonly", Severity: "warning", FiredAt: now},
		},
	}
	v := Project(in)
	cases := map[string]struct{ health, change string }{
		"crit":     {HealthCritical, ChangeUnchanged},
		"warnonly": {HealthWarning, ChangeUnchanged},
		"stale":    {HealthUnknown, ChangeStale},
		"fresh":    {HealthOK, ChangeUnchanged},
	}
	for id, want := range cases {
		n, ok := findNode(v, id)
		if !ok {
			t.Fatalf("node %s missing", id)
		}
		if n.Health != want.health || n.ChangeState != want.change {
			t.Errorf("%s: got %s/%s want %s/%s", id, n.Health, n.ChangeState, want.health, want.change)
		}
	}
	crit, _ := findNode(v, "crit")
	if crit.Metrics["alert_count"] != 2 {
		t.Errorf("crit alert_count should be 2, got %v", crit.Metrics["alert_count"])
	}
}

// Multi-source corroboration raises edge confidence above a single source.
func TestProjectEdgeConfidenceCorroboration(t *testing.T) {
	now := baseNow()
	mk := func(proto string, bidir, resolved bool) float64 {
		v := Project(Input{Now: now,
			Devices: []DeviceFact{{ID: "a", LastSeen: now}, {ID: "b", LastSeen: now}},
			Links:   []LinkFact{{Source: "a", Target: "b", Protocol: proto, Bidirectional: bidir, Resolved: resolved, LastSeen: now}},
		})
		e, _ := findEdge(v, "lnk:a--b")
		return e.Confidence
	}
	single := mk("lldp", false, false) // 0.5
	both := mk("lldp+cdp", true, true) // 0.5+0.2+0.15+0.1 = 0.95
	if !(both > single) {
		t.Fatalf("corroborated edge (%v) must beat single-source (%v)", both, single)
	}
	if both < 0.94 || both > 0.96 {
		t.Fatalf("lldp+cdp/bidir/resolved should be ~0.95, got %v", both)
	}
}

// bgp_ls relationship is a routed adjacency, not a physical connection.
func TestProjectBGPLSRelationship(t *testing.T) {
	now := baseNow()
	v := Project(Input{Now: now,
		Devices: []DeviceFact{{ID: "r1", LastSeen: now}, {ID: "r2", LastSeen: now}},
		Links:   []LinkFact{{Source: "r1", Target: "r2", Protocol: "bgp_ls", IGP: "isis-l2", Area: "0", LastSeen: now}},
	})
	e, _ := findEdge(v, "lnk:r1--r2")
	if e.Relationship != RelRoutedAdjacency {
		t.Fatalf("bgp_ls should be routed_adjacency, got %s", e.Relationship)
	}
	if len(e.Evidence) == 0 || e.Evidence[0].Detail == "" {
		t.Fatalf("bgp_ls evidence should carry IGP detail, got %+v", e.Evidence)
	}
}

// Groups roll up by site with worst-child health; ungrouped nodes make no group.
func TestProjectGroupsBySite(t *testing.T) {
	now := baseNow()
	v := Project(Input{Now: now,
		Devices: []DeviceFact{
			{ID: "a", Site: "dc1", LastSeen: now},
			{ID: "b", Site: "dc1", LastSeen: now},
			{ID: "c", LastSeen: now}, // no site → ungrouped
		},
		Alerts: []AlertFact{{DeviceID: "b", Severity: "critical", FiredAt: now}},
	})
	if len(v.Groups) != 1 {
		t.Fatalf("want 1 site group, got %d", len(v.Groups))
	}
	g := v.Groups[0]
	if g.ID != "site:dc1" || len(g.Children) != 2 || g.Health != HealthCritical {
		t.Fatalf("group rollup wrong: %+v", g)
	}
}

// path_trace uses a measured path verbatim (sanitized to present, deduped nodes).
func TestProjectPathTraceMeasured(t *testing.T) {
	now := baseNow()
	v := Project(Input{Mode: ModePathTrace, Now: now,
		Devices: []DeviceFact{{ID: "a", LastSeen: now}, {ID: "b", LastSeen: now}, {ID: "c", LastSeen: now}},
		Links: []LinkFact{
			{Source: "a", Target: "b", Protocol: "lldp", LastSeen: now},
			{Source: "b", Target: "c", Protocol: "lldp", LastSeen: now},
		},
		Paths: []PathFact{{ID: "p1", Hops: []string{"a", "a", "b", "", "ghost", "c"}}},
	})
	if v.LayoutType != "path_first" {
		t.Fatalf("path_trace layout should be path_first, got %s", v.LayoutType)
	}
	want := []string{"a", "b", "c"}
	if len(v.Path) != 3 || v.Path[0] != "a" || v.Path[1] != "b" || v.Path[2] != "c" {
		t.Fatalf("measured path should sanitize to %v, got %v", want, v.Path)
	}
}

// path_trace with no measured path falls back to IGP-weighted SPF over endpoints.
func TestProjectPathTraceComputed(t *testing.T) {
	now := baseNow()
	v := Project(Input{Mode: ModePathTrace, Now: now, SrcID: "a", DstID: "c",
		Devices: []DeviceFact{{ID: "a", LastSeen: now}, {ID: "b", LastSeen: now}, {ID: "c", LastSeen: now}},
		Links: []LinkFact{
			{Source: "a", Target: "b", Protocol: "lldp", Metric: 1, LastSeen: now},
			{Source: "b", Target: "c", Protocol: "lldp", Metric: 1, LastSeen: now},
			{Source: "a", Target: "c", Protocol: "lldp", Metric: 10, LastSeen: now},
		},
	})
	if len(v.Path) != 3 || v.Path[1] != "b" {
		t.Fatalf("SPF should pick cheap a-b-c path, got %v", v.Path)
	}
}

// nodeKind honors role → type → vendor → name, so a Fortinet firewall whose
// SNMP type is "generic" still renders as a firewall, not a switch.
func TestProjectNodeKindInference(t *testing.T) {
	now := baseNow()
	v := Project(Input{Now: now, Devices: []DeviceFact{
		{ID: "dmz-fw", Name: "dmz-fw", Type: "generic", Role: "firewall", Vendor: "fortinet", LastSeen: now},
		{ID: "pa1", Name: "pa1", Type: "generic", Vendor: "palo alto", LastSeen: now},
		{ID: "edge-fw", Name: "edge-fw", Type: "generic", LastSeen: now}, // name token only
		{ID: "leaf1", Name: "leaf1", Type: "switch", Vendor: "arista", LastSeen: now},
		{ID: "core-rtr", Name: "core-rtr", Type: "router", LastSeen: now},
		{ID: "software-sw", Name: "software", Type: "generic", LastSeen: now}, // must NOT match "fw"
	}})
	want := map[string]string{
		"dmz-fw": KindFirewall, "pa1": KindFirewall, "edge-fw": KindFirewall,
		"leaf1": KindSwitch, "core-rtr": KindRouter, "software-sw": KindSwitch,
	}
	for id, k := range want {
		n, ok := findNode(v, id)
		if !ok {
			t.Fatalf("node %s missing", id)
		}
		if n.Kind != k {
			t.Errorf("%s: kind=%s want %s", id, n.Kind, k)
		}
	}
}

// A completely empty input still yields a well-formed view (no nil slices/panics).
func TestProjectEmptyInput(t *testing.T) {
	v := Project(Input{Now: baseNow()})
	if v.Nodes == nil || v.Edges == nil || v.Groups == nil || v.Overlays == nil {
		t.Fatal("empty input must still produce non-nil slices")
	}
	if len(v.Nodes) != 0 || len(v.Edges) != 0 {
		t.Fatalf("empty input should have no nodes/edges, got %d/%d", len(v.Nodes), len(v.Edges))
	}
	if len(v.Overlays) == 0 || v.Overlays[0] != "health" {
		t.Fatalf("health overlay should always be present, got %v", v.Overlays)
	}
}
