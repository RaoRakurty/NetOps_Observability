package main

import (
	"strings"
	"testing"
)

// fixtures mimic what loadCorrSlice + mergeTimelineEvidence produce: signal maps
// with an authoritative `attached` flag and the raw fields buildRcaPathView reads.

func pvSig(m map[string]any) map[string]any {
	if _, ok := m["attached"]; !ok {
		m["attached"] = true
	}
	if _, ok := m["modality_class"]; !ok {
		m["modality_class"] = "control_plane"
	}
	if _, ok := m["observer_id"]; !ok {
		m["observer_id"] = "obs1"
	}
	return m
}

// golden-like suspected local link fault: link + BGP + probe loss, all grounded
// on e2e-edge1 → Suspected.
func goldenInputs() (map[string]any, []map[string]any, []map[string]any) {
	meta := map[string]any{"verdict_tier": "suspected", "top_confidence": 0.5, "trigger_signal": "t3", "evidence_missing": "[]"}
	sigs := []map[string]any{
		pvSig(map[string]any{"signal_id": "t1", "entity_type": "interface", "entity_id": "e2e-edge1:GigabitEthernet0/1", "kind": "link_state_change"}),
		pvSig(map[string]any{"signal_id": "t2", "entity_type": "device", "entity_id": "e2e-edge1", "kind": "bgp_adjacency_change", "attrs": `{"peer":"10.99.0.2","state":"down"}`}),
		pvSig(map[string]any{"signal_id": "t3", "entity_type": "path", "entity_id": "vantage-e2e->e2e-edge1", "kind": "probe_loss", "modality_class": "active_probe", "observer_id": "obs2", "is_trigger": true, "probe_authority": "high", "probe_scope": "customer_path"}),
	}
	edges := []map[string]any{
		{"from_node": "device:e2e-edge1:bgp_adjacency_change", "to_node": "path:vantage-e2e->e2e-edge1:probe_loss", "grounding_kind": "topo", "grounding_ref": "shared:e2e-edge1", "weight": 1.0, "direction_basis": "none"},
		{"from_node": "interface:e2e-edge1:GigabitEthernet0/1:link_state_change", "to_node": "path:vantage-e2e->e2e-edge1:probe_loss", "grounding_kind": "topo", "grounding_ref": "shared:e2e-edge1", "weight": 1.0, "direction_basis": "none"},
	}
	return meta, sigs, edges
}

func findAnn(v rcaPathView, tt, tid string) *rcaAnnotation {
	for i := range v.Annotations {
		if v.Annotations[i].TargetType == tt && v.Annotations[i].TargetID == tid {
			return &v.Annotations[i]
		}
	}
	return nil
}

// #7 link_state_change → exact interface edge annotation.
func TestRcaPathView_LinkToEdge(t *testing.T) {
	meta, sigs, edges := goldenInputs()
	v := buildRcaPathView("obj", meta, sigs, edges)
	a := findAnn(v, "edge", "e2e-edge1:GigabitEthernet0/1")
	if a == nil {
		t.Fatalf("no edge annotation for the interface; got %+v", v.Annotations)
	}
	if a.Status != "suspected_down" {
		t.Fatalf("link edge status = %q, want suspected_down", a.Status)
	}
}

// #8 BGP adjacency → BGP session edge (device->peer).
func TestRcaPathView_BgpToSession(t *testing.T) {
	meta, sigs, edges := goldenInputs()
	v := buildRcaPathView("obj", meta, sigs, edges)
	a := findAnn(v, "edge", "e2e-edge1->10.99.0.2")
	if a == nil {
		t.Fatalf("no BGP session annotation; got %+v", v.Annotations)
	}
	if a.Status != "suspected_down" {
		t.Fatalf("bgp edge status = %q, want suspected_down", a.Status)
	}
}

// #9 probe loss → path_segment when the locus is known.
func TestRcaPathView_ProbeToSegment(t *testing.T) {
	meta, sigs, edges := goldenInputs()
	v := buildRcaPathView("obj", meta, sigs, edges)
	a := findAnn(v, "path_segment", "e2e-edge1")
	if a == nil {
		t.Fatalf("no path_segment annotation; got %+v", v.Annotations)
	}
	if a.Status != "degraded" {
		t.Fatalf("probe segment status = %q, want degraded", a.Status)
	}
	if v.Title != "Where evidence points — not confirmed" {
		t.Fatalf("title = %q", v.Title)
	}
}

// #10 probe loss → whole path with uncertainty when no locus/hops are known.
func TestRcaPathView_ProbeToWholePath(t *testing.T) {
	meta := map[string]any{"verdict_tier": "undetermined", "top_confidence": 0.2, "trigger_signal": "p1", "evidence_missing": "[]"}
	sigs := []map[string]any{
		pvSig(map[string]any{"signal_id": "p1", "entity_type": "path", "entity_id": "vantage-x->cloud-y", "kind": "probe_loss", "modality_class": "active_probe", "observer_id": "o1", "probe_authority": "high", "probe_scope": "customer_path", "is_trigger": true}),
	}
	v := buildRcaPathView("obj", meta, sigs, nil) // no edges → no locus
	a := findAnn(v, "path", "vantage-x->cloud-y")
	if a == nil {
		t.Fatalf("expected whole-path annotation; got %+v", v.Annotations)
	}
	if a.Status != "degraded" || a.Reason == "" {
		t.Fatalf("whole-path annotation = %+v", a)
	}
}

// #11 internal/debug probes must NOT create customer RCA overlays.
func TestRcaPathView_InternalExcluded(t *testing.T) {
	meta := map[string]any{"verdict_tier": "suspected", "top_confidence": 0.5, "trigger_signal": "d1", "evidence_missing": "[]"}
	sigs := []map[string]any{
		pvSig(map[string]any{"signal_id": "d1", "entity_type": "path", "entity_id": "prober->clickhouse", "kind": "probe_loss", "modality_class": "active_probe", "observer_id": "o1", "probe_authority": "debug_only", "probe_scope": "internal_self_probe", "is_trigger": true}),
	}
	v := buildRcaPathView("obj", meta, sigs, nil)
	if !v.Internal {
		t.Fatal("debug-only probe object should be flagged internal")
	}
	if v.Title != "Internal monitoring path" {
		t.Fatalf("internal title = %q", v.Title)
	}
	for _, a := range v.Annotations {
		if a.Status != "internal_only" {
			t.Fatalf("internal object annotation must be internal_only, got %q", a.Status)
		}
	}
}

// #12 the overlay never mutates the base inputs (edges/signals unchanged).
func TestRcaPathView_NoBaseMutation(t *testing.T) {
	meta, sigs, edges := goldenInputs()
	edgeCount := len(edges)
	firstEdgeRef := edges[0]["grounding_ref"]
	sigKind := sigs[0]["kind"]
	_ = buildRcaPathView("obj", meta, sigs, edges)
	if len(edges) != edgeCount || edges[0]["grounding_ref"] != firstEdgeRef {
		t.Fatal("buildRcaPathView mutated the base topology edges")
	}
	if sigs[0]["kind"] != sigKind {
		t.Fatal("buildRcaPathView mutated the base signals")
	}
}

// confirmed verdict → confirmed_down + "Likely fault location".
func TestRcaPathView_ConfirmedTitleAndState(t *testing.T) {
	meta, sigs, edges := goldenInputs()
	meta["verdict_tier"] = "confirmed"
	v := buildRcaPathView("obj", meta, sigs, edges)
	if v.Title != "Likely fault location" {
		t.Fatalf("confirmed title = %q", v.Title)
	}
	if a := findAnn(v, "edge", "e2e-edge1:GigabitEthernet0/1"); a == nil || a.Status != "confirmed_down" {
		t.Fatalf("confirmed link edge = %+v", a)
	}
}

// suspected → missing "independent observer".
func TestRcaPathView_MissingIndependentObserver(t *testing.T) {
	meta, sigs, edges := goldenInputs()
	v := buildRcaPathView("obj", meta, sigs, edges)
	found := false
	for _, m := range v.MissingEvidenceSummary {
		if strings.Contains(m, "independent observer") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an independent-observer missing-evidence note; got %v", v.MissingEvidenceSummary)
	}
}
