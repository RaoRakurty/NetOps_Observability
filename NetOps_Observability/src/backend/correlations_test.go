package main

import (
	"fmt"
	"strings"
	"testing"
)

// isUUIDToken gates every value interpolated into correlations SQL / proxied
// replay URLs — shape validation, never quote-escaping (SR-011 discipline).
func TestIsUUIDToken(t *testing.T) {
	valid := []string{
		"9f0537bd-0787-547e-a6fc-6692acaec13c",
		"B8C6C907-D0FD-570C-BE97-D18E257FC61F",
	}
	for _, v := range valid {
		if !isUUIDToken(v) {
			t.Errorf("%s should be valid", v)
		}
	}
	invalid := []string{
		"",
		"9f0537bd",
		"9f0537bd-0787-547e-a6fc-6692acaec13cX", // too long
		"9f0537bd-0787-547e-a6fc-6692acaec13'",  // quote
		"9f0537bd_0787_547e_a6fc_6692acaec13c",  // wrong separators
		"zf0537bd-0787-547e-a6fc-6692acaec13c",  // non-hex
		"9f0537bd-0787-547e-a6fc-6692acaec13c; DROP ALL", // injection shape
	}
	for _, v := range invalid {
		if isUUIDToken(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}

// isDatetimeToken gates the object-window bounds before they are interpolated
// into the timeline ts filter (same SR-011 shape-validation discipline).
func TestIsDatetimeToken(t *testing.T) {
	valid := []string{
		"2026-06-14 05:11:39.836", "2026-06-14 05:11:39", "2026-01-01 00:00:00.000",
		"2026-06-14T05:11:39Z", "2026-06-14T05:11:39.836Z", // RFC 3339 wire form (chISO, S3)
	}
	for _, v := range valid {
		if !isDatetimeToken(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	invalid := []string{
		"",
		"short",                      // < 10 chars
		"2026-06-14 05:11:39'; DROP", // quote + injection
		"now() - INTERVAL 1 DAY",     // function call (parens/letters)
		"2026-06-14 05:11:39.836xxxxxxxxxxxxxxxxxxxxxxxx", // too long (> 32)
	}
	for _, v := range invalid {
		if isDatetimeToken(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}

// sig builds a window signal row with the fields the linkage derivation reads.
// node key = entity_type:entity_id:kind (mirrors engine.py build_nodes).
func sig(id, modality, etype, eid, kind string) map[string]any {
	return map[string]any{
		"signal_id": id, "modality_class": modality,
		"entity_type": etype, "entity_id": eid, "kind": kind,
		"observer_id": "obs-" + id,
	}
}
func edge(from, to, gkind, gref string) map[string]any {
	return map[string]any{
		"from_node": from, "to_node": to,
		"grounding_kind": gkind, "grounding_ref": gref,
		"weight": 0.8, "direction_basis": "none",
	}
}
func ev(signalID, role, subjectID string) map[string]any {
	return map[string]any{"signal_id": signalID, "role": role, "subject_kind": "edge", "subject_id": subjectID, "note": ""}
}

// Linkage is DERIVED from graph membership: a signal is attached iff its episode
// (entity_type:entity_id:kind) is a node on an edge; *_clear is recovery; the
// rest are concurrent-unlinked with a faithful reason. This is the data behind
// "what the engine linked vs ignored, and why".
func TestMergeTimelineEvidence_LinkageStatusAndCounts(t *testing.T) {
	sigs := []map[string]any{
		sig("s1", "active_probe", "path", "a->b", "probe_rtt_anomaly"),           // trigger, attached
		sig("s2", "control_plane", "device", "r1", "bgp_state_anomaly"),          // attached (edge peer)
		sig("s3", "active_probe", "path", "a->c", "probe_rtt_anomaly_clear"),     // recovery (clear)
		sig("s4", "device_telemetry", "device", "r2", "device_resource_anomaly"), // unlinked (no grounding)
	}
	edges := []map[string]any{
		edge("path:a->b:probe_rtt_anomaly", "device:r1:bgp_state_anomaly", "seam", "sm-1"),
	}
	counts := mergeTimelineEvidence(sigs, nil, edges, "s1")

	if counts["total"] != 4 || counts["attached"] != 2 || counts["unattached"] != 2 {
		t.Fatalf("bad attach counts: %+v", counts)
	}
	if counts["recovery"] != 1 || counts["unlinked"] != 1 {
		t.Fatalf("bad recovery/unlinked split: %+v", counts)
	}
	if g := counts["by_grounding"].(map[string]int); g["seam"] != 1 {
		t.Errorf("by_grounding should count the seam edge: %+v", g)
	}
	abm := counts["attached_by_modality"].(map[string]int)
	if abm["active_probe"] != 1 || abm["control_plane"] != 1 {
		t.Errorf("attached_by_modality wrong: %+v", abm)
	}
	// per-signal linkage
	if sigs[0]["link_status"] != "attached" || sigs[0]["is_trigger"] != true {
		t.Errorf("s1 should be attached trigger: %+v", sigs[0])
	}
	if le := sigs[0]["linked_edges"].([]map[string]any); len(le) != 1 || le[0]["grounding_ref"] != "sm-1" {
		t.Errorf("s1 should carry the grounded edge it sits on: %+v", sigs[0]["linked_edges"])
	}
	if sigs[0]["link_role"] != "supporting" {
		t.Errorf("attached s1 should default to supporting role: %+v", sigs[0])
	}
	if sigs[2]["link_status"] != "recovery" || sigs[2]["attached"] != false {
		t.Errorf("s3 (_clear) must be recovery/unattached: %+v", sigs[2])
	}
	if sigs[3]["link_status"] != "unlinked" {
		t.Errorf("s4 must be unlinked: %+v", sigs[3])
	}
	// s4 (device:r2) shares no token with the probe-path/device:r1 graph → "no shared token".
	if r := fmt.Sprintf("%v", sigs[3]["link_reason"]); !strings.Contains(r, "no shared seam endpoint or topology token") {
		t.Errorf("unlinked reason must explain the topology-gap: %q", r)
	}
	if obs := counts["attached_observers"]; obs != 2 {
		t.Errorf("attached_observers should be 2 (obs-s1, obs-s2): %v", obs)
	}
}

// A concurrent signal that SHARES a grounding token with the graph but still
// wasn't linked must be told it fell below the attach threshold — not that it
// shares nothing. And a signal with no resolvable identity reads as malformed.
func TestMergeTimelineEvidence_ReasonRefinement(t *testing.T) {
	sigs := []map[string]any{
		sig("s1", "active_probe", "path", "api->x", "probe_rtt_anomaly"),     // attached
		sig("s2", "active_probe", "path", "api->y", "probe_rtt_anomaly"),     // shares 'api' token, not linked
		sig("s3", "device_telemetry", "device", "unknown", "metric_anomaly"), // malformed identity
	}
	edges := []map[string]any{
		edge("path:api->x:probe_rtt_anomaly", "path:api->z:probe_rtt_anomaly", "topo", "shared:api"),
	}
	mergeTimelineEvidence(sigs, nil, edges, "s1")
	if r := fmt.Sprintf("%v", sigs[1]["link_reason"]); !strings.Contains(r, "no edge met the attach threshold") {
		t.Errorf("s2 shares the 'api' token → below-threshold reason expected: %q", r)
	}
	if sigs[2]["link_status"] != "malformed" {
		t.Errorf("s3 (entity_id=unknown) must be malformed: %+v", sigs[2])
	}
}

// A singleton object has 0 edges; its trigger episode must still read attached
// (it IS the object), not orphaned as unlinked.
func TestMergeTimelineEvidence_SingletonTriggerAttached(t *testing.T) {
	sigs := []map[string]any{
		sig("s1", "active_probe", "path", "p->x", "probe_rtt_anomaly"),       // trigger episode
		sig("s2", "active_probe", "path", "p->x", "probe_rtt_anomaly_clear"), // its clear
	}
	counts := mergeTimelineEvidence(sigs, nil, nil, "s1")
	if counts["attached"] != 1 {
		t.Fatalf("singleton trigger episode should be attached: %+v", counts)
	}
	if sigs[0]["link_status"] != "attached" {
		t.Errorf("trigger must be attached even with no edges: %+v", sigs[0])
	}
	if sigs[1]["link_status"] != "recovery" {
		t.Errorf("the clear must be recovery: %+v", sigs[1])
	}
}

// Forward-compat: if the engine ever writes signal-level evidence rows, they ride
// along on the matching signal without affecting graph-derived attachment.
func TestMergeTimelineEvidence_SignalEvidencePassthrough(t *testing.T) {
	sigs := []map[string]any{sig("s1", "control_plane", "device", "r1", "bgp_state_anomaly")}
	evs := []map[string]any{ev("s1", "supports", "e1"), ev("s1", "discriminates", "hypA")}
	counts := mergeTimelineEvidence(sigs, evs, nil, "")
	got := sigs[0]["evidence"].([]map[string]any)
	if len(got) != 2 {
		t.Fatalf("expected 2 evidence rows, got %d", len(got))
	}
	if br := counts["by_role"].(map[string]int); br["supports"] != 1 || br["discriminates"] != 1 {
		t.Errorf("by_role rollup wrong: %+v", br)
	}
}

// No edges at all → every signal unlinked or recovery, nothing attached.
func TestMergeTimelineEvidence_NoEdgesAllUnlinked(t *testing.T) {
	sigs := []map[string]any{
		sig("s1", "device_telemetry", "device", "d1", "metric_anomaly"),
		sig("s2", "active_probe", "path", "a->b", "probe_loss"),
	}
	counts := mergeTimelineEvidence(sigs, nil, nil, "")
	if counts["attached"] != 0 || counts["unattached"] != 2 || counts["unlinked"] != 2 {
		t.Fatalf("no edges → all unlinked: %+v", counts)
	}
}

// groundingTokens MUST stay in lock-step with the Python engine's
// engine.py Node.tokens(): the ':' device-split and '->' path-split are what
// let the Inspector honestly say "shares a token" vs "no shared token at all".
// If the two implementations drift, the read-side explanation stops matching
// the gate that actually built (or refused) the edge. This pins both forms and
// the positive/negative grounding cases the lab scenarios rely on.
func TestGroundingTokens_MirrorEngineNodeTokens(t *testing.T) {
	tok := func(id string) map[string]bool {
		return groundingTokens(map[string]any{"entity_id": id})
	}

	// device-scoped interface id → {full id, device part}
	iface := tok("leaf1:Gi0/1")
	for _, want := range []string{"leaf1:Gi0/1", "leaf1"} {
		if !iface[want] {
			t.Errorf("interface id missing token %q: %v", want, iface)
		}
	}

	// two interfaces on the SAME device share the device token (local-link-fault grounding)
	if !tokensIntersect(tok("leaf1:Gi0/1"), tok("leaf1:Eth2")) {
		t.Error("two interfaces on one device must share the device token")
	}
	// interfaces on DIFFERENT devices must not share — the gate's negative case
	if tokensIntersect(tok("leaf1:Gi0/1"), tok("spine9:Eth1")) {
		t.Error("interfaces on different devices must not share a token")
	}

	// path id a->b → {full id, both endpoints}; two vantages to the SAME target
	// share the target token (the cross-vantage DIA grounding from the E2E test).
	a, b := tok("vp-a->8.8.8.8"), tok("vp-b->8.8.8.8")
	if !a["8.8.8.8"] || !a["vp-a"] {
		t.Errorf("path id must yield both endpoints: %v", a)
	}
	if a["vp-b"] {
		t.Errorf("path tokens must not include the other vantage: %v", a)
	}
	if !tokensIntersect(a, b) {
		t.Error("two vantages to the same target must share the target token")
	}

	// declared entity_tokens flow through (JSON []any and []string forms)
	if !groundingTokens(map[string]any{"entity_id": "x", "entity_tokens": []any{"site-A"}})["site-A"] {
		t.Error("declared entity_tokens ([]any) dropped")
	}
	if !groundingTokens(map[string]any{"entity_id": "x", "entity_tokens": []string{"site-B"}})["site-B"] {
		t.Error("declared entity_tokens ([]string) dropped")
	}
}
