package main

import (
	"fmt"
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
		"9f0537bd-0787-547e-a6fc-6692acaec13cX",          // too long
		"9f0537bd-0787-547e-a6fc-6692acaec13'",           // quote
		"9f0537bd_0787_547e_a6fc_6692acaec13c",           // wrong separators
		"zf0537bd-0787-547e-a6fc-6692acaec13c",           // non-hex
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
	valid := []string{"2026-06-14 05:11:39.836", "2026-06-14 05:11:39", "2026-01-01 00:00:00.000"}
	for _, v := range valid {
		if !isDatetimeToken(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	invalid := []string{
		"",
		"short",                                           // < 10 chars
		"2026-06-14 05:11:39'; DROP",                      // quote + injection
		"now() - INTERVAL 1 DAY",                          // function call (parens/letters)
		"2026-06-14T05:11:39Z",                            // T/Z not allowed (we emit space form)
		"2026-06-14 05:11:39.836xxxxxxxxxxxxxxxxxxxxxxxx", // too long (> 32)
	}
	for _, v := range invalid {
		if isDatetimeToken(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}

func sig(id, modality string) map[string]any {
	return map[string]any{"signal_id": id, "modality_class": modality}
}
func ev(signalID, role, subjectID string) map[string]any {
	return map[string]any{"signal_id": signalID, "role": role, "subject_kind": "edge", "subject_id": subjectID, "note": ""}
}

// The timeline join must mark every window signal attached/unattached, attach
// its evidence role(s), flag the trigger, and roll up counts — the data behind
// "what happened, what the engine attached vs ignored, which planes, what
// contradicts". Pure join, no ClickHouse.
func TestMergeTimelineEvidence_AttachedUnattachedAndCounts(t *testing.T) {
	sigs := []map[string]any{
		sig("s1", "device_telemetry"), // trigger + supported
		sig("s2", "control_plane"),    // supported
		sig("s3", "passive_flow"),     // contradicts
		sig("s4", "device_telemetry"), // UNATTACHED (concurrent, engine ignored)
	}
	evs := []map[string]any{
		ev("s1", "supports", "e1"),
		ev("s2", "supports", "e1"),
		ev("s3", "contradicts", "e1"),
	}
	counts := mergeTimelineEvidence(sigs, evs, "s1")

	if counts["total"] != 4 || counts["attached"] != 3 || counts["unattached"] != 1 {
		t.Fatalf("bad counts: %+v", counts)
	}
	byRole := counts["by_role"].(map[string]int)
	if byRole["supports"] != 2 || byRole["contradicts"] != 1 {
		t.Errorf("bad by_role: %+v", byRole)
	}
	byMod := counts["by_modality"].(map[string]int)
	if byMod["device_telemetry"] != 2 || byMod["control_plane"] != 1 || byMod["passive_flow"] != 1 {
		t.Errorf("bad by_modality: %+v", byMod)
	}
	// per-signal enrichment
	if sigs[0]["attached"] != true || sigs[0]["is_trigger"] != true {
		t.Errorf("s1 should be attached + trigger: %+v", sigs[0])
	}
	if got := sigs[0]["evidence"].([]map[string]any); len(got) != 1 || got[0]["role"] != "supports" {
		t.Errorf("s1 evidence role wrong: %+v", sigs[0]["evidence"])
	}
	if sigs[3]["attached"] != false || sigs[3]["is_trigger"] != false {
		t.Errorf("s4 must be unattached + not trigger (concurrent, ignored): %+v", sigs[3])
	}
	if sigs[3]["evidence"] != nil {
		// nil slice → JSON null; ensure no phantom evidence on an unattached signal
		if ev, ok := sigs[3]["evidence"].([]map[string]any); ok && len(ev) != 0 {
			t.Errorf("unattached signal must carry no evidence: %+v", ev)
		}
	}
}

// A signal supporting multiple subjects keeps all its evidence rows.
func TestMergeTimelineEvidence_MultiSubject(t *testing.T) {
	sigs := []map[string]any{sig("s1", "control_plane")}
	evs := []map[string]any{ev("s1", "supports", "e1"), ev("s1", "discriminates", "hypA")}
	mergeTimelineEvidence(sigs, evs, "")
	got := sigs[0]["evidence"].([]map[string]any)
	if len(got) != 2 {
		t.Fatalf("expected 2 evidence rows, got %d", len(got))
	}
}

// Honest "nothing proven yet": no evidence → every signal unattached, empty roles.
func TestMergeTimelineEvidence_NoEvidence(t *testing.T) {
	sigs := []map[string]any{sig("s1", "device_telemetry"), sig("s2", "active_probe")}
	counts := mergeTimelineEvidence(sigs, nil, "")
	if counts["attached"] != 0 || counts["unattached"] != 2 {
		t.Fatalf("no evidence → all unattached: %+v", counts)
	}
	if len(counts["by_role"].(map[string]int)) != 0 {
		t.Errorf("by_role must be empty with no evidence")
	}
	for _, s := range sigs {
		if s["attached"] != false {
			t.Errorf("signal must be unattached: %+v", s)
		}
	}
}

// Guard the contract that the response shape is JSON-marshalable maps (no typed
// structs leaking) — fmt-based key access mirrors what the handler does.
func TestMergeTimelineEvidence_TriggerOnlyFlagsTrigger(t *testing.T) {
	sigs := []map[string]any{sig("s1", "x"), sig("s2", "x")}
	mergeTimelineEvidence(sigs, nil, "s2")
	if fmt.Sprintf("%v", sigs[0]["is_trigger"]) != "false" || fmt.Sprintf("%v", sigs[1]["is_trigger"]) != "true" {
		t.Errorf("only s2 should be the trigger")
	}
}
