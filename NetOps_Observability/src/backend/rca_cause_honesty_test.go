package main

// rca_cause_honesty_test.go — #113 point 4: wherever a root cause is not
// identified, the document pairs the honest non-claim with the best live
// hypothesis ("possibly because of X") and its evidence STATE (what is in
// hand, what is still missing — including the engine's own evidence_missing
// shortfalls). A bare "Not identified" is banned when a hypothesis exists;
// with no hypothesis, the absence is stated, never guessed.

import (
	"strings"
	"testing"
)

func TestCauseHonestyPossiblyBecauseOfWithEvidenceState(t *testing.T) {
	meta := testMeta("open", "suspected", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.5, "suspected",
			[]string{"bgp_adjacency_change"}, []string{"probe_loss"}, nil, "isp", false))
	meta["evidence_missing"] = `["path hop 10.0.0.9 did not respond — unknown segment preserved, not bridged"]`
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	rc := rep.RootCause
	if rc.Identified {
		t.Fatal("suspected case must not identify a root cause")
	}
	if !strings.Contains(rc.Statement, "possibly because of ") {
		t.Fatalf("statement lacks the possibly-wording: %q", rc.Statement)
	}
	if rc.PossibleCause == "" {
		t.Fatal("possible_cause must name the best hypothesis")
	}
	if len(rc.EvidenceKnown) == 0 {
		t.Fatalf("evidence_known must carry the satisfied evidence: %+v", rc)
	}
	// hypothesis gaps AND the object's own evidence_missing both surface
	joined := strings.Join(rc.EvidenceMissing, " | ")
	if !strings.Contains(joined, "path hop 10.0.0.9") {
		t.Fatalf("object-level evidence_missing lost: %v", rc.EvidenceMissing)
	}

	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	for _, want := range []string{
		"possibly because of", "Possible cause (unconfirmed)",
		"Evidence in hand", "Evidence still missing",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("rendered report missing %q", want)
		}
	}
	// the Key facts row must not render the dead-end wording
	if strings.Contains(doc, ">Not identified<") {
		t.Fatal("bare 'Not identified' rendered despite a live hypothesis")
	}
}

func TestCauseHonestyNoHypothesisStatesAbsence(t *testing.T) {
	meta := testMeta("open", "undetermined", "undetermined", nil)
	rep := buildTestReport(t, meta, []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true, nil),
	})
	rc := rep.RootCause
	if rc.PossibleCause != "" || len(rc.EvidenceKnown) != 0 {
		t.Fatalf("no-hypothesis case must not invent a possible cause: %+v", rc)
	}
	if rc.Statement != "Root cause has not been identified." {
		t.Fatalf("statement = %q", rc.Statement)
	}
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(string(html), "no cause hypothesis has supporting evidence yet") {
		t.Fatal("key facts must state the honest absence, not a bare 'Not identified'")
	}
}

func TestCauseHonestyContradictedHypothesisIsNeverThePossibleCause(t *testing.T) {
	meta := testMeta("open", "suspected", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.2, "suspected",
			[]string{"bgp_adjacency_change"}, nil, nil, "isp", true)) // contradicted
	rep := buildTestReport(t, meta, []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
	})
	if rep.RootCause.PossibleCause != "" {
		t.Fatalf("a ruled-out hypothesis must never be offered as the possible cause: %+v", rep.RootCause)
	}
}
