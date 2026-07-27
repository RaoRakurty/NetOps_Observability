package rca

import (
	"testing"
)

// (Test 10) a hypothesis whose required confirmation evidence is still MISSING
// cannot render as confirmed — it stays observed (P1 issue-family confirmation
// gate; the "underlay confirmed while missing = observe underlay status" defect).
// Generic across issue families.
func TestHypothesisConfirmedRequiresNoMissingEvidence(t *testing.T) {
	// verdict says confirmed, but the hypothesis still needs underlay evidence.
	hyp := testHyp("sig.ent.cloud.underlay-path-down", 0.9, "confirmed",
		[]string{"probe_loss"}, []string{"underlay_status|route_to_peer_missing"}, nil, "netops", false)
	meta := testMeta("open", "confirmed", "sig.ent.cloud.underlay-path-down", hyp)
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.60.10.10", "crit",
			"2026-07-12 18:12:00", true, map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if !rep.Quality.Passed {
		t.Fatalf("builder emitted a report failing its own gate: %+v", rep.Quality.Errors)
	}
	if len(rep.Hypotheses) == 0 {
		t.Fatal("no hypotheses rendered")
	}
	h := rep.Hypotheses[0]
	if h.ObservationState == "confirmed" {
		t.Fatalf("hypothesis with missing required evidence must not be confirmed: %+v", h)
	}
	if len(h.Missing) == 0 {
		t.Fatal("expected the hypothesis to carry missing required evidence")
	}
}
