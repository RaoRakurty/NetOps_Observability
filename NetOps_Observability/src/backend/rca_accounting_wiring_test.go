package main

import "testing"

// TestAccounting_WiredIntoBuildRcaReport verifies buildRcaReport derives the
// EvidenceAccounting from the same window slice it renders — the counts reconcile
// with the report's own signal summary, and a well-formed case carries no
// invariant error. (Also the sole non-test reader of rep.evidenceAccounting.)
func TestAccounting_WiredIntoBuildRcaReport(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.9, "confirmed",
			[]string{"bgp_adjacency_change", "probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss", "active_probe", "lan-vantage-1", "path", "lan-vantage-1->10.0.0.1", "crit", "2026-07-12 18:12:30", true,
			map[string]any{"probe_scope": "customer_path", "probe_authority": "high"}),
		// unattached window filler (not case-linked)
		testSig("probe_ok", "active_probe", "prober", "path", "prober->10.0.0.1", "info", "2026-07-12 18:11:00", false, nil),
	}
	rep := buildTestReport(t, meta, sigs)

	acc, err := rep.evidenceAccounting()
	if err != nil {
		t.Fatalf("accounting invariant error on a well-formed report: %v", err)
	}
	if acc.WindowObservationCount() != 3 {
		t.Errorf("window observations = %d, want 3", acc.WindowObservationCount())
	}
	if acc.CaseLinkedSignalCount() != 2 {
		t.Errorf("case-linked = %d, want 2", acc.CaseLinkedSignalCount())
	}
	// control_plane device + high-authority vantage probe → 2 independent sources.
	if acc.IndependentObserverCount() != 2 {
		t.Errorf("independent sources = %d, want 2", acc.IndependentObserverCount())
	}
	// The accounting's case-linked count must equal the rendered summary's attached.
	if acc.CaseLinkedSignalCount() != rep.Signals.Attached {
		t.Errorf("accounting case-linked (%d) disagrees with signal_summary.attached (%d)",
			acc.CaseLinkedSignalCount(), rep.Signals.Attached)
	}
	// The reconciliation ladder is populated (constraint 10).
	if len(acc.Ladder.Rungs) == 0 {
		t.Errorf("reconciliation ladder is empty")
	}
}
