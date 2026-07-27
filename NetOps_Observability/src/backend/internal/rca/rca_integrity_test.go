package rca

// rca_integrity_test.go — the pure half of Phase 1 immutability (postmortem
// spec §7): the embedded integrity block and snapshot-hash stability across
// re-renders of an unchanged analysis. The append-only tenant-keyed revision
// REGISTER tests stay with the integrator in package main.

import (
	"strings"
	"testing"
	"time"
)

func integrityReport(t *testing.T) Report {
	t.Helper()
	meta := testMeta("closed", "suspected", "undetermined",
		testHyp("sig.x", 0.4, "suspected", []string{"probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss_clear", "active_probe", "prober", "path", "prober->svc", "info", "2026-07-12 18:15:15", false,
			map[string]any{"clear_ts": "2026-07-12 18:15:15"}),
	}
	return buildTestReport(t, meta, sigs)
}

func TestIntegrityBlockCompleteAndStable(t *testing.T) {
	rep := integrityReport(t)
	integ, err := ComputeReportIntegrity(rep)
	if err != nil {
		t.Fatalf("integrity: %v", err)
	}
	if !strings.HasPrefix(integ.AnalysisSnapshotHash, "sha256:") || len(integ.AnalysisSnapshotHash) != len("sha256:")+64 {
		t.Fatalf("snapshot hash malformed: %q", integ.AnalysisSnapshotHash)
	}
	if integ.PolicyVersion != ReportPolicyVersion || integ.TemplateVersion != ReportTemplateVersion {
		t.Fatalf("versions missing: %+v", integ)
	}
	if integ.StatusAsOf == "" || !strings.Contains(integ.StatusAsOf, "incident ") {
		t.Fatalf("status-as-of missing: %q", integ.StatusAsOf)
	}
	if integ.ContentHash != "" {
		t.Fatal("content hash must be set only when a document is rendered")
	}

	// The SAME analysis re-generated later hashes identically (generated-at and
	// freshness strings are normalized out) — the register can be idempotent.
	rep2 := rep
	rep2.GeneratedAt = FmtUTC(rcaTestNow.Add(45 * time.Minute))
	rep2.Evidence.LastObservation = "45m ago"
	integ2, err := ComputeReportIntegrity(rep2)
	if err != nil {
		t.Fatalf("integrity2: %v", err)
	}
	if integ2.AnalysisSnapshotHash != integ.AnalysisSnapshotHash {
		t.Fatal("unchanged analysis must keep its snapshot hash across re-renders")
	}

	// A CHANGED analysis is a different snapshot.
	rep3 := rep
	rep3.States.Analysis = "confirmed"
	integ3, _ := ComputeReportIntegrity(rep3)
	if integ3.AnalysisSnapshotHash == integ.AnalysisSnapshotHash {
		t.Fatal("a changed analysis must change the snapshot hash")
	}
}
