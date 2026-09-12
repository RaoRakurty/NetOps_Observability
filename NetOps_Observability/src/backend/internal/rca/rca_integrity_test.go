// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_integrity_test.go — the pure half of Phase 1 immutability (postmortem
// spec §7): the embedded integrity block and snapshot-hash stability across
// re-renders of an unchanged analysis. The append-only tenant-keyed revision
// REGISTER tests stay with the integrator in package main.

import (
	"netops/backend/internal/ticketing"
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

// The generation wall clock leaks into the report through more than
// GeneratedAt: a CONFIRMED case stamps Decision.EscalationAt from the
// generation stamp, every symptom row carries an agoShort freshness string
// (Evidence.Symptoms[*].Last, projected into Semantics.Symptoms[*].Last), and
// a still-active case's summary strings embed the elapsed duration. None of
// these change the ANALYSIS, so none may change the snapshot hash — otherwise
// every render of a confirmed case appends a new revision (revision spam) and
// FindBySnapshot dedupe never matches.
func TestIntegritySnapshotNormalizesGenerationClock(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.9, "confirmed",
			[]string{"bgp_adjacency_change", "probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.0.0.1", "crit", "2026-07-12 18:12:30", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	build := func(now time.Time) Report {
		return BuildReport(ReportInput{
			ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Meta: meta, Signals: sigs,
			Policy: ticketing.DefaultIncidentPolicy("t1"), Now: now,
		})
	}
	rep1 := build(rcaTestNow)
	rep2 := build(rcaTestNow.Add(90 * time.Minute))

	// Fixture preconditions — the volatile fields must actually be exercised.
	if rep1.Decision.EscalationState != "triggered" || rep1.Decision.EscalationAt == "" {
		t.Fatalf("fixture must trigger escalation: %+v", rep1.Decision)
	}
	if rep1.Decision.EscalationAt == rep2.Decision.EscalationAt {
		t.Fatal("fixture must stamp different escalation times across renders")
	}
	if len(rep1.Evidence.Symptoms) == 0 || rep1.Evidence.Symptoms[0].Last == "" {
		t.Fatalf("fixture must carry symptom freshness strings: %+v", rep1.Evidence.Symptoms)
	}
	if rep1.Evidence.Symptoms[0].Last == rep2.Evidence.Symptoms[0].Last {
		t.Fatal("fixture must produce different freshness strings across renders")
	}

	integ1, err := ComputeReportIntegrity(rep1)
	if err != nil {
		t.Fatalf("integrity 1: %v", err)
	}
	integ2, err := ComputeReportIntegrity(rep2)
	if err != nil {
		t.Fatalf("integrity 2: %v", err)
	}
	if integ1.AnalysisSnapshotHash != integ2.AnalysisSnapshotHash {
		t.Fatal("an unchanged CONFIRMED analysis re-rendered later must keep its snapshot hash (EscalationAt and Symptoms[*].Last are generation-clock display fields, not analysis)")
	}

	// Normalization happens on a COPY — the caller's report (which still renders
	// these fields in the document) must not be mutated.
	if rep1.Decision.EscalationAt != FmtUTC(rcaTestNow) {
		t.Fatalf("ComputeReportIntegrity mutated Decision.EscalationAt: %q", rep1.Decision.EscalationAt)
	}
	if rep1.Evidence.Symptoms[0].Last == "" || rep1.Semantics.Symptoms[0].Last == "" {
		t.Fatal("ComputeReportIntegrity mutated the caller's Symptoms slices (shallow copy shares the backing arrays)")
	}
}
